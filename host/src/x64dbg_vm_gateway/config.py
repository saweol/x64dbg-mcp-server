"""Gateway configuration model.

The dataclasses below are a shared contract (other modules import them).
Feature A owns ``load_config`` / ``default_config_path`` / validation and may
ADD optional fields, but must not rename or remove existing ones.

File format: TOML (see docs/VM_ORCHESTRATION_PLAN.md section 5.1 for an example).
Secrets are never stored in the file: only the NAME of an environment variable
(``*_env`` fields) is stored, and values are resolved lazily via ``resolve_secret``.

Validation errors are ``ConfigError`` whose message names the offending dotted
key (e.g. ``profiles.win10.backends.x64.port``) and whose ``details`` carry
``{"key": <dotted key>, "path": <config file>}``. Error messages never include
values read from the file, so a secret pasted into the wrong key cannot leak
through an error message or log line.

Thread-safety: loading is a pure function of the file contents and the given
environment; the resulting dataclasses are immutable.
"""

from __future__ import annotations

import ipaddress
import math
import os
import posixpath
import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath
from typing import Any
from urllib.parse import urlsplit

from .contracts import Secret
from .errors import ConfigError
from .platform import host_system


@dataclass(frozen=True)
class BackendConfig:
    id: str  # "x64" | "x32" | custom
    arch: str  # "x64" | "x32"
    port: int | None = None  # vmware mode: http://<guest_host>:<port>/
    url: str | None = None  # endpoint mode (or explicit override)
    exe: str | None = None  # guest path of x64dbg.exe / x32dbg.exe
    config: str | None = None  # guest path of mcp_config.json (token_source=guest-config)
    launch_task: str | None = None  # schtasks name used for (elevated) relaunch
    token_env: str | None = None  # env var holding the bearer token (token_source=env)


@dataclass(frozen=True)
class RetentionConfig:
    max_gateway_snapshots: int = 10
    max_age_days: int = 14


@dataclass(frozen=True)
class ProfileConfig:
    name: str
    mode: str = "vmware"  # "vmware" | "endpoint"
    vmx: str | None = None
    vmrun: str = "auto"  # path or "auto"
    vmrun_type: str = "auto"  # "ws" | "fusion" | "auto"
    clean_snapshot: str | None = None
    protected_snapshots: tuple[str, ...] = ()
    guest_user: str | None = None
    guest_password_env: str | None = None
    guest_host: str = "auto"  # "auto" (vmrun getGuestIPAddress) or a fixed host/IP
    job_root_guest: str = "C:\\mcp\\jobs"
    require_isolation: bool = True
    token_source: str = "guest-config"  # noqa: S105 - "guest-config" | "env", not a secret
    snapshot_prefix: str = "gw-"
    retention: RetentionConfig = field(default_factory=RetentionConfig)
    backends: tuple[BackendConfig, ...] = ()
    relaunch_mode: str = "task"  # "task" (schtasks /run) | "direct" (runProgramInGuest -interactive)


@dataclass(frozen=True)
class HttpServerConfig:
    """Gateway's own streamable-HTTP front-end (M3: other PCs connect to the gateway)."""

    enabled: bool = False
    bind: str = "127.0.0.1"
    port: int = 9100
    tls_cert: str | None = None
    tls_key: str | None = None
    allow_clients: tuple[str, ...] = ()  # CIDRs; empty = loopback only
    token_envs: dict[str, str] = field(default_factory=dict)  # scope -> env var: read|analyze|admin


@dataclass(frozen=True)
class GatewayConfig:
    jobs_root: str = "~/mcp-lab/jobs"
    default_profile: str | None = None
    max_call_s: float = 110.0  # client tool-call budget (see plan 5.5)
    profiles: dict[str, ProfileConfig] = field(default_factory=dict)
    http: HttpServerConfig = field(default_factory=HttpServerConfig)
    config_path: str | None = None

    def profile(self, name: str | None = None) -> ProfileConfig:
        key = name or self.default_profile
        if key is None:
            if len(self.profiles) == 1:
                return next(iter(self.profiles.values()))
            raise ConfigError("no profile selected and no default_profile configured")
        try:
            return self.profiles[key]
        except KeyError:
            raise ConfigError(f"unknown profile: {key!r}") from None

    @property
    def jobs_root_path(self) -> Path:
        return Path(self.jobs_root).expanduser()


def resolve_secret(env_name: str | None, environ: dict[str, str] | None = None) -> Secret | None:
    """Return the secret stored in environment variable ``env_name`` (or None)."""
    if not env_name:
        return None
    env = os.environ if environ is None else environ
    val = env.get(env_name)
    return Secret(val) if val else None


# ════════════════════════════════════════════════════════════════════
# Loader (feature A)
# ════════════════════════════════════════════════════════════════════

ENV_CONFIG_PATH = "X64DBG_VM_GATEWAY_CONFIG"
APP_DIR_NAME = "x64dbg-vm-gateway"
CONFIG_FILE_NAME = "config.toml"

MODES = ("vmware", "endpoint")
VMRUN_TYPES = ("ws", "fusion", "auto")
TOKEN_SOURCES = ("guest-config", "env")
RELAUNCH_MODES = ("task", "direct")
ARCHES = ("x64", "x32")
HTTP_SCOPES = ("read", "analyze", "admin")

_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_PROFILE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_BACKEND_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")

# Keys that look like an inline secret. Matching keys are refused outright.
_SECRET_KEYS = frozenset({"guest_password", "password", "passwd", "token", "auth_token", "secret",
                          "api_key", "apikey"})
_SECRET_SUFFIXES = ("_password", "_passwd", "_token", "_secret", "_api_key", "_apikey")
_SECRET_KEY_SUGGESTION = {
    "guest_password": "guest_password_env",
    "password": "guest_password_env",
    "passwd": "guest_password_env",
    "token": "token_env",
    "auth_token": "token_env",
    "bearer_token": "token_env",
}

# Value kinds used by the schema below.
_STR, _FLOAT, _INT, _BOOL, _STR_LIST, _STR_MAP = "string", "number", "integer", "boolean", "array", "table"

# File keys per section -> kind. Structural keys (sub-tables) are listed separately.
_GATEWAY_KEYS = {"jobs_root": _STR, "default_profile": _STR, "max_call_s": _FLOAT}
_GATEWAY_STRUCTURAL = frozenset({"profiles", "http", "config_path"})
_HTTP_KEYS = {"enabled": _BOOL, "bind": _STR, "port": _INT, "tls_cert": _STR, "tls_key": _STR,
              "allow_clients": _STR_LIST, "token_envs": _STR_MAP}
_PROFILE_KEYS = {
    "mode": _STR, "vmx": _STR, "vmrun": _STR, "vmrun_type": _STR, "clean_snapshot": _STR,
    "protected_snapshots": _STR_LIST, "guest_user": _STR, "guest_password_env": _STR,
    "guest_host": _STR, "job_root_guest": _STR, "require_isolation": _BOOL, "token_source": _STR,
    "snapshot_prefix": _STR, "relaunch_mode": _STR,
}
_PROFILE_STRUCTURAL = frozenset({"name", "retention", "backends"})
_RETENTION_KEYS = {"max_gateway_snapshots": _INT, "max_age_days": _INT}
_BACKEND_KEYS = {"id": _STR, "arch": _STR, "port": _INT, "url": _STR, "exe": _STR, "config": _STR,
                 "launch_task": _STR, "token_env": _STR}

_SECTION_FIELDS: dict[str, frozenset[str]] = {
    "gateway": frozenset(_GATEWAY_KEYS) | _GATEWAY_STRUCTURAL,
    "http": frozenset(_HTTP_KEYS),
    "profile": frozenset(_PROFILE_KEYS) | _PROFILE_STRUCTURAL,
    "retention": frozenset(_RETENTION_KEYS),
    "backend": frozenset(_BACKEND_KEYS),
}


def schema_field_names(section: str) -> frozenset[str]:
    """Dataclass field names the loader handles for ``section`` (drift guard for tests)."""
    return _SECTION_FIELDS[section]


def _looks_like_inline_secret(key: str) -> bool:
    k = key.lower()
    if k.endswith(("_env", "_envs")):
        return False
    return k in _SECRET_KEYS or k.endswith(_SECRET_SUFFIXES)


def default_config_path(*, system: str | None = None, environ: Mapping[str, str] | None = None) -> Path:
    """Per-OS default config location.

    Linux/macOS: ``$XDG_CONFIG_HOME/x64dbg-vm-gateway/config.toml`` when
    XDG_CONFIG_HOME is an absolute path, else ``~/.config/x64dbg-vm-gateway/config.toml``.
    Windows: ``%APPDATA%\\x64dbg-vm-gateway\\config.toml``.
    """
    env = os.environ if environ is None else environ
    if host_system(system) == "Windows":
        appdata = env.get("APPDATA")
        if not appdata:
            profile = env.get("USERPROFILE") or str(Path.home())
            appdata = str(PureWindowsPath(profile, "AppData", "Roaming"))
        return Path(str(PureWindowsPath(appdata, APP_DIR_NAME, CONFIG_FILE_NAME)))
    xdg = env.get("XDG_CONFIG_HOME")
    if xdg and posixpath.isabs(xdg):
        base = xdg
    else:
        base = posixpath.join(env.get("HOME") or str(Path.home()), ".config")
    return Path(posixpath.join(base, APP_DIR_NAME, CONFIG_FILE_NAME))


def load_config(
    path: Path | str | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    system: str | None = None,
) -> GatewayConfig:
    """Load and validate the gateway config.

    Path resolution: explicit ``path`` > env ``X64DBG_VM_GATEWAY_CONFIG`` >
    ``default_config_path()``. Raises ConfigError on any problem.
    """
    env = os.environ if environ is None else environ
    if path is not None:
        source = Path(path).expanduser()
    elif env.get(ENV_CONFIG_PATH):
        source = Path(env[ENV_CONFIG_PATH]).expanduser()
    else:
        source = default_config_path(system=system, environ=env)
    where = str(source)

    try:
        raw = source.read_bytes()
    except FileNotFoundError:
        raise ConfigError(
            f"config file not found: {where}",
            stage="config",
            hint=f"run `x64dbg-vm-gateway init`, or point {ENV_CONFIG_PATH} at a config file",
            details={"path": where},
        ) from None
    except OSError as e:
        raise ConfigError(f"cannot read config file {where}: {e.strerror}", stage="config",
                          details={"path": where}) from None
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except UnicodeDecodeError:
        raise ConfigError(f"config file is not valid UTF-8: {where}", stage="config",
                          details={"path": where}) from None
    except tomllib.TOMLDecodeError as e:
        # tomllib messages carry only a description and line/column, never file content.
        raise ConfigError(f"invalid TOML in {where}: {e}", stage="config", details={"path": where}) from None
    return config_from_dict(data, source=where)


def config_from_dict(data: Mapping[str, Any], *, source: str | None = None) -> GatewayConfig:
    """Validate an already-parsed TOML document (e.g. built by ``init``)."""
    return _Parser(source).gateway(data)


class _Parser:
    """Validates one document; ``source`` is only used for error context."""

    def __init__(self, source: str | None) -> None:
        self.source = source

    # ── error helpers ───────────────────────────────────────────────
    def error(self, key: str, problem: str, hint: str | None = None) -> ConfigError:
        where = f" (in {self.source})" if self.source else ""
        return ConfigError(f"config key {key}: {problem}{where}", stage="config", hint=hint,
                           details={"key": key, "path": self.source})

    def check_keys(self, table: Mapping[str, Any], prefix: str, allowed: frozenset[str] | set[str]) -> None:
        for key in table:
            dotted = f"{prefix}.{key}" if prefix else key
            if _looks_like_inline_secret(key):
                suggestion = _SECRET_KEY_SUGGESTION.get(key.lower(), "the matching *_env key")
                raise self.error(
                    dotted,
                    "inline secrets are not allowed in the config file; store the secret in an "
                    f"environment variable and put the variable NAME in {suggestion}",
                    hint="supported *_env keys: profiles.<name>.guest_password_env, "
                         "profiles.<name>.backends.<id>.token_env, http.token_envs.<scope>",
                )
            if key not in allowed:
                raise self.error(dotted, "unknown key")

    def table(self, value: Any, key: str) -> Mapping[str, Any]:
        if not isinstance(value, dict):
            raise self.error(key, f"expected a table, got {_type_name(value)}")
        return value

    def typed(self, value: Any, kind: str, key: str) -> Any:
        ok = {
            _STR: isinstance(value, str),
            _INT: isinstance(value, int) and not isinstance(value, bool),
            _FLOAT: isinstance(value, int | float) and not isinstance(value, bool),
            _BOOL: isinstance(value, bool),
            _STR_LIST: isinstance(value, list) and all(isinstance(v, str) for v in value),
            _STR_MAP: isinstance(value, dict) and all(isinstance(v, str) for v in value.values()),
        }[kind]
        if not ok:
            want = "an array of strings" if kind == _STR_LIST else (
                "a table of strings" if kind == _STR_MAP else f"a {kind}")
            raise self.error(key, f"expected {want}, got {_type_name(value)}")
        if kind == _STR and not value.strip():
            # No string setting has a meaningful empty value: an empty path, host or
            # name only fails later and further from its cause. (An empty
            # snapshot_prefix would even make every snapshot look gateway-owned.)
            raise self.error(key, "must not be empty")
        if kind == _FLOAT:
            return float(value)
        if kind == _STR_LIST:
            return tuple(value)
        if kind == _STR_MAP:
            return dict(value)
        return value

    def fields(self, table: Mapping[str, Any], prefix: str, schema: Mapping[str, str]) -> dict[str, Any]:
        return {k: self.typed(v, schema[k], f"{prefix}.{k}") for k, v in table.items() if k in schema}

    def choice(self, value: str, allowed: tuple[str, ...], key: str) -> str:
        if value not in allowed:
            raise self.error(key, f"must be one of {', '.join(allowed)}")
        return value

    def port(self, value: int, key: str) -> int:
        if not 1 <= value <= 65535:
            raise self.error(key, "port must be in 1..65535")
        return value

    def env_name(self, value: str, key: str) -> str:
        if not _ENV_NAME_RE.match(value):
            # Never echo the value: users sometimes paste the secret itself here.
            raise self.error(key, "must be the NAME of an environment variable ([A-Za-z_][A-Za-z0-9_]*)",
                             hint="put the secret in the environment and only its variable name here")
        return value

    # ── sections ────────────────────────────────────────────────────
    def gateway(self, data: Mapping[str, Any]) -> GatewayConfig:
        self.check_keys(data, "", {"gateway", "http", "profiles"})
        gw = self.table(data.get("gateway", {}), "gateway")
        self.check_keys(gw, "gateway", set(_GATEWAY_KEYS))
        values = self.fields(gw, "gateway", _GATEWAY_KEYS)
        if "max_call_s" in values and not (math.isfinite(values["max_call_s"]) and values["max_call_s"] > 0):
            raise self.error("gateway.max_call_s", "must be a finite number greater than 0")

        http = self.http(self.table(data.get("http", {}), "http"))

        profiles_tbl = self.table(data.get("profiles", {}), "profiles")
        profiles: dict[str, ProfileConfig] = {}
        for name, body in profiles_tbl.items():
            profiles[name] = self.profile(name, self.table(body, f"profiles.{name}"))

        default = values.get("default_profile")
        if default is not None and default not in profiles:
            raise self.error("gateway.default_profile",
                             "names a profile that is not defined under [profiles]")
        return GatewayConfig(**values, profiles=profiles, http=http, config_path=self.source)

    def http(self, tbl: Mapping[str, Any]) -> HttpServerConfig:
        self.check_keys(tbl, "http", set(_HTTP_KEYS))
        values = self.fields(tbl, "http", _HTTP_KEYS)
        if "port" in values:
            self.port(values["port"], "http.port")
        for i, cidr in enumerate(values.get("allow_clients", ())):
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                raise self.error(f"http.allow_clients[{i}]", "not a valid IP address or CIDR") from None
        for scope, env in values.get("token_envs", {}).items():
            key = f"http.token_envs.{scope}"
            if scope not in HTTP_SCOPES:
                raise self.error(key, f"unknown scope (expected one of {', '.join(HTTP_SCOPES)})")
            self.env_name(env, key)
        has_cert, has_key = "tls_cert" in values, "tls_key" in values
        if has_cert != has_key:
            missing = "http.tls_key" if has_cert else "http.tls_cert"
            raise self.error(missing, "tls_cert and tls_key must be set together")
        bind = values.get("bind", HttpServerConfig.bind)
        if values.get("enabled") and not values.get("token_envs") and not _is_loopback_host(bind):
            raise self.error(
                "http.token_envs",
                "required when http.enabled = true and http.bind is not a loopback address "
                "(other machines could otherwise call the gateway without authentication)",
                hint="set http.token_envs.<read|analyze|admin> to environment variable NAMES",
            )
        return HttpServerConfig(**values)

    def profile(self, name: str, tbl: Mapping[str, Any]) -> ProfileConfig:
        prefix = f"profiles.{name}"
        if not _PROFILE_NAME_RE.match(name):
            raise self.error(prefix, "profile names may only contain letters, digits, '_', '-' and '.'")
        self.check_keys(tbl, prefix, set(_PROFILE_KEYS) | {"retention", "backends"})
        values = self.fields(tbl, prefix, _PROFILE_KEYS)

        mode = self.choice(values.get("mode", "vmware"), MODES, f"{prefix}.mode")
        if "vmrun_type" in values:
            self.choice(values["vmrun_type"], VMRUN_TYPES, f"{prefix}.vmrun_type")
        token_source = self.choice(values.get("token_source", "guest-config"), TOKEN_SOURCES,
                                   f"{prefix}.token_source")
        if mode == "endpoint":
            if values.get("token_source") == "guest-config":  # noqa: S105 - enum value, not a secret
                raise self.error(f"{prefix}.token_source",
                                 "guest-config is not available in endpoint mode (there is no guest to "
                                 "read mcp_config.json from); use \"env\" with token_env on each backend")
            # Endpoint profiles can only take their token from the environment.
            token_source = values["token_source"] = "env"  # noqa: S105 - enum value, not a secret
        if "relaunch_mode" in values:
            self.choice(values["relaunch_mode"], RELAUNCH_MODES, f"{prefix}.relaunch_mode")
        if mode == "vmware" and not values.get("vmx"):
            raise self.error(f"{prefix}.vmx", "required when mode = \"vmware\"")
        if "guest_password_env" in values:
            self.env_name(values["guest_password_env"], f"{prefix}.guest_password_env")

        retention = self.retention(self.table(tbl.get("retention", {}), f"{prefix}.retention"),
                                   f"{prefix}.retention")
        backends_tbl = self.table(tbl.get("backends", {}), f"{prefix}.backends")
        backends: list[BackendConfig] = []
        seen: set[str] = set()
        for key, body in backends_tbl.items():
            dotted = f"{prefix}.backends.{key}"
            b = self.backend(key, self.table(body, dotted), dotted, mode)
            if b.id in seen:
                raise self.error(f"{dotted}.id", "duplicate backend id")
            seen.add(b.id)
            if token_source == "env" and not b.token_env:  # noqa: S105 - enum value, not a secret
                why = "in endpoint mode" if mode == "endpoint" else "when token_source = \"env\""
                raise self.error(f"{dotted}.token_env", f"required {why}")
            if token_source == "guest-config" and not b.config:  # noqa: S105 - enum value, not a secret
                raise self.error(f"{dotted}.config",
                                 "required when token_source = \"guest-config\" (guest path of the "
                                 "backend's mcp_config.json)")
            backends.append(b)

        if mode == "vmware" and token_source == "guest-config" and backends:  # noqa: S105 - enum value
            # Reading mcp_config.json out of the guest needs guest credentials.
            for key in ("guest_user", "guest_password_env"):
                if key not in values:
                    raise self.error(f"{prefix}.{key}",
                                     "required when token_source = \"guest-config\" (the backend token is "
                                     "read from mcp_config.json inside the guest)")

        return ProfileConfig(name=name, **values, retention=retention, backends=tuple(backends))

    def retention(self, tbl: Mapping[str, Any], prefix: str) -> RetentionConfig:
        self.check_keys(tbl, prefix, set(_RETENTION_KEYS))
        values = self.fields(tbl, prefix, _RETENTION_KEYS)
        for k, v in values.items():
            if v < 0:
                raise self.error(f"{prefix}.{k}", "must be >= 0")
        return RetentionConfig(**values)

    def backend(self, key: str, tbl: Mapping[str, Any], dotted: str, mode: str) -> BackendConfig:
        self.check_keys(tbl, dotted, set(_BACKEND_KEYS))
        values = self.fields(tbl, dotted, _BACKEND_KEYS)

        bid = values.pop("id", key)
        if not _BACKEND_ID_RE.match(bid):
            raise self.error(f"{dotted}.id" if "id" in tbl else dotted,
                             "backend ids may only contain letters, digits, '_' and '-'")
        arch = values.pop("arch", None)
        if arch is None:
            if bid not in ARCHES:
                raise self.error(f"{dotted}.arch", "required when the backend id is not x64 or x32")
            arch = bid
        self.choice(arch, ARCHES, f"{dotted}.arch")

        if "port" in values:
            self.port(values["port"], f"{dotted}.port")
        if "url" in values and not _is_http_url(values["url"]):
            raise self.error(f"{dotted}.url", "must be an http:// or https:// URL with a host")
        if "token_env" in values:
            self.env_name(values["token_env"], f"{dotted}.token_env")
        if mode == "endpoint" and "url" not in values:
            raise self.error(f"{dotted}.url", "required when mode = \"endpoint\"")
        if "port" not in values and "url" not in values:
            raise self.error(dotted, "a backend needs a port (vmware mode) or a url")
        return BackendConfig(id=bid, arch=arch, **values)


def _is_loopback_host(host: str) -> bool:
    """True for "localhost" and loopback IP literals; any other name counts as exposed."""
    if host.strip().lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip()).is_loopback
    except ValueError:
        return False


def _is_http_url(url: str) -> bool:
    try:
        parts = urlsplit(url)
        _ = parts.port  # raises ValueError for a non-numeric or out-of-range port
    except ValueError:
        return False
    return parts.scheme in ("http", "https") and bool(parts.hostname)


def _type_name(value: Any) -> str:
    return {bool: "boolean", int: "integer", float: "number", str: "string", list: "array",
            dict: "table"}.get(type(value), type(value).__name__)
