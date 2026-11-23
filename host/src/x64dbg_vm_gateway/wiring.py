"""Wiring: turn a ``GatewayConfig`` profile into live components (plan 3.1, 5.1).

``build_runtime`` assembles one :class:`Runtime` per profile: VM provider, vmrun
runner, guest channel, backend clients, supervisor, proxy, tool catalog and the
VM operation lock. ``build_app`` returns the orchestrator (``app.Gateway``) that
builds runtimes lazily, so constructing it never touches the VM, the guest or
the jobs directory.

Secrets: values are looked up by the ``*_env`` names of the config in an
environment mapping built by :func:`resolve_environ` (the process environment
over the optional ``gateway.env_file``); ``os.environ`` is never modified.
Guest passwords and bearer tokens only travel as ``contracts.Secret`` and never
appear in reprs, log lines or exception text.

Backend endpoints are resolved lazily. Until :meth:`Runtime.connect` resolved
a backend (guest IP + token), its entry in ``Runtime.clients`` is an
:class:`UnresolvedClient` placeholder, so the supervisor and the proxy (which
share that dict) always find every configured backend id. The placeholder
reports itself unhealthy and refuses calls with ``VmNotReady``; callers must
``connect`` before asking the supervisor to recover a backend.

Thread-safety: ``Runtime`` guards its caches (guest IP, tokens, resolved
clients) with one re-entrant lock that is held only for in-memory work, never
across guest or VM I/O (token copies, ``getGuestIPAddress``) and never while
waiting for ``VmOpLock``. Token reads of one backend are serialised by a
per-backend lock, so a slow read never blocks ``resolved_url``/``guest_ip`` or
``session_status``. A token generation counter (bumped whenever tokens are
dropped, e.g. after a revert) keeps a read that raced with the drop from being
cached or published.
"""

from __future__ import annotations

import inspect
import json
import logging
import os
import re
import stat
import tempfile
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from . import platform as gw_platform
from .backend import HttpBackendClient
from .catalog import ToolCatalog, builtin_for_version, default_cache_dir, version_tuple
from .config import BackendConfig, GatewayConfig, ProfileConfig, resolve_secret
from .contracts import (
    BackendClient,
    BackendEndpoint,
    Clock,
    GuestChannel,
    GuestCredentials,
    Secret,
    SystemClock,
    ToolCallResult,
    ToolInfo,
    VmProvider,
    VmrunRunner,
)
from .errors import (
    BackendAuthError,
    BackendError,
    CancelledByVmOp,
    ConfigError,
    GuestOperationError,
    VmNotReady,
)
from .guest import VixChannel
from .locks import VmOpLock
from .proxy import Proxy
from .supervisor import HealthReport, Supervisor
from .vmrun import NullProvider, VmrunCli, VmrunProvider

if TYPE_CHECKING:  # app imports wiring; avoid the cycle at runtime
    from .app import Gateway

log = logging.getLogger(__name__)

__all__ = [
    "BUILTIN_V1_9",
    "BUILTIN_V1_10",
    "GUEST_IP_TIMEOUT_S",
    "MAX_GUEST_CONFIG_BYTES",
    "MIN_TOKEN_LEN",
    "PROVISION_HINT",
    "Runtime",
    "UnresolvedClient",
    "build_app",
    "build_runtime",
    "builtin_catalog_for",
    "guest_credentials",
    "make_catalog",
    "parse_guest_token",
    "read_env_file",
    "resolve_environ",
]

PROVISION_HINT = "run: x64dbg-vm-gateway provision"
#: Shortest AuthToken accepted from a guest mcp_config.json. The clean-snapshot contract
#: (plan 5.7) and guest/provision.ps1 use 32+ characters; the plugin itself refuses
#: shorter tokens for non-loopback binds (netpolicy.MIN_EXTERNAL_TOKEN_LEN).
MIN_TOKEN_LEN = 32
MAX_TOKEN_LEN = 64  # cfgjson.zig MAX_TOKEN_LEN
MAX_GUEST_CONFIG_BYTES = 64 * 1024
GUEST_IP_TIMEOUT_S = 120.0
#: How long ``connect`` waits for another thread's token read of the same backend.
TOKEN_READ_WAIT_S = 180.0
#: ``GET /`` timeout when a new client first learns the plugin version (``Runtime.connect``).
VERSION_PROBE_TIMEOUT_S = 2.0
_CONNECT_ATTEMPTS = 3
BUILTIN_V1_9 = "data/tools-v1.9.json"
BUILTIN_V1_10 = "data/tools-v1.10.json"

#: the supervisor's default crash-loop limit (read from its signature, not copied)
_SUPERVISOR_MAX_RESTARTS = int(inspect.signature(Supervisor).parameters["max_restarts_per_job"].default)

_ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_VERSION_SAFE_RE = re.compile(r"[^A-Za-z0-9._-]")
_BOMS = (b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff")


# ── environment / env file ──────────────────────────────────────────
def _env_error(path: Path, problem: str, hint: str | None = None, **details: Any) -> ConfigError:
    return ConfigError(
        f"env file {path}: {problem}", stage="config", hint=hint, details={"path": str(path), **details}
    )


def read_env_file(path: str | os.PathLike[str], *, system: str | None = None) -> dict[str, str]:
    """Parse a ``KEY=VALUE`` file. No shell expansion; values are never echoed in errors.

    Blank lines and ``#`` comments are ignored, an optional ``export `` prefix is
    accepted and one pair of matching surrounding quotes is stripped. On POSIX
    hosts the file must not be readable or writable by group/other.
    """
    p = Path(path).expanduser()
    try:
        st = p.stat()
    except FileNotFoundError:
        raise _env_error(p, "not found", hint="fix gateway.env_file or create the file") from None
    except OSError as e:
        raise _env_error(p, f"cannot read it ({e.strerror or type(e).__name__})") from None
    if not stat.S_ISREG(st.st_mode):
        raise _env_error(p, "not a regular file")
    if gw_platform.host_system(system) != "Windows" and st.st_mode & 0o066:
        raise _env_error(
            p, f"group/other may access it (mode {stat.S_IMODE(st.st_mode):04o})", hint=f"chmod 600 {p}"
        )
    try:
        text = p.read_bytes().decode("utf-8")
    except UnicodeDecodeError:
        raise _env_error(p, "not valid UTF-8") from None
    except OSError as e:
        raise _env_error(p, f"cannot read it ({e.strerror or type(e).__name__})") from None
    out: dict[str, str] = {}
    for lineno, raw in enumerate(text.lstrip("﻿").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        key, sep, value = line.partition("=")
        key = key.strip()
        if not sep or not _ENV_NAME_RE.fullmatch(key):
            raise _env_error(
                p, f"line {lineno}: expected KEY=VALUE with KEY like [A-Za-z_][A-Za-z0-9_]*", line=lineno
            )
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        out[key] = value
    return out


def resolve_environ(
    config: GatewayConfig, environ: Mapping[str, str] | None = None, *, system: str | None = None
) -> dict[str, str]:
    """The mapping ``*_env`` names are resolved in: ``environ`` (default ``os.environ``)
    over the values of ``config.env_file`` (the real environment wins). A relative
    env file path is relative to the config file's directory."""
    base = dict(os.environ if environ is None else environ)
    if not config.env_file:
        return base
    path = Path(config.env_file).expanduser()
    if not path.is_absolute() and config.config_path:
        path = Path(config.config_path).expanduser().parent / path
    return {**read_env_file(path, system=system), **base}


def guest_credentials(profile: ProfileConfig, environ: Mapping[str, str]) -> GuestCredentials | None:
    """Guest user (``guest_user`` or the variable named by ``guest_user_env``) and the
    password from ``guest_password_env``; None when either part is missing."""
    user = profile.guest_user
    if not user and profile.guest_user_env:
        user = environ.get(profile.guest_user_env) or None
    password = resolve_secret(profile.guest_password_env, dict(environ))
    if not user or password is None:
        return None
    return GuestCredentials(user=user, password=password)


# ── guest token (mcp_config.json) ───────────────────────────────────
def _token_error(backend_id: str, problem: str) -> BackendAuthError:
    return BackendAuthError(
        f"backend {backend_id}: the guest mcp_config.json is unusable ({problem})",
        stage="token",
        hint=f"{PROVISION_HINT} (it rewrites the plugin configs with valid tokens)",
        details={"backend": backend_id, "problem": problem},
    )


def parse_guest_token(data: bytes, backend_id: str) -> Secret:
    """Extract ``AuthToken`` from a guest ``mcp_config.json``, leniently.

    BOMs and NUL bytes are stripped first (this also reads ASCII-only UTF-16). An
    empty or zero-filled file, invalid JSON, a missing token, or one that is not
    32-64 printable ASCII characters without surrounding spaces raises
    BackendAuthError pointing at the provision command. The token and the file
    content never appear in the error.
    """
    if len(data) > MAX_GUEST_CONFIG_BYTES:
        raise _token_error(backend_id, f"file larger than {MAX_GUEST_CONFIG_BYTES} bytes")
    raw = data
    for bom in _BOMS:
        if raw.startswith(bom):
            raw = raw[len(bom) :]
            break
    text = raw.replace(b"\x00", b"").decode("utf-8", errors="replace").strip().lstrip("﻿").strip()
    if not text:
        raise _token_error(backend_id, "empty or zero-filled")
    try:
        doc = json.loads(text)
    except (ValueError, RecursionError):
        raise _token_error(backend_id, "not valid JSON") from None
    if not isinstance(doc, dict):
        raise _token_error(backend_id, "not a JSON object")
    token = doc.get("AuthToken")
    if not isinstance(token, str) or not token:
        raise _token_error(backend_id, "AuthToken is missing")
    if not MIN_TOKEN_LEN <= len(token) <= MAX_TOKEN_LEN:
        raise _token_error(backend_id, f"AuthToken must be {MIN_TOKEN_LEN}-{MAX_TOKEN_LEN} characters")
    if token != token.strip(" ") or any(not 0x20 <= ord(c) <= 0x7E for c in token):
        raise _token_error(
            backend_id, "AuthToken has spaces at its ends or non-printable/non-ASCII characters"
        )
    return Secret(token)


# ── tool catalog ────────────────────────────────────────────────────
def builtin_catalog_for(version: str | None) -> str:
    """Builtin tool list for a plugin version (``catalog.builtin_for_version``): the newest
    shipped list not newer than ``version``, else the oldest (tools-v1.9.json)."""
    return builtin_for_version(version)


def make_catalog(profile: ProfileConfig, cache_dir: Path | str | None = None) -> ToolCatalog:
    """The profile's catalog (cache under ``<cache_dir>/<profile>``).

    Each backend uses the builtin list of its own plugin version (cached, then live,
    see ``catalog``); backends never seen yet default to the list of the newest
    version in that cache (the debuggers of one guest usually share a build).
    """
    cdir = Path(cache_dir).expanduser() if cache_dir is not None else default_cache_dir()
    cdir = cdir / profile.name
    probe = ToolCatalog(BUILTIN_V1_9, cache_dir=cdir)
    versions = [v for v in (probe.server_version(b.id) for b in profile.backends) if version_tuple(v)]
    if not versions:
        return probe
    newest = max(versions, key=lambda v: version_tuple(v) or (0, 0))
    choice = builtin_catalog_for(newest)
    return probe if choice == BUILTIN_V1_9 else ToolCatalog(choice, cache_dir=cdir)


# ── placeholder client ──────────────────────────────────────────────
class UnresolvedClient:
    """``BackendClient`` stand-in until the backend's URL and token are known."""

    def __init__(self, endpoint: BackendEndpoint, reason: str = "not connected yet") -> None:
        self.endpoint = endpoint
        self.reason = reason

    def __repr__(self) -> str:
        return f"UnresolvedClient(id={self.endpoint.id!r}, reason={self.reason!r})"

    def _refuse(self) -> VmNotReady:
        return VmNotReady(
            f"backend {self.endpoint.id}: endpoint not resolved ({self.reason})",
            stage="connect",
            hint="the VM may be starting; call session_status",
            next_tool="session_status",
            details={"backend": self.endpoint.id},
        )

    def health_l1(self, timeout_s: float = 2.0) -> bool:
        return False

    def health_l2(self, timeout_s: float = 5.0) -> bool:
        return False

    def initialize(self, timeout_s: float = 10.0) -> dict[str, Any]:
        raise self._refuse()

    def list_tools(self, timeout_s: float = 10.0) -> list[ToolInfo]:
        raise self._refuse()

    def call_tool(self, name: str, arguments: Mapping[str, Any] | None, timeout_s: float) -> ToolCallResult:
        raise self._refuse()

    def cancel_all(self) -> None:
        return None


def _placeholder(cfg: BackendConfig, reason: str) -> UnresolvedClient:
    return UnresolvedClient(
        BackendEndpoint(
            id=cfg.id,
            arch=cfg.arch,
            url="",
            token=Secret(""),
            exe=cfg.exe,
            config_path=cfg.config,
            launch_task=cfg.launch_task,
        ),
        reason,
    )


# ── runtime ─────────────────────────────────────────────────────────
@dataclass(eq=False)
class Runtime:
    """Everything the orchestrator needs for one profile (see module docstring)."""

    profile: ProfileConfig
    vm: VmProvider
    runner: VmrunRunner | None
    channel: GuestChannel | None
    backends: dict[str, BackendConfig]
    clients: dict[str, BackendClient]  # shared with supervisor and proxy; entries are replaced
    supervisor: Supervisor
    proxy: Proxy
    catalog: ToolCatalog
    lock: VmOpLock
    clock: Clock
    environ: Mapping[str, str] = field(default_factory=dict, repr=False)
    client_factory: Callable[..., BackendClient] = field(default=HttpBackendClient, repr=False)
    #: set by the orchestrator: called with (backend_id, report) before a hung debugger is killed
    hang_listener: Callable[[str, HealthReport], None] | None = field(default=None, repr=False)
    #: crash-loop limit of the supervisor (relaunches per job / per backend window)
    restart_limit: int = 3
    _mutex: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)
    _ip: str | None = field(default=None, init=False, repr=False)
    _tokens: dict[str, Secret] = field(default_factory=dict, init=False, repr=False)
    _token_gen: int = field(default=0, init=False, repr=False)
    _token_locks: dict[str, threading.Lock] = field(default_factory=dict, init=False, repr=False)
    _resolved: dict[str, str] = field(default_factory=dict, init=False, repr=False)  # backend -> url
    _catalog_epoch: dict[str, int] = field(default_factory=dict, init=False, repr=False)

    # ── backends ────────────────────────────────────────────────────
    def backend(self, backend_id: str) -> BackendConfig:
        try:
            return self.backends[backend_id]
        except KeyError:
            raise ConfigError(
                f"unknown backend: {backend_id!r}",
                hint=f"configured backends: {', '.join(self.backends) or 'none'}",
            ) from None

    def default_backend_id(self) -> str | None:
        return next(iter(self.backends), None)

    def resolved_url(self, backend_id: str) -> str | None:
        """URL of the connected client, or None while the backend is unresolved.

        Lock-free on purpose (a dict read is atomic): status polling must never
        wait behind a token read or an IP lookup.
        """
        return self._resolved.get(backend_id)

    # ── guest IP ────────────────────────────────────────────────────
    def _lookup_ip(self, wait: bool) -> str | None:
        if self.profile.mode != "vmware":
            return None
        host = self.profile.guest_host
        if host and host != "auto":
            return host
        return self.vm.guest_ip(wait=wait, timeout_s=GUEST_IP_TIMEOUT_S)

    def guest_ip(self, *, wait: bool = False) -> str | None:
        """Cached guest IP (``guest_host`` when fixed); looked up once when unknown."""
        with self._mutex:
            if self._ip is not None:
                return self._ip
        ip = self._lookup_ip(wait)
        with self._mutex:
            if self._ip is None and ip:
                self._ip = ip
            return self._ip

    def refresh_guest_ip(self) -> str | None:
        """Look the IP up again (``getGuestIPAddress -wait``, after a revert/start).

        When it changed, every client is rebuilt for the new address (in place in
        the shared ``clients`` dict).
        """
        ip = self._lookup_ip(True) or None
        with self._mutex:
            old, self._ip = self._ip, ip
            if ip != old:
                log.info("profile %s: guest IP %s -> %s", self.profile.name, old, ip)
                self._rebuild_clients("guest IP changed")
            return ip

    # ── tokens ──────────────────────────────────────────────────────
    def _token_lock(self, backend_id: str) -> threading.Lock:
        with self._mutex:
            return self._token_locks.setdefault(backend_id, threading.Lock())

    def _token(self, cfg: BackendConfig, *, wait: bool = True) -> tuple[Secret, int]:
        """The backend's token and the token generation it belongs to.

        Reads it (env or guest copy) outside the runtime mutex; one reader per
        backend at a time. ``wait=False`` raises VmNotReady instead of waiting for
        another thread's read. A read that raced with ``drop_tokens`` /
        ``invalidate_clients(drop_tokens=True)`` is returned but not cached; callers
        compare the generation before publishing anything built from it.
        """
        with self._mutex:
            cached, gen = self._tokens.get(cfg.id), self._token_gen
        if cached is not None:
            return cached, gen
        lock = self._token_lock(cfg.id)
        acquired = lock.acquire(timeout=TOKEN_READ_WAIT_S) if wait else lock.acquire(blocking=False)
        if not acquired:
            raise VmNotReady(
                f"backend {cfg.id}: its token is being read from the guest",
                stage="token",
                hint="retry in a few seconds; see session_status",
                next_tool="session_status",
                details={"backend": cfg.id},
                retryable=True,
            )
        try:
            with self._mutex:  # another thread may have read it while we waited
                cached, gen = self._tokens.get(cfg.id), self._token_gen
            if cached is not None:
                return cached, gen
            token = self._load_token(cfg)
            with self._mutex:
                if gen == self._token_gen:
                    self._tokens[cfg.id] = token
            return token, gen
        finally:
            lock.release()

    def _load_token(self, cfg: BackendConfig) -> Secret:
        if self.profile.token_source == "env":  # noqa: S105 - token source kind, not a secret
            token = resolve_secret(cfg.token_env, dict(self.environ))
            if token is None:
                raise BackendAuthError(
                    f"backend {cfg.id}: environment variable {cfg.token_env} is not set",
                    stage="token",
                    hint="export it or add it to gateway.env_file",
                    details={"backend": cfg.id, "env": cfg.token_env},
                )
            return token
        return self._read_guest_token(cfg)

    def _read_guest_token(self, cfg: BackendConfig) -> Secret:
        if self.channel is None:
            raise ConfigError(f"backend {cfg.id}: token_source guest-config needs a guest channel")
        if not cfg.config:
            raise ConfigError(
                f"backend {cfg.id}: no guest path for mcp_config.json (backends.{cfg.id}.config)"
            )
        with tempfile.TemporaryDirectory(prefix="x64gw-token-") as td:
            local = Path(td) / "mcp_config.json"
            try:
                self.channel.copy_from_guest(cfg.config, local)
            except GuestOperationError as e:
                raise BackendAuthError(
                    f"backend {cfg.id}: cannot read mcp_config.json from the guest ({e.code})",
                    stage="token",
                    hint=f"check profiles.{self.profile.name}.backends.{cfg.id}.config; {PROVISION_HINT}",
                    details={"backend": cfg.id, "path": cfg.config},
                ) from e
            try:
                if os.name == "posix":
                    os.chmod(local, 0o600)
                with local.open("rb") as f:
                    data = f.read(MAX_GUEST_CONFIG_BYTES + 1)
            except OSError:
                raise _token_error(cfg.id, "the copied file cannot be read") from None
        return parse_guest_token(data, cfg.id)

    def refresh_token(self, backend_id: str) -> None:
        """Re-read the backend's token and hand it to its client (supervisor token refresher)."""
        cfg = self.backend(backend_id)
        with self._mutex:
            self._tokens.pop(backend_id, None)
        token, gen = self._token(cfg)  # guest I/O outside the mutex
        with self._mutex:
            if gen != self._token_gen:
                return  # tokens were dropped meanwhile (revert): the next connect reads afresh
            client = self.clients.get(backend_id)
            update = getattr(client, "update_token", None)
            if backend_id in self._resolved and callable(update):
                update(token)

    def drop_tokens(self) -> None:
        with self._mutex:
            self._tokens.clear()
            self._token_gen += 1

    # ── clients ─────────────────────────────────────────────────────
    @staticmethod
    def _url_for(cfg: BackendConfig, ip: str | None) -> str | None:
        if cfg.url:
            return cfg.url
        if not ip:
            return None
        host = f"[{ip}]" if ":" in ip else ip
        return f"http://{host}:{cfg.port}/"

    def backend_url(self, backend_id: str) -> str:
        cfg = self.backend(backend_id)
        url = self._url_for(cfg, None if cfg.url else self.guest_ip())
        if url is None:
            raise VmNotReady(
                f"backend {backend_id}: the guest IP address is unknown",
                stage="connect",
                hint="start the VM and wait for VMware Tools; see session_status",
                next_tool="session_status",
                details={"backend": backend_id},
            )
        return url

    def _make_client(self, cfg: BackendConfig, url: str, token: Secret) -> BackendClient:
        endpoint = BackendEndpoint(
            id=cfg.id,
            arch=cfg.arch,
            url=url,
            token=token,
            exe=cfg.exe,
            config_path=cfg.config,
            launch_task=cfg.launch_task,
        )
        client = self.client_factory(endpoint, clock=self.clock)
        listen = getattr(client, "on_server_version", None)
        if callable(listen):
            # GET / (health checks) and initialize report the plugin version: the catalog then
            # uses the builtin list of that version for this backend (catalog module docstring)
            listen(lambda version, _bid=cfg.id: self.catalog.set_server_version(_bid, version))
        return client

    def _learn_version(self, backend_id: str, client: BackendClient) -> None:
        """First contact with a new client: ask ``GET /`` for the plugin version, so the tool
        flags are those of that version before the first call. Best effort: a backend that
        does not answer is reported by the call or health check that follows."""
        probe = getattr(client, "server_info", None)
        if not callable(probe):
            return
        try:
            probe(timeout_s=VERSION_PROBE_TIMEOUT_S)  # the client's version listener does the rest
        except (BackendError, CancelledByVmOp) as e:
            log.debug("backend %s: version probe failed (%s)", backend_id, e.code)

    def connect(self, backend_id: str, *, wait: bool = True) -> BackendClient:
        """Return a usable client for ``backend_id``, resolving URL and token if needed.

        The guest IP lookup and the token read run outside the runtime mutex; the
        client is published only if neither the tokens nor the guest IP changed
        meanwhile (else it resolves again). ``wait=False`` refuses with VmNotReady
        instead of waiting for another thread's token read (status polling).

        Raises VmNotReady (no guest IP, endpoint keeps changing, read in progress),
        BackendAuthError (token unavailable or unusable), ConfigError, or
        guest-channel errors while reading the token.
        """
        cfg = self.backend(backend_id)
        for _ in range(_CONNECT_ATTEMPTS):
            url = self.backend_url(backend_id)  # may look the guest IP up (no mutex held)
            with self._mutex:
                if self._resolved.get(backend_id) == url:
                    return self.clients[backend_id]
            token, gen = self._token(cfg, wait=wait)  # may copy from the guest (no mutex held)
            with self._mutex:
                current = self._url_for(cfg, self._ip)
                if gen != self._token_gen or current != url:
                    continue  # a revert / IP change raced with this resolution: start over
                if self._resolved.get(backend_id) == url:
                    return self.clients[backend_id]  # another thread published it meanwhile
                client = self._make_client(cfg, url, token)
                self.clients[backend_id] = client
                self._resolved[backend_id] = url
            self._learn_version(backend_id, client)  # backend I/O: outside the mutex
            return client
        raise VmNotReady(
            f"backend {backend_id}: the endpoint changed while it was being resolved",
            stage="connect",
            hint="the VM is changing state; call session_status and retry",
            next_tool="session_status",
            details={"backend": backend_id},
        )

    def _rebuild_clients(self, reason: str) -> None:
        """Caller holds the mutex. Rebuild resolved clients whose token is cached, else placeholders."""
        for bid, cfg in self.backends.items():
            token = self._tokens.get(bid)
            url = self._url_for(cfg, self._ip) if token is not None else None
            if token is not None and url is not None:
                self.clients[bid] = self._make_client(cfg, url, token)
                self._resolved[bid] = url
            else:
                self.clients[bid] = _placeholder(cfg, reason)
                self._resolved.pop(bid, None)
            self._catalog_epoch.pop(bid, None)

    def invalidate_clients(self, *, drop_tokens: bool = False, reason: str = "VM state changed") -> None:
        """Forget every resolved client (and the cached tokens when ``drop_tokens``)."""
        with self._mutex:
            if drop_tokens:
                self._tokens.clear()
                self._token_gen += 1
            for bid, cfg in self.backends.items():
                self.clients[bid] = _placeholder(cfg, reason)
            self._resolved.clear()
            self._catalog_epoch.clear()

    def cancel_backend_calls(self) -> None:
        """VmOpLock preempt hook: abort in-flight backend calls (CANCELLED_BY_VM_OP)."""
        for client in list(self.clients.values()):
            try:
                client.cancel_all()
            except Exception:  # noqa: BLE001 - one broken client must not stop the others
                log.exception("cancel_all failed")

    # ── catalog ─────────────────────────────────────────────────────
    def refresh_catalog(self, backend_id: str, *, force: bool = False) -> str | None:
        """Fetch ``initialize`` + ``tools/list`` once per epoch; return the plugin version."""
        epoch = self.supervisor.epoch(backend_id)
        with self._mutex:
            if not force and self._catalog_epoch.get(backend_id) == epoch:
                return self.catalog.server_version(backend_id)
        client = self.connect(backend_id)
        info = client.initialize(timeout_s=10.0)
        server = info.get("serverInfo")
        raw_version = server.get("version") if isinstance(server, dict) else None
        version = _VERSION_SAFE_RE.sub("", str(raw_version))[:32] if raw_version is not None else ""
        tools = client.list_tools(timeout_s=10.0)
        self.catalog.update_from_live(backend_id, version or "unknown", tools)
        instructions = info.get("instructions")
        if isinstance(instructions, str) and instructions.strip():
            self.catalog.update_instructions(backend_id, instructions)
        with self._mutex:
            self._catalog_epoch[backend_id] = epoch
        return version or None

    # ── supervisor hooks ────────────────────────────────────────────
    def _on_hang(self, backend_id: str, report: HealthReport) -> None:
        listener = self.hang_listener
        if listener is not None:
            listener(backend_id, report)


def build_runtime(
    config: GatewayConfig,
    profile_name: str | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    clock: Clock | None = None,
    vm: VmProvider | None = None,
    runner: VmrunRunner | None = None,
    channel: GuestChannel | None = None,
    cache_dir: Path | str | None = None,
    system: str | None = None,
    find_vmrun: Callable[..., str] | None = None,
    client_factory: Callable[..., BackendClient] | None = None,
    supervisor_options: Mapping[str, Any] | None = None,
) -> Runtime:
    """Assemble the runtime of ``profile_name`` (default profile when None).

    ``environ`` is the already resolved environment (see :func:`resolve_environ`);
    None resolves it from ``os.environ`` and ``config.env_file``. ``vm``/``channel``
    /``runner`` may be injected (tests); vmrun is only located when the profile is
    in vmware mode and something still needs a real runner.
    """
    prof = config.profile(profile_name)
    env = dict(environ) if environ is not None else resolve_environ(config, system=system)
    clk: Clock = clock if clock is not None else SystemClock()
    if prof.mode == "vmware":
        if runner is None and (vm is None or channel is None):
            if not prof.vmx:
                raise ConfigError(f"profile {prof.name}: vmx is required in vmware mode")
            locate = find_vmrun or gw_platform.find_vmrun
            path = locate(prof.vmrun, system=system)
            runner = VmrunCli(
                path,
                prof.vmx,
                gw_platform.vmrun_type(prof.vmrun_type, system),
                guest_credentials(prof, env),
                system=system,
                clock=clk,
            )
        if vm is None:
            assert runner is not None and prof.vmx
            vm = VmrunProvider(runner, prof.vmx, clock=clk)
        if channel is None:
            assert runner is not None
            channel = VixChannel(runner)
        sup_vm: VmProvider | None = vm
    else:
        vm = vm if vm is not None else NullProvider()
        channel = None
        sup_vm = None  # no VM: only the HTTP health rows apply

    backends = {b.id: b for b in prof.backends}
    clients: dict[str, BackendClient] = {
        bid: _placeholder(cfg, "not connected yet") for bid, cfg in backends.items()
    }
    catalog = make_catalog(prof, cache_dir)
    lock = VmOpLock()
    holder: dict[str, Runtime] = {}

    def refresher(backend_id: str) -> None:
        holder["rt"].refresh_token(backend_id)

    def hang_hook(backend_id: str, report: HealthReport) -> None:
        holder["rt"]._on_hang(backend_id, report)

    sup_opts = dict(supervisor_options or {})
    supervisor = Supervisor(
        vm=sup_vm,
        guest=channel,
        clients=clients,
        backends=backends,
        relaunch_mode=prof.relaunch_mode,
        token_refresher=refresher,
        clock=clk,
        hang_hook=hang_hook,
        **sup_opts,
    )
    proxy = Proxy(catalog, clients, supervisor, max_call_s=config.max_call_s, clock=clk)
    rt = Runtime(
        profile=prof,
        vm=vm,
        runner=runner,
        channel=channel,
        backends=backends,
        clients=clients,
        supervisor=supervisor,
        proxy=proxy,
        catalog=catalog,
        lock=lock,
        clock=clk,
        environ=env,
        client_factory=client_factory or HttpBackendClient,
        restart_limit=int(sup_opts.get("max_restarts_per_job", _SUPERVISOR_MAX_RESTARTS)),
    )
    holder["rt"] = rt
    lock.add_preempt_hook(rt.cancel_backend_calls)
    return rt


def build_app(
    config: GatewayConfig,
    *,
    profile: str | None = None,
    environ: Mapping[str, str] | None = None,
    clock: Clock | None = None,
    cache_dir: Path | str | None = None,
) -> Gateway:
    """The orchestrator for ``config``. Reads the env file (ConfigError if unusable) and
    validates ``profile``; runtimes and the job store are created on first use."""
    from .app import Gateway

    env = resolve_environ(config, environ)
    config.profile(profile)  # unknown profile -> ConfigError now, not on first use

    def factory(name: str) -> Runtime:
        return build_runtime(config, name, environ=env, clock=clock, cache_dir=cache_dir)

    return Gateway(config, runtime_factory=factory, default_profile=profile, clock=clock)
