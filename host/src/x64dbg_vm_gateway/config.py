"""Gateway configuration model.

The dataclasses below are a shared contract (other modules import them).
Feature A owns ``load_config`` / ``default_config_path`` / validation and may
ADD optional fields, but must not rename or remove existing ones.

File format: TOML (see docs/VM_ORCHESTRATION_PLAN.md section 5.1 for an example).
Secrets are never stored in the file: only the NAME of an environment variable
(``*_env`` fields) is stored, and values are resolved lazily via ``resolve_secret``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .contracts import Secret


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
    token_source: str = "guest-config"  # "guest-config" | "env"
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
        from .errors import ConfigError

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
    import os

    if not env_name:
        return None
    env = os.environ if environ is None else environ
    val = env.get(env_name)
    return Secret(val) if val else None


def default_config_path() -> Path:  # implemented by feature A
    raise NotImplementedError


def load_config(path: Path | None = None) -> GatewayConfig:  # implemented by feature A
    raise NotImplementedError
