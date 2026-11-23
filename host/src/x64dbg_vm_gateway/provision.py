"""Guest provisioning, plugin deployment and x64dbg discovery (plan 5.7).

Everything goes through a ``contracts.GuestChannel`` (VixChannel in production)
plus the VM provider, so it is unit-testable with FakeGuest / FakeVm.

- :func:`discover_x64dbg` searches the guest for x64dbg installations
  (``<root>\\x64\\x64dbg.exe`` / ``<root>\\x32\\x32dbg.exe``) and reports plugin
  files and ``mcp_config.json`` health without ever returning a token.
- :func:`provision_guest` runs the packaged ``guest/provision.ps1`` (job root +
  ACL, plugin configs, ``[Engine] DisableDatabaseCompression=1`` in each
  debugger's ini file, elevated ``MCP-x64dbg`` / ``MCP-x32dbg`` logon tasks,
  auto-logon, power settings), optionally reboots and waits until every
  provisioned backend port answers, and optionally (re)takes the clean snapshot.
- :func:`install_plugin` replaces the plugin DLLs with a new build (backing
  every replaced build up once in ``<root>\\<arch>\\plugins_backup``, never in
  ``plugins\\``), relaunches the debuggers through the logon tasks and reports
  what answers.
- :func:`guest_boot_time` reads the guest's ``LastBootUpTime``; the reboot wait
  compares it, together with the guest's uptime, with the values read before the
  reboot (E2).

E1-E7 name the defects found by the real-VM end-to-end run of 2026-11-23
(docs/PHASE0_RESULTS.md: row V4 and the section "E2E 중 추가로 확인한 사실"; E7 is
the ``<plugin>.bak`` that install_plugin left in ``plugins\\``).

Facts behind the design (Phase 0 and that run): vmrun wraps every program
argument in double quotes without escaping (E3, row V4; handled by
``guest.escape_for_vmrun``; scripts go through ``ps.run_powershell*``); there is
no interactive session before auto-logon, so debuggers are (re)started through
the scheduled tasks; after a reboot both plugins answered within 44 s; a reboot
can be over between two 5 s polls (E2, "재부팅 감지"), hence the boot-time comparison;
``GET /`` without a token answers 401 on plugins up to v1.10, which already
proves the HTTP server is up.

Plugin v1.10 (this repo) counts every unauthenticated request from a non-loopback
address as a failed login and answers 429 for ``AuthLockoutSeconds`` (default
300 s) after five within 60 s. Readiness waits therefore stop probing a port once
it has answered, and treat 429 as "server up". v1.10 also refuses to bind a
non-loopback address unless ``mcp_config.json`` has ``AllowExternal: true`` and a
non-empty ``AllowedClients``; provisioning writes both (``allowed_clients``,
by default the host's own address on the guest's network).

Snapshots: protected snapshots and the profile's clean snapshot are never
deleted (plan 5.7), not even with ``overwrite_snapshot``; provision into a new
name instead and point the profile at it.

Secrets: the guest password travels only in a params file (0600 on the host,
deleted in ``finally``; the guest script deletes its copy on read and the host
removes it if the script never ran), and not at all for ``dry_run``. It is never
logged, and every free text that comes back from the guest (log, error, output,
planned actions) is scrubbed of it before it reaches a summary or an exception;
host-supplied values (root, user, ...) are returned as given. Bearer tokens are
only handed to the injectable ``info_probe``.

Verification status: the guest-side PowerShell (provision.ps1 beyond the
version verified in Phase 0, the discovery script and the ps.py wrappers) is
covered only by unit tests that emulate the guest, plus a syntax check that runs
where ``pwsh`` is installed. It has not been run on Windows PowerShell 5.1:
exercise it on the spike VM (tests/vm) before relying on it.

These functions do not take the VM-operation lock or pause the supervisor; the
caller (CLI / app) must do that around them.

Thread-safety: functions keep no state; concurrent calls against the same guest
are not supported (they would fight over the same files and processes).
"""

from __future__ import annotations

import contextlib
import http.client
import ipaddress
import json
import logging
import math
import os
import re
import secrets
import socket
import tempfile
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from importlib import resources
from importlib.resources.abc import Traversable
from pathlib import Path, PureWindowsPath
from types import MappingProxyType
from typing import Any, Protocol, runtime_checkable

from .config import BackendConfig, ProfileConfig
from .contracts import Clock, GuestChannel, Secret, ToolsState, VmProvider
from .errors import (
    BackendUnavailable,
    ConfigError,
    GatewayError,
    GuestOperationError,
    PathNotAllowed,
    ProtectedSnapshotError,
    StateViolation,
    TransferError,
    VmNotReady,
)
from .guest import GUEST_ENV_ERRORS, fold_case, validate_guest_path
from .pe import sha256_file
from .ps import DEFAULT_GUEST_TMP_DIR, fetch_guest_text, ps_quote, run_powershell, run_powershell_file
from .supervisor import SCHTASKS_EXE

__all__ = [
    "ARCH_SPECS",
    "LOG_PATH",
    "MCP_DIR",
    "READY_STATUSES",
    "RESULT_PATH",
    "SHUTDOWN_EXE",
    "ArchSpec",
    "HttpProbe",
    "InfoProbe",
    "LocalIpFor",
    "RuntimeLike",
    "default_http_probe",
    "default_info_probe",
    "default_local_ip_for",
    "discover_x64dbg",
    "guest_boot_time",
    "install_plugin",
    "packaged_provision_script",
    "provision_guest",
]

log = logging.getLogger(__name__)

MCP_DIR = "C:\\mcp"
RESULT_PATH = "C:\\mcp\\provision.result.json"
LOG_PATH = "C:\\mcp\\provision.log"
SHUTDOWN_EXE = "C:\\Windows\\System32\\shutdown.exe"
REBOOT_ARGS: tuple[str, ...] = ("/r", "/t", "2", "/f")
#: HTTP status of a plugin that has locked this host out after failed logins (v1.10+).
LOCKED_OUT_STATUS = 429
#: ``GET /`` answers that prove the plugin's HTTP server is up (401: no token sent;
#: 429: locked out, which only a running server can answer).
READY_STATUSES = frozenset({200, 401, LOCKED_OUT_STATUS})
#: Plugin limit on ``AllowedClients`` entries (netpolicy.MAX_ALLOWED_CLIENTS).
MAX_ALLOWED_CLIENTS = 64


@dataclass(frozen=True)
class ArchSpec:
    arch: str
    exe: str  # debugger image in <root>\<arch>\
    plugin: str  # plugin file in <root>\<arch>\plugins\
    task: str  # scheduled task registered by provision.ps1


ARCH_SPECS: Mapping[str, ArchSpec] = MappingProxyType({
    "x64": ArchSpec("x64", "x64dbg.exe", "x64dbg-MCP-Server.dp64", "MCP-x64dbg"),
    "x32": ArchSpec("x32", "x32dbg.exe", "x64dbg-MCP-Server.dp32", "MCP-x32dbg"),
})

#: ``http_probe(ip, port, timeout_s) -> HTTP status of GET / or None`` (never raises).
HttpProbe = Callable[[str, int, float], "int | None"]
#: ``info_probe(ip, port, timeout_s, token) -> GET / JSON object or None`` (never raises).
InfoProbe = Callable[[str, int, float, Secret], "dict[str, Any] | None"]
TokenFor = Callable[[str], "Secret | str | None"]
#: ``local_ip_for(guest_ip) -> host address the guest sees this host connect from``.
LocalIpFor = Callable[[str], "str | None"]

_PROBE_BODY_LIMIT = 64 * 1024
_RESULT_LIMIT = 256 * 1024
_LOG_TAIL_BYTES = 64 * 1024
_LOG_TAIL_LINES = 40
_TEXT_LIMIT = 300
_CONFIG_STATES = frozenset({"valid", "missing", "empty", "corrupt", "bad_token"})
_USER_FORBIDDEN = frozenset('"/[]:;|=,+*?<>')
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_MARKER = "MCPJSON:"
#: Ports dark this many polls in a row (Tools still running) count as the reboot.
_DARK_ROUNDS = 2
#: While waiting for the reboot, a port is probed until it has answered this often
#: (each unauthenticated answer is a failed login for the plugin; 5 lock the host out).
_DOWN_PHASE_ANSWERS = 3
#: ``Win32_OperatingSystem.LastBootUpTime`` as ISO-8601 UTC (.NET round-trip format "o"),
#: and the uptime ``now - LastBootUpTime`` in seconds (both UTC, invariant culture).
_BOOT_MARKER = "MCPBOOT:"
_UPTIME_MARKER = "MCPUPTIME:"
_BOOT_SCRIPT = (
    "$os = Get-CimInstance -ClassName Win32_OperatingSystem -Property LastBootUpTime\n"
    "$boot = $os.LastBootUpTime.ToUniversalTime()\n"
    "$up = ((Get-Date).ToUniversalTime() - $boot).TotalSeconds\n"
    f"'{_BOOT_MARKER}' + $boot.ToString('o')\n"
    f"'{_UPTIME_MARKER}' + $up.ToString('F3', [System.Globalization.CultureInfo]::InvariantCulture)"
)
_BOOT_RE = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,7}))?Z")
_UPTIME_RE = re.compile(r"\d{1,12}(?:\.\d{1,9})?")
#: Upper bound for one boot-time read (PowerShell start-up in a loaded guest can be slow).
_BOOT_READ_TIMEOUT_S = 60.0
#: Jitter allowed in both values (the boot time is computed by Windows on every query).
#: A reboot moves the boot time forward AND makes the uptime drop; see _is_new_boot.
_BOOT_TIME_TOLERANCE_S = 1.0
#: Plugin backups live in ``<root>\<arch>\plugins_backup`` (E7: never in plugins\, which
#: x64dbg scans for plugins), named ``<plugin>.<UTC yyyymmddTHHMMSSZ>.bak``.
BACKUP_DIR_NAME = "plugins_backup"
_BACKUP_STAMP = "%Y%m%dT%H%M%SZ"
#: Later seconds tried when a backup name is already taken (same second, or a file left there).
_BACKUP_NAME_TRIES = 120
_BACKUP_HASH_TIMEOUT_S = 120.0
_BACKUP_HASH_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$dirs = @(__DIRS__)
$rows = New-Object System.Collections.Generic.List[object]
foreach ($d in $dirs) {
    if (-not (Test-Path -LiteralPath $d -PathType Container)) { continue }
    foreach ($f in @(Get-ChildItem -LiteralPath $d -File -Force)) {
        if (-not $f.Name.EndsWith('.bak', [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        $h = $null
        try {
            $h = (Get-FileHash -Algorithm SHA256 -LiteralPath $f.FullName).Hash.ToLowerInvariant()
        } catch { }
        $rows.Add([pscustomobject]@{ dir = $d; name = $f.Name; sha256 = $h })
    }
}
'MCPJSON:' + (ConvertTo-Json -InputObject @($rows) -Depth 3 -Compress)
"""


@runtime_checkable
class RuntimeLike(Protocol):
    """What provisioning needs from the gateway runtime (one profile's live objects)."""

    vm: VmProvider
    channel: GuestChannel
    profile: ProfileConfig
    backends: Mapping[str, BackendConfig]  # backend id -> config
    clock: Clock

    def guest_ip(self) -> str | None: ...


# ── HTTP probes (real I/O; injectable in every public function) ─────
def _http_get_root(ip: str, port: int, timeout: float, token: Secret | None,
                   *, read_body: bool) -> tuple[int | None, bytes]:
    conn = http.client.HTTPConnection(ip, port, timeout=timeout)
    headers = {"Accept": "application/json"}
    if token is not None:
        headers["Authorization"] = "Bearer " + token.reveal()
    deadline = time.monotonic() + max(timeout, 0.1) * 2
    try:
        conn.request("GET", "/", headers=headers)
        resp = conn.getresponse()
        body = b""
        while read_body and len(body) < _PROBE_BODY_LIMIT and time.monotonic() < deadline:
            chunk = resp.read1(_PROBE_BODY_LIMIT - len(body))
            if not chunk:
                break
            body += chunk
        return resp.status, body
    except (OSError, http.client.HTTPException, ValueError):
        return None, b""
    finally:
        conn.close()


def default_http_probe(ip: str, port: int, timeout: float) -> int | None:
    """HTTP status of an unauthenticated ``GET /``; None when nothing answers."""
    status, _ = _http_get_root(ip, port, timeout, None, read_body=False)
    return status


def default_info_probe(ip: str, port: int, timeout: float, token: Secret) -> dict[str, Any] | None:
    """``GET /`` with the bearer token; the JSON object (name, version, ...) or None."""
    status, body = _http_get_root(ip, port, timeout, token, read_body=True)
    if status != 200:
        return None
    try:
        doc = json.loads(body.decode("utf-8", errors="replace"))
    except ValueError:
        return None
    return doc if isinstance(doc, dict) else None


def default_local_ip_for(remote_ip: str) -> str | None:
    """IPv4 address of the host interface that routes to ``remote_ip``, or None.

    A UDP ``connect`` only selects the route; no packet is sent.
    """
    try:
        target = str(ipaddress.IPv4Address(remote_ip))
    except ValueError:
        return None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2.0)
            s.connect((target, 9))  # discard port; nothing is sent
            addr = s.getsockname()[0]
    except OSError:
        return None
    try:
        ip = ipaddress.IPv4Address(addr)
    except ValueError:
        return None
    return None if ip.is_unspecified else str(ip)


def _safe_probe(probe: HttpProbe, ip: str, port: int, timeout: float) -> int | None:
    try:
        status = probe(ip, port, timeout)
    except (OSError, GatewayError, ValueError, http.client.HTTPException):
        return None
    return status if isinstance(status, int) and not isinstance(status, bool) else None


# ── small helpers ───────────────────────────────────────────────────
def packaged_provision_script() -> Traversable:
    """The provision.ps1 shipped inside the package (identical to guest/provision.ps1)."""
    return resources.files(__package__).joinpath("data").joinpath("guest").joinpath("provision.ps1")


def _clip(text: str, limit: int = _TEXT_LIMIT) -> str:
    return text if len(text) <= limit else text[:limit] + "..."


def _gjoin(*parts: str) -> str:
    return str(PureWindowsPath(*parts))


def _positive(name: str, value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float) or not math.isfinite(value) \
            or value <= 0:
        raise ValueError(f"{name} must be a positive finite number")
    return float(value)


def _as_secret(value: Secret | str | None) -> Secret | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError("secrets must be str / contracts.Secret")
    if not value:
        return None
    return value if isinstance(value, Secret) else Secret(value)


def _check_user(user: object) -> str:
    if not isinstance(user, str) or not user.strip() or len(user) > 104:
        raise ConfigError("guest user must be a non-empty account name", stage="provision")
    if any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F or c in _USER_FORBIDDEN for c in user):
        raise ConfigError("guest user contains characters Windows does not allow in account names",
                          stage="provision", details={"user": _clip(repr(user), 80)})
    return user


def _check_bind(bind: object) -> str:
    # The plugin only binds IPv4 ("IpAddress must be a valid IPv4 address").
    try:
        return str(ipaddress.IPv4Address(str(bind).strip()))
    except ValueError:
        raise ConfigError("bind must be an IPv4 address (e.g. 0.0.0.0 or the guest's host-only IP)",
                          stage="provision", details={"bind": _clip(repr(bind), 80)}) from None


def _check_allowed_clients(value: object) -> list[str]:
    """Normalised IPv4 addresses / CIDR ranges (duplicates dropped, order kept)."""
    if isinstance(value, str | bytes) or not isinstance(value, Iterable):
        raise ConfigError("allowed_clients must be a list of IPv4 addresses or CIDR ranges",
                          stage="provision", details={"allowed_clients": _clip(repr(value), 80)})
    out: list[str] = []
    for item in value:
        try:
            if not isinstance(item, str):
                raise ValueError(item)
            text = item.strip()
            entry = (str(ipaddress.IPv4Network(text, strict=False)) if "/" in text
                     else str(ipaddress.IPv4Address(text)))
        except ValueError:
            raise ConfigError("allowed_clients entries must be IPv4 addresses or CIDR ranges",
                              stage="provision", details={"entry": _clip(repr(item), 80)}) from None
        if entry not in out:
            out.append(entry)
    if len(out) > MAX_ALLOWED_CLIENTS:
        raise ConfigError(f"allowed_clients has more than {MAX_ALLOWED_CLIENTS} entries (plugin limit)",
                          stage="provision", details={"count": len(out)})
    return out


def _resolve_allowed_clients(runtime: RuntimeLike, bind_ip: str, allowed_clients: object,
                             local_ip_for: LocalIpFor) -> list[str]:
    """``AllowedClients`` for the plugin configs ([] for a loopback bind without a list)."""
    loopback = ipaddress.IPv4Address(bind_ip).is_loopback
    if allowed_clients is not None:
        allowed = _check_allowed_clients(allowed_clients)
    elif loopback:
        return []
    else:
        guest = runtime.guest_ip()
        host: str | None = None
        if guest:
            try:
                host = local_ip_for(guest)
            except (OSError, ValueError):
                host = None
        allowed = _check_allowed_clients([host]) if host else []
    if not allowed and not loopback:
        raise ConfigError(
            f"bind {bind_ip} is not loopback, and the plugin (v1.10+) then refuses to start "
            "without a non-empty AllowedClients list", stage="provision",
            details={"bind": bind_ip},
            hint="pass allowed_clients=[<this host's IP on the guest network>] (or a CIDR range), "
                 "or bind=127.0.0.1")
    return allowed


def _ports_by_arch(backends: Mapping[str, BackendConfig]) -> dict[str, int]:
    """{"x64": port, "x32": port} for provision.ps1 (its configs are per architecture)."""
    ports: dict[str, int] = {}
    for b in backends.values():
        if b.port is None:
            continue
        if b.arch in ports:
            raise ConfigError(f"two backends use architecture {b.arch}; provisioning writes one "
                              "mcp_config.json per architecture", stage="provision",
                              details={"arch": b.arch})
        ports[b.arch] = b.port
    return ports


def _scrub(value: Any, hidden: Sequence[str]) -> Any:
    """Replace every secret value inside strings (recursively) with ``***``.

    Only for free text written by the guest: a short password can be a substring of
    ordinary values (e.g. equal to the account name), which must not be mangled.
    """
    if isinstance(value, str):
        for s in hidden:
            if s:
                value = value.replace(s, "***")
        return value
    if isinstance(value, dict):
        return {k: _scrub(v, hidden) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_scrub(v, hidden) for v in value]
    return value


def _tail_lines(text: str | None, n: int = _LOG_TAIL_LINES) -> list[str]:
    if not text:
        return []
    lines = [_clip(line.rstrip()) for line in text.splitlines() if line.strip()]
    return lines[-n:]


def _delete_if_exists(channel: GuestChannel, path: str) -> bool:
    if channel.file_exists(path):
        channel.delete_file(path)
        return True
    return False


def _str_or_none(value: Any, limit: int = 260) -> str | None:
    return _clip(value, limit) if isinstance(value, str) else None


def _int_or_none(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _clean_plugin(value: Any) -> dict[str, Any]:
    v = value if isinstance(value, dict) else {}
    sha = v.get("sha256")
    return {
        "present": v.get("present") is True,
        "file_version": _str_or_none(v.get("file_version"), 64),
        "size": _int_or_none(v.get("size")),
        "mtime": _str_or_none(v.get("mtime"), 40),
        "sha256": sha if isinstance(sha, str) and _SHA256_RE.fullmatch(sha) else None,
    }


# ── readiness polling ───────────────────────────────────────────────
@dataclass
class _Observation:
    tools: ToolsState | None  # None: the query itself failed (nothing was observed)
    ip: str | None
    statuses: dict[str, int | None] = field(default_factory=dict)

    @property
    def tools_running(self) -> bool:
        return self.tools == ToolsState.RUNNING

    @property
    def ready(self) -> bool:
        return self.tools_running and bool(self.ip) and all(s in READY_STATUSES
                                                            for s in self.statuses.values())

    @property
    def tools_down(self) -> bool:
        """VMware answered that Tools are not running: the guest OS is not up."""
        return self.tools in (ToolsState.INSTALLED, ToolsState.NOT_INSTALLED)

    @property
    def ports_dark(self) -> bool:
        """Tools running and the IP known, yet no backend answers.

        "No backend answers" rather than "some backend is missing": one port that was
        already dead before the reboot must not be mistaken for the reboot itself.
        A failed Tools query, UNKNOWN or a missing IP is neither down nor dark.
        """
        return (self.tools_running and bool(self.ip) and bool(self.statuses)
                and not any(s in READY_STATUSES for s in self.statuses.values()))

    @property
    def pending(self) -> list[str]:
        return sorted(bid for bid, s in self.statuses.items() if s not in READY_STATUSES)

    def details(self) -> dict[str, Any]:
        return {"tools_state": self.tools.value if self.tools is not None else None,
                "tools_running": self.tools_running, "ip": self.ip,
                "readiness": dict(self.statuses), "pending": self.pending}


class _PortProber:
    """Probes backend ports with ``GET /``, at most ``answers`` times per port that answers.

    Once a port has answered (200/401/429) that often for the current guest IP, its
    last answer is reused instead of probing again: plugins from v1.10 count every
    unauthenticated request as a failed login and lock this host out after five
    within 60 s. A new guest IP (new boot / lease) starts the count afresh.
    """

    def __init__(self, probe: HttpProbe, timeout_s: float, *, answers: int) -> None:
        self._probe = probe
        self._timeout_s = timeout_s
        self._answers = answers
        self._ip: str | None = None
        self._seen: dict[str, tuple[int, int]] = {}  # backend id -> (answers so far, last status)

    def __call__(self, ip: str, bid: str, port: int) -> int | None:
        if ip != self._ip:
            self._ip, self._seen = ip, {}
        count, last = self._seen.get(bid, (0, 0))
        if count >= self._answers:
            return last
        status = _safe_probe(self._probe, ip, port, self._timeout_s)
        if status in READY_STATUSES:
            self._seen[bid] = (count + 1, status)
        return status


def _observe(runtime: RuntimeLike, targets: Mapping[str, int],
             probe_port: Callable[[str, str, int], int | None]) -> _Observation:
    tools: ToolsState | None
    try:
        tools = runtime.vm.tools_state()
    except GatewayError as exc:
        log.debug("Tools state query failed (%s); nothing observed this round", exc.code)
        tools = None
    ip: str | None = None
    if tools == ToolsState.RUNNING:
        try:
            ip = runtime.guest_ip()
        except GatewayError:
            ip = None
    statuses: dict[str, int | None] = dict.fromkeys(targets)
    if ip:
        for bid, port in targets.items():
            statuses[bid] = probe_port(ip, bid, port)
    return _Observation(tools, ip, statuses)


def _poll_until(clock: Clock, deadline: float, poll_s: float, check: Callable[[], bool]) -> bool:
    """Call ``check`` until it returns True or ``deadline`` passes (checked once more at the end)."""
    max_polls = int(max(0.0, deadline - clock.monotonic()) / poll_s) + 2  # in case the clock stalls
    for _ in range(max_polls):
        if check():
            return True
        remaining = deadline - clock.monotonic()
        if remaining <= 0:
            return False
        clock.sleep(min(poll_s, remaining))
    return False


def _wait_up(runtime: RuntimeLike, targets: Mapping[str, int], *, deadline: float, poll_s: float,
             probe: HttpProbe, probe_timeout_s: float, stage: str, timeout_s: float,
             extra: Mapping[str, Any] | None = None) -> _Observation:
    last: list[_Observation] = []
    prober = _PortProber(probe, probe_timeout_s, answers=1)

    def ready() -> bool:
        last[:] = [_observe(runtime, targets, prober)]
        return last[0].ready

    if _poll_until(runtime.clock, deadline, poll_s, ready):
        obs = last[0]
        locked = sorted(bid for bid, s in obs.statuses.items() if s == LOCKED_OUT_STATUS)
        if locked:
            log.warning("backend(s) %s answered HTTP 429: the plugin has locked this host out after "
                        "failed logins, and refuses the gateway's requests until the lockout ends "
                        "(AuthLockoutSeconds, default 300 s)", ", ".join(locked))
        return obs
    obs = last[0] if last else _Observation(None, None, dict.fromkeys(targets))
    raise VmNotReady(
        f"guest backends not ready within {timeout_s:g}s (waiting for: "
        f"{', '.join(obs.pending) or 'VMware Tools / guest IP'})",
        stage=stage,
        details={"phase": "up", "timeout_s": timeout_s, **obs.details(), **(extra or {})},
        hint="the debuggers start from the MCP-x64dbg / MCP-x32dbg logon tasks after auto-logon; "
             "take a screenshot (vm_screenshot) to look for a logon screen or a modal dialog",
    )


def _boot_datetime(value: str | None) -> datetime | None:
    """Parse a boot time from :func:`guest_boot_time` (ISO-8601 UTC, up to 7 fraction digits)."""
    m = _BOOT_RE.fullmatch(value) if isinstance(value, str) else None
    if m is None:
        return None
    try:
        dt = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=UTC)
    except ValueError:
        return None
    return dt + timedelta(microseconds=int(((m.group(2) or "") + "000000")[:6]))


@dataclass(frozen=True)
class _BootReading:
    """One answer of the boot query: ``LastBootUpTime`` and, when reported, the uptime."""

    iso: str  # as reported, e.g. 2026-11-23T13:16:44.5000000Z
    at: datetime
    uptime_s: float | None


def _marked(output: str, marker: str) -> str | None:
    lines = [ln.strip() for ln in output.splitlines() if ln.strip().startswith(marker)]
    return lines[-1][len(marker):].strip() if lines else None


def _query_boot(channel: GuestChannel, timeout_s: float, guest_tmp_dir: str) -> _BootReading | None:
    res = run_powershell(channel, _BOOT_SCRIPT, timeout_s=_positive("timeout_s", timeout_s),
                         guest_tmp_dir=guest_tmp_dir)
    if not res.ok:
        return None
    iso = _marked(res.output, _BOOT_MARKER)
    at = _boot_datetime(iso)
    if iso is None or at is None:
        return None
    up = _marked(res.output, _UPTIME_MARKER)
    uptime = float(up) if up is not None and _UPTIME_RE.fullmatch(up) else None
    return _BootReading(iso, at, uptime)


def guest_boot_time(channel: GuestChannel, *, timeout_s: float = _BOOT_READ_TIMEOUT_S,
                    guest_tmp_dir: str = DEFAULT_GUEST_TMP_DIR) -> str | None:
    """The guest's last boot time as an ISO-8601 UTC string (e.g. ``2026-11-23T13:16:44.5000000Z``).

    Reads ``(Get-CimInstance Win32_OperatingSystem).LastBootUpTime`` with
    :func:`ps.run_powershell`. Returns None when the script ran but gave no
    usable value (non-zero exit, no or malformed ``MCPBOOT:`` line). Raises the
    channel's errors (Tools not running, vmrun timeout, ...), so "the guest did
    not answer" stays distinguishable from "it answered nothing usable".
    """
    reading = _query_boot(channel, timeout_s, guest_tmp_dir)
    return reading.iso if reading is not None else None


def _read_boot(channel: GuestChannel, *, timeout_s: float = _BOOT_READ_TIMEOUT_S,
               guest_tmp_dir: str = DEFAULT_GUEST_TMP_DIR) -> _BootReading | None:
    """Boot time plus uptime (same query as :func:`guest_boot_time`); None unless both are usable.

    The reboot detection needs both (see :func:`_is_new_boot`). Raises the channel's errors.
    """
    reading = _query_boot(channel, timeout_s, guest_tmp_dir)
    return reading if reading is not None and reading.uptime_s is not None else None


def _is_new_boot(before: _BootReading, now: _BootReading) -> bool:
    """True when ``now`` was read after a boot later than the one ``before`` was read in.

    Both conditions must hold (each beyond ``_BOOT_TIME_TOLERANCE_S``):

    - the boot time moved forward. A reboot moves it by at least the old uptime.
    - the uptime dropped below the uptime read before. Without a reboot the
      uptime only grows. This check is what a guest clock step cannot fake:
      Windows is expected to move ``LastBootUpTime`` with the clock (the kernel
      adjusts its recorded boot time when the system time is set; not yet
      measured on the spike VM), so a step forward (VMware Tools time sync
      after a revert, w32time) would move the boot time forward without a
      reboot, while ``now - LastBootUpTime`` stays the uptime.

    Should the boot time instead stay put across a clock step, the first
    condition rules the step out. Either way a step alone is never a reboot.
    The price: a reboot read only once the new uptime has passed the old one is
    not recognised here; the secondary "down" signal of :func:`_wait_reboot`
    covers such slow reboots.
    """
    if before.uptime_s is None or now.uptime_s is None:
        return False
    moved = (now.at - before.at).total_seconds() > _BOOT_TIME_TOLERANCE_S
    dropped = now.uptime_s + _BOOT_TIME_TOLERANCE_S < before.uptime_s
    return moved and dropped


def _boot_time_before_reboot(channel: GuestChannel) -> _BootReading | None:
    """Boot time and uptime read before the reboot request; None (logged) when unusable."""
    try:
        value = _read_boot(channel)
    except GatewayError as exc:
        log.warning("could not read the guest boot time and uptime before the reboot (%s); only the "
                    "guest going down can show the reboot, and a fast reboot may be missed", exc.code)
        return None
    if value is None:
        log.warning("the guest reported no usable boot time and uptime; only the guest going down can "
                    "show the reboot, and a fast reboot may be missed")
    return value


@dataclass
class _RebootWatch:
    before: _BootReading | None  # read before the reboot was requested
    signal: str | None = None  # "boot_time" | "down": what showed the reboot
    after: str | None = None  # the new boot time, when that showed the reboot
    last: str | None = None  # last boot time read while waiting

    @property
    def before_iso(self) -> str | None:
        return self.before.iso if self.before is not None else None

    def read(self, channel: GuestChannel, remaining_s: float) -> bool:
        """Read boot time and uptime once; True when they show a new boot (:func:`_is_new_boot`).

        A failed or unusable read (guest going down, Tools starting, vmrun
        timeout) is no evidence either way and returns False.
        """
        if self.before is None or remaining_s <= 0:
            return False
        try:
            now = _read_boot(channel, timeout_s=min(_BOOT_READ_TIMEOUT_S, remaining_s))
        except GatewayError as exc:
            log.debug("guest boot time not readable while waiting for the reboot (%s)", exc.code)
            return False
        if now is None:
            return False
        self.last = now.iso
        if _is_new_boot(self.before, now):
            self.after = now.iso
            return True
        return False


def _wait_reboot(runtime: RuntimeLike, targets: Mapping[str, int], *, wait_ready_s: float, poll_s: float,
                 probe: HttpProbe, probe_timeout_s: float,
                 boot_before: _BootReading | None) -> tuple[float, _Observation, _RebootWatch]:
    """Wait until the guest has rebooted, then until every target answers.

    Primary signal (E2): compared with ``boot_before`` (read before the reboot
    was requested), the guest's boot time moved forward and its uptime dropped
    (:func:`_is_new_boot`; the uptime keeps a guest clock step from passing for
    a reboot). Both are read once per poll while VMware reports Tools running;
    failed reads are skipped. A guest that is down for less than one poll
    interval is still seen this way (the E2 failure: LastBootUpTime moved
    22:16:44 -> 22:22:29, yet no poll saw the guest down).

    Secondary signal (the only one when ``boot_before`` is None): the guest seen
    going down: VMware reporting Tools as not running, or every port dark for
    ``_DARK_ROUNDS`` polls in a row while Tools still run. A failed or UNKNOWN
    Tools query and a missing guest IP are no evidence either way: polling goes
    on, so the still-running old debuggers can never pass for the rebooted ones.

    Both share one deadline, ``wait_ready_s`` after the call.
    """
    clock = runtime.clock
    start = clock.monotonic()
    deadline = start + wait_ready_s
    prober = _PortProber(probe, probe_timeout_s, answers=_DOWN_PHASE_ANSWERS)
    watch = _RebootWatch(boot_before)
    dark_rounds = 0

    def rebooted() -> bool:
        nonlocal dark_rounds
        obs = _observe(runtime, targets, prober)
        dark_rounds = dark_rounds + 1 if obs.ports_dark else 0
        if obs.tools_running and watch.read(runtime.channel, deadline - clock.monotonic()):
            watch.signal = "boot_time"
            return True
        if obs.tools_down or dark_rounds >= _DARK_ROUNDS:
            watch.signal = "down"
            return True
        return False

    if not _poll_until(clock, deadline, poll_s, rebooted):
        if watch.before is None:
            raise VmNotReady(
                f"the guest did not go down within {wait_ready_s:g}s after the reboot was requested "
                "(its boot time and uptime could not be read, so only going down could show the reboot)",
                stage="reboot", details={"phase": "down", "timeout_s": wait_ready_s, "boot_time": None},
                hint="the old debugger instances are still answering; check that shutdown.exe can run",
            )
        before = watch.before_iso
        last = f" (last read: {watch.last})" if watch.last and watch.last != before else ""
        unread = "" if watch.last else "; it could not be read again since"
        raise VmNotReady(
            f"the guest did not reboot within {wait_ready_s:g}s after the reboot was requested: "
            f"its boot time is still {before}{last}{unread}",
            stage="reboot",
            details={"phase": "down", "timeout_s": wait_ready_s, "boot_time": before,
                     "last_boot_time": watch.last},
            hint="shutdown.exe /r may have been refused or the guest hangs while shutting down; "
                 "take a screenshot (vm_screenshot)",
        )
    obs = _wait_up(runtime, targets, deadline=deadline, poll_s=poll_s, probe=probe,
                   probe_timeout_s=probe_timeout_s, stage="reboot", timeout_s=wait_ready_s)
    return clock.monotonic() - start, obs, watch


# ── clean snapshot ──────────────────────────────────────────────────
@dataclass(frozen=True)
class _SnapshotPlan:
    name: str
    exists: bool
    action: str  # "take" | "replace" | "refuse"
    error: GatewayError | None = None

    def public(self) -> dict[str, Any]:
        return {"name": self.name, "exists": self.exists, "action": self.action}


def _protected_snapshots(profile: ProfileConfig) -> set[str]:
    """Case-folded names never deleted: ``protected_snapshots`` plus the clean snapshot
    (the same set policy.check_snapshot_delete protects)."""
    names = {p.casefold() for p in profile.protected_snapshots if isinstance(p, str)}
    if profile.clean_snapshot:
        names.add(profile.clean_snapshot.casefold())
    return names


def _plan_snapshot(runtime: RuntimeLike, name: str, overwrite: bool) -> _SnapshotPlan:
    if not isinstance(name, str) or not name.strip():
        raise ConfigError("clean_snapshot must be a non-empty snapshot name", stage="snapshot")
    folded = name.casefold()
    same = [s.name for s in runtime.vm.list_snapshots() if s.name.casefold() == folded]
    exists = bool(same)
    if not exists:
        return _SnapshotPlan(name, False, "take")
    protected = folded in _protected_snapshots(runtime.profile)
    if not overwrite:
        return _SnapshotPlan(name, True, "refuse", StateViolation(
            f"snapshot {name!r} already exists", stage="snapshot", details={"snapshot": name},
            hint="choose another name (protected snapshots and the profile's clean snapshot are "
                 "never replaced)" if protected
            else "pass overwrite_snapshot=True to replace it, or choose another name"))
    if protected:
        # Plan 5.7: the protected list (and the profile's clean snapshot) is never deleted.
        # Replacing means delete-then-take, and a failed take would leave no clean snapshot.
        return _SnapshotPlan(name, True, "refuse", ProtectedSnapshotError(
            f"snapshot {name!r} is protected (or is the profile's clean snapshot) and is never deleted",
            stage="snapshot", details={"snapshot": name},
            hint="provision into a new snapshot name and point the profile's clean_snapshot at it; "
                 "delete the old snapshot in VMware yourself once the new one works"))
    if len(same) > 1 or same[0] != name:
        return _SnapshotPlan(name, True, "refuse", StateViolation(
            f"snapshot name {name!r} does not identify exactly one snapshot", stage="snapshot",
            details={"snapshot": name, "matches": same}, hint="rename or delete the duplicates in VMware"))
    return _SnapshotPlan(name, True, "replace")


def _take_snapshot(runtime: RuntimeLike, name: str, overwrite: bool) -> dict[str, Any]:
    """Take ``name``; with a "replace" plan the old one is deleted first.

    The VM provider cannot rename snapshots, so a replacement cannot be taken
    first under another name. When the take fails after the delete, the error
    says so (``details['old_snapshot_deleted']``) and the failure is logged.
    """
    plan = _plan_snapshot(runtime, name, overwrite)  # re-check: the VM may have changed meanwhile
    if plan.error is not None:
        raise plan.error
    step, deleted = "delete_snapshot", False
    try:
        if plan.action == "replace":
            log.warning("deleting snapshot %r to replace it", name)
            runtime.vm.delete_snapshot(name)
            deleted = True
        step = "take_snapshot"
        runtime.vm.take_snapshot(name)
    except GatewayError as exc:
        exc.details.update({"snapshot": name, "step": step, "old_snapshot_deleted": deleted})
        if deleted:
            log.error("snapshot %r was deleted, but taking its replacement failed (%s): "
                      "the VM has no snapshot of that name now", name, exc.code)
            exc.hint = (f"the old snapshot {name!r} is already deleted; the guest is provisioned, so "
                        f"take {name!r} again once the cause is fixed"
                        + (f" ({exc.hint})" if exc.hint else ""))
        else:
            log.error("snapshot %r: %s failed (%s)", name, step, exc.code)
        raise
    log.info("snapshot %r taken", name)
    return {"name": name, "replaced": plan.action == "replace"}


# ── provisioning ────────────────────────────────────────────────────
def _copy_params(channel: GuestChannel, params: Mapping[str, Any], guest_path: str) -> None:
    """Write the params JSON to a 0600 host temp file, copy it into the guest, delete it."""
    # ensure_ascii: PowerShell 5.1 reads BOM-less files in the ANSI code page; \\u escapes survive.
    data = json.dumps(params, ensure_ascii=True).encode("ascii")
    fd, name = tempfile.mkstemp(prefix="x64dbg-gw-provision-", suffix=".json")  # 0600 on POSIX
    path = Path(name)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        channel.copy_to_guest(path, guest_path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            path.unlink()


def _remove_guest_params(channel: GuestChannel, guest_path: str) -> None:
    try:
        if _delete_if_exists(channel, guest_path):
            log.warning("guest params file was still present after provisioning; deleted it")
    except GatewayError as exc:
        log.warning("could not verify that the guest params file was removed (%s); delete %s by hand",
                    exc.code, guest_path)


def _read_result(channel: GuestChannel) -> dict[str, Any] | None:
    text = fetch_guest_text(channel, RESULT_PATH, max_bytes=_RESULT_LIMIT)
    if not text:
        return None
    try:
        doc = json.loads(text)
    except ValueError:
        return None
    return doc if isinstance(doc, dict) else None


def _clean_backends(value: Any) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    if not isinstance(value, dict):
        return out
    for arch, v in value.items():
        if arch not in ARCH_SPECS or not isinstance(v, dict):
            continue
        out[arch] = {
            "exe": _str_or_none(v.get("exe")),
            "config": _str_or_none(v.get("config")),
            "port": _int_or_none(v.get("port")),
            "task": _str_or_none(v.get("task"), 64),
            "token_length": _int_or_none(v.get("token_length")),
            "token_generated": v.get("token_generated") is True,
            "plugin": _clean_plugin(v.get("plugin")),
            # x64dbg's ini next to the exe, where the script turned database compression off
            "settings_ini": _str_or_none(v.get("settings_ini")),
            "db_compression": _str_or_none(v.get("db_compression"), 16),
        }
    return out


def provision_guest(
    runtime: RuntimeLike,
    *,
    x64dbg_root: str,
    user: str,
    password: Secret | None,
    autologon: bool = True,
    bind: str = "0.0.0.0",  # noqa: S104 - plugin bind address inside the isolated guest
    job_root: str | None = None,
    reboot: bool = True,
    wait_ready_s: float = 300.0,
    clean_snapshot: str | None = None,
    overwrite_snapshot: bool = False,
    http_probe: HttpProbe = default_http_probe,
    allowed_clients: Sequence[str] | None = None,
    local_ip_for: LocalIpFor = default_local_ip_for,
    no_sleep: bool = True,
    dry_run: bool = False,
    poll_s: float = 5.0,
    probe_timeout_s: float = 3.0,
    script_timeout_s: float = 600.0,
) -> dict[str, Any]:
    """Provision the guest for the clean-snapshot contract (plan 5.7) and return a summary.

    Steps: validate arguments and the snapshot slot (before any guest change);
    ``mkdir C:\\mcp``; remove a stale result file; copy the params JSON (ports
    from ``runtime.backends``, job root defaulting to ``profile.job_root_guest``)
    and run the packaged provision.ps1 as a file; read
    ``provision.result.json`` / ``provision.log``. Then, unless ``dry_run``:
    read the guest's boot time and uptime, reboot (``shutdown.exe /r /t 2 /f``,
    not awaited) and wait until the boot time has moved forward with the uptime
    dropping (or, as a secondary signal, the guest was seen going down) and
    VMware Tools plus every
    provisioned backend port answer (HTTP 200, 401 or 429), all within
    ``wait_ready_s``; finally take ``clean_snapshot``. The summary's
    ``reboot_signal`` ("boot_time" / "down") and ``boot_time`` (``before`` /
    ``after``) say how the reboot was recognised. An
    existing snapshot of that name is refused unless ``overwrite_snapshot``,
    which deletes it first; protected snapshots and the profile's clean
    snapshot are never deleted, even then. Without a reboot the readiness wait
    still runs before a snapshot, because the snapshot must capture running
    debuggers.

    The plugin configs are merged (keys the script does not manage are kept).
    With a non-empty ``allowed_clients`` (IPv4 addresses / CIDR ranges) they
    also get ``AllowExternal: true`` and ``AllowedClients``. A non-loopback
    ``bind`` requires them (plugin v1.10+ refuses to start otherwise): when
    ``allowed_clients`` is None they default to the host's own address towards
    the guest IP (``local_ip_for``), and without one the call is refused up
    front. A loopback bind without ``allowed_clients`` leaves both keys as
    they are.

    ``dry_run`` asks the script for its planned actions only (``actions`` and
    ``plan`` in the summary), does not send the password, and performs no
    reboot and no snapshot change.

    Raises ConfigError / PathNotAllowed / ValueError for bad arguments,
    StateViolation / ProtectedSnapshotError for the snapshot slot,
    GuestOperationError when the script reports failure, VmNotReady when the
    guest does not come back in time, and the channel's / VM provider's errors
    otherwise (a failed snapshot step adds ``step`` and
    ``old_snapshot_deleted`` to the error's details). The summary never
    contains the password.
    """
    root = validate_guest_path(x64dbg_root)
    jr = validate_guest_path(job_root if job_root is not None else runtime.profile.job_root_guest)
    account = _check_user(user)
    bind_ip = _check_bind(bind)
    wait_ready_s = _positive("wait_ready_s", wait_ready_s)
    poll_s = _positive("poll_s", poll_s)
    probe_timeout_s = _positive("probe_timeout_s", probe_timeout_s)
    script_timeout_s = _positive("script_timeout_s", script_timeout_s)
    secret = _as_secret(password)
    if autologon and secret is None:
        raise ConfigError("autologon requires the guest password", stage="provision",
                          hint="set the guest password environment variable of the profile, "
                               "or pass autologon=False")
    ports = _ports_by_arch(runtime.backends)
    allowed = _resolve_allowed_clients(runtime, bind_ip, allowed_clients, local_ip_for)
    snap_plan = _plan_snapshot(runtime, clean_snapshot, overwrite_snapshot) if clean_snapshot else None
    if snap_plan is not None and snap_plan.error is not None and not dry_run:
        raise snap_plan.error

    hidden = [secret.reveal()] if secret is not None else []
    params: dict[str, Any] = {
        "x64dbg_root": root, "user": account, "autologon": bool(autologon), "bind": bind_ip,
        "ports": ports, "job_root": jr, "no_sleep": bool(no_sleep), "dry_run": bool(dry_run),
        "allowed_clients": allowed,
    }
    if autologon and secret is not None and not dry_run:
        params["password"] = secret.reveal()  # a dry run only plans: the guest never needs it

    channel = runtime.channel
    log.info("provisioning guest: root=%s user=%s autologon=%s dry_run=%s", root, account, autologon, dry_run)
    channel.mkdir(MCP_DIR)
    _delete_if_exists(channel, RESULT_PATH)  # a stale "ok" must not pass for this run
    guest_params = _gjoin(MCP_DIR, f"provision-{secrets.token_hex(8)}.json")
    try:
        _copy_params(channel, params, guest_params)
        with resources.as_file(packaged_provision_script()) as script_path:
            res = run_powershell_file(channel, script_path, params={"ParamsFile": guest_params},
                                      timeout_s=script_timeout_s)
    finally:
        params.pop("password", None)
        _remove_guest_params(channel, guest_params)

    result = _read_result(channel)
    log_tail = _scrub(_tail_lines(fetch_guest_text(channel, LOG_PATH, max_bytes=_LOG_TAIL_BYTES,
                                                   tail=True)), hidden)
    status = result.get("status") if result is not None else None
    if res.exit_code != 0 or status != "ok":
        error = result.get("error") if result is not None else None
        reason = (error if isinstance(error, str) and error
                  else f"provision.ps1 exited with code {res.exit_code}"
                  + ("" if result is not None else " and wrote no result file"))
        raise GuestOperationError(
            _scrub(f"guest provisioning failed: {_clip(reason)}", hidden),
            stage="provision",
            details=_scrub({"exit_code": res.exit_code, "status": _str_or_none(status, 40),
                            "error": _str_or_none(error), "log_tail": log_tail,
                            "output_tail": _tail_lines(res.output, 20)}, hidden),
            hint=f"see {LOG_PATH} in the guest; dry_run=True shows the planned actions",
        )

    backends = _clean_backends(result.get("backends"))
    skipped = result.get("skipped") if isinstance(result.get("skipped"), list) else []
    # Host-supplied values are returned as given; only guest free text is scrubbed.
    summary: dict[str, Any] = {
        "status": "ok",
        "dry_run": bool(dry_run),
        "x64dbg_root": root,
        "user": account,
        "bind": bind_ip,
        "allowed_clients": list(allowed),
        "job_root": jr,
        "autologon": result.get("autologon") is True,
        "backends": backends,
        "skipped": [a for a in skipped if a in ARCH_SPECS],
        "rebooted": False,
        "reboot_signal": None,  # "boot_time" | "down": what showed the reboot
        "boot_time": None,  # {"before": ISO | None, "after": ISO | None} after a reboot
        "ready_s": None,
        "readiness": {},
        "snapshot": None,
        "log_tail": log_tail,
    }
    if dry_run:
        actions = result.get("actions")
        summary["actions"] = _scrub([_clip(a) for a in actions if isinstance(a, str)][:200]
                                    if isinstance(actions, list) else [], hidden)
        summary["plan"] = {"reboot": bool(reboot),
                           "snapshot": snap_plan.public() if snap_plan is not None else None}
        return summary

    if not backends:
        raise GuestOperationError(
            f"no x64dbg.exe / x32dbg.exe found under {root}; nothing was provisioned for the debuggers",
            stage="provision", details={"x64dbg_root": root, "log_tail": log_tail},
            hint="pass the release folder that contains x64\\ and x32\\ (see discover_x64dbg)")
    targets = {b.id: b.port for b in runtime.backends.values() if b.port is not None and b.arch in backends}

    if reboot:
        boot_before = _boot_time_before_reboot(channel)
        channel.run_program(SHUTDOWN_EXE, list(REBOOT_ARGS), wait=False)
        log.info("guest reboot requested (boot time %s); waiting up to %gs for %s",
                 boot_before.iso if boot_before is not None else "unknown", wait_ready_s,
                 ", ".join(targets))
        ready_s, obs, watch = _wait_reboot(runtime, targets, wait_ready_s=wait_ready_s, poll_s=poll_s,
                                           probe=http_probe, probe_timeout_s=probe_timeout_s,
                                           boot_before=boot_before)
        summary.update(rebooted=True, ready_s=round(ready_s, 1), readiness=dict(obs.statuses),
                       reboot_signal=watch.signal,
                       boot_time={"before": watch.before_iso, "after": watch.after})
    elif snap_plan is not None:
        start = runtime.clock.monotonic()
        obs = _wait_up(runtime, targets, deadline=start + wait_ready_s, poll_s=poll_s, probe=http_probe,
                       probe_timeout_s=probe_timeout_s, stage="snapshot", timeout_s=wait_ready_s)
        summary.update(ready_s=round(runtime.clock.monotonic() - start, 1), readiness=dict(obs.statuses))

    if snap_plan is not None:
        summary["snapshot"] = _take_snapshot(runtime, snap_plan.name, overwrite_snapshot)
    return summary


# ── plugin deployment ───────────────────────────────────────────────
def _kill_debuggers(runtime: RuntimeLike, images: Iterable[str], *, kill_wait_s: float) -> list[int]:
    """Kill every guest process whose image is one of ``images`` and wait until they are gone."""
    channel, clock = runtime.channel, runtime.clock
    wanted = {i.lower() for i in images}
    victims = [p for p in channel.list_processes() if p.image_name in wanted]
    killed: list[int] = []
    for p in victims:
        try:
            channel.kill_process(p.pid)
            killed.append(p.pid)
        except GatewayError as exc:
            if isinstance(exc, GUEST_ENV_ERRORS):
                raise
            log.info("debugger pid %d could not be killed (%s); probably already gone", p.pid, exc.code)
    pids = {p.pid for p in victims}
    alive = set(pids)

    def gone() -> bool:
        nonlocal alive
        alive = {p.pid for p in channel.list_processes()} & pids
        return not alive

    if pids and not _poll_until(clock, clock.monotonic() + kill_wait_s, 0.5, gone):
        raise BackendUnavailable(
            f"debugger process(es) did not exit within {kill_wait_s:g}s; the plugin was not replaced",
            stage="install_plugin", details={"pids": sorted(alive), "timeout_s": kill_wait_s},
            hint="the DLL stays locked while a debugger runs; take a screenshot (vm_screenshot)",
        )
    return sorted(killed)


def _utc_now(clock: Clock) -> datetime:
    """The clock's UTC time, whole seconds (backup names); the host clock if it cannot be parsed."""
    try:
        now = datetime.fromisoformat(clock.now_iso())
    except (TypeError, ValueError):
        now = datetime.now(UTC)
    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)
    return now.astimezone(UTC).replace(microsecond=0)


def _known_backups(channel: GuestChannel, dirs: Sequence[str]) -> dict[str, dict[str, str | None]] | None:
    """``{folded dir: {file name: sha256 or None}}`` of the ``*.bak`` files in ``dirs``.

    Hashed in the guest (one PowerShell run for all folders, Get-FileHash). None
    when the listing failed or is unreadable: then every replaced plugin gets a
    new backup (a duplicate is harmless, a missing backup is not). Guest
    environment errors propagate.
    """
    script = _BACKUP_HASH_SCRIPT.replace("__DIRS__", ", ".join(ps_quote(d) for d in dirs))
    try:
        res = run_powershell(channel, script, timeout_s=_BACKUP_HASH_TIMEOUT_S)
    except GatewayError as exc:
        if isinstance(exc, GUEST_ENV_ERRORS):
            raise
        log.warning("could not list the existing plugin backups (%s); every replaced plugin is backed up",
                    exc.code)
        return None
    lines = [line for line in res.output.splitlines() if line.startswith(_MARKER)]
    rows: Any = None
    if res.ok and lines:
        try:
            rows = json.loads(lines[-1][len(_MARKER):])
        except ValueError:
            rows = None
    if isinstance(rows, dict):
        rows = [rows]  # Windows PowerShell may unwrap a one-element array
    if not isinstance(rows, list):
        log.warning("could not list the existing plugin backups (exit code %d); every replaced plugin "
                    "is backed up", res.exit_code)
        return None
    known: dict[str, dict[str, str | None]] = {fold_case(d): {} for d in dirs}
    for row in rows:
        if not isinstance(row, dict):
            continue
        d, name, sha = row.get("dir"), row.get("name"), row.get("sha256")
        if not isinstance(d, str) or fold_case(d) not in known or not isinstance(name, str) \
                or not name or "\\" in name or "/" in name:
            continue
        digest = sha.lower() if isinstance(sha, str) else ""
        known[fold_case(d)][name] = digest if _SHA256_RE.fullmatch(digest) else None
    return known


@dataclass
class _Backups:
    """The backups of one plugin in its ``plugins_backup`` folder (names as listed)."""

    directory: str
    plugin: str  # plugin file name, e.g. x64dbg-MCP-Server.dp64
    stamp: datetime
    hashes: dict[str, str | None] = field(default_factory=dict)  # file name -> sha256 (None: unknown)

    def same_as(self, sha: str) -> str | None:
        """Path of an existing backup with this SHA-256, if any."""
        for name in sorted(self.hashes):
            if self.hashes[name] == sha:
                return _gjoin(self.directory, name)
        return None

    def _free_path(self, channel: GuestChannel) -> str:
        taken = {fold_case(n) for n in self.hashes}
        for i in range(_BACKUP_NAME_TRIES):
            name = f"{self.plugin}.{(self.stamp + timedelta(seconds=i)).strftime(_BACKUP_STAMP)}.bak"
            path = _gjoin(self.directory, name)
            if fold_case(name) in taken or channel.file_exists(path):
                continue
            return path
        raise GuestOperationError(f"no free backup name in {self.directory}", stage="install_plugin",
                                  details={"backup_dir": self.directory},
                                  hint=f"clean up old backups in {self.directory}")

    def store(self, channel: GuestChannel, local: Path, sha: str) -> tuple[str, bool]:
        """Back ``local`` (a host copy of a guest plugin) up; returns (path, created).

        Nothing is written when a backup with the same SHA-256 exists already.
        """
        same = self.same_as(sha)
        if same is not None:
            return same, False
        channel.mkdir(self.directory)
        path = self._free_path(channel)
        channel.copy_to_guest(local, path)
        self.hashes[PureWindowsPath(path).name] = sha
        return path, True


def _fetch_and_hash(channel: GuestChannel, guest_path: str, local: Path) -> str:
    channel.copy_from_guest(guest_path, local)
    return sha256_file(local)


def _adopt_legacy_backup(channel: GuestChannel, legacy: str, backups: _Backups, tmp: Path) -> str | None:
    """Move a file left in plugins\\ (``<plugin>.bak`` of earlier versions, a stale
    ``<plugin>.old``) into ``plugins_backup``.

    Best effort (the install does not depend on it): an identical backup that
    exists already makes it a plain delete. Returns the backup path, or None
    (logged) when it could not be moved. Guest environment errors propagate.
    """
    try:
        local = tmp / ("leftover" + PureWindowsPath(legacy).suffix)
        path, _created = backups.store(channel, local, _fetch_and_hash(channel, legacy, local))
        channel.delete_file(legacy)
    except GatewayError as exc:
        if isinstance(exc, GUEST_ENV_ERRORS):
            raise
        log.warning("could not move the old plugin backup %s into %s (%s); x64dbg may still see it",
                    legacy, backups.directory, exc.code)
        return None
    log.info("moved the old plugin backup %s to %s", legacy, path)
    return path


def _discard_upload(channel: GuestChannel, new: str) -> None:
    """Best effort after a failure before the swap: remove the uploaded ``.new`` (E7)."""
    try:
        _delete_if_exists(channel, new)
    except GatewayError as exc:
        log.warning("could not remove %s (%s); the next install removes it", new, exc.code)


def _settle_stale_old(channel: GuestChannel, old: str, target: str, backups: _Backups, tmp: Path) -> None:
    """Deal with a ``<plugin>.old`` left by an interrupted install, before the swap.

    Without ``target`` the earlier run died between its two renames: ``.old`` is
    the previous plugin and the only copy of it, so it is renamed back to
    ``target`` (and then backed up like any current plugin); if that rename
    fails, the error names it in ``previous_plugin``. Next to an existing
    ``target`` it is a stale extra copy: moved into ``plugins_backup``, or
    deleted when that fails (as before).
    """
    if not channel.file_exists(target):
        try:
            channel.rename(old, target)
        except GatewayError as exc:
            exc.details.update({"target": target, "restored": False, "previous_plugin": old})
            raise
        log.warning("found %s but no %s (an interrupted install); moved it back before installing",
                    old, target)
        return
    if _adopt_legacy_backup(channel, old, backups, tmp) is None:
        _delete_if_exists(channel, old)


def _replace_plugin(channel: GuestChannel, local: Path, target: str, backups: _Backups) -> dict[str, Any]:
    """Swap in ``local`` as ``target``; back the replaced build up in ``plugins_backup`` first.

    Steps: upload ``target.new``; move a ``target.bak`` left by earlier versions
    into the backup folder; settle a stale ``target.old`` (:func:`_settle_stale_old`:
    put back as ``target`` when ``target`` is missing, else moved to the backup
    folder); copy the current plugin to the host, hash it and copy it to
    ``<backup dir>\\<plugin>.<UTC stamp>.bak`` unless a backup with the same
    SHA-256 exists; only then rename ``target`` to ``target.old`` and ``.new``
    into place, and delete ``.old``. A failure before the swap removes ``.new``
    again (best effort), so nothing but the plugin itself stays in plugins\\
    (E7). When the second rename fails, ``.old`` is moved back, so a failure
    never leaves the debugger without a plugin unless the move back fails too
    (the error's details then name ``previous_plugin``); ``.new`` is then kept
    and named in ``details['uploaded']``.

    Returns ``backup`` ("created": this call stored it; "kept": an identical
    backup existed; "none": there was no plugin to back up), ``backup_path`` and
    ``legacy_backup`` (where an old ``.bak`` from plugins\\ went, else None).
    """
    new, old, legacy = target + ".new", target + ".old", target + ".bak"
    result: dict[str, Any] = {"backup": "none", "backup_path": None, "legacy_backup": None}
    try:
        _delete_if_exists(channel, new)
        channel.copy_to_guest(local, new)  # upload first: the old plugin stays until the copy worked
        with tempfile.TemporaryDirectory(prefix="x64dbg-gw-plugin-") as tmp:
            if channel.file_exists(legacy):
                result["legacy_backup"] = _adopt_legacy_backup(channel, legacy, backups, Path(tmp))
            if channel.file_exists(old):
                _settle_stale_old(channel, old, target, backups, Path(tmp))
            if not channel.file_exists(target):
                channel.rename(new, target)
                return result
            current = Path(tmp) / "current.bin"
            path, created = backups.store(channel, current, _fetch_and_hash(channel, target, current))
    except GatewayError:
        _discard_upload(channel, new)
        raise
    result.update(backup="created" if created else "kept", backup_path=path)
    channel.rename(target, old)
    try:
        channel.rename(new, target)
    except GatewayError as exc:
        try:
            channel.rename(old, target)
            restored = True
        except GatewayError as undo:
            restored = False
            log.error("plugin swap failed and %s could not be moved back to %s (%s)", old, target, undo.code)
        exc.details.update({"target": target, "uploaded": new, "restored": restored, "backup_path": path})
        if not restored:
            exc.details["previous_plugin"] = old
        raise
    try:
        channel.delete_file(old)
    except GatewayError as exc:
        log.warning("could not delete %s (%s); the next install removes it", old, exc.code)
    return result


def _task_for(arch: str, by_arch: Mapping[str, BackendConfig]) -> str:
    cfg = by_arch.get(arch)
    return cfg.launch_task if cfg is not None and cfg.launch_task else ARCH_SPECS[arch].task


def _relaunch_quietly(channel: GuestChannel, tasks: Sequence[str]) -> list[str]:
    """Best effort after a failed install: start ``tasks``; returns the ones that started."""
    started: list[str] = []
    for task in tasks:
        try:
            rc = channel.run_program(SCHTASKS_EXE, ["/run", "/tn", task], wait=True, timeout_s=60.0)
        except GatewayError as exc:
            log.warning("could not relaunch %s after the failed install (%s)", task, exc.code)
            continue
        if rc in (0, None):
            started.append(task)
        else:
            log.warning("schtasks /run /tn %s exited with %s after the failed install", task, rc)
    return started


def install_plugin(
    runtime: RuntimeLike,
    *,
    dist_dir: Path | str,
    x64dbg_root: str,
    relaunch: bool = True,
    wait_ready_s: float = 120.0,
    http_probe: HttpProbe = default_http_probe,
    token_for: TokenFor | None = None,
    info_probe: InfoProbe = default_info_probe,
    poll_s: float = 2.0,
    probe_timeout_s: float = 3.0,
    kill_wait_s: float = 30.0,
) -> dict[str, Any]:
    """Deploy a plugin build into the guest's x64dbg and relaunch the debuggers.

    ``dist_dir`` must contain ``x64/plugins/x64dbg-MCP-Server.dp64`` and
    ``x32/plugins/x64dbg-MCP-Server.dp32``. For each architecture present
    under ``x64dbg_root`` in the guest: running ``x64dbg.exe`` / ``x32dbg.exe``
    processes are killed (matched by image name) and awaited, the new file is
    uploaded as ``<plugin>.new``, the current plugin is backed up to
    ``<root>\\<arch>\\plugins_backup\\<plugin>.<UTC yyyymmddTHHMMSSZ>.bak``
    unless a backup with the same SHA-256 is there already (a taken name moves
    to the next free second), and ``.new`` is renamed into place. A
    ``<plugin>.bak`` that earlier versions left in ``plugins\\`` is moved to
    ``plugins_backup`` too (E7: x64dbg scans ``plugins\\``). The SHA-256 of the
    existing backups is computed in the guest by one PowerShell run before the
    debuggers are killed; when that fails, every replaced plugin is backed up.
    ``installed[arch]`` reports ``backup`` ("created" / "kept" / "none"),
    ``backup_path`` and ``legacy_backup``.

    With ``relaunch`` the logon tasks (``launch_task`` of the backend, default
    MCP-x64dbg / MCP-x32dbg) are started with ``schtasks /run`` and every
    backend port must answer ``GET /`` (200/401/429) within ``wait_ready_s``
    (each port is asked until it answers once, to stay clear of the plugin's
    auth lockout). The
    plugin version is read from ``GET /`` only when ``token_for(backend_id)``
    returns a token (unauthenticated ``GET /`` answers 401 up to v1.10).

    Raises TransferError (missing build output), GuestOperationError (no x64dbg
    under the root, schtasks failure), BackendUnavailable (a debugger did not
    exit) and VmNotReady (ports not answering; ``details['installed']`` then
    says what was replaced). When uploading or swapping a plugin fails after
    the debuggers were killed, the channel's error is raised with
    ``details`` ``failed_arch``, ``installed`` (what was already replaced),
    ``killed`` and ``relaunched`` (the logon tasks started again, with
    ``relaunch``, so the debuggers come back with the plugin they had).
    """
    dist = Path(dist_dir)
    local = {arch: dist / arch / "plugins" / spec.plugin for arch, spec in ARCH_SPECS.items()}
    missing = [str(p) for p in local.values() if not p.is_file()]
    if missing:
        raise TransferError("plugin build output not found", stage="install_plugin",
                            details={"dist_dir": str(dist), "missing": missing},
                            hint="build the plugin and pass the folder holding x64\\plugins and x32\\plugins")
    # Read the local builds before anything in the guest changes.
    builds = {arch: {"sha256": sha256_file(path), "size": path.stat().st_size}
              for arch, path in local.items()}
    root = validate_guest_path(x64dbg_root)
    wait_ready_s = _positive("wait_ready_s", wait_ready_s)
    poll_s = _positive("poll_s", poll_s)
    probe_timeout_s = _positive("probe_timeout_s", probe_timeout_s)
    kill_wait_s = _positive("kill_wait_s", kill_wait_s)
    channel, clock = runtime.channel, runtime.clock

    present = [a for a, spec in ARCH_SPECS.items() if channel.file_exists(_gjoin(root, a, spec.exe))]
    if not present:
        raise GuestOperationError(f"no x64dbg.exe / x32dbg.exe under {root}", stage="install_plugin",
                                  details={"x64dbg_root": root}, hint="see discover_x64dbg")
    by_arch: dict[str, BackendConfig] = {}
    for b in runtime.backends.values():
        by_arch.setdefault(b.arch, b)
    # Read-only steps before the debuggers die: what is backed up already, and the stamp.
    backup_dirs = {a: _gjoin(root, a, BACKUP_DIR_NAME) for a in present}
    known = _known_backups(channel, [backup_dirs[a] for a in present])
    stamp = _utc_now(clock)
    killed = _kill_debuggers(runtime, [ARCH_SPECS[a].exe for a in present], kill_wait_s=kill_wait_s)

    installed: dict[str, dict[str, Any]] = {}
    arch = present[0]
    try:
        for arch in present:
            spec = ARCH_SPECS[arch]
            plugin_dir = _gjoin(root, arch, "plugins")
            target = _gjoin(plugin_dir, spec.plugin)
            prefix = fold_case(spec.plugin + ".")
            listed = known.get(fold_case(backup_dirs[arch]), {}) if known is not None else {}
            backups = _Backups(backup_dirs[arch], spec.plugin, stamp,
                               {n: h for n, h in listed.items() if fold_case(n).startswith(prefix)})
            try:
                channel.mkdir(plugin_dir)
                result = _replace_plugin(channel, local[arch], target, backups)
            except GatewayError as exc:
                exc.details.setdefault("target", target)
                raise
            installed[arch] = {"guest_path": target, **result, **builds[arch]}
            log.info("plugin %s installed at %s (backup: %s %s)", arch, target, result["backup"],
                     result["backup_path"] or "-")
    except GatewayError as exc:
        # The debuggers are dead and an upload/swap failed: say what was done, and bring the
        # debuggers back (each plugin file is either the new build or the one it replaced).
        relaunched = _relaunch_quietly(channel, [_task_for(a, by_arch) for a in present]) if relaunch else []
        log.error("plugin install failed for %s (%s); installed: %s; relaunched: %s",
                  arch, exc.code, ", ".join(installed) or "none", ", ".join(relaunched) or "none")
        exc.details.update({"failed_arch": arch, "installed": installed, "killed": killed,
                            "relaunched": relaunched})
        if exc.hint is None:
            exc.hint = ("architectures missing from details['installed'] keep their previous plugin "
                        "(if details['restored'] is false it is at details['previous_plugin'] and must "
                        "be renamed back by hand); fix the cause and run install_plugin again")
        raise

    summary: dict[str, Any] = {"x64dbg_root": root, "installed": installed,
                               "skipped": [a for a in ARCH_SPECS if a not in present],
                               "killed": killed, "relaunched": False, "backends": {}}
    if not relaunch:
        return summary

    failures: dict[str, int] = {}
    for arch in present:
        task = _task_for(arch, by_arch)
        rc = channel.run_program(SCHTASKS_EXE, ["/run", "/tn", task], wait=True, timeout_s=60.0)
        if rc not in (0, None):
            failures[task] = rc
    summary["relaunched"] = True
    if failures:
        raise GuestOperationError(
            "schtasks /run failed; the debuggers were not relaunched", stage="install_plugin",
            details={"tasks": failures, "installed": installed},
            hint="run guest provisioning first (it registers the MCP-x64dbg / MCP-x32dbg tasks)")

    targets = {b.id: b.port for b in runtime.backends.values() if b.port is not None and b.arch in present}
    obs = _wait_up(runtime, targets, deadline=clock.monotonic() + wait_ready_s, poll_s=poll_s,
                   probe=http_probe, probe_timeout_s=probe_timeout_s, stage="install_plugin",
                   timeout_s=wait_ready_s, extra={"installed": installed})
    for bid, port in targets.items():
        version: str | None = None
        token = _as_secret(token_for(bid)) if token_for is not None else None
        if token is not None and obs.ip:
            try:
                info = info_probe(obs.ip, port, probe_timeout_s, token)
            except (OSError, GatewayError, ValueError, http.client.HTTPException):
                info = None
            v = info.get("version") if isinstance(info, dict) else None
            version = _clip(v, 64) if isinstance(v, str) else None
        summary["backends"][bid] = {"port": port, "status": obs.statuses.get(bid), "version": version}
    return summary


# ── discovery ───────────────────────────────────────────────────────
# Read-only. Search bases: every top-level folder of each user profile (Desktop,
# Downloads, Documents, ...) and of C:\ (minus Windows/Users/ProgramData/...),
# skipping junctions, plus caller-supplied roots; each searched to __MAX_DEPTH__.
_DISCOVER_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$maxDepth = __MAX_DEPTH__
$archs = @(
    @{ id = 'x64'; exe = 'x64dbg.exe'; plugin = 'x64dbg-MCP-Server.dp64' },
    @{ id = 'x32'; exe = 'x32dbg.exe'; plugin = 'x64dbg-MCP-Server.dp32' }
)
$skipTop = @('Windows', 'Users', 'ProgramData', '$Recycle.Bin', 'System Volume Information',
    'Recovery', 'PerfLogs', 'Config.Msi', 'Documents and Settings')
$skipProfile = @('AppData')
function Get-Dirs([string]$Path) {
    @(Get-ChildItem -LiteralPath $Path -Directory -Force |
        Where-Object { -not ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) })
}
$bases = New-Object System.Collections.Generic.List[string]
$seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
function Add-Base([string]$Path) {
    if (-not $Path) { return }
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return }
    if ($seen.Add($Path)) { $bases.Add($Path) }
}
$profiles = @(Get-Dirs 'C:\Users')
# Most likely places first: Desktop / Downloads (also OneDrive-redirected ones).
Add-Base ([Environment]::GetFolderPath('Desktop'))
foreach ($u in $profiles) {
    foreach ($sub in @('Desktop', 'Downloads', 'OneDrive\Desktop', 'Documents')) {
        Add-Base (Join-Path $u.FullName $sub)
    }
}
foreach ($extra in @(__EXTRA_ROOTS__)) { Add-Base $extra }
foreach ($u in $profiles) {
    foreach ($d in (Get-Dirs $u.FullName)) {
        if ($skipProfile -notcontains $d.Name) { Add-Base $d.FullName }
    }
}
foreach ($d in (Get-Dirs 'C:\')) {
    if ($skipTop -notcontains $d.Name) { Add-Base $d.FullName }
}
$roots = [ordered]@{}
foreach ($b in $bases) {
    $found = @(Get-ChildItem -LiteralPath $b -Recurse -Depth $maxDepth -File -Force -Filter 'x??dbg.exe')
    foreach ($f in $found) {
        $arch = $f.Directory.Name.ToLowerInvariant()
        $isX64 = ($f.Name -eq 'x64dbg.exe') -and ($arch -eq 'x64')
        $isX32 = ($f.Name -eq 'x32dbg.exe') -and ($arch -eq 'x32')
        if ($isX64 -or $isX32) {
            $root = $f.Directory.Parent.FullName
            $key = $root.ToLowerInvariant()
            if (-not $roots.Contains($key)) { $roots[$key] = $root }
        }
    }
}
function Get-ConfigState([string]$Path) {
    # Never returns the token: only whether it is usable.
    $info = [ordered]@{ state = 'missing'; port = $null; bind = $null }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $info }
    try {
        $raw = [System.IO.File]::ReadAllText($Path)
        if ($raw.Trim([char]0).Trim().Length -eq 0) { $info.state = 'empty'; return $info }
        $cfg = $raw | ConvertFrom-Json
        if ($cfg.Port) { $info.port = [int]$cfg.Port }
        if ($cfg.IpAddress) { $info.bind = [string]$cfg.IpAddress }
        $tokenOk = [string]$cfg.AuthToken -match '^[A-Za-z0-9]{32,64}$'
        $info.state = if ($tokenOk) { 'valid' } else { 'bad_token' }
    } catch { $info.state = 'corrupt' }
    return $info
}
function Get-PluginInfo([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return [ordered]@{ present = $false } }
    $item = Get-Item -LiteralPath $Path -Force
    $version = $null
    try { $version = $item.VersionInfo.FileVersion } catch { }
    return [ordered]@{
        present = $true; size = $item.Length; mtime = $item.LastWriteTimeUtc.ToString('s') + 'Z'
        file_version = $version
    }
}
$out = New-Object System.Collections.Generic.List[object]
foreach ($root in $roots.Values) {
    $entry = [ordered]@{ root = $root }
    foreach ($a in $archs) {
        $dir = Join-Path $root $a.id
        $entry[$a.id] = [ordered]@{
            exe = (Test-Path -LiteralPath (Join-Path $dir $a.exe) -PathType Leaf)
            plugin = (Get-PluginInfo (Join-Path (Join-Path $dir 'plugins') $a.plugin))
            config = (Get-ConfigState (Join-Path $dir 'mcp_config.json'))
        }
    }
    $out.Add([pscustomobject]$entry)
}
'MCPJSON:' + (ConvertTo-Json -InputObject @($out) -Depth 6 -Compress)
"""


def _clean_config(value: Any) -> dict[str, Any]:
    v = value if isinstance(value, dict) else {}
    state = v.get("state")
    port = _int_or_none(v.get("port"))
    return {
        "state": state if state in _CONFIG_STATES else "unknown",
        "port": port if port is not None and 1 <= port <= 65535 else None,
        "bind": _str_or_none(v.get("bind"), 64),
    }


def _clean_discovery(item: Any) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    try:
        root = validate_guest_path(item.get("root"))  # type: ignore[arg-type]
    except PathNotAllowed:
        log.info("discovery: ignoring an unusable root path reported by the guest")
        return None
    entry: dict[str, Any] = {"root": root}
    for arch, spec in ARCH_SPECS.items():
        sub = item.get(arch) if isinstance(item.get(arch), dict) else {}
        exe = sub.get("exe") is True
        plugin = _clean_plugin(sub.get("plugin"))
        config = _clean_config(sub.get("config"))
        info: dict[str, Any] = {"exe": exe, "plugin": plugin, "config": config,
                                "ready": exe and plugin["present"] and config["state"] == "valid"}
        if exe and config["state"] != "valid":
            info["hint"] = (f"{arch}\\mcp_config.json is {config['state']}: run guest provisioning "
                            "(x64dbg-vm-gateway provision) to rewrite it with a fresh token")
        elif exe and not plugin["present"]:
            info["hint"] = f"{spec.plugin} is missing: deploy it with install_plugin"
        entry[arch] = info
    return entry


def discover_x64dbg(
    channel: GuestChannel,
    *,
    extra_roots: Sequence[str] = (),
    max_depth: int = 4,
    timeout_s: float = 600.0,
    guest_tmp_dir: str = DEFAULT_GUEST_TMP_DIR,
) -> list[dict[str, Any]]:
    """Find x64dbg installations in the guest (read-only).

    Searches every top-level folder of each user profile (Desktop, Downloads,
    ...) and of ``C:\\`` (system folders and junctions excluded) plus
    ``extra_roots``, ``max_depth`` levels deep, for ``<root>\\x64\\x64dbg.exe``
    and ``<root>\\x32\\x32dbg.exe``. Per root it reports for x64 and x32:
    ``exe`` present, ``plugin`` file info, ``config`` (state ``valid`` /
    ``missing`` / ``empty`` (zero-filled) / ``corrupt`` / ``bad_token``, port,
    bind), ``ready`` and a ``hint`` when something needs fixing. Tokens are
    never returned. Guest output is untrusted: unknown fields are dropped and
    roots failing ``validate_guest_path`` are skipped.
    """
    roots = [validate_guest_path(r) for r in extra_roots]
    if isinstance(max_depth, bool) or not isinstance(max_depth, int) or not 0 <= max_depth <= 10:
        raise ValueError("max_depth must be an int in 0..10")
    script = (_DISCOVER_SCRIPT.replace("__MAX_DEPTH__", str(max_depth))
              .replace("__EXTRA_ROOTS__", ", ".join(ps_quote(r) for r in roots)))
    res = run_powershell(channel, script, timeout_s=_positive("timeout_s", timeout_s),
                         guest_tmp_dir=guest_tmp_dir)
    lines = [line for line in res.output.splitlines() if line.startswith(_MARKER)]
    doc: Any = None
    if res.ok and lines:
        try:
            doc = json.loads(lines[-1][len(_MARKER):])
        except ValueError:
            doc = None
    if isinstance(doc, dict):
        doc = [doc]  # Windows PowerShell may unwrap a one-element array
    if not isinstance(doc, list):
        raise GuestOperationError("x64dbg discovery failed in the guest", stage="discover",
                                  details={"exit_code": res.exit_code,
                                           "output_tail": _tail_lines(res.output, 20)})
    return [e for e in (_clean_discovery(item) for item in doc) if e is not None]
