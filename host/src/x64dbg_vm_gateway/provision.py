"""Guest provisioning, plugin deployment and x64dbg discovery (plan 5.7).

Everything goes through a ``contracts.GuestChannel`` (VixChannel in production)
plus the VM provider, so it is unit-testable with FakeGuest / FakeVm.

- :func:`discover_x64dbg` searches the guest for x64dbg installations
  (``<root>\\x64\\x64dbg.exe`` / ``<root>\\x32\\x32dbg.exe``) and reports plugin
  files and ``mcp_config.json`` health without ever returning a token.
- :func:`provision_guest` runs the packaged ``guest/provision.ps1`` (job root +
  ACL, plugin configs, elevated ``MCP-x64dbg`` / ``MCP-x32dbg`` logon tasks,
  auto-logon, power settings), optionally reboots and waits until every
  provisioned backend port answers, and optionally (re)takes the clean snapshot.
- :func:`install_plugin` replaces the plugin DLLs with a new build (backing the
  original up once), relaunches the debuggers through the logon tasks and
  reports what answers.

Phase 0 facts behind the design: vmrun mangles double quotes in program
arguments (hence ``ps.run_powershell*``); there is no interactive session before
auto-logon, so debuggers are (re)started through the scheduled tasks; after a
reboot both plugins answered within 44 s; ``GET /`` without a token answers 401
on plugins up to v1.10, which already proves the HTTP server is up.

Secrets: the guest password travels only in a params file (0600 on the host,
deleted in ``finally``; the guest script deletes its copy on read and the host
removes it if the script never ran). It is never logged, and every text that
comes back from the guest is scrubbed of it before it reaches a summary or an
exception. Bearer tokens are only handed to the injectable ``info_probe``.

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
import tempfile
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
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
from .guest import GUEST_ENV_ERRORS, validate_guest_path
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
    "RuntimeLike",
    "default_http_probe",
    "default_info_probe",
    "discover_x64dbg",
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
#: ``GET /`` answers that prove the plugin's HTTP server is up (401: no token sent).
READY_STATUSES = frozenset({200, 401})


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

_PROBE_BODY_LIMIT = 64 * 1024
_RESULT_LIMIT = 256 * 1024
_LOG_TAIL_BYTES = 64 * 1024
_LOG_TAIL_LINES = 40
_TEXT_LIMIT = 300
_CONFIG_STATES = frozenset({"valid", "missing", "empty", "corrupt", "bad_token"})
_USER_FORBIDDEN = frozenset('"/[]:;|=,+*?<>')
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_MARKER = "MCPJSON:"


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
    try:
        return str(ipaddress.ip_address(str(bind).strip()))
    except ValueError:
        raise ConfigError("bind must be an IP address (e.g. 0.0.0.0 or the host-only adapter IP)",
                          stage="provision", details={"bind": _clip(repr(bind), 80)}) from None


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
    """Replace every secret value inside strings (recursively) with ``***``."""
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
    tools_running: bool
    ip: str | None
    statuses: dict[str, int | None] = field(default_factory=dict)

    @property
    def ready(self) -> bool:
        return self.tools_running and bool(self.ip) and all(s in READY_STATUSES
                                                            for s in self.statuses.values())

    @property
    def down(self) -> bool:
        # "No backend answers" rather than "some backend is missing": one port that was
        # already dead before the reboot must not be mistaken for the reboot itself.
        # Without any port to probe only Tools / the guest IP can show the reboot.
        if not self.tools_running or not self.ip:
            return True
        return bool(self.statuses) and not any(s in READY_STATUSES for s in self.statuses.values())

    @property
    def pending(self) -> list[str]:
        return sorted(bid for bid, s in self.statuses.items() if s not in READY_STATUSES)

    def details(self) -> dict[str, Any]:
        return {"tools_running": self.tools_running, "ip": self.ip, "readiness": dict(self.statuses),
                "pending": self.pending}


def _observe(runtime: RuntimeLike, targets: Mapping[str, int], probe: HttpProbe,
             probe_timeout_s: float) -> _Observation:
    try:
        tools_running = runtime.vm.tools_state() == ToolsState.RUNNING
    except GatewayError:
        tools_running = False
    ip: str | None = None
    if tools_running:
        try:
            ip = runtime.guest_ip()
        except GatewayError:
            ip = None
    statuses: dict[str, int | None] = dict.fromkeys(targets)
    if ip:
        for bid, port in targets.items():
            statuses[bid] = _safe_probe(probe, ip, port, probe_timeout_s)
    return _Observation(tools_running, ip, statuses)


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

    def ready() -> bool:
        last[:] = [_observe(runtime, targets, probe, probe_timeout_s)]
        return last[0].ready

    if _poll_until(runtime.clock, deadline, poll_s, ready):
        return last[0]
    obs = last[0] if last else _Observation(False, None, dict.fromkeys(targets))
    raise VmNotReady(
        f"guest backends not ready within {timeout_s:g}s (waiting for: "
        f"{', '.join(obs.pending) or 'VMware Tools / guest IP'})",
        stage=stage,
        details={"phase": "up", "timeout_s": timeout_s, **obs.details(), **(extra or {})},
        hint="the debuggers start from the MCP-x64dbg / MCP-x32dbg logon tasks after auto-logon; "
             "take a screenshot (vm_screenshot) to look for a logon screen or a modal dialog",
    )


def _wait_reboot(runtime: RuntimeLike, targets: Mapping[str, int], *, wait_ready_s: float, poll_s: float,
                 probe: HttpProbe, probe_timeout_s: float) -> tuple[float, _Observation]:
    """Wait until the guest is seen going down, then until every target answers."""
    clock = runtime.clock
    start = clock.monotonic()
    deadline = start + wait_ready_s
    if not _poll_until(clock, deadline, poll_s,
                       lambda: _observe(runtime, targets, probe, probe_timeout_s).down):
        raise VmNotReady(
            f"the guest did not go down within {wait_ready_s:g}s after the reboot was requested",
            stage="reboot", details={"phase": "down", "timeout_s": wait_ready_s},
            hint="the old debugger instances are still answering; check that shutdown.exe can run",
        )
    obs = _wait_up(runtime, targets, deadline=deadline, poll_s=poll_s, probe=probe,
                   probe_timeout_s=probe_timeout_s, stage="reboot", timeout_s=wait_ready_s)
    return clock.monotonic() - start, obs


# ── clean snapshot ──────────────────────────────────────────────────
@dataclass(frozen=True)
class _SnapshotPlan:
    name: str
    exists: bool
    action: str  # "take" | "replace" | "refuse"
    error: GatewayError | None = None

    def public(self) -> dict[str, Any]:
        return {"name": self.name, "exists": self.exists, "action": self.action}


def _plan_snapshot(runtime: RuntimeLike, name: str, overwrite: bool) -> _SnapshotPlan:
    if not isinstance(name, str) or not name.strip():
        raise ConfigError("clean_snapshot must be a non-empty snapshot name", stage="snapshot")
    folded = name.casefold()
    same = [s.name for s in runtime.vm.list_snapshots() if s.name.casefold() == folded]
    exists = bool(same)
    if not exists:
        return _SnapshotPlan(name, False, "take")
    if not overwrite:
        return _SnapshotPlan(name, True, "refuse", StateViolation(
            f"snapshot {name!r} already exists", stage="snapshot", details={"snapshot": name},
            hint="pass overwrite_snapshot=True to replace it, or choose another name"))
    clean = runtime.profile.clean_snapshot
    protected = {p.casefold() for p in runtime.profile.protected_snapshots}
    if folded in protected and (clean is None or folded != clean.casefold()):
        return _SnapshotPlan(name, True, "refuse", ProtectedSnapshotError(
            f"snapshot {name!r} is protected and is not this profile's clean snapshot",
            stage="snapshot", details={"snapshot": name}))
    if len(same) > 1 or same[0] != name:
        return _SnapshotPlan(name, True, "refuse", StateViolation(
            f"snapshot name {name!r} does not identify exactly one snapshot", stage="snapshot",
            details={"snapshot": name, "matches": same}, hint="rename or delete the duplicates in VMware"))
    return _SnapshotPlan(name, True, "replace")


def _take_snapshot(runtime: RuntimeLike, name: str, overwrite: bool) -> dict[str, Any]:
    plan = _plan_snapshot(runtime, name, overwrite)  # re-check: the VM may have changed meanwhile
    if plan.error is not None:
        raise plan.error
    if plan.action == "replace":
        log.warning("replacing snapshot %r", name)
        runtime.vm.delete_snapshot(name)
    runtime.vm.take_snapshot(name)
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
    reboot (``shutdown.exe /r /t 2 /f``, not awaited) and wait for the guest to
    go down and for VMware Tools plus every provisioned backend port (HTTP 200
    or 401) within ``wait_ready_s``; finally take ``clean_snapshot`` (an
    existing one is refused unless ``overwrite_snapshot``, which deletes it
    first; protected snapshots other than the profile's clean snapshot are
    never replaced). Without a reboot the readiness wait still runs before a
    snapshot, because the snapshot must capture running debuggers.

    ``dry_run`` asks the script for its planned actions only (``actions`` and
    ``plan`` in the summary) and performs no reboot and no snapshot change.

    Raises ConfigError / PathNotAllowed / ValueError for bad arguments,
    StateViolation / ProtectedSnapshotError for the snapshot slot,
    GuestOperationError when the script reports failure, VmNotReady when the
    guest does not come back in time, and the channel's errors otherwise.
    The summary never contains the password.
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
    snap_plan = _plan_snapshot(runtime, clean_snapshot, overwrite_snapshot) if clean_snapshot else None
    if snap_plan is not None and snap_plan.error is not None and not dry_run:
        raise snap_plan.error

    hidden = [secret.reveal()] if secret is not None else []
    params: dict[str, Any] = {
        "x64dbg_root": root, "user": account, "autologon": bool(autologon), "bind": bind_ip,
        "ports": ports, "job_root": jr, "no_sleep": bool(no_sleep), "dry_run": bool(dry_run),
    }
    if autologon and secret is not None:
        params["password"] = secret.reveal()

    channel = runtime.channel
    log.info("provisioning guest: root=%s user=%s autologon=%s dry_run=%s", root, account, autologon, dry_run)
    channel.mkdir(MCP_DIR)
    _delete_if_exists(channel, RESULT_PATH)  # a stale "ok" must not pass for this run
    guest_params = _gjoin(MCP_DIR, f"provision-{secrets.token_hex(8)}.json")
    try:
        _copy_params(channel, params, guest_params)
        with resources.as_file(packaged_provision_script()) as script_path:
            res = run_powershell_file(channel, script_path, ["-ParamsFile", guest_params],
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
    summary: dict[str, Any] = {
        "status": "ok",
        "dry_run": bool(dry_run),
        "x64dbg_root": root,
        "user": account,
        "bind": bind_ip,
        "job_root": jr,
        "autologon": result.get("autologon") is True,
        "backends": backends,
        "skipped": [a for a in skipped if a in ARCH_SPECS],
        "rebooted": False,
        "ready_s": None,
        "readiness": {},
        "snapshot": None,
        "log_tail": log_tail,
    }
    if dry_run:
        actions = result.get("actions")
        summary["actions"] = [_clip(a) for a in actions if isinstance(a, str)][:200] \
            if isinstance(actions, list) else []
        summary["plan"] = {"reboot": bool(reboot),
                           "snapshot": snap_plan.public() if snap_plan is not None else None}
        return _scrub(summary, hidden)

    if not backends:
        raise GuestOperationError(
            f"no x64dbg.exe / x32dbg.exe found under {root}; nothing was provisioned for the debuggers",
            stage="provision", details={"x64dbg_root": root, "log_tail": log_tail},
            hint="pass the release folder that contains x64\\ and x32\\ (see discover_x64dbg)")
    targets = {b.id: b.port for b in runtime.backends.values() if b.port is not None and b.arch in backends}

    if reboot:
        channel.run_program(SHUTDOWN_EXE, list(REBOOT_ARGS), wait=False)
        log.info("guest reboot requested; waiting up to %gs for %s", wait_ready_s, ", ".join(targets))
        ready_s, obs = _wait_reboot(runtime, targets, wait_ready_s=wait_ready_s, poll_s=poll_s,
                                    probe=http_probe, probe_timeout_s=probe_timeout_s)
        summary.update(rebooted=True, ready_s=round(ready_s, 1), readiness=dict(obs.statuses))
    elif snap_plan is not None:
        start = runtime.clock.monotonic()
        obs = _wait_up(runtime, targets, deadline=start + wait_ready_s, poll_s=poll_s, probe=http_probe,
                       probe_timeout_s=probe_timeout_s, stage="snapshot", timeout_s=wait_ready_s)
        summary.update(ready_s=round(runtime.clock.monotonic() - start, 1), readiness=dict(obs.statuses))

    if snap_plan is not None:
        summary["snapshot"] = _take_snapshot(runtime, snap_plan.name, overwrite_snapshot)
    return _scrub(summary, hidden)


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


def _replace_plugin(channel: GuestChannel, local: Path, target: str) -> str:
    """Swap in ``local`` as ``target`` via ``target.new``; back the original up to ``.bak`` once.

    Returns "created" (this call made the backup), "kept" (an earlier backup was
    left untouched) or "none" (there was nothing to back up).
    """
    new, bak = target + ".new", target + ".bak"
    _delete_if_exists(channel, new)
    channel.copy_to_guest(local, new)  # upload first: the old plugin stays until the copy worked
    has_backup = channel.file_exists(bak)
    if channel.file_exists(target):
        if has_backup:
            channel.delete_file(target)
            backup = "kept"
        else:
            channel.rename(target, bak)
            backup = "created"
    else:
        backup = "kept" if has_backup else "none"
    channel.rename(new, target)
    return backup


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
    uploaded as ``<plugin>.new``, the current plugin is renamed to
    ``<plugin>.bak`` if no backup exists yet (otherwise it is deleted, so the
    backup always holds the original build), and ``.new`` is renamed into place.

    With ``relaunch`` the logon tasks (``launch_task`` of the backend, default
    MCP-x64dbg / MCP-x32dbg) are started with ``schtasks /run`` and every
    backend port must answer ``GET /`` (200/401) within ``wait_ready_s``. The
    plugin version is read from ``GET /`` only when ``token_for(backend_id)``
    returns a token (unauthenticated ``GET /`` answers 401 up to v1.10).

    Raises TransferError (missing build output), GuestOperationError (no x64dbg
    under the root, schtasks failure), BackendUnavailable (a debugger did not
    exit) and VmNotReady (ports not answering; ``details['installed']`` then
    says what was replaced).
    """
    dist = Path(dist_dir)
    local = {arch: dist / arch / "plugins" / spec.plugin for arch, spec in ARCH_SPECS.items()}
    missing = [str(p) for p in local.values() if not p.is_file()]
    if missing:
        raise TransferError("plugin build output not found", stage="install_plugin",
                            details={"dist_dir": str(dist), "missing": missing},
                            hint="build the plugin and pass the folder holding x64\\plugins and x32\\plugins")
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
    killed = _kill_debuggers(runtime, [ARCH_SPECS[a].exe for a in present], kill_wait_s=kill_wait_s)

    installed: dict[str, dict[str, Any]] = {}
    for arch in present:
        spec = ARCH_SPECS[arch]
        plugin_dir = _gjoin(root, arch, "plugins")
        target = _gjoin(plugin_dir, spec.plugin)
        channel.mkdir(plugin_dir)
        backup = _replace_plugin(channel, local[arch], target)
        installed[arch] = {"guest_path": target, "backup": backup,
                           "backup_path": target + ".bak" if backup != "none" else None,
                           "sha256": sha256_file(local[arch]), "size": local[arch].stat().st_size}
        log.info("plugin %s installed at %s (backup: %s)", arch, target, backup)

    summary: dict[str, Any] = {"x64dbg_root": root, "installed": installed,
                               "skipped": [a for a in ARCH_SPECS if a not in present],
                               "killed": killed, "relaunched": False, "backends": {}}
    if not relaunch:
        return summary

    by_arch: dict[str, BackendConfig] = {}
    for b in runtime.backends.values():
        by_arch.setdefault(b.arch, b)
    failures: dict[str, int] = {}
    for arch in present:
        cfg = by_arch.get(arch)
        task = cfg.launch_task if cfg is not None and cfg.launch_task else ARCH_SPECS[arch].task
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
    return [ordered]@{
        present = $true; size = $item.Length; mtime = $item.LastWriteTimeUtc.ToString('s') + 'Z'
        file_version = $item.VersionInfo.FileVersion
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
