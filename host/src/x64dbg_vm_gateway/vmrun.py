"""vmrun runner and VM providers (plan 5.2).

- ``VmrunCli`` implements ``contracts.VmrunRunner``: runs vmrun as an argv list
  (never a shell), enforces a timeout, strips vmrun's noise lines and maps its
  ``Error: ...`` text to typed ``errors.VmrunError`` subclasses. The guest
  password is masked as ``***`` everywhere it could surface (exception
  message, ``details``, repr).
- ``VmrunProvider`` implements ``contracts.VmProvider`` on top of any runner.
- ``NullProvider`` implements ``contracts.VmProvider`` for endpoint-mode
  profiles that have no VM.

Thread-safety: all three classes keep only immutable configuration, so their
methods may be called from several threads at once. They do not serialise VM
operations against each other: callers hold ``locks.VmOpLock`` for that.
"""

from __future__ import annotations

import ipaddress
import os
import re
import subprocess
import tempfile
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import IO, Any

from .contracts import (
    Clock,
    GuestCredentials,
    IsolationReport,
    PowerState,
    Snapshot,
    SystemClock,
    ToolsState,
    VmrunResult,
    VmrunRunner,
)
from .errors import (
    ConfigError,
    GuestAuthFailed,
    GuestOperationError,
    SnapshotNotFound,
    ToolsNotRunning,
    VmLocked,
    VmNotRunning,
    VmrunError,
    VmrunTimeout,
)
from .platform import decode_output, host_system, subprocess_kwargs

MASK = "***"
DETAIL_LIMIT_BYTES = 4096
MAX_CAPTURE_BYTES = 32 * 1024 * 1024  # upper bound on how much vmrun output is read back
KILL_REAP_TIMEOUT_S = 5.0
DEFAULT_TIMEOUT_S = 120.0
_TRUNCATED = "...[truncated]"

# Lines vmrun prints on every invocation on some hosts; never meaningful.
NOISE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^\[AppLoader\]"),
    re.compile(r'^An up-to-date "libaio" or "libaio1" package from your system is preferred'),
    re.compile(r"^Warning: program compiled against libxml \d+ using older \d+"),
)

# ── error classification ────────────────────────────────────────────
# Case-insensitive substring rules, first match wins. Derived from real vmrun
# 1.17.0 output where it could be captured safely (tests/fixtures/vmrun/) and
# from VIX error wording otherwise; error_messages.json records the provenance.
_ERROR_RULES: tuple[tuple[type[VmrunError], tuple[str, ...]], ...] = (
    (ToolsNotRunning, ("tools are not running", "tools is not running", "tools not running",
                       "tools are not installed", "tools is not installed", "tools not installed")),
    (GuestAuthFailed, ("invalid user name or password", "user name or password is incorrect",
                       "unknown user name or bad password", "authentication failure", "authentication failed",
                       "login failure", "login failed", "logon failure", "cannot authenticate",
                       "incorrect password", "invalid password", "invalid credentials")),
    (VmLocked, ("failed to lock", "is locked", "appears to be in use", "already in use",
                "in use by another", "another operation", "operation is in progress",
                "operation in progress", "operation is already in progress", "is busy")),
    (VmNotRunning, ("not powered on", "needs to be powered on", "must be powered on",
                    "virtual machine is not running", "vm is not running", "is powered off")),
)
_SNAPSHOT_MISSING = ("not found", "does not exist", "doesn't exist", "no such", "cannot find",
                     "could not find", "unable to find")
# Errors about the VM/vmrun itself: never re-labelled as guest-operation failures.
_GENERIC = ("cannot open vm", "virtual machine cannot be found", "unrecognized command",
            "should not be powered on", "insufficient permissions in the host")
_GUEST_COMMAND_RE = re.compile(r"(inguest|guesttohost|hosttoguest)$", re.IGNORECASE)

_HINTS: dict[type[VmrunError], tuple[str, str | None]] = {
    VmNotRunning: ("the VM is not powered on; start it first", "session_status"),
    ToolsNotRunning: ("VMware Tools is not running in the guest; wait for the guest to finish booting",
                      "session_status"),
    GuestAuthFailed: ("check profiles.<name>.guest_user and the variable named by guest_password_env", None),
    SnapshotNotFound: ("list the available snapshots first", "vm_snapshots_list"),
    VmLocked: ("another VMware operation holds the VM; retry shortly", None),
}


def is_guest_command(command: str) -> bool:
    """True for vmrun commands that act inside the guest (``*InGuest``, file copies)."""
    return bool(_GUEST_COMMAND_RE.search(command))


def classify_error(text: str, command: str, *, guest: bool = False,
                   vmx: str | None = None) -> type[VmrunError]:
    """Map vmrun error text to the most specific ``VmrunError`` subclass."""
    low = text.lower()
    if vmx:
        # The VM path can contain arbitrary words ("not running", "snapshot"...).
        low = low.replace(vmx.lower(), " ")
    for cls, needles in _ERROR_RULES:
        if any(n in low for n in needles):
            return cls
    if "snapshot" in low and any(n in low for n in _SNAPSHOT_MISSING):
        return SnapshotNotFound
    if any(n in low for n in _GENERIC):
        return VmrunError
    if guest or is_guest_command(command):
        return GuestOperationError
    return VmrunError


def filter_noise(text: str) -> str:
    """Drop vmrun noise lines and CRs; strip leading/trailing blank lines (keeps TAB indentation)."""
    kept = [ln.rstrip("\r") for ln in text.splitlines()]
    kept = [ln for ln in kept if not any(p.match(ln) for p in NOISE_PATTERNS)]
    return "\n".join(kept).strip("\n")


def _truncate(text: str, limit: int = DETAIL_LIMIT_BYTES) -> str:
    data = text.encode("utf-8", errors="replace")
    if len(data) <= limit:
        return text
    keep = data[: limit - len(_TRUNCATED)].decode("utf-8", errors="ignore")
    return keep + _TRUNCATED


def _error_line(*texts: str) -> str | None:
    for text in texts:
        for line in text.splitlines():
            s = line.strip()
            if s[:6].lower() == "error:":
                return s[6:].strip()
    return None


def _last_line(*texts: str) -> str:
    for text in texts:
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        if lines:
            return lines[-1]
    return ""


# ════════════════════════════════════════════════════════════════════
class VmrunCli:
    """Runs ``vmrun -T <type> [-gu U -gp P] <command> [<vmx>] <params...>``.

    Output is redirected to anonymous temporary files rather than pipes: after
    ``start`` a daemonised child (vmware-vmx) may inherit the handles, and with
    pipes we would wait for an EOF that only comes when the VM stops.
    """

    def __init__(
        self,
        vmrun_path: str,
        vmx: str | None,
        host_type: str,
        creds: GuestCredentials | None,
        *,
        system: str | None = None,
        popen: Callable[..., Any] = subprocess.Popen,
        clock: Clock | None = None,
    ) -> None:
        self._vmrun = vmrun_path
        self._vmx = vmx
        self._host_type = host_type
        self._creds = creds
        self._system = host_system(system)
        self._popen = popen
        self._clock: Clock = clock or SystemClock()

    @property
    def vmx(self) -> str | None:
        return self._vmx

    @property
    def host_type(self) -> str:
        return self._host_type

    def __repr__(self) -> str:
        user = self._creds.user if self._creds else None
        return (f"VmrunCli(vmrun={self._vmrun!r}, vmx={self._vmx!r}, host_type={self._host_type!r}, "
                f"guest_user={user!r})")

    # ── public ──────────────────────────────────────────────────────
    def run(self, command: str, *params: str, guest: bool = False,
            timeout_s: float = DEFAULT_TIMEOUT_S, vmx: bool = True) -> VmrunResult:
        if guest and self._creds is None:
            raise GuestAuthFailed(
                f"vmrun {command} needs guest credentials but none are configured",
                stage="vmrun",
                hint="set profiles.<name>.guest_user and guest_password_env (and export that variable)",
                details={"command": command},
            )
        if vmx and not self._vmx:
            raise ConfigError(f"vmrun {command} needs a vmx path but this profile has none")
        argv = self._argv(command, params, guest=guest, vmx=vmx)
        timeout = float(timeout_s) if timeout_s and timeout_s > 0 else DEFAULT_TIMEOUT_S
        started = self._clock.monotonic()

        with tempfile.TemporaryFile() as out_f, tempfile.TemporaryFile() as err_f:
            spawn_error: str | None = None
            try:
                proc = self._popen(argv, stdin=subprocess.DEVNULL, stdout=out_f, stderr=err_f,
                                   shell=False, close_fds=True, **subprocess_kwargs(self._system))
            except OSError as e:
                spawn_error = _truncate(self._scrub(e.strerror or type(e).__name__))
            if spawn_error is not None:
                # Raised outside the handler so the OSError (whose filename/text could carry
                # the command line) is not kept as __context__.
                raise VmrunError(
                    f"cannot execute vmrun at {self._vmrun}: {spawn_error}",
                    stage="vmrun",
                    hint="check the vmrun path (profiles.<name>.vmrun) and its permissions",
                    details=self._details(argv, None, "", "", command, started),
                )
            timed_out = False
            try:
                returncode: int | None = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                returncode = self._kill(proc)
            except BaseException:
                self._kill(proc)
                raise
            stdout = self._read(out_f)
            stderr = self._read(err_f)

        if timed_out:
            raise VmrunTimeout(
                f"vmrun {command} timed out after {timeout:g}s and was killed",
                stage="vmrun",
                hint="the VM or VMware may be busy; check the VM state before retrying",
                details={**self._details(argv, returncode, stdout, stderr, command, started),
                         "timeout_s": timeout},
            )
        error_text = _error_line(stdout, stderr)
        if returncode != 0 or error_text is not None:
            raise self._error(command, argv, returncode, stdout, stderr, error_text, guest, started)
        return VmrunResult(int(returncode or 0), stdout, stderr)

    # ── internals ───────────────────────────────────────────────────
    def _argv(self, command: str, params: Sequence[str], *, guest: bool, vmx: bool) -> list[str]:
        argv = [self._vmrun, "-T", self._host_type]
        if guest and self._creds is not None:
            argv += ["-gu", self._creds.user, "-gp", self._creds.password.reveal()]
        argv.append(command)
        if vmx and self._vmx:
            argv.append(self._vmx)
        argv += [str(p) for p in params]
        return argv

    @staticmethod
    def _kill(proc: Any) -> int | None:
        try:
            proc.kill()
        except OSError:
            pass  # already gone
        try:
            return proc.wait(timeout=KILL_REAP_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            return None

    def _read(self, f: IO[bytes]) -> str:
        f.seek(0)
        return filter_noise(decode_output(f.read(MAX_CAPTURE_BYTES), self._system))

    def _scrub(self, text: str) -> str:
        if self._creds is not None:
            secret = self._creds.password.reveal()
            if secret:
                text = text.replace(secret, MASK)
        return text

    def _masked_argv(self, argv: Sequence[str]) -> list[str]:
        out: list[str] = []
        for i, arg in enumerate(argv):
            if i > 0 and argv[i - 1] == "-gp":
                out.append(MASK)
            else:
                out.append(_truncate(self._scrub(arg)))
        return out

    def _details(self, argv: Sequence[str], returncode: int | None, stdout: str, stderr: str,
                 command: str, started: float) -> dict[str, Any]:
        return {
            "argv": self._masked_argv(argv),
            "returncode": returncode,
            "stdout": _truncate(self._scrub(stdout)),
            "stderr": _truncate(self._scrub(stderr)),
            "command": command,
            "elapsed_s": round(max(0.0, self._clock.monotonic() - started), 3),
        }

    def _error(self, command: str, argv: Sequence[str], returncode: int | None, stdout: str, stderr: str,
               error_text: str | None, guest: bool, started: float) -> VmrunError:
        if error_text is not None:
            text = self._scrub(error_text)
            message = f"vmrun {command} failed: {text}"
        else:
            text = self._scrub(f"{stdout}\n{stderr}")
            last = self._scrub(_last_line(stderr, stdout))
            message = f"vmrun {command} failed with exit code {returncode}" + (f": {last}" if last else "")
        cls = classify_error(text, command, guest=guest, vmx=self._vmx)
        hint, next_tool = _HINTS.get(cls, (None, None))
        return cls(_truncate(message), stage="vmrun", hint=hint, next_tool=next_tool,
                   details=self._details(argv, returncode, stdout, stderr, command, started))


# ════════════════════════════════════════════════════════════════════
_VMX_LINE = re.compile(r"^([A-Za-z0-9_.:\-]+)\s*=\s*(.*?)\s*$")
_SNAPSHOT_HEADER = re.compile(r"^Total snapshots:\s*\d+\s*$", re.IGNORECASE)
_RUNNING_HEADER = re.compile(r"^Total running VMs:\s*\d+\s*$", re.IGNORECASE)
_SHARED_FOLDER_RE = re.compile(r"^sharedfolder(\d+)\.present$")
_ETHERNET_RE = re.compile(r"^ethernet(\d+)\.present$")


def parse_vmx(text: str) -> dict[str, str]:
    """Parse ``key = "value"`` lines; keys are lower-cased (vmx keys are case-insensitive)."""
    keys: dict[str, str] = {}
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = _VMX_LINE.match(s)
        if not m:
            continue
        value = m.group(2)
        if len(value) >= 2 and value[0] == value[-1] == '"':
            value = value[1:-1]
        keys[m.group(1).lower()] = value
    return keys


def parse_snapshot_tree(text: str) -> list[Snapshot]:
    """Parse ``listSnapshots <vmx> showTree``: depth = leading TABs, parent = nearest shallower name."""
    result: list[Snapshot] = []
    stack: list[Snapshot] = []
    header_seen = False
    for raw_line in text.splitlines():
        line = raw_line.rstrip("\r")
        if not line.strip():
            continue
        if not header_seen and not result and _SNAPSHOT_HEADER.match(line.strip()):
            header_seen = True
            continue
        depth = len(line) - len(line.lstrip("\t"))
        name = line[depth:].rstrip()
        while stack and stack[-1].depth >= depth:
            stack.pop()
        snap = Snapshot(name=name, depth=depth, parent=stack[-1].name if stack else None)
        result.append(snap)
        stack.append(snap)
    return result


def _truthy(value: str | None) -> bool:
    return value is not None and value.strip().lower() in ("true", "yes", "1")


def _falsy(value: str | None) -> bool:
    return value is not None and value.strip().lower() in ("false", "no", "0")


def _first_line(text: str) -> str:
    for line in text.splitlines():
        if line.strip():
            return line.strip()
    return ""


def _check_snapshot_name(name: str) -> None:
    if not name or name != name.strip() or any(ord(c) < 32 or ord(c) == 127 for c in name):
        raise VmrunError(
            "invalid snapshot name: it must be non-empty, without control characters or "
            "leading/trailing whitespace",
            stage="validate",
        )


class VmrunProvider:
    """``contracts.VmProvider`` backed by a ``VmrunRunner`` (normally ``VmrunCli``)."""

    DEFAULT_TIMEOUTS: Mapping[str, float] = {
        "list": 30.0,
        "checkToolsState": 30.0,
        "getGuestIPAddress": 30.0,
        "listSnapshots": 60.0,
        "snapshot": 900.0,
        "revertToSnapshot": 600.0,
        "deleteSnapshot": 1800.0,  # disk consolidation can be slow
        "start": 300.0,
        "stop": 300.0,
        "suspend": 300.0,
        "captureScreen": 60.0,
    }

    def __init__(
        self,
        runner: VmrunRunner,
        vmx: str,
        *,
        clock: Clock | None = None,
        vmx_reader: Callable[[str], str] | None = None,
        timeouts: Mapping[str, float] | None = None,
    ) -> None:
        self.runner = runner
        self.vmx = vmx
        self.clock: Clock = clock or SystemClock()
        self._vmx_reader = vmx_reader or _read_text
        self._timeouts = {**self.DEFAULT_TIMEOUTS, **(timeouts or {})}

    def __repr__(self) -> str:
        return f"VmrunProvider(vmx={self.vmx!r})"

    def _run(self, command: str, *params: str, guest: bool = False, vmx: bool = True) -> VmrunResult:
        return self.runner.run(command, *params, guest=guest, vmx=vmx,
                               timeout_s=self._timeouts.get(command, DEFAULT_TIMEOUT_S))

    # ── state ───────────────────────────────────────────────────────
    def power_state(self) -> PowerState:
        res = self._run("list", vmx=False)
        for line in res.stdout.splitlines():
            s = line.strip()
            if not s or _RUNNING_HEADER.match(s):
                continue
            if _same_path(s, self.vmx):
                return PowerState.RUNNING
        return PowerState.SUSPENDED if self._suspended_on_disk() else PowerState.OFF

    def _suspended_on_disk(self) -> bool:
        vmx = Path(self.vmx)
        stem = vmx.stem.lower()
        try:
            for entry in vmx.parent.iterdir():
                name = entry.name.lower()
                if name.endswith(".vmss") and name.startswith(stem):
                    return True
        except OSError:
            pass
        try:
            keys = self._vmx_keys()
        except ConfigError:
            return False
        state = keys.get("checkpoint.vmstate", "").strip()
        if not state:
            return False
        target = Path(state)
        if not target.is_absolute():
            target = vmx.parent / target
        return target.exists()

    def tools_state(self) -> ToolsState:
        try:
            res = self._run("checkToolsState")
        except VmNotRunning:
            return ToolsState.UNKNOWN
        value = _first_line(res.stdout).lower().replace("_", " ")
        return {
            "running": ToolsState.RUNNING,
            "installed": ToolsState.INSTALLED,
            "not installed": ToolsState.NOT_INSTALLED,
        }.get(value, ToolsState.UNKNOWN)

    def guest_ip(self, *, wait: bool = False, timeout_s: float = 60.0) -> str | None:
        params = ("-wait",) if wait else ()
        timeout = timeout_s if wait else self._timeouts["getGuestIPAddress"]
        try:
            res = self.runner.run("getGuestIPAddress", *params, timeout_s=timeout)
        except VmrunError:
            return None
        try:
            ip = ipaddress.IPv4Address(_first_line(res.stdout))
        except ValueError:
            return None
        return None if ip.is_unspecified else str(ip)

    # ── snapshots ───────────────────────────────────────────────────
    def list_snapshots(self) -> list[Snapshot]:
        return parse_snapshot_tree(self._run("listSnapshots", "showTree").stdout)

    def take_snapshot(self, name: str) -> None:
        _check_snapshot_name(name)
        self._run("snapshot", name)

    def revert_snapshot(self, name: str) -> None:
        _check_snapshot_name(name)
        self._run("revertToSnapshot", name)

    def delete_snapshot(self, name: str) -> None:
        # Never pass andDeleteChildren: child snapshots are not ours to remove.
        _check_snapshot_name(name)
        self._run("deleteSnapshot", name)

    # ── power ───────────────────────────────────────────────────────
    def start(self, *, gui: bool = False) -> None:
        self._run("start", "gui" if gui else "nogui")

    def stop(self, *, hard: bool = False) -> None:
        self._run("stop", "hard" if hard else "soft")

    def suspend(self) -> None:
        self._run("suspend", "soft")

    def screenshot(self, host_path: Path) -> None:
        self._run("captureScreen", str(host_path), guest=True)

    # ── isolation (plan 5.7 items 5 and 6) ──────────────────────────
    def _vmx_keys(self) -> dict[str, str]:
        try:
            text = self._vmx_reader(self.vmx)
        except OSError as e:
            raise ConfigError(f"cannot read vmx file {self.vmx}: {e.strerror or type(e).__name__}",
                              stage="isolation", details={"path": self.vmx}) from None
        return parse_vmx(text)

    def isolation_report(self) -> IsolationReport:
        keys = self._vmx_keys()
        hgfs_disabled = _truthy(keys.get("isolation.tools.hgfs.disable"))

        enabled = writable = False
        for n in _indexes(keys, _SHARED_FOLDER_RE):
            present = _truthy(keys.get(f"sharedfolder{n}.present"))
            if present and _truthy(keys.get(f"sharedfolder{n}.enabled")):
                enabled = True
                writable = writable or _truthy(keys.get(f"sharedfolder{n}.writeaccess"))
        shared_enabled = enabled and not hgfs_disabled

        networks: list[str] = []
        for n in _indexes(keys, _ETHERNET_RE):
            if not _truthy(keys.get(f"ethernet{n}.present")):
                continue
            if _falsy(keys.get(f"ethernet{n}.startconnected")):
                networks.append("disconnected")
                continue
            # VMware writes no connectionType for the default (bridged) adapter.
            networks.append(keys.get(f"ethernet{n}.connectiontype", "").strip().lower() or "bridged")

        return IsolationReport(
            shared_folders_enabled=shared_enabled,
            shared_folders_writable=shared_enabled and writable,
            network_types=tuple(networks),
        )


def _indexes(keys: Mapping[str, str], pattern: re.Pattern[str]) -> list[int]:
    found = {int(m.group(1)) for k in keys if (m := pattern.match(k))}
    return sorted(found)


def _read_text(path: str) -> str:
    return Path(path).read_text(encoding="utf-8", errors="replace")


def _same_path(a: str, b: str) -> bool:
    def norm(p: str) -> str:
        try:
            return os.path.normcase(os.path.realpath(p))
        except (OSError, ValueError):
            return os.path.normcase(os.path.abspath(p))

    if norm(a) == norm(b):
        return True
    try:
        return os.path.samefile(a, b)
    except (OSError, ValueError):
        return False


# ════════════════════════════════════════════════════════════════════
class NullProvider:
    """``contracts.VmProvider`` for endpoint-mode profiles: no VM to control."""

    MESSAGE = "profile is in endpoint mode: VM control is unavailable"

    def _unavailable(self) -> ConfigError:
        return ConfigError(self.MESSAGE, stage="vm", hint="use a profile with mode = \"vmware\"")

    def power_state(self) -> PowerState:
        return PowerState.UNKNOWN

    def tools_state(self) -> ToolsState:
        return ToolsState.UNKNOWN

    def guest_ip(self, *, wait: bool = False, timeout_s: float = 60.0) -> str | None:
        return None

    def isolation_report(self) -> IsolationReport:
        return IsolationReport(None, None, ())

    def list_snapshots(self) -> list[Snapshot]:
        raise self._unavailable()

    def take_snapshot(self, name: str) -> None:
        raise self._unavailable()

    def revert_snapshot(self, name: str) -> None:
        raise self._unavailable()

    def delete_snapshot(self, name: str) -> None:
        raise self._unavailable()

    def start(self, *, gui: bool = False) -> None:
        raise self._unavailable()

    def stop(self, *, hard: bool = False) -> None:
        raise self._unavailable()

    def suspend(self) -> None:
        raise self._unavailable()

    def screenshot(self, host_path: Path) -> None:
        raise self._unavailable()
