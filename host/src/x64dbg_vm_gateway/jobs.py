"""Persistent job state machine (docs/VM_ORCHESTRATION_PLAN.md section 4.1).

A *job* is one sample analysed in one VM profile. Its state lives in
``<root>/<job_id>/state.json``; next to it are ``input/``, ``artifacts/``,
``logs/`` and an append-only ``intent.log``.

Persistence protocol (every state change):

1. Serialise the new state in memory (a value that is not JSON fails here,
   before anything touches the disk).
2. Append one JSON line describing the intended change to ``intent.log`` and
   fsync it.
3. Write ``state.json`` atomically: temp file in the same directory, fsync,
   ``os.replace``, then fsync the directory (POSIX).

A crash between 2 and 3 leaves the old ``state.json`` plus an intent whose
sequence number is ahead of the recorded history; ``recover_scan`` reports
that as ``flags["interrupted_transition"]``.

Invariants enforced here (plan 4.1):

- Only the edges in ``TRANSITIONS`` are legal; terminal states are final.
- ``DISCARDED`` is never a ``transition()`` target. Only ``discard()`` with
  ``actor == "human-cli"`` can enter it, so no MCP tool can skip collection.
- ``REVERTING`` is entered only from ``COLLECTED`` or ``DISCARDED``.
- A profile has at most one non-terminal job at a time.
- Job ids are validated against ``JOB_ID_RE`` before they touch a path.

Thread-safety: every public ``JobStore`` method takes one internal re-entrant
lock, so a store may be shared by worker threads. Separate processes are kept
apart by an exclusive lock file ``<root>/.lock`` held from ``open()`` until
``close()``. Acquisition and stale-lock reclaim are themselves serialised by
an OS advisory lock on ``<root>/.lock.guard``, so two processes cannot both
reclaim the same stale lock. The ``Job`` objects handed out are deep copies;
mutating them never changes the store.
"""

from __future__ import annotations

import contextlib
import copy
import dataclasses
import errno
import json
import os
import re
import secrets
import shutil
import socket
import sys
import threading
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType, TracebackType
from typing import Any

from .contracts import TERMINAL_JOB_STATES, Clock, JobState, SampleInfo, SystemClock
from .errors import LockTimeout, PathNotAllowed, StateViolation

__all__ = [
    "DISCARDABLE_STATES",
    "DISCARD_ACTOR",
    "JOB_ID_RE",
    "TRANSITIONS",
    "CorruptJob",
    "Job",
    "JobNotFound",
    "JobStore",
    "pid_alive",
    "validate_job_id",
]

JOB_ID_RE = re.compile(r"^[0-9]{8}-[0-9]{6}-[0-9a-f]{6}$")
"""Job id: ``YYYYMMDD-HHMMSS-<6 hex>`` (UTC). Always use ``fullmatch``."""

DISCARD_ACTOR = "human-cli"
"""The only actor allowed to discard a job (``x64dbg-vm-gateway discard <job>``)."""

SCHEMA_VERSION = 1

_S = JobState
TRANSITIONS: Mapping[JobState, frozenset[JobState]] = MappingProxyType({
    _S.CREATED: frozenset({_S.PREPARING_VM, _S.FAILED}),
    _S.PREPARING_VM: frozenset({_S.VM_READY, _S.FAILED}),
    _S.VM_READY: frozenset({_S.UPLOADING, _S.FAILED}),
    # UPLOADING -> UPLOADING: retry after a hash mismatch (3 attempts, then FAILED).
    _S.UPLOADING: frozenset({_S.UPLOADED, _S.UPLOADING, _S.FAILED}),
    _S.UPLOADED: frozenset({_S.LOADING, _S.FAILED}),
    _S.LOADING: frozenset({_S.ANALYZING, _S.FAILED}),
    # ANALYZING -> ANALYZING: mirrored tool calls / debugger relaunch (epoch + 1).
    # ANALYZING -> DISCARDED exists in the plan but only via JobStore.discard().
    _S.ANALYZING: frozenset({_S.ANALYZING, _S.COLLECTING, _S.FAILED}),
    _S.COLLECTING: frozenset({_S.COLLECTED, _S.COLLECTED_PARTIAL, _S.FAILED}),
    # COLLECTED -> ANALYZING: keep analysing after an intermediate collect.
    _S.COLLECTED: frozenset({_S.REVERTING, _S.ANALYZING, _S.FAILED}),
    _S.COLLECTED_PARTIAL: frozenset({_S.COLLECTING, _S.FAILED}),
    _S.DISCARDED: frozenset({_S.REVERTING, _S.FAILED}),
    _S.REVERTING: frozenset({_S.DONE, _S.FAILED}),
    _S.DONE: frozenset(),
    _S.FAILED: frozenset(),
})
"""Legal ``transition()`` edges. Every non-terminal state may also go to FAILED."""

DISCARDABLE_STATES: frozenset[JobState] = frozenset(
    s for s in JobState if s not in TERMINAL_JOB_STATES and s not in (_S.REVERTING, _S.DISCARDED)
)
"""States a human may discard from.

The plan's diagram draws only ``ANALYZING -> DISCARDED``. Discard is also the
human's escape hatch for a job left behind by a crash (``recover_scan`` flags
it but never resumes it), and such a job blocks its profile because
``create()`` refuses a second live job. Therefore every live state except
REVERTING (already on its way to DONE) is discardable. The actor check keeps
this out of reach of MCP tools.
"""

_STATE_FILE = "state.json"
_INTENT_FILE = "intent.log"
_LOCK_FILE = ".lock"
_GUARD_FILE = ".lock.guard"
_SUBDIRS = ("input", "artifacts", "logs")
_UPDATABLE_FIELDS = frozenset(
    {"sample", "backend_id", "epoch", "restarts", "manifest_path", "flags", "error"}
)
_CORRUPT_RE = re.compile(r"state\.json\.corrupt-([0-9]+)")
_TEMP_RE = re.compile(r"\.state\.json\.[0-9a-f]{12}\.tmp")  # see _atomic_write
_MAX_ID_ATTEMPTS = 8
_MAX_STATE_BYTES = 16 * 1024 * 1024
_INTENT_TAIL_BYTES = 64 * 1024
_LOCK_POLL_S = 0.25
_GUARD_POLL_S = 0.05

_POSIX = os.name == "posix"
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_BINARY = getattr(os, "O_BINARY", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)  # vmrun children must not inherit store fds


# ── job id ──────────────────────────────────────────────────────────
def validate_job_id(job_id: object) -> str:
    """Return ``job_id`` if it is a canonical job id, else raise PathNotAllowed.

    Job ids become directory names, so anything else (``..``, separators, a
    trailing newline, upper-case hex) is rejected as a path-traversal attempt.
    """
    if not isinstance(job_id, str) or JOB_ID_RE.fullmatch(job_id) is None:
        raise PathNotAllowed("invalid job id", details={"job_id": _clip(repr(job_id), 80)})
    return job_id


def _clip(text: str, limit: int = 200) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


# ── job model ───────────────────────────────────────────────────────
@dataclass
class Job:
    """One analysis job. ``to_json``/``from_json`` define the state.json schema."""

    id: str
    profile: str
    state: JobState
    created_at: str
    updated_at: str
    guest_root: str  # e.g. C:\mcp\jobs\<id>
    host_root: str  # absolute host directory <root>/<id>
    sample: SampleInfo | None = None
    backend_id: str | None = None
    epoch: int = 0
    restarts: int = 0
    history: list[dict[str, Any]] = field(default_factory=list)
    manifest_path: str | None = None
    flags: dict[str, Any] = field(default_factory=dict)
    error: dict[str, Any] | None = None

    @property
    def terminal(self) -> bool:
        return JobState(self.state) in TERMINAL_JOB_STATES

    def to_json(self) -> dict[str, Any]:
        """Return a JSON-ready dict (a deep copy; safe to mutate)."""
        return {
            "version": SCHEMA_VERSION,
            "id": self.id,
            "profile": self.profile,
            "state": JobState(self.state).value,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "guest_root": self.guest_root,
            "host_root": self.host_root,
            "sample": dataclasses.asdict(self.sample) if self.sample is not None else None,
            "backend_id": self.backend_id,
            "epoch": self.epoch,
            "restarts": self.restarts,
            "history": copy.deepcopy(self.history),
            "manifest_path": self.manifest_path,
            "flags": copy.deepcopy(self.flags),
            "error": copy.deepcopy(self.error),
        }

    @classmethod
    def from_json(cls, data: str | bytes | Mapping[str, Any]) -> Job:
        """Parse and validate a job document; raise ValueError if it is malformed."""
        if isinstance(data, str | bytes):
            try:
                data = json.loads(data)
            except (ValueError, RecursionError) as e:  # JSONDecodeError/UnicodeDecodeError are ValueErrors
                raise ValueError(f"job state is not valid JSON ({type(e).__name__})") from None
        if not isinstance(data, Mapping):
            raise ValueError("job state must be a JSON object")
        version = data.get("version", SCHEMA_VERSION)
        if version != SCHEMA_VERSION:
            raise ValueError("unsupported job state schema version")
        job_id = _req_str(data, "id")
        if JOB_ID_RE.fullmatch(job_id) is None:
            raise ValueError("job state has an invalid id")
        try:
            state = JobState(data.get("state"))
        except ValueError:
            raise ValueError("job state has an unknown state value") from None
        history = data.get("history", [])
        if not isinstance(history, list) or not all(isinstance(h, dict) for h in history):
            raise ValueError("job field 'history' must be a list of objects")
        flags = data.get("flags", {})
        if not isinstance(flags, dict):
            raise ValueError("job field 'flags' must be an object")
        error = data.get("error")
        if error is not None and not isinstance(error, dict):
            raise ValueError("job field 'error' must be an object or null")
        return cls(
            id=job_id,
            profile=_req_str(data, "profile"),
            state=state,
            created_at=_req_str(data, "created_at"),
            updated_at=_req_str(data, "updated_at"),
            guest_root=_req_str(data, "guest_root"),
            host_root=_req_str(data, "host_root"),
            sample=_sample_from_json(data.get("sample")),
            backend_id=_opt_str(data, "backend_id"),
            epoch=_nonneg_int(data, "epoch"),
            restarts=_nonneg_int(data, "restarts"),
            history=copy.deepcopy(history),
            manifest_path=_opt_str(data, "manifest_path"),
            flags=copy.deepcopy(flags),
            error=copy.deepcopy(error),
        )


def _req_str(data: Mapping[str, Any], key: str) -> str:
    v = data.get(key)
    if not isinstance(v, str):
        raise ValueError(f"job field {key!r} must be a string")
    return v


def _opt_str(data: Mapping[str, Any], key: str) -> str | None:
    v = data.get(key)
    if v is not None and not isinstance(v, str):
        raise ValueError(f"job field {key!r} must be a string or null")
    return v


def _nonneg_int(data: Mapping[str, Any], key: str) -> int:
    v = data.get(key, 0)
    if type(v) is not int or v < 0:  # rejects bool, float, str
        raise ValueError(f"job field {key!r} must be a non-negative integer")
    return v


_SAMPLE_TYPES: dict[str, tuple[type, ...]] = {
    "host_path": (str,),
    "sha256": (str,),
    "size": (int,),
    "kind": (str,),
    "arch": (str, type(None)),
    "guest_path": (str, type(None)),
    "original_name": (str, type(None)),
}


def _sample_from_json(v: object) -> SampleInfo | None:
    if v is None:
        return None
    if not isinstance(v, dict):
        raise ValueError("job field 'sample' must be an object or null")
    kwargs: dict[str, Any] = {}
    for f in dataclasses.fields(SampleInfo):
        if f.name in v:
            val = v[f.name]
            types = _SAMPLE_TYPES.get(f.name)
            if types is not None and (not isinstance(val, types) or isinstance(val, bool)):
                raise ValueError(f"sample field {f.name!r} has the wrong type")
            kwargs[f.name] = val
        elif f.default is dataclasses.MISSING and f.default_factory is dataclasses.MISSING:
            raise ValueError(f"sample field {f.name!r} is missing")
    if kwargs["size"] < 0:
        raise ValueError("sample field 'size' must be non-negative")
    return SampleInfo(**kwargs)


@dataclass(frozen=True)
class CorruptJob:
    """A job directory whose state.json is missing or unparseable.

    The bad file has been renamed to ``state.json.corrupt-N``; the job is not
    loaded and needs a human. ``corrupt_files`` lists every quarantined copy.
    """

    job_id: str
    path: str
    reason: str
    corrupt_files: tuple[str, ...] = ()

    def to_json(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "path": self.path,
            "reason": self.reason,
            "corrupt_files": list(self.corrupt_files),
            "corrupt": True,
        }


class JobNotFound(StateViolation):
    """No (valid) job with this id. Wire code stays STATE_VIOLATION (errors.py owns codes)."""


# ── process liveness ────────────────────────────────────────────────
def pid_alive(pid: int) -> bool:
    """Best-effort check whether process ``pid`` exists on this machine.

    Errors on the side of "alive" when the answer is unknown, because a false
    "dead" would let two gateways share one jobs root.
    """
    if type(pid) is not int or pid <= 0:
        return False
    if sys.platform == "win32":  # pragma: no cover - exercised on Windows hosts only
        return _win_pid_alive(pid)
    try:
        os.kill(pid, 0)  # signal 0: existence/permission probe only
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists, owned by another user
    except OSError:
        return True
    stat = _proc_stat(pid)
    return not (stat is not None and stat[0] == "Z")  # an unreaped zombie holds no lock


_default_pid_alive = pid_alive


def _win_pid_alive(pid: int) -> bool:  # pragma: no cover - Windows only
    # os.kill(pid, 0) would TerminateProcess() on Windows, so query the handle instead.
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    process_query_limited_information = 0x1000
    still_active = 259
    error_access_denied = 5
    handle = kernel32.OpenProcess(process_query_limited_information, False, pid)
    if not handle:
        return ctypes.get_last_error() == error_access_denied  # type: ignore[attr-defined]
    try:
        code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
            return True
        return code.value == still_active
    finally:
        kernel32.CloseHandle(handle)


def _proc_stat(pid: int) -> tuple[str, str] | None:
    """(state, starttime) from /proc/<pid>/stat on Linux, else None."""
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            raw = f.read(4096).decode("ascii", "replace")
    except OSError:
        return None
    rest = raw[raw.rfind(")") + 2:].split()  # fields after "pid (comm)"
    if len(rest) < 20:
        return None
    return rest[0], rest[19]  # field 3 = state, field 22 = starttime


def _process_identity(pid: int) -> str | None:
    """A token that changes when ``pid`` is reused (Linux: boot id + start time)."""
    stat = _proc_stat(pid)
    if stat is None:
        return None
    try:
        with open("/proc/sys/kernel/random/boot_id", "rb") as f:
            boot = f.read(64).decode("ascii", "replace").strip()
    except OSError:
        boot = ""
    return f"{boot}:{stat[1]}"


# ── low-level file helpers ──────────────────────────────────────────
def _chmod_private(path: Path, mode: int) -> None:
    if _POSIX:
        os.chmod(path, mode)


def _mkdir_private(path: Path) -> None:
    path.mkdir(mode=0o700)
    _chmod_private(path, 0o700)  # mkdir's mode is filtered by the umask


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        view = view[n:]


def _fsync_dir(path: Path) -> None:
    if not _POSIX:
        return
    with contextlib.suppress(OSError):  # durability hint only; the rename already happened
        fd = os.open(path, os.O_RDONLY | _O_CLOEXEC)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _append_line(path: Path, line: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | _O_NOFOLLOW | _O_BINARY | _O_CLOEXEC, 0o600)
    try:
        if _POSIX:
            os.fchmod(fd, 0o600)
        _write_all(fd, line)
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_write(path: Path, data: bytes) -> None:
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_BINARY | _O_CLOEXEC, 0o600)
    try:
        try:
            if _POSIX:
                os.fchmod(fd, 0o600)
            _write_all(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    _fsync_dir(path.parent)


def _read_capped(path: Path, limit: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | _O_NOFOLLOW | _O_BINARY | _O_CLOEXEC)
    try:
        with os.fdopen(fd, "rb", closefd=False) as f:
            data = f.read(limit + 1)
    finally:
        os.close(fd)
    if len(data) > limit:
        raise ValueError("job state file is too large")
    return data


def _dump_state(doc: Mapping[str, Any]) -> bytes:
    # ensure_ascii keeps lone surrogates (undecodable host file names) writable.
    return (json.dumps(doc, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("ascii")


def _dump_line(doc: Mapping[str, Any]) -> bytes:
    return (json.dumps(doc, sort_keys=True, allow_nan=False, separators=(",", ":")) + "\n").encode("ascii")


def _parse_iso_utc(text: str) -> datetime:
    dt = datetime.fromisoformat(text)
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


def _as_state(value: JobState | str) -> JobState:
    return value if isinstance(value, JobState) else JobState(value)


def _as_states(value: JobState | str | Iterable[JobState | str] | None) -> frozenset[JobState] | None:
    if value is None:
        return None
    if isinstance(value, JobState | str):
        return frozenset({_as_state(value)})
    return frozenset(_as_state(v) for v in value)


def _check_update_fields(updates: Mapping[str, Any]) -> None:
    bad = sorted(set(updates) - _UPDATABLE_FIELDS)
    if bad:
        raise TypeError(f"job fields cannot be updated this way: {', '.join(bad)}")


def _apply_updates(job: Job, updates: Mapping[str, Any]) -> None:
    for key, value in updates.items():
        if key == "sample" and isinstance(value, Mapping):
            value = SampleInfo(**value)
        setattr(job, key, copy.deepcopy(value))
    Job.from_json(job.to_json())  # type/shape validation (raises ValueError)


# ── inter-process guard ─────────────────────────────────────────────
class _GuardLock:
    """Short-lived inter-process mutex on ``<root>/.lock.guard``.

    It serialises lock-file acquisition and stale-lock reclaim. The OS drops
    an advisory lock when its holder dies, so a crash cannot leave it held.
    On a filesystem without advisory locks it degrades to no-op; the O_EXCL
    lock file still protects the normal case.
    """

    def __init__(self, path: Path, clock: Clock, timeout_s: float) -> None:
        self._path = path
        self._clock = clock
        self._timeout_s = timeout_s
        self._fd: int | None = None
        self._locked = False

    def __enter__(self) -> _GuardLock:
        # Read-only is enough for flock/msvcrt.locking and survives a narrow umask.
        self._fd = os.open(self._path, os.O_RDONLY | os.O_CREAT | _O_NOFOLLOW | _O_BINARY | _O_CLOEXEC, 0o600)
        if _POSIX:
            with contextlib.suppress(OSError):
                os.fchmod(self._fd, 0o600)
        deadline = self._clock.monotonic() + self._timeout_s
        while True:
            try:
                self._os_lock(self._fd)
                self._locked = True
                return self
            except OSError as e:
                if e.errno not in (errno.EAGAIN, errno.EACCES, errno.EWOULDBLOCK, errno.EDEADLK):
                    return self  # locking unsupported here
                if self._clock.monotonic() >= deadline:
                    os.close(self._fd)
                    self._fd = None
                    raise LockTimeout("timed out waiting for the jobs-root guard lock",
                                      details={"lock": str(self._path)}) from None
                self._clock.sleep(_GUARD_POLL_S)

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None,
                 tb: TracebackType | None) -> None:
        if self._fd is None:
            return
        try:
            if self._locked:
                with contextlib.suppress(OSError):
                    self._os_unlock(self._fd)
        finally:
            os.close(self._fd)
            self._fd = None
            self._locked = False

    @staticmethod
    def _os_lock(fd: int) -> None:
        if sys.platform == "win32":  # pragma: no cover - Windows only
            import msvcrt

            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    @staticmethod
    def _os_unlock(fd: int) -> None:
        if sys.platform == "win32":  # pragma: no cover - Windows only
            import msvcrt

            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_UN)


# ── store ───────────────────────────────────────────────────────────
class JobStore:
    """Persistent job registry rooted at ``root`` (e.g. ``~/mcp-lab/jobs``).

    Use ``with JobStore(root) as store:`` or ``open()``/``close()``. Every other
    method requires the store to be open and raises RuntimeError otherwise.

    ``id_factory`` returns complete job ids (tests); by default an id is the
    clock's UTC time plus 6 random hex digits. ``pid``/``pid_alive`` exist so
    tests can simulate other processes; production code leaves them alone.
    """

    def __init__(
        self,
        root: Path | str,
        *,
        clock: Clock | None = None,
        id_factory: Callable[[], str] | None = None,
        pid: int | None = None,
        pid_alive: Callable[[int], bool] | None = None,
        guard_timeout_s: float = 5.0,
    ) -> None:
        self.root = Path(root).expanduser().resolve()
        self._clock: Clock = clock if clock is not None else SystemClock()
        self._id_factory = id_factory if id_factory is not None else self._default_id
        self._real_pid = pid is None
        self._pid = os.getpid() if pid is None else pid
        self._pid_alive = pid_alive if pid_alive is not None else _default_pid_alive
        self._guard_timeout_s = guard_timeout_s
        self._host = socket.gethostname()
        self._lock = threading.RLock()
        self._jobs: dict[str, Job] = {}
        self._open = False
        self._nonce: str | None = None

    # ── lifecycle ───────────────────────────────────────────────────
    def open(self, *, timeout_s: float = 0.0) -> JobStore:
        """Take the root's process lock and load all jobs. Idempotent.

        Raises LockTimeout if another live process holds the root for longer
        than ``timeout_s`` seconds.
        """
        with self._lock:
            if self._open:
                return self
            self._ensure_root()
            self._acquire_process_lock(timeout_s)
            try:
                self._jobs = self._load_valid_jobs()
            except BaseException:
                self._release_process_lock()
                raise
            self._open = True
            return self

    def close(self) -> None:
        """Release the process lock (only if this store still owns it). Idempotent."""
        with self._lock:
            if not self._open:
                return
            try:
                self._release_process_lock()
            finally:
                self._open = False
                self._jobs = {}

    def __enter__(self) -> JobStore:
        return self.open()

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None,
                 tb: TracebackType | None) -> None:
        self.close()

    # ── queries ─────────────────────────────────────────────────────
    def job_dir(self, job_id: str) -> Path:
        """Host directory of ``job_id`` (validated; may not exist)."""
        return self.root / validate_job_id(job_id)

    def get(self, job_id: str) -> Job:
        validate_job_id(job_id)
        with self._lock:
            self._require_open()
            return copy.deepcopy(self._get_locked(job_id))

    def list(self, profile: str | None = None) -> list[Job]:
        """All loaded jobs (oldest first), optionally only those of ``profile``."""
        with self._lock:
            self._require_open()
            return [copy.deepcopy(j) for _, j in sorted(self._jobs.items())
                    if profile is None or j.profile == profile]

    def active(self, profile: str) -> Job | None:
        """The profile's non-terminal job (DISCARDED counts as live), or None."""
        with self._lock:
            self._require_open()
            job = self._active_locked(profile)
            return copy.deepcopy(job) if job is not None else None

    # ── mutations ───────────────────────────────────────────────────
    def create(self, profile: str, guest_job_root: str) -> Job:
        """Create a CREATED job for ``profile``; refuse if one is still live."""
        if not isinstance(profile, str) or not profile.strip():
            raise ValueError("profile must be a non-empty string")
        if not isinstance(guest_job_root, str) or not guest_job_root.strip("\\ "):
            raise ValueError("guest_job_root must be a non-empty Windows path")
        if any(ord(c) < 0x20 for c in guest_job_root):
            raise ValueError("guest_job_root contains control characters")
        guest_base = guest_job_root.rstrip("\\")
        with self._lock:
            self._require_open()
            current = self._active_locked(profile)
            if current is not None:
                raise StateViolation(
                    f"profile {profile!r} already has a live job",
                    details={"job_id": current.id, "state": current.state.value, "profile": profile},
                    hint="finish or discard the existing job first",
                    next_tool="session_status",
                )
            job_id, job_dir = self._allocate_job_dir()
            now = self._clock.now_iso()
            job = Job(id=job_id, profile=profile, state=JobState.CREATED, created_at=now, updated_at=now,
                      guest_root=guest_base + "\\" + job_id, host_root=str(job_dir))
            try:
                for sub in _SUBDIRS:
                    _mkdir_private(job_dir / sub)
                self._persist(job, {"op": "create", "profile": profile})
            except BaseException:
                shutil.rmtree(job_dir, ignore_errors=True)  # our own, just-created directory
                raise
            self._jobs[job_id] = job
            return copy.deepcopy(job)

    def transition(
        self,
        job_id: str,
        to: JobState | str,
        *,
        reason: str,
        expect_from: JobState | str | Iterable[JobState | str] | None = None,
        **updates: Any,
    ) -> Job:
        """Move a job along a legal edge, optionally updating non-state fields.

        ``expect_from`` guards against a concurrent change (compare-and-set).
        ``updates`` may set: sample, backend_id, epoch, restarts, manifest_path,
        flags, error (``flags`` replaces the whole dict).
        """
        validate_job_id(job_id)
        target = _as_state(to)
        expected = _as_states(expect_from)
        _check_update_fields(updates)
        if not isinstance(reason, str):
            raise TypeError("reason must be a string")
        with self._lock:
            self._require_open()
            cur = self._get_locked(job_id)
            details: dict[str, Any] = {"job_id": job_id, "state": cur.state.value, "to": target.value}
            if target is JobState.DISCARDED:
                raise StateViolation("DISCARDED can only be set by a human with `x64dbg-vm-gateway discard`",
                                     details=details)
            if expected is not None and cur.state not in expected:
                wanted = sorted(s.value for s in expected)
                raise StateViolation(
                    f"job {job_id} is {cur.state.value}, expected {'/'.join(wanted)}",
                    details={**details, "expected": wanted},
                    next_tool="session_status",
                )
            if target not in TRANSITIONS[cur.state]:
                raise StateViolation(f"illegal job transition {cur.state.value} -> {target.value}",
                                     details=details, next_tool="session_status")
            return self._commit_transition(cur, target, reason, updates, actor=None)

    def discard(self, job_id: str, actor: str, *, reason: str = "discarded by a human via the CLI") -> Job:
        """Mark a job DISCARDED. Only ``actor == "human-cli"`` may do this."""
        validate_job_id(job_id)
        if not isinstance(actor, str) or actor != DISCARD_ACTOR:
            raise StateViolation("only a human using the CLI may discard a job",
                                 details={"job_id": job_id, "actor": _clip(repr(actor), 40)},
                                 hint="ask the user to run `x64dbg-vm-gateway discard <job>`")
        if not isinstance(reason, str):
            raise TypeError("reason must be a string")
        with self._lock:
            self._require_open()
            cur = self._get_locked(job_id)
            if cur.state not in DISCARDABLE_STATES:
                raise StateViolation(f"job {job_id} cannot be discarded while {cur.state.value}",
                                     details={"job_id": job_id, "state": cur.state.value})
            return self._commit_transition(cur, JobState.DISCARDED, reason, {}, actor=actor)

    def update(self, job_id: str, **fields: Any) -> Job:
        """Change non-state fields (sample, backend_id, epoch, restarts, manifest_path, flags, error)."""
        validate_job_id(job_id)
        _check_update_fields(fields)
        with self._lock:
            self._require_open()
            cur = self._get_locked(job_id)
            if not fields:
                return copy.deepcopy(cur)
            new = copy.deepcopy(cur)
            _apply_updates(new, fields)
            new.updated_at = self._clock.now_iso()
            self._persist(new, {"op": "update", "fields": sorted(fields)})
            self._jobs[job_id] = new
            return copy.deepcopy(new)

    def recover_scan(self) -> list[Job | CorruptJob]:
        """Rescan the disk after a (re)start (plan 4.1 invariant 3).

        Returns every non-terminal job, each with ``flags["needs_recovery"] =
        True`` persisted (state untouched; nothing is resumed), plus a
        ``CorruptJob`` for every job directory without a valid state.json.
        A corrupt state.json is renamed to ``state.json.corrupt-N`` first.
        """
        with self._lock:
            self._require_open()
            out: list[Job | CorruptJob] = []
            fresh: dict[str, Job] = {}
            for job_dir in self._iter_job_dirs():
                self._remove_stale_temp_files(job_dir)
                try:
                    job = self._read_job(job_dir)
                except FileNotFoundError:
                    out.append(CorruptJob(job_dir.name, str(job_dir), "state.json is missing",
                                          self._corrupt_files(job_dir)))
                    continue
                except (OSError, ValueError) as e:
                    out.append(self._quarantine(job_dir, e))
                    continue
                if not job.terminal:
                    job = self._flag_needs_recovery(job_dir, job)
                    out.append(copy.deepcopy(job))
                fresh[job.id] = job
            self._jobs = fresh
            return out

    # ── internals (callers hold self._lock) ─────────────────────────
    def _require_open(self) -> None:
        if not self._open:
            raise RuntimeError("JobStore is not open; call open() or use it as a context manager")

    def _get_locked(self, job_id: str) -> Job:
        job = self._jobs.get(job_id)
        if job is None:
            raise JobNotFound(f"unknown job {job_id}", details={"job_id": job_id}, next_tool="session_status")
        return job

    def _active_locked(self, profile: str) -> Job | None:
        live = [j for j in self._jobs.values() if j.profile == profile and not j.terminal]
        return max(live, key=lambda j: j.id) if live else None

    def _commit_transition(self, cur: Job, target: JobState, reason: str, updates: Mapping[str, Any],
                           *, actor: str | None) -> Job:
        new = copy.deepcopy(cur)
        if updates:
            _apply_updates(new, updates)
        now = self._clock.now_iso()
        entry: dict[str, Any] = {"from": cur.state.value, "to": target.value, "at": now, "reason": reason}
        if actor is not None:
            entry["actor"] = actor
        new.history.append(entry)
        new.state = target
        new.updated_at = now
        intent = {"op": "transition", "from": cur.state.value, "to": target.value, "reason": reason,
                  "seq": len(new.history)}
        if actor is not None:
            intent["actor"] = actor
        self._persist(new, intent)
        self._jobs[new.id] = new
        return copy.deepcopy(new)

    def _persist(self, job: Job, intent: Mapping[str, Any]) -> None:
        """Intent first (fsynced), then the atomic state replace. See module docstring."""
        job_dir = self.job_dir(job.id)
        payload = _dump_state(job.to_json())  # fails before any write if not serialisable
        line = _dump_line({"at": self._clock.now_iso(), "job_id": job.id, **intent})
        _append_line(job_dir / _INTENT_FILE, line)
        _atomic_write(job_dir / _STATE_FILE, payload)

    def _default_id(self) -> str:
        stamp = _parse_iso_utc(self._clock.now_iso()).strftime("%Y%m%d-%H%M%S")
        return f"{stamp}-{secrets.token_hex(3)}"

    def _allocate_job_dir(self) -> tuple[str, Path]:
        for _ in range(_MAX_ID_ATTEMPTS):
            job_id = validate_job_id(self._id_factory())
            job_dir = self.root / job_id
            try:
                _mkdir_private(job_dir)
            except FileExistsError:
                continue
            return job_id, job_dir
        raise StateViolation("could not allocate a unique job id", details={"attempts": _MAX_ID_ATTEMPTS})

    def _ensure_root(self) -> None:
        if not self.root.exists():
            self.root.mkdir(parents=True, exist_ok=True)
            _chmod_private(self.root, 0o700)

    def _iter_job_dirs(self) -> Iterator[Path]:
        for entry in sorted(self.root.iterdir(), key=lambda p: p.name):
            if JOB_ID_RE.fullmatch(entry.name) and not entry.is_symlink() and entry.is_dir():
                yield entry

    def _read_job(self, job_dir: Path) -> Job:
        job = Job.from_json(_read_capped(job_dir / _STATE_FILE, _MAX_STATE_BYTES))
        if job.id != job_dir.name:
            raise ValueError("job id does not match its directory name")
        job.host_root = str(job_dir)  # the directory is authoritative if the root moved
        return job

    def _load_valid_jobs(self) -> dict[str, Job]:
        jobs: dict[str, Job] = {}
        for job_dir in self._iter_job_dirs():
            with contextlib.suppress(OSError, ValueError):  # recover_scan reports these
                job = self._read_job(job_dir)
                jobs[job.id] = job
        return jobs

    @staticmethod
    def _remove_stale_temp_files(job_dir: Path) -> None:
        # Left by a crash inside _atomic_write. Safe to delete: we hold the root's
        # process lock, so no other writer can own them.
        for p in job_dir.iterdir():
            if _TEMP_RE.fullmatch(p.name):
                with contextlib.suppress(OSError):
                    p.unlink()

    @staticmethod
    def _corrupt_files(job_dir: Path) -> tuple[str, ...]:
        found: list[tuple[int, str]] = []
        for p in job_dir.iterdir():
            m = _CORRUPT_RE.fullmatch(p.name)
            if m:
                found.append((int(m.group(1)), str(p)))
        return tuple(name for _, name in sorted(found))

    def _quarantine(self, job_dir: Path, exc: BaseException) -> CorruptJob:
        reason = _clip(f"{type(exc).__name__}: {exc}", 300)
        n = 1
        while (job_dir / f"{_STATE_FILE}.corrupt-{n}").exists():
            n += 1
        try:
            os.rename(job_dir / _STATE_FILE, job_dir / f"{_STATE_FILE}.corrupt-{n}")
        except OSError as e:
            reason += f"; could not quarantine ({type(e).__name__})"
        return CorruptJob(job_dir.name, str(job_dir), reason, self._corrupt_files(job_dir))

    def _flag_needs_recovery(self, job_dir: Path, job: Job) -> Job:
        flags = copy.deepcopy(job.flags)
        changed = False
        if flags.get("needs_recovery") is not True:
            flags["needs_recovery"] = True
            changed = True
        interrupted = self._interrupted_transition(job_dir, job)
        if interrupted is not None and flags.get("interrupted_transition") != interrupted:
            flags["interrupted_transition"] = interrupted
            changed = True
        if not changed:
            return job
        new = copy.deepcopy(job)
        new.flags = flags
        new.updated_at = self._clock.now_iso()
        self._persist(new, {"op": "recover", "fields": ["flags"]})
        return new

    @staticmethod
    def _interrupted_transition(job_dir: Path, job: Job) -> dict[str, Any] | None:
        """The last logged transition intent if it never reached state.json."""
        try:
            with open(job_dir / _INTENT_FILE, "rb") as f:
                size = f.seek(0, os.SEEK_END)
                f.seek(max(0, size - _INTENT_TAIL_BYTES))
                tail = f.read()
        except OSError:
            return None
        for raw in reversed(tail.splitlines()):
            try:
                rec = json.loads(raw)
            except (ValueError, RecursionError):
                continue  # torn first line of the tail window, or garbage
            if not isinstance(rec, dict) or rec.get("op") != "transition":
                continue
            seq = rec.get("seq")
            if type(seq) is int and seq > len(job.history):
                return {k: rec.get(k) for k in ("from", "to", "at", "reason")}
            return None
        return None

    # ── process lock ────────────────────────────────────────────────
    def _lock_record(self) -> dict[str, Any]:
        rec: dict[str, Any] = {"pid": self._pid, "host": self._host, "nonce": self._nonce,
                               "created_at": self._clock.now_iso()}
        if self._real_pid:
            ident = _process_identity(self._pid)
            if ident is not None:
                rec["start"] = ident
        return rec

    def _acquire_process_lock(self, timeout_s: float) -> None:
        deadline = self._clock.monotonic() + max(0.0, timeout_s)
        while True:
            owner = self._try_lock_once()
            if owner is None:
                return
            remaining = deadline - self._clock.monotonic()
            if remaining <= 0:
                raise LockTimeout(
                    "jobs root is in use by another gateway process",
                    details={"lock": str(self.root / _LOCK_FILE), "owner_pid": owner.get("pid"),
                             "owner_host": owner.get("host")},
                    hint="stop the other gateway; if it no longer exists, delete the lock file",
                )
            self._clock.sleep(min(_LOCK_POLL_S, remaining))

    def _try_lock_once(self) -> dict[str, Any] | None:
        """Create the lock file. Return None on success, else the live owner's record."""
        path = self.root / _LOCK_FILE
        with _GuardLock(self.root / _GUARD_FILE, self._clock, self._guard_timeout_s):
            owner: dict[str, Any] = {}
            for _ in range(2):
                try:
                    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_BINARY
                                 | _O_CLOEXEC, 0o600)
                except FileExistsError:
                    try:
                        record = self._read_lock(path)
                    except FileNotFoundError:
                        continue  # released meanwhile; retry the create
                    except OSError as e:
                        # Unreadable (permissions, symlink, ...): we cannot prove it is
                        # stale, so treat it as held. Only garbled content counts as stale.
                        return {"pid": None, "host": None, "error": type(e).__name__}
                    if record is not None and self._owner_alive(record):
                        return record
                    owner = record or {}
                    with contextlib.suppress(FileNotFoundError):
                        os.unlink(path)  # stale: dead owner or torn write
                    continue
                self._nonce = secrets.token_hex(8)
                try:
                    try:
                        if _POSIX:
                            os.fchmod(fd, 0o600)
                        _write_all(fd, _dump_line(self._lock_record()))
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                except BaseException:
                    self._nonce = None
                    with contextlib.suppress(OSError):
                        os.unlink(path)
                    raise
                return None
            return owner  # someone outside the guard keeps recreating it; treat as held

    @staticmethod
    def _read_lock(path: Path) -> dict[str, Any] | None:
        """Parsed lock record, or None if its content is garbled. I/O errors propagate."""
        try:
            data = json.loads(_read_capped(path, 4096))
        except (ValueError, RecursionError):
            return None
        if not isinstance(data, dict):
            return None
        pid = data.get("pid")
        if type(pid) is not int or pid <= 0:
            return None
        return data

    def _owner_alive(self, record: Mapping[str, Any]) -> bool:
        host = record.get("host")
        if isinstance(host, str) and host and host != self._host:
            return True  # cannot probe a pid on another machine: fail closed
        pid = record["pid"]
        if not self._pid_alive(pid):
            return False
        start = record.get("start")
        if isinstance(start, str) and self._pid_alive is _default_pid_alive:
            current = _process_identity(pid)
            if current is not None and current != start:
                return False  # the pid was reused by an unrelated process
        return True

    def _release_process_lock(self) -> None:
        if self._nonce is None:
            return
        path = self.root / _LOCK_FILE
        try:
            with _GuardLock(self.root / _GUARD_FILE, self._clock, self._guard_timeout_s):
                try:
                    record = self._read_lock(path)
                except OSError:
                    record = None  # gone or unreadable: not provably ours, leave it alone
                if record is not None and record.get("nonce") == self._nonce:
                    with contextlib.suppress(FileNotFoundError):
                        os.unlink(path)
        finally:
            self._nonce = None
