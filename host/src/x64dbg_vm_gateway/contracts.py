"""Shared contracts between gateway modules.

This file is the integration boundary for parallel development. Implementers
may ADD optional fields/methods; they must not rename or remove anything here
without updating every implementer and test.

Threading model: every API in this package is synchronous and thread-safe
unless stated otherwise. Front-ends call it from worker threads.
"""

from __future__ import annotations

import enum
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, runtime_checkable


# ── secrets ─────────────────────────────────────────────────────────
class Secret(str):
    """A str whose repr/str never reveals the value. Use ``.reveal()`` to read it."""

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return "Secret('***')"

    def __str__(self) -> str:
        return "***"

    def __format__(self, spec: str) -> str:
        return "***"

    def reveal(self) -> str:
        return str.__str__(self)


# ── clock (injectable for tests) ────────────────────────────────────
@runtime_checkable
class Clock(Protocol):
    def monotonic(self) -> float: ...
    def sleep(self, seconds: float) -> None: ...
    def now_iso(self) -> str: ...


class SystemClock:
    def monotonic(self) -> float:
        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        if seconds > 0:
            time.sleep(seconds)

    def now_iso(self) -> str:
        return datetime.now(UTC).isoformat(timespec="seconds")


# ── VM ──────────────────────────────────────────────────────────────
class PowerState(enum.StrEnum):
    RUNNING = "running"
    OFF = "off"
    SUSPENDED = "suspended"
    UNKNOWN = "unknown"


class ToolsState(enum.StrEnum):
    RUNNING = "running"
    INSTALLED = "installed"  # installed but not running
    NOT_INSTALLED = "not_installed"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Snapshot:
    name: str
    depth: int = 0
    parent: str | None = None


@dataclass(frozen=True)
class IsolationReport:
    shared_folders_enabled: bool | None
    shared_folders_writable: bool | None
    network_types: tuple[str, ...]  # e.g. ("bridged",), ("hostonly",), ("nat",)

    @property
    def isolated(self) -> bool:
        """Fail closed: unknown shared-folder state or no NIC information is NOT isolated."""
        if self.shared_folders_enabled is None or self.shared_folders_enabled:
            return False
        if not self.network_types:
            return False
        return all(t in ("hostonly", "none", "disconnected") for t in self.network_types)


@runtime_checkable
class VmProvider(Protocol):
    """Controls one VM. Implemented by vmrun.VmrunProvider (and NullProvider for endpoint mode)."""

    def power_state(self) -> PowerState: ...
    def tools_state(self) -> ToolsState: ...
    def guest_ip(self, *, wait: bool = False, timeout_s: float = 60.0) -> str | None: ...
    def list_snapshots(self) -> list[Snapshot]: ...
    def take_snapshot(self, name: str) -> None: ...
    def revert_snapshot(self, name: str) -> None: ...
    def delete_snapshot(self, name: str) -> None: ...
    def start(self, *, gui: bool = False) -> None: ...
    def stop(self, *, hard: bool = False) -> None: ...
    def suspend(self) -> None: ...
    def screenshot(self, host_path: Path) -> None: ...
    def isolation_report(self) -> IsolationReport: ...


# ── vmrun runner (shared by vmrun.VmrunProvider and guest.VixChannel) ──
@dataclass(frozen=True)
class VmrunResult:
    returncode: int
    stdout: str  # vmrun noise lines ([AppLoader]..., libxml warnings) already removed
    stderr: str


@runtime_checkable
class VmrunRunner(Protocol):
    """Executes ``vmrun -T <type> [-gu USER -gp PASS] <command> [<vmx>] <params...>``.

    - argv list only (never a shell); the vmx path is inserted automatically
      when ``vmx=True``.
    - ``guest=True`` adds guest credentials (-gu/-gp); the password must never
      appear in logs, exceptions or ``details`` (mask it as ``***``).
    - On failure raises an errors.VmrunError subclass mapped from vmrun's
      ``Error: ...`` text (VmNotRunning, ToolsNotRunning, GuestAuthFailed,
      SnapshotNotFound, VmLocked, GuestOperationError, VmrunTimeout, VmrunError).
      It never returns a result with a non-zero returncode.
    - The raw vmrun text is kept in ``exc.message`` / ``details['stdout'|'stderr']``
      so callers can recognise guest-level outcomes such as
      'Guest program exited with non-zero exit code: N' or 'The file does not exist.'
      (both map to GuestOperationError; vmrun exits 255 for them).
    - Usage mistakes detected before vmrun starts: ConfigError (vmx=True but no vmx
      path configured) and GuestAuthFailed (guest=True but no credentials).
    """

    def run(self, command: str, *params: str, guest: bool = False,
            timeout_s: float = 120.0, vmx: bool = True) -> VmrunResult: ...


# ── guest channel ───────────────────────────────────────────────────
@dataclass(frozen=True)
class GuestCredentials:
    user: str
    password: Secret

    def __repr__(self) -> str:
        return f"GuestCredentials(user={self.user!r}, password='***')"


@dataclass(frozen=True)
class GuestProcess:
    pid: int
    owner: str
    cmd: str

    @property
    def image_name(self) -> str:
        """Lower-cased executable file name, e.g. 'x64dbg.exe'."""
        c = self.cmd.strip().strip('"')
        exe = c.split('"')[0] if '"' in c else c.split(" ")[0]
        return exe.replace("/", "\\").rsplit("\\", 1)[-1].lower()


@runtime_checkable
class GuestChannel(Protocol):
    """Operations inside the guest OS. Guest paths are Windows paths (str).

    All methods raise errors.GuestOperationError / GuestAuthFailed / ToolsNotRunning
    / VmrunTimeout on failure. Host-side problems in copy_to_guest/copy_from_guest
    (missing host source, missing host destination folder, destination that is a
    symlink or a directory) raise errors.TransferError. Invalid arguments raise
    TypeError/ValueError, and guest paths failing validation raise PathNotAllowed.
    """

    def run_program(
        self,
        exe: str,
        args: Sequence[str] = (),
        *,
        wait: bool = True,
        interactive: bool = False,
        active_window: bool = False,
        timeout_s: float | None = None,
    ) -> int | None: ...

    def run_script(self, interpreter: str, script: str, *, wait: bool = True,
                   timeout_s: float | None = None) -> None: ...
    def copy_to_guest(self, host_path: Path, guest_path: str) -> None: ...
    def copy_from_guest(self, guest_path: str, host_path: Path) -> None: ...
    def list_processes(self) -> list[GuestProcess]: ...
    def kill_process(self, pid: int) -> None: ...
    def mkdir(self, guest_path: str) -> None: ...
    def file_exists(self, guest_path: str) -> bool: ...
    def dir_exists(self, guest_path: str) -> bool: ...
    def list_dir(self, guest_path: str) -> list[str]: ...
    def delete_file(self, guest_path: str) -> None: ...
    def rename(self, src: str, dst: str) -> None: ...


# ── backend (x64dbg plugin over MCP/HTTP) ───────────────────────────
@dataclass(frozen=True)
class BackendEndpoint:
    id: str  # "x64", "x32", or a custom id
    arch: str  # "x64" | "x32"
    url: str  # e.g. "http://192.168.56.10:9094/"
    token: Secret
    exe: str | None = None  # guest path to x64dbg.exe / x32dbg.exe
    config_path: str | None = None  # guest path to mcp_config.json
    launch_task: str | None = None  # schtasks task name used to (re)launch elevated

    def __repr__(self) -> str:
        return f"BackendEndpoint(id={self.id!r}, arch={self.arch!r}, url={self.url!r}, token='***')"


@dataclass(frozen=True)
class ToolInfo:
    name: str
    description: str
    input_schema: dict[str, Any]
    read_only: bool


@dataclass
class ToolCallResult:
    texts: list[str]
    is_error: bool = False
    raw: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class BackendClient(Protocol):
    """Talks to one x64dbg-MCP plugin instance.

    Raises errors.BackendUnavailable (refused/reset), BackendAuthError (401),
    BackendTimeout, BackendProtocolError. Must never retry by itself.
    ``health_l1``/``health_l2`` return False for unreachable, slow or malformed
    backends but RAISE BackendAuthError on HTTP 401 so AUTH can be told apart from DEAD.
    Implementations may additionally offer ``update_token(token: Secret)`` and
    ``server_info(timeout_s) -> dict`` (HttpBackendClient does); callers must
    feature-test them with ``getattr`` because they are not part of this Protocol.
    ``cancel_all()`` must unblock every in-flight call within ~1s (used when a
    VM operation preempts backend traffic).
    """

    endpoint: BackendEndpoint

    def health_l1(self, timeout_s: float = 2.0) -> bool: ...
    def health_l2(self, timeout_s: float = 5.0) -> bool: ...
    def initialize(self, timeout_s: float = 10.0) -> dict[str, Any]: ...
    def list_tools(self, timeout_s: float = 10.0) -> list[ToolInfo]: ...
    def call_tool(self, name: str, arguments: Mapping[str, Any] | None,
                  timeout_s: float) -> ToolCallResult: ...
    def cancel_all(self) -> None: ...


# ── jobs ────────────────────────────────────────────────────────────
class JobState(enum.StrEnum):
    CREATED = "CREATED"
    PREPARING_VM = "PREPARING_VM"
    VM_READY = "VM_READY"
    UPLOADING = "UPLOADING"
    UPLOADED = "UPLOADED"
    LOADING = "LOADING"
    ANALYZING = "ANALYZING"
    COLLECTING = "COLLECTING"
    COLLECTED = "COLLECTED"
    COLLECTED_PARTIAL = "COLLECTED_PARTIAL"
    REVERTING = "REVERTING"
    DONE = "DONE"
    FAILED = "FAILED"
    DISCARDED = "DISCARDED"


TERMINAL_JOB_STATES = frozenset({JobState.DONE, JobState.FAILED})


@dataclass
class SampleInfo:
    host_path: str
    sha256: str
    size: int
    kind: str  # "exe" | "dll" | "dotnet-exe" | "dotnet-dll" | "non-pe"
    arch: str | None  # "x64" | "x32" | None
    guest_path: str | None = None
    original_name: str | None = None
    # IL-only i386 .NET image (AnyCPU): runs as a 64-bit process on 64-bit Windows,
    # so it must be routed to x64dbg even though the PE Machine field says x32.
    dotnet_anycpu: bool = False
