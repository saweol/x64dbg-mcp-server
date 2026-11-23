"""In-memory GuestChannel used by unit tests across features.

Guest paths are case-insensitive Windows paths. Behaviour hooks let tests
script failures without subclassing:

    g = FakeGuest()
    g.fail_next("copy_to_guest", GuestOperationError("boom"))
    g.on_run_program = lambda exe, args, **kw: 0
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path, PureWindowsPath

from x64dbg_vm_gateway.contracts import GuestProcess
from x64dbg_vm_gateway.errors import GuestOperationError


def _norm(p: str) -> str:
    return str(PureWindowsPath(p)).rstrip("\\").lower()


class FakeGuest:
    def __init__(self) -> None:
        self.files: dict[str, bytes] = {}  # normalized path -> content
        self.dirs: set[str] = {"c:"}
        self.processes: list[GuestProcess] = []
        self.calls: list[tuple[str, tuple, dict]] = []
        self._failures: dict[str, list[Exception]] = {}
        self._next_pid = 1000
        self.on_run_program: Callable[..., int | None] | None = None
        self.on_run_script: Callable[..., None] | None = None

    # ── test helpers ────────────────────────────────────────────────
    def fail_next(self, method: str, exc: Exception, times: int = 1) -> None:
        self._failures.setdefault(method, []).extend([exc] * times)

    def _maybe_fail(self, method: str) -> None:
        q = self._failures.get(method)
        if q:
            raise q.pop(0)

    def _record(self, method: str, *args, **kwargs) -> None:
        self.calls.append((method, args, kwargs))
        self._maybe_fail(method)

    def add_process(self, cmd: str, owner: str = "mcp") -> GuestProcess:
        self._next_pid += 4
        p = GuestProcess(pid=self._next_pid, owner=owner, cmd=cmd)
        self.processes.append(p)
        return p

    def write(self, guest_path: str, data: bytes) -> None:
        self.files[_norm(guest_path)] = data
        parent = _norm(str(PureWindowsPath(guest_path).parent))
        self.dirs.add(parent)

    def read(self, guest_path: str) -> bytes:
        return self.files[_norm(guest_path)]

    def calls_of(self, method: str) -> list[tuple[tuple, dict]]:
        return [(a, k) for m, a, k in self.calls if m == method]

    # ── GuestChannel ────────────────────────────────────────────────
    def run_program(self, exe: str, args: Sequence[str] = (), *, wait: bool = True,
                    interactive: bool = False, active_window: bool = False,
                    timeout_s: float | None = None) -> int | None:
        self._record("run_program", exe, tuple(args), wait=wait, interactive=interactive,
                     active_window=active_window, timeout_s=timeout_s)
        if self.on_run_program:
            return self.on_run_program(exe, tuple(args), wait=wait, interactive=interactive)
        return 0 if wait else None

    def run_script(self, interpreter: str, script: str, *, wait: bool = True,
                   timeout_s: float | None = None) -> None:
        self._record("run_script", interpreter, script, wait=wait, timeout_s=timeout_s)
        if self.on_run_script:
            self.on_run_script(interpreter, script, wait=wait)

    def copy_to_guest(self, host_path: Path, guest_path: str) -> None:
        self._record("copy_to_guest", host_path, guest_path)
        parent = _norm(str(PureWindowsPath(guest_path).parent))
        if parent not in self.dirs:
            raise GuestOperationError(f"guest directory does not exist: {parent}")
        self.files[_norm(guest_path)] = Path(host_path).read_bytes()

    def copy_from_guest(self, guest_path: str, host_path: Path) -> None:
        self._record("copy_from_guest", guest_path, host_path)
        key = _norm(guest_path)
        if key not in self.files:
            raise GuestOperationError(f"guest file not found: {guest_path}")
        Path(host_path).write_bytes(self.files[key])

    def list_processes(self) -> list[GuestProcess]:
        self._record("list_processes")
        return list(self.processes)

    def kill_process(self, pid: int) -> None:
        self._record("kill_process", pid)
        before = len(self.processes)
        self.processes = [p for p in self.processes if p.pid != pid]
        if len(self.processes) == before:
            raise GuestOperationError(f"no such process: {pid}")

    def mkdir(self, guest_path: str) -> None:
        self._record("mkdir", guest_path)
        p = PureWindowsPath(guest_path)
        for i in range(1, len(p.parts) + 1):
            self.dirs.add(_norm(str(PureWindowsPath(*p.parts[:i]))))

    def file_exists(self, guest_path: str) -> bool:
        self._record("file_exists", guest_path)
        return _norm(guest_path) in self.files

    def dir_exists(self, guest_path: str) -> bool:
        self._record("dir_exists", guest_path)
        return _norm(guest_path) in self.dirs

    def list_dir(self, guest_path: str) -> list[str]:
        self._record("list_dir", guest_path)
        base = _norm(guest_path) + "\\"
        names = {k[len(base):].split("\\", 1)[0] for k in list(self.files) + list(self.dirs)
                 if k.startswith(base)}
        return sorted(n for n in names if n)

    def delete_file(self, guest_path: str) -> None:
        self._record("delete_file", guest_path)
        if self.files.pop(_norm(guest_path), None) is None:
            raise GuestOperationError(f"guest file not found: {guest_path}")

    def rename(self, src: str, dst: str) -> None:
        self._record("rename", src, dst)
        key = _norm(src)
        if key not in self.files:
            raise GuestOperationError(f"guest file not found: {src}")
        self.files[_norm(dst)] = self.files.pop(key)
