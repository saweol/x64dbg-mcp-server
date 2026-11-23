"""In-memory VmProvider and FakeClock shared by unit tests."""

from __future__ import annotations

from pathlib import Path

from x64dbg_vm_gateway.contracts import IsolationReport, PowerState, Snapshot, ToolsState
from x64dbg_vm_gateway.errors import SnapshotNotFound


class FakeClock:
    """Deterministic clock: sleep() advances time instantly."""

    def __init__(self, start: float = 1000.0) -> None:
        self.t = start
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.t += max(0.0, seconds)

    def advance(self, seconds: float) -> None:
        self.t += seconds

    def now_iso(self) -> str:
        return f"2026-11-23T00:00:{int(self.t) % 60:02d}+00:00"


class FakeVm:
    def __init__(self) -> None:
        self.power = PowerState.RUNNING
        self.tools = ToolsState.RUNNING
        self.ip: str | None = "192.168.56.10"
        self.snapshots: list[Snapshot] = [Snapshot("MCP_CLEAN")]
        self.isolation = IsolationReport(False, False, ("hostonly",))
        self.calls: list[tuple[str, tuple]] = []
        self.revert_leaves_suspended = True  # mirrors reported vmrun behaviour

    def _rec(self, name: str, *args) -> None:
        self.calls.append((name, args))

    def power_state(self) -> PowerState:
        self._rec("power_state")
        return self.power

    def tools_state(self) -> ToolsState:
        self._rec("tools_state")
        return self.tools if self.power == PowerState.RUNNING else ToolsState.UNKNOWN

    def guest_ip(self, *, wait: bool = False, timeout_s: float = 60.0) -> str | None:
        self._rec("guest_ip", wait)
        return self.ip if self.power == PowerState.RUNNING else None

    def list_snapshots(self) -> list[Snapshot]:
        self._rec("list_snapshots")
        return list(self.snapshots)

    def take_snapshot(self, name: str) -> None:
        self._rec("take_snapshot", name)
        self.snapshots.append(Snapshot(name))

    def revert_snapshot(self, name: str) -> None:
        self._rec("revert_snapshot", name)
        if name not in {s.name for s in self.snapshots}:
            raise SnapshotNotFound(f"snapshot not found: {name}")
        self.power = PowerState.SUSPENDED if self.revert_leaves_suspended else PowerState.RUNNING

    def delete_snapshot(self, name: str) -> None:
        self._rec("delete_snapshot", name)
        before = len(self.snapshots)
        self.snapshots = [s for s in self.snapshots if s.name != name]
        if len(self.snapshots) == before:
            raise SnapshotNotFound(f"snapshot not found: {name}")

    def start(self, *, gui: bool = False) -> None:
        self._rec("start", gui)
        self.power = PowerState.RUNNING

    def stop(self, *, hard: bool = False) -> None:
        self._rec("stop", hard)
        self.power = PowerState.OFF

    def suspend(self) -> None:
        self._rec("suspend")
        self.power = PowerState.SUSPENDED

    def screenshot(self, host_path: Path) -> None:
        self._rec("screenshot", host_path)
        Path(host_path).write_bytes(b"\x89PNG\r\n\x1a\nfake")

    def isolation_report(self) -> IsolationReport:
        self._rec("isolation_report")
        return self.isolation
