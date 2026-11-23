"""FakeVm with the host-side instance view of ``vmrun.VmrunProvider`` (K-vm contract).

The real provider adds (feature-tested by the orchestrator with ``getattr``):

- ``instance_report() -> {"listed": bool, "pids": [int], "orphans": [int]}``: whether
  ``vmrun list`` shows the .vmx, every host ``vmware-vmx`` process whose command line
  ends with this .vmx, and the ones that are not the registered instance;
- ``vm_process_ids() -> list[int]``: the same pids.

Model (E1 on the spike VM): the registered instance exists while the VM is RUNNING.
``lingering`` pids belong to an earlier instance of the same .vmx that is not listed:
each one exits after ``exit_after_polls`` instance queries (None: never, an orphan).
``start()`` adds a new registered pid, plus a second one when ``start_duplicates``.
"""

from __future__ import annotations

from typing import Any

from tests.fakes.fake_vm import FakeVm
from x64dbg_vm_gateway.contracts import PowerState


class InstanceVm(FakeVm):
    def __init__(self) -> None:
        super().__init__()
        self._next_pid = 5000
        self.registered: list[int] = [self._new_pid()]  # pids of the instance vmrun lists
        self.lingering: dict[int, int | None] = {}  # pid -> polls left before it exits (None: never)
        self.start_duplicates = False
        self.instance_polls = 0
        self.report_error: Exception | None = None

    def _new_pid(self) -> int:
        self._next_pid += 1
        return self._next_pid

    # ── scripting ───────────────────────────────────────────────────
    def add_orphan(self, exit_after_polls: int | None = None) -> int:
        pid = self._new_pid()
        self.lingering[pid] = exit_after_polls
        return pid

    def _tick(self) -> None:
        self.instance_polls += 1
        for pid, left in list(self.lingering.items()):
            if left is None:
                continue
            if left <= 1:
                del self.lingering[pid]
            else:
                self.lingering[pid] = left - 1

    # ── VmProvider overrides that change the instances ──────────────
    def revert_snapshot(self, name: str) -> None:
        super().revert_snapshot(name)
        self._lose_instance()

    def stop(self, *, hard: bool = False) -> None:
        super().stop(hard=hard)
        self._lose_instance()

    def suspend(self) -> None:
        super().suspend()
        self._lose_instance()

    def _lose_instance(self) -> None:
        if self.power != PowerState.RUNNING:
            self.registered = []

    def start(self, *, gui: bool = False) -> None:
        super().start(gui=gui)
        if not self.registered:
            self.registered = [self._new_pid()]
        if self.start_duplicates:
            self.registered.append(self._new_pid())

    # ── the K-vm contract ───────────────────────────────────────────
    def instance_report(self) -> dict[str, Any]:
        self._rec("instance_report")
        if self.report_error is not None:
            raise self.report_error
        self._tick()
        listed = self.power == PowerState.RUNNING and bool(self.registered)
        pids = list(self.registered) + list(self.lingering)
        orphans = list(self.lingering) + (list(self.registered[1:]) if listed else list(self.registered))
        return {"listed": listed, "pids": pids, "orphans": orphans}

    def vm_process_ids(self) -> list[int]:
        self._rec("vm_process_ids")
        if self.report_error is not None:
            raise self.report_error
        self._tick()
        return list(self.registered) + list(self.lingering)


class PidsOnlyVm(InstanceVm):
    """A provider that offers ``vm_process_ids`` but not ``instance_report``."""

    def __getattribute__(self, name: str) -> Any:
        if name == "instance_report":
            raise AttributeError(name)
        return super().__getattribute__(name)
