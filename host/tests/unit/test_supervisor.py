"""Supervisor: health classification (plan 5.4), relaunch, epochs, crash loop, pause."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Mapping
from typing import Any

import pytest

from tests.fakes.fake_plugin_server import FakePluginServer
from x64dbg_vm_gateway.backend import HttpBackendClient
from x64dbg_vm_gateway.config import BackendConfig
from x64dbg_vm_gateway.contracts import (
    BackendEndpoint,
    PowerState,
    Secret,
    ToolCallResult,
    ToolInfo,
    ToolsState,
)
from x64dbg_vm_gateway.errors import (
    BackendAuthError,
    BackendThrottled,
    BackendUnavailable,
    CancelledByVmOp,
    ConfigError,
    CrashLoop,
    GuestOperationError,
    LockTimeout,
    ToolsNotRunning,
    VmNotReady,
)
from x64dbg_vm_gateway.supervisor import HealthReport, HealthState, Supervisor

EXE = "C:\\x64dbg\\release\\x64\\x64dbg.exe"
TASK = "x64dbg-mcp-x64"
SCHTASKS = "C:\\Windows\\System32\\schtasks.exe"


class ScriptedClient:
    """In-memory BackendClient whose health answers are programmable.

    ``l1`` / ``l2`` may be a bool, an exception instance, or a zero-arg callable
    returning either.
    """

    def __init__(self, backend_id: str = "x64") -> None:
        self.endpoint = BackendEndpoint(id=backend_id, arch="x64", url="http://10.0.0.1:9094/",
                                        token=Secret("tok"), exe=EXE, launch_task=TASK)
        self.l1: Any = True
        self.l2: Any = True
        self.l1_calls = 0
        self.l2_calls = 0
        self.cancelled = 0

    @staticmethod
    def _eval(v: Any) -> bool:
        if callable(v):
            v = v()
        if isinstance(v, BaseException):
            raise v
        return bool(v)

    def health_l1(self, timeout_s: float = 2.0) -> bool:
        self.l1_calls += 1
        return self._eval(self.l1)

    def health_l2(self, timeout_s: float = 5.0) -> bool:
        self.l2_calls += 1
        return self._eval(self.l2)

    def initialize(self, timeout_s: float = 10.0) -> dict[str, Any]:
        return {}

    def list_tools(self, timeout_s: float = 10.0) -> list[ToolInfo]:
        return []

    def call_tool(self, name: str, arguments: Mapping[str, Any] | None, timeout_s: float) -> ToolCallResult:
        return ToolCallResult(texts=["ok"])

    def cancel_all(self) -> None:
        self.cancelled += 1

    # helpers
    def up(self) -> None:
        self.l1 = True
        self.l2 = True

    def down(self) -> None:
        self.l1 = False
        self.l2 = False


@pytest.fixture
def client() -> ScriptedClient:
    return ScriptedClient()


def cfg(**kw: Any) -> BackendConfig:
    base: dict[str, Any] = dict(id="x64", arch="x64", port=9094, exe=EXE, launch_task=TASK)
    base.update(kw)
    return BackendConfig(**base)


def make_sup(vm, guest, clock, client, *, mode: str = "task", backend: BackendConfig | None = None,
             refresher: Callable[[str], None] | None = None, **kw: Any) -> Supervisor:
    return Supervisor(vm=vm, guest=guest, clients={"x64": client}, backends={"x64": backend or cfg()},
                      relaunch_mode=mode, token_refresher=refresher, clock=clock, **kw)


def relaunch_brings_up(guest, client) -> None:
    def on_run(exe, args, **kw):
        guest.add_process(f'"{EXE}"')
        client.up()
        return 0 if kw.get("wait") else None

    guest.on_run_program = on_run


# ── classification ──────────────────────────────────────────────────
def test_healthy(fake_vm, fake_guest, fake_clock, client):
    sup = make_sup(fake_vm, fake_guest, fake_clock, client)
    r = sup.check("x64")
    assert isinstance(r, HealthReport) and r.state is HealthState.HEALTHY
    assert client.l1_calls == 1 and client.l2_calls == 1


def test_vm_down(fake_vm, fake_guest, fake_clock, client):
    fake_vm.power = PowerState.SUSPENDED
    r = make_sup(fake_vm, fake_guest, fake_clock, client).check("x64")
    assert r.state is HealthState.VM_DOWN
    assert client.l1_calls == 0


def test_tools_down(fake_vm, fake_guest, fake_clock, client):
    fake_vm.tools = ToolsState.INSTALLED
    r = make_sup(fake_vm, fake_guest, fake_clock, client).check("x64")
    assert r.state is HealthState.TOOLS_DOWN


def test_l1_refused_no_process_is_dead(fake_vm, fake_guest, fake_clock, client):
    client.down()
    fake_guest.add_process("C:\\Windows\\notepad.exe")
    r = make_sup(fake_vm, fake_guest, fake_clock, client).check("x64")
    assert r.state is HealthState.DEAD


def test_l1_refused_process_present_is_loading_then_hung(fake_vm, fake_guest, fake_clock, client):
    client.down()
    fake_guest.add_process(f'"{EXE}" -noupdate')
    sup = make_sup(fake_vm, fake_guest, fake_clock, client, boot_grace_s=90)
    assert sup.check("x64").state is HealthState.LOADING
    fake_clock.advance(60)
    assert sup.check("x64").state is HealthState.LOADING
    fake_clock.advance(31)
    r = sup.check("x64")
    assert r.state is HealthState.HUNG
    assert r.details["pids"]


def test_loading_timer_resets_when_process_disappears(fake_vm, fake_guest, fake_clock, client):
    client.down()
    p = fake_guest.add_process(EXE)
    sup = make_sup(fake_vm, fake_guest, fake_clock, client, boot_grace_s=90)
    assert sup.check("x64").state is HealthState.LOADING
    fake_clock.advance(80)
    fake_guest.processes.remove(p)
    assert sup.check("x64").state is HealthState.DEAD
    fake_guest.add_process(EXE)
    fake_clock.advance(20)
    assert sup.check("x64").state is HealthState.LOADING  # timer restarted


def test_guest_listing_failure_is_unknown(fake_vm, fake_guest, fake_clock, client):
    client.down()
    fake_guest.fail_next("list_processes", ToolsNotRunning("tools gone"))
    r = make_sup(fake_vm, fake_guest, fake_clock, client).check("x64")
    assert r.state is HealthState.UNKNOWN
    assert r.details["error"] == "TOOLS_NOT_RUNNING"


def test_l2_hang_needs_threshold_and_window(fake_vm, fake_guest, fake_clock, client):
    client.l2 = False
    sup = make_sup(fake_vm, fake_guest, fake_clock, client, l2_fail_threshold=3, l2_min_window_s=30)
    r1 = sup.check("x64")
    assert r1.state is HealthState.HEALTHY and r1.details["l2_failures"] == 1
    fake_clock.advance(10)
    assert sup.check("x64").state is HealthState.HEALTHY
    fake_clock.advance(10)
    assert sup.check("x64").state is HealthState.HEALTHY  # 3 failures but only 20 s
    fake_clock.advance(10)
    r4 = sup.check("x64")
    assert r4.state is HealthState.HUNG and r4.details["l2_failures"] == 4


def test_l2_success_resets_failures(fake_vm, fake_guest, fake_clock, client):
    client.l2 = False
    sup = make_sup(fake_vm, fake_guest, fake_clock, client)
    sup.check("x64")
    fake_clock.advance(20)
    sup.check("x64")
    client.l2 = True
    assert sup.check("x64").state is HealthState.HEALTHY
    client.l2 = False
    fake_clock.advance(40)
    sup.check("x64")
    fake_clock.advance(1)
    assert sup.check("x64").state is HealthState.HEALTHY  # count restarted at 1


def test_auth_refresher_called_once_per_epoch(fake_vm, fake_guest, fake_clock, client):
    calls: list[str] = []
    client.l1 = BackendAuthError("401")
    sup = make_sup(fake_vm, fake_guest, fake_clock, client, refresher=calls.append)
    assert sup.check("x64").state is HealthState.AUTH
    assert calls == ["x64"]
    assert sup.check("x64").state is HealthState.AUTH
    assert calls == ["x64"]  # not again in the same epoch
    sup.bump_epoch("x64", "vm revert")
    sup.check("x64")
    assert calls == ["x64", "x64"]


def test_auth_refresher_fixes_token(fake_vm, fake_guest, fake_clock, client):
    client.l1 = BackendAuthError("401")
    sup = make_sup(fake_vm, fake_guest, fake_clock, client, refresher=lambda b: client.up())
    assert sup.check("x64").state is HealthState.HEALTHY


def test_auth_refresher_failure_reports_auth(fake_vm, fake_guest, fake_clock, client):
    client.l1 = BackendAuthError("401")

    def boom(_: str) -> None:
        raise GuestOperationError("cannot read config")

    r = make_sup(fake_vm, fake_guest, fake_clock, client, refresher=boom).check("x64")
    assert r.state is HealthState.AUTH
    assert r.details["refresh_error"] == "GUEST_OP_FAILED"


def test_auth_on_l2(fake_vm, fake_guest, fake_clock, client):
    client.l2 = BackendAuthError("401")
    assert make_sup(fake_vm, fake_guest, fake_clock, client).check("x64").state is HealthState.AUTH


def test_unknown_backend(fake_vm, fake_guest, fake_clock, client):
    sup = make_sup(fake_vm, fake_guest, fake_clock, client)
    with pytest.raises(ConfigError):
        sup.check("x99")
    with pytest.raises(ConfigError):
        sup.epoch("x99")


# ── throttling (HTTP 429 auth lockout, plugin v1.10) ────────────────
def test_throttled_on_l1_is_its_own_state(fake_vm, fake_guest, fake_clock, client):
    client.l1 = BackendThrottled("429", retry_after_s=30)
    fake_guest.add_process(f'"{EXE}"')
    r = make_sup(fake_vm, fake_guest, fake_clock, client).check("x64")
    assert r.state is HealthState.THROTTLED
    assert r.details["retry_after_s"] == 30
    assert client.l2_calls == 0
    assert fake_guest.calls_of("list_processes") == []  # alive by definition: no process probing


def test_throttled_on_l2(fake_vm, fake_guest, fake_clock, client):
    client.l2 = BackendThrottled("429", retry_after_s=3)
    r = make_sup(fake_vm, fake_guest, fake_clock, client).check("x64")
    assert r.state is HealthState.THROTTLED and r.details["retry_after_s"] == 3


def test_throttling_never_counts_as_l2_failure(fake_vm, fake_guest, fake_clock, client):
    client.l2 = BackendThrottled("429", retry_after_s=300)
    sup = make_sup(fake_vm, fake_guest, fake_clock, client, l2_fail_threshold=1, l2_min_window_s=0)
    for _ in range(5):
        assert sup.check("x64").state is HealthState.THROTTLED
        fake_clock.advance(60)


def test_ensure_alive_never_kills_or_relaunches_a_throttled_backend(fake_vm, fake_guest, fake_clock, client):
    client.l1 = BackendThrottled("429", retry_after_s=120)
    fake_guest.add_process(f'"{EXE}"')
    sup = make_sup(fake_vm, fake_guest, fake_clock, client)
    with pytest.raises(BackendThrottled) as ei:
        sup.ensure_alive("x64", job_id="j1", reason="test")
    assert ei.value.details["retry_after_s"] == 120 and ei.value.details["backend"] == "x64"
    assert fake_guest.calls_of("kill_process") == [] and fake_guest.calls_of("run_program") == []
    assert sup.epoch("x64") == 0 and sup.restarts("j1") == 0


def test_relaunched_backend_that_throttles_stops_the_ready_wait(fake_vm, fake_guest, fake_clock, client):
    client.down()

    def on_run(exe, args, **kw):
        fake_guest.add_process(f'"{EXE}"')
        client.l1 = BackendThrottled("429", retry_after_s=60)
        return 0 if kw.get("wait") else None

    fake_guest.on_run_program = on_run
    sup = make_sup(fake_vm, fake_guest, fake_clock, client, relaunch_ready_timeout_s=600)
    with pytest.raises(BackendThrottled):
        sup.ensure_alive("x64", reason="test")
    assert len(fake_guest.calls_of("run_program")) == 1
    assert client.l1_calls <= 3  # no polling loop against a locked-out plugin


# ── endpoint mode ───────────────────────────────────────────────────
def test_endpoint_mode_classification(fake_clock, client):
    sup = Supervisor(vm=None, guest=None, clients={"x64": client}, backends={}, relaunch_mode="direct",
                     clock=fake_clock)
    assert sup.check("x64").state is HealthState.HEALTHY
    client.down()
    assert sup.check("x64").state is HealthState.DEAD
    client.l1 = BackendAuthError("401")
    assert sup.check("x64").state is HealthState.AUTH


def test_endpoint_mode_cannot_relaunch(fake_clock, client):
    client.down()
    sup = Supervisor(vm=None, guest=None, clients={"x64": client}, backends={}, relaunch_mode="direct",
                     clock=fake_clock)
    with pytest.raises(BackendUnavailable) as ei:
        sup.ensure_alive("x64", reason="test")
    assert "endpoint mode" in (ei.value.hint or "")
    assert sup.epoch("x64") == 0


# ── ensure_alive ────────────────────────────────────────────────────
def test_ensure_alive_healthy_returns_epoch_without_relaunch(fake_vm, fake_guest, fake_clock, client):
    sup = make_sup(fake_vm, fake_guest, fake_clock, client)
    assert sup.ensure_alive("x64", reason="probe") == 0
    assert fake_guest.calls_of("run_program") == []


def test_ensure_alive_task_mode_relaunch(fake_vm, fake_guest, fake_clock, client):
    client.down()
    relaunch_brings_up(fake_guest, client)
    sup = make_sup(fake_vm, fake_guest, fake_clock, client, mode="task")
    assert sup.ensure_alive("x64", job_id="j1", reason="dead") == 1
    (args, kw), = fake_guest.calls_of("run_program")
    assert args == (SCHTASKS, ("/run", "/tn", TASK))
    assert kw["wait"] is True
    assert sup.epoch("x64") == 1
    assert sup.restarts("j1") == 1
    assert sup.check("x64").state is HealthState.HEALTHY


def test_ensure_alive_direct_mode_relaunch(fake_vm, fake_guest, fake_clock, client):
    client.down()
    relaunch_brings_up(fake_guest, client)
    sup = make_sup(fake_vm, fake_guest, fake_clock, client, mode="direct")
    assert sup.ensure_alive("x64", reason="dead") == 1
    (args, kw), = fake_guest.calls_of("run_program")
    assert args == (EXE, ())
    assert kw["wait"] is False and kw["interactive"] is True and kw["active_window"] is True


def test_ensure_alive_hung_kills_first(fake_vm, fake_guest, fake_clock, client):
    p = fake_guest.add_process(f'"{EXE}"')
    other = fake_guest.add_process("C:\\Windows\\explorer.exe")
    client.l2 = False
    sup = make_sup(fake_vm, fake_guest, fake_clock, client, l2_fail_threshold=3, l2_min_window_s=30)
    for _ in range(3):
        sup.check("x64")
        fake_clock.advance(15)
    assert sup.check("x64").state is HealthState.HUNG

    def on_run(exe, args, **kw):
        assert all(proc.pid != p.pid for proc in fake_guest.processes), "must kill before relaunch"
        fake_guest.add_process(f'"{EXE}"')
        client.up()
        return 0

    fake_guest.on_run_program = on_run
    assert sup.ensure_alive("x64", reason="hang") == 1
    killed = [a[0] for a, _ in fake_guest.calls_of("kill_process")]
    assert killed == [p.pid] and other in fake_guest.processes


def test_ensure_alive_loading_waits_without_relaunch(fake_vm, fake_guest, fake_clock, client):
    fake_guest.add_process(EXE)
    client.down()
    sup = make_sup(fake_vm, fake_guest, fake_clock, client, boot_grace_s=90)
    start = fake_clock.monotonic()

    def l1() -> bool:
        return fake_clock.monotonic() - start >= 20

    client.l1 = l1
    client.l2 = True
    assert sup.ensure_alive("x64", reason="loading") == 0  # never seen up in this epoch: no bump
    assert fake_guest.calls_of("run_program") == []


def test_ensure_alive_loading_after_being_up_bumps_epoch(fake_vm, fake_guest, fake_clock, client):
    sup = make_sup(fake_vm, fake_guest, fake_clock, client)
    assert sup.check("x64").state is HealthState.HEALTHY  # seen up in epoch 0
    fake_guest.add_process(EXE)
    client.down()
    start = fake_clock.monotonic()
    client.l1 = lambda: fake_clock.monotonic() - start >= 10
    client.l2 = True
    assert sup.ensure_alive("x64", reason="external restart") == 1
    assert fake_guest.calls_of("run_program") == []


def test_transient_l1_failure_of_the_same_instance_does_not_bump(fake_vm, fake_guest, fake_clock, client):
    fake_guest.add_process(EXE)
    sup = make_sup(fake_vm, fake_guest, fake_clock, client)
    assert sup.check("x64").state is HealthState.HEALTHY  # seen up; its pid is recorded
    start = fake_clock.monotonic()
    client.l1 = lambda: fake_clock.monotonic() - start >= 10  # L1 hiccup, same process
    assert sup.ensure_alive("x64", reason="probe") == 0
    assert sup.epoch_history("x64") == []


def test_external_restart_with_a_new_pid_bumps(fake_vm, fake_guest, fake_clock, client):
    old = fake_guest.add_process(EXE)
    sup = make_sup(fake_vm, fake_guest, fake_clock, client)
    assert sup.check("x64").state is HealthState.HEALTHY
    fake_guest.processes.remove(old)
    fake_guest.add_process(EXE)  # restarted outside the gateway
    start = fake_clock.monotonic()
    client.l1 = lambda: fake_clock.monotonic() - start >= 10
    assert sup.ensure_alive("x64", reason="probe") == 1


def test_note_up_marks_the_epoch_as_seen(fake_vm, fake_guest, fake_clock, client):
    """A successful proxied call proves the backend was up even if check() never ran."""
    sup = make_sup(fake_vm, fake_guest, fake_clock, client)
    sup.note_up("x64", 0)
    fake_guest.add_process(EXE)
    client.down()
    start = fake_clock.monotonic()
    client.l1 = lambda: fake_clock.monotonic() - start >= 10
    client.l2 = True
    assert sup.ensure_alive("x64", reason="external restart") == 1  # pids unknown: assume restarted
    sup.note_up("x64", 0)  # stale epoch: ignored
    assert sup.epoch("x64") == 1


def test_ensure_alive_loading_too_long_kills_and_relaunches(fake_vm, fake_guest, fake_clock, client):
    fake_guest.add_process(EXE)
    client.down()
    relaunch_brings_up(fake_guest, client)
    sup = make_sup(fake_vm, fake_guest, fake_clock, client, boot_grace_s=30)
    assert sup.ensure_alive("x64", reason="stuck") == 1
    assert fake_guest.calls_of("kill_process")


def test_ensure_alive_not_ready_in_time(fake_vm, fake_guest, fake_clock, client):
    client.down()
    fake_guest.on_run_program = lambda exe, args, **kw: 0  # launches nothing
    sup = make_sup(fake_vm, fake_guest, fake_clock, client, relaunch_ready_timeout_s=120)
    t0 = fake_clock.monotonic()
    with pytest.raises(BackendUnavailable) as ei:
        sup.ensure_alive("x64", reason="dead")
    # a relaunch was issued: whatever comes up later is a fresh debugger
    assert sup.epoch("x64") == 1
    assert 120 <= fake_clock.monotonic() - t0 <= 130
    assert ei.value.details["timeout_s"] == 120


def test_launched_but_slow_debugger_keeps_the_bumped_epoch(fake_vm, fake_guest, fake_clock, client):
    """Review finding: launch ok, readiness times out, debugger finishes booting later."""
    client.down()
    fake_guest.on_run_program = lambda exe, args, **kw: (fake_guest.add_process(EXE), 0)[1]
    sup = make_sup(fake_vm, fake_guest, fake_clock, client, relaunch_ready_timeout_s=60)
    with pytest.raises(BackendUnavailable):
        sup.ensure_alive("x64", reason="dead")
    assert sup.epoch("x64") == 1
    client.up()  # the new debugger finished booting by itself
    assert sup.check("x64").state is HealthState.HEALTHY
    # no second relaunch and no double bump: the launch was already accounted for
    assert sup.ensure_alive("x64", reason="probe") == 1
    assert len(fake_guest.calls_of("run_program")) == 1


def test_kill_then_launch_failure_bumps_epoch(fake_vm, fake_guest, fake_clock, client):
    fake_guest.add_process(EXE)
    client.l2 = False
    sup = make_sup(fake_vm, fake_guest, fake_clock, client)
    _make_hung(sup, fake_clock)
    fake_guest.on_run_program = lambda exe, args, **kw: 1  # schtasks /run fails
    with pytest.raises(BackendUnavailable) as ei:
        sup.ensure_alive("x64", reason="hang")
    assert ei.value.details["exit_code"] == 1
    assert fake_guest.calls_of("kill_process")
    assert sup.epoch("x64") == 1  # the hung debugger and its debuggee state are gone


def test_ensure_alive_max_wait_bounds_the_ready_wait(fake_vm, fake_guest, fake_clock, client):
    client.down()
    fake_guest.on_run_program = lambda exe, args, **kw: (fake_guest.add_process(EXE), 0)[1]
    sup = make_sup(fake_vm, fake_guest, fake_clock, client, relaunch_ready_timeout_s=120)
    t0 = fake_clock.monotonic()
    with pytest.raises(BackendUnavailable) as ei:
        sup.ensure_alive("x64", reason="dead", max_wait_s=10)
    assert fake_clock.monotonic() - t0 <= 15
    assert ei.value.details["relaunch_pending"] is True
    assert sup.epoch("x64") == 1
    assert len(fake_guest.calls_of("run_program")) == 1


def test_ensure_alive_zero_budget_still_issues_the_relaunch(fake_vm, fake_guest, fake_clock, client):
    client.down()
    fake_guest.on_run_program = lambda exe, args, **kw: (fake_guest.add_process(EXE), 0)[1]
    sup = make_sup(fake_vm, fake_guest, fake_clock, client)
    with pytest.raises(BackendUnavailable) as ei:
        sup.ensure_alive("x64", reason="dead", max_wait_s=0)
    assert ei.value.details["relaunch_pending"] is True
    assert len(fake_guest.calls_of("run_program")) == 1
    assert sup.epoch("x64") == 1


def test_ensure_alive_max_wait_bounds_the_loading_wait(fake_vm, fake_guest, fake_clock, client):
    fake_guest.add_process(EXE)
    client.down()
    sup = make_sup(fake_vm, fake_guest, fake_clock, client, boot_grace_s=90)
    t0 = fake_clock.monotonic()
    with pytest.raises(BackendUnavailable) as ei:
        sup.ensure_alive("x64", reason="loading", max_wait_s=10)
    assert fake_clock.monotonic() - t0 <= 15
    assert ei.value.details["state"] == "LOADING"
    assert fake_guest.calls_of("run_program") == []
    assert sup.epoch("x64") == 0


def test_ensure_alive_schtasks_failure(fake_vm, fake_guest, fake_clock, client):
    client.down()
    fake_guest.on_run_program = lambda exe, args, **kw: 1
    sup = make_sup(fake_vm, fake_guest, fake_clock, client)
    with pytest.raises(BackendUnavailable) as ei:
        sup.ensure_alive("x64", reason="dead")
    assert ei.value.details["exit_code"] == 1


def test_task_mode_requires_launch_task(fake_vm, fake_guest, fake_clock, client):
    client.down()
    client.endpoint = BackendEndpoint(id="x64", arch="x64", url="http://h/", token=Secret("t"))
    sup = make_sup(fake_vm, fake_guest, fake_clock, client, backend=cfg(launch_task=None))
    with pytest.raises(ConfigError):
        sup.ensure_alive("x64", job_id="j1", reason="dead")
    # rejected before any side effect: no restart counted, no epoch change
    assert sup.restarts("j1") == 0
    assert sup.epoch("x64") == 0


def test_invalid_relaunch_mode(fake_vm, fake_guest, fake_clock, client):
    with pytest.raises(ConfigError):
        make_sup(fake_vm, fake_guest, fake_clock, client, mode="magic")


def test_ensure_alive_vm_down_and_auth(fake_vm, fake_guest, fake_clock, client):
    sup = make_sup(fake_vm, fake_guest, fake_clock, client)
    fake_vm.power = PowerState.OFF
    with pytest.raises(VmNotReady):
        sup.ensure_alive("x64", reason="x")
    fake_vm.power = PowerState.RUNNING
    client.l1 = BackendAuthError("401")
    with pytest.raises(BackendAuthError):
        sup.ensure_alive("x64", reason="x")
    assert fake_guest.calls_of("run_program") == []


def test_crash_loop_after_max_restarts(fake_vm, fake_guest, fake_clock, client):
    relaunch_brings_up(fake_guest, client)
    sup = make_sup(fake_vm, fake_guest, fake_clock, client, max_restarts_per_job=3)
    for i in range(3):
        client.down()
        fake_guest.processes.clear()
        assert sup.ensure_alive("x64", job_id="j1", reason="crash") == i + 1
    client.down()
    fake_guest.processes.clear()
    with pytest.raises(CrashLoop) as ei:
        sup.ensure_alive("x64", job_id="j1", reason="crash")
    assert ei.value.details["debugger_killed_by_target"] == 3
    assert ei.value.details["job_id"] == "j1"
    assert sup.epoch("x64") == 3
    # a different job (or no job) is not affected
    assert sup.ensure_alive("x64", job_id="j2", reason="crash") == 4
    sup.forget_job("j1")
    assert sup.restarts("j1") == 0


def test_crash_loop_without_job_id(fake_vm, fake_guest, fake_clock, client):
    """Relaunches without a job are limited per backend within a sliding window."""
    relaunch_brings_up(fake_guest, client)
    sup = make_sup(fake_vm, fake_guest, fake_clock, client, max_restarts_per_job=3, crash_loop_window_s=600)

    def crash() -> int:
        client.down()
        fake_guest.processes.clear()
        return sup.ensure_alive("x64", reason="crash")

    assert [crash() for _ in range(3)] == [1, 2, 3]
    with pytest.raises(CrashLoop) as ei:
        crash()
    assert ei.value.details["job_id"] is None
    assert ei.value.details["debugger_killed_by_target"] == 3
    assert sup.jobless_restarts("x64") == 3
    fake_clock.advance(601)  # old relaunches leave the window
    assert crash() == 4
    sup.bump_epoch("x64", "vm revert")  # a revert starts from a clean state
    assert sup.jobless_restarts("x64") == 0


def test_concurrent_callers_share_one_relaunch(fake_vm, fake_guest, fake_clock, client):
    client.down()

    def on_run(exe, args, **kw):
        time.sleep(0.3)  # real time: keep the relaunch lock held while the other caller waits
        fake_guest.add_process(EXE)
        client.up()
        return 0

    fake_guest.on_run_program = on_run
    sup = make_sup(fake_vm, fake_guest, fake_clock, client)
    barrier = threading.Barrier(3)
    results: list[int] = []
    errs: list[BaseException] = []

    def worker() -> None:
        barrier.wait()
        try:
            results.append(sup.ensure_alive("x64", reason="dead"))
        except BaseException as e:  # noqa: BLE001
            errs.append(e)

    ts = [threading.Thread(target=worker) for _ in range(3)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(timeout=10)
    assert not errs
    assert results == [1, 1, 1]
    assert len(fake_guest.calls_of("run_program")) == 1


def test_bounded_caller_during_another_relaunch_reports_pending(fake_vm, fake_guest, fake_clock, client):
    client.down()
    started = threading.Event()

    def on_run(exe, args, **kw):
        started.set()
        time.sleep(0.5)  # real time: hold the relaunch lock
        fake_guest.add_process(EXE)
        client.up()
        return 0

    fake_guest.on_run_program = on_run
    sup = make_sup(fake_vm, fake_guest, fake_clock, client)
    t = threading.Thread(target=lambda: sup.ensure_alive("x64", reason="dead"))
    t.start()
    assert started.wait(5)
    with pytest.raises(LockTimeout) as ei:
        sup.ensure_alive("x64", reason="dead", max_wait_s=0.05)
    t.join(5)
    assert ei.value.details["relaunch_pending"] is True
    assert len(fake_guest.calls_of("run_program")) == 1


# ── pause / resume / epochs ─────────────────────────────────────────
def test_pause_blocks_check_and_relaunch(fake_vm, fake_guest, fake_clock, client):
    client.down()
    relaunch_brings_up(fake_guest, client)
    sup = make_sup(fake_vm, fake_guest, fake_clock, client)
    sup.pause()
    assert sup.is_paused()
    assert sup.check("x64").state is HealthState.PAUSED
    assert client.l1_calls == 0
    with pytest.raises(CancelledByVmOp):
        sup.ensure_alive("x64", reason="x")
    assert fake_guest.calls_of("run_program") == []
    sup.resume()
    assert not sup.is_paused()
    assert sup.ensure_alive("x64", reason="x") == 1


def test_paused_context_manager_nests(fake_vm, fake_guest, fake_clock, client):
    sup = make_sup(fake_vm, fake_guest, fake_clock, client)
    with sup.paused():
        with sup.paused():
            assert sup.is_paused()
        assert sup.is_paused()
    assert not sup.is_paused()


def test_pause_during_relaunch_wait_aborts(fake_vm, fake_guest, fake_clock, client):
    client.down()
    sup = make_sup(fake_vm, fake_guest, fake_clock, client)

    def on_run(exe, args, **kw):
        sup.pause()  # a VM operation starts while we wait for readiness
        return 0

    fake_guest.on_run_program = on_run
    with pytest.raises(CancelledByVmOp):
        sup.ensure_alive("x64", reason="dead")
    assert sup.epoch("x64") == 1  # the relaunch had been issued before the VM operation began


def test_resume_clears_loading_timer(fake_vm, fake_guest, fake_clock, client):
    client.down()
    fake_guest.add_process(EXE)
    sup = make_sup(fake_vm, fake_guest, fake_clock, client, boot_grace_s=90)
    sup.check("x64")
    fake_clock.advance(85)
    with sup.paused():
        fake_clock.advance(60)
    assert sup.check("x64").state is HealthState.LOADING


def test_bump_epoch(fake_vm, fake_guest, fake_clock, client):
    sup = make_sup(fake_vm, fake_guest, fake_clock, client)
    assert sup.epoch("x64") == 0
    assert sup.bump_epoch("x64", "vm revert") == 1
    assert sup.epoch("x64") == 1
    hist = sup.epoch_history("x64")
    assert hist[-1]["epoch"] == 1 and hist[-1]["reason"] == "vm revert"


# ── hang handling details ───────────────────────────────────────────
def _make_hung(sup, fake_clock) -> None:
    for _ in range(4):
        sup.check("x64")
        fake_clock.advance(15)


def test_kill_failure_for_already_exited_process_is_tolerated(fake_vm, fake_guest, fake_clock, client):
    p = fake_guest.add_process(EXE)
    client.l2 = False
    sup = make_sup(fake_vm, fake_guest, fake_clock, client)
    _make_hung(sup, fake_clock)
    real_kill = fake_guest.kill_process

    def kill_exits_first(pid: int) -> None:
        fake_guest.processes = [x for x in fake_guest.processes if x.pid != pid]  # exited meanwhile
        raise GuestOperationError(f"no such process: {pid}")

    fake_guest.kill_process = kill_exits_first  # type: ignore[method-assign]
    relaunch_brings_up(fake_guest, client)
    assert sup.ensure_alive("x64", reason="hang") == 1
    fake_guest.kill_process = real_kill  # type: ignore[method-assign]
    assert p not in fake_guest.processes


def _slow_exit(guest, listings_until_exit: int | None) -> None:
    """kill_process succeeds but the process only disappears after N more listings (None: never)."""
    pending: dict[int, int] = {}
    real_list = guest.list_processes

    def kill(pid: int) -> None:
        guest.calls.append(("kill_process", (pid,), {}))
        pending[pid] = listings_until_exit if listings_until_exit is not None else 10**9

    def listing():  # type: ignore[no-untyped-def]
        for pid in list(pending):
            pending[pid] -= 1
            if pending[pid] < 0:
                guest.processes = [x for x in guest.processes if x.pid != pid]
                del pending[pid]
        return real_list()

    guest.kill_process = kill
    guest.list_processes = listing


def test_hung_kill_waits_for_the_process_to_exit(fake_vm, fake_guest, fake_clock, client):
    p = fake_guest.add_process(EXE)
    client.l2 = False
    sup = make_sup(fake_vm, fake_guest, fake_clock, client)
    _make_hung(sup, fake_clock)
    _slow_exit(fake_guest, listings_until_exit=2)

    def on_run(exe, args, **kw):
        assert all(x.pid != p.pid for x in fake_guest.processes), "old instance must be gone first"
        fake_guest.add_process(EXE)
        client.up()
        return 0

    fake_guest.on_run_program = on_run
    assert sup.ensure_alive("x64", reason="hang") == 1


def test_hung_process_that_never_exits_blocks_the_relaunch(fake_vm, fake_guest, fake_clock, client):
    fake_guest.add_process(EXE)
    client.l2 = False
    sup = make_sup(fake_vm, fake_guest, fake_clock, client, kill_exit_timeout_s=10)
    _make_hung(sup, fake_clock)
    _slow_exit(fake_guest, listings_until_exit=None)
    relaunch_brings_up(fake_guest, client)
    t0 = fake_clock.monotonic()
    with pytest.raises(BackendUnavailable) as ei:
        sup.ensure_alive("x64", reason="hang")
    assert fake_clock.monotonic() - t0 <= 15
    assert ei.value.details["pids"]
    assert fake_guest.calls_of("run_program") == []  # never two instances on one port
    assert sup.epoch("x64") == 1  # the kill was accepted: the old state is gone


def test_kill_failure_with_process_still_present_aborts(fake_vm, fake_guest, fake_clock, client):
    fake_guest.add_process(EXE)
    client.l2 = False
    sup = make_sup(fake_vm, fake_guest, fake_clock, client)
    _make_hung(sup, fake_clock)
    fake_guest.fail_next("kill_process", GuestOperationError("access denied"))
    relaunch_brings_up(fake_guest, client)
    with pytest.raises(GuestOperationError):
        sup.ensure_alive("x64", reason="hang")
    assert fake_guest.calls_of("run_program") == []  # no second instance next to the hung one
    assert sup.epoch("x64") == 0


def test_hang_hook_called_before_kill(fake_vm, fake_guest, fake_clock, client):
    fake_guest.add_process(EXE)
    client.l2 = False
    seen: list[tuple[str, HealthState, int]] = []

    def hook(backend_id: str, report: HealthReport) -> None:
        seen.append((backend_id, report.state, len(fake_guest.calls_of("kill_process"))))
        raise RuntimeError("screenshot failed")  # must not break recovery

    sup = make_sup(fake_vm, fake_guest, fake_clock, client, hang_hook=hook)
    _make_hung(sup, fake_clock)
    relaunch_brings_up(fake_guest, client)
    assert sup.ensure_alive("x64", reason="hang") == 1
    assert seen == [("x64", HealthState.HUNG, 0)]


def test_loading_wait_is_bounded_even_if_clock_stalls(fake_vm, fake_guest, client):
    class StalledClock:
        def monotonic(self) -> float:
            return 5.0

        def sleep(self, seconds: float) -> None:
            pass

        def now_iso(self) -> str:
            return "2026-11-23T00:00:00+00:00"

    fake_guest.add_process(EXE)
    client.down()
    relaunch_brings_up(fake_guest, client)
    sup = make_sup(fake_vm, fake_guest, StalledClock(), client, boot_grace_s=10, poll_interval_s=1,
                   relaunch_ready_timeout_s=5)
    # loading never ends by the clock; the bounded wait gives up and treats it as hung
    assert sup.ensure_alive("x64", reason="stuck") == 1
    assert fake_guest.calls_of("kill_process")


def test_ready_wait_is_bounded_even_if_clock_stalls(fake_vm, fake_guest, client):
    class StalledClock:
        def monotonic(self) -> float:
            return 5.0

        def sleep(self, seconds: float) -> None:
            pass

        def now_iso(self) -> str:
            return "2026-11-23T00:00:00+00:00"

    client.down()
    fake_guest.on_run_program = lambda exe, args, **kw: 0  # never comes up
    sup = make_sup(fake_vm, fake_guest, StalledClock(), client, poll_interval_s=1, relaunch_ready_timeout_s=5)
    with pytest.raises(BackendUnavailable):
        sup.ensure_alive("x64", reason="dead")
    assert client.l1_calls < 20


# ── integration with the real HTTP client and fake plugin server ────
def test_relaunch_against_fake_plugin_server(fake_vm, fake_guest, fake_clock):
    srv = FakePluginServer(token="tok-int").start()
    try:
        ep = BackendEndpoint(id="x64", arch="x64", url=srv.url, token=Secret("tok-int"), exe=EXE)
        http_client = HttpBackendClient(ep)
        sup = Supervisor(vm=fake_vm, guest=fake_guest, clients={"x64": http_client},
                         backends={"x64": cfg()}, relaunch_mode="direct", clock=fake_clock)
        assert sup.check("x64").state is HealthState.HEALTHY
        srv.stop()
        assert sup.check("x64").state is HealthState.DEAD

        def on_run(exe, args, **kw):
            fake_guest.add_process(EXE)
            srv.restart()
            return None

        fake_guest.on_run_program = on_run
        assert sup.ensure_alive("x64", reason="dead") == 1
        assert sup.check("x64").state is HealthState.HEALTHY
    finally:
        srv.stop()
