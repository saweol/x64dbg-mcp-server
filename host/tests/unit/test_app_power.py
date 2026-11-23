"""vm_power with a live job (J-integ): starting/resuming is allowed while ANALYZING (host sleep
suspends the VM), stopping/suspending/resetting keeps the revert rules."""

from __future__ import annotations

import threading

import pytest

from tests.fakes.fake_runtime import make_lab
from x64dbg_vm_gateway.contracts import JobState, PowerState
from x64dbg_vm_gateway.errors import StateViolation


@pytest.fixture
def lab(tmp_path):
    lab = make_lab(tmp_path)
    yield lab
    lab.close()


def test_start_resumes_a_vm_suspended_during_the_analysis(lab):
    gw = lab.gateway()
    res = gw.analysis_start(str(lab.sample()))
    lab.vm.power = PowerState.SUSPENDED  # the host went to sleep
    out = gw.vm_power("start")
    assert out["power"] == "running" and out["resumed"] is True
    assert out["epochs"]["x64"] == res["epoch"]  # resuming keeps the debuggee
    assert gw.call_mirrored("StepOver")["is_error"] is False  # no BACKEND_RESTARTED
    assert gw.session_status()["job"]["state"] == JobState.ANALYZING


def test_start_of_a_running_vm_while_analyzing_is_a_no_op(lab):
    gw = lab.gateway()
    gw.analysis_start(str(lab.sample()))
    starts = len([c for c in lab.vm.calls if c[0] == "start"])
    assert gw.vm_power("start")["power"] == "running"
    assert len([c for c in lab.vm.calls if c[0] == "start"]) == starts


def test_start_of_a_running_vm_does_not_preempt_debugger_calls(lab):
    # Nothing is started, so nothing may be cancelled: a write lock would run the preempt
    # hooks (CANCELLED_BY_VM_OP for in-flight calls) and pause supervision for a no-op.
    gw = lab.gateway()
    res = gw.analysis_start(str(lab.sample()))
    rt = gw.runtime()
    preempted: list[int] = []
    rt.lock.add_preempt_hook(lambda: preempted.append(1))
    holding, release = threading.Event(), threading.Event()

    def in_flight_call() -> None:  # a debugger call holds the read lock meanwhile
        with rt.lock.read(timeout_s=5):
            holding.set()
            release.wait(10)

    worker = threading.Thread(target=in_flight_call, daemon=True)
    worker.start()
    try:
        assert holding.wait(5)
        writes: list[int] = []
        real_write = rt.lock.write

        def write(*args, **kwargs):
            writes.append(1)
            return real_write(*args, **kwargs)

        rt.lock.write = write  # type: ignore[method-assign]
        out = gw.vm_power("start", wait_s=5)
    finally:
        release.set()
        worker.join(5)
    assert out["power"] == "running" and out["started"] is False and out["resumed"] is False
    assert out["epochs"]["x64"] == res["epoch"]
    assert writes == [] and preempted == []
    assert not rt.supervisor.is_paused()


def test_start_of_a_stopped_vm_still_takes_the_write_lock(lab):
    # control: a real start changes the VM and must exclude everything else
    gw = lab.gateway()
    lab.vm.power = PowerState.OFF
    rt = gw.runtime()
    writes: list[int] = []
    real_write = rt.lock.write

    def write(*args, **kwargs):
        writes.append(1)
        return real_write(*args, **kwargs)

    rt.lock.write = write  # type: ignore[method-assign]
    out = gw.vm_power("start")
    assert out["started"] is True and writes == [1]


@pytest.mark.parametrize("action", ["stop", "suspend", "reset"])
def test_stop_suspend_and_reset_are_refused_while_analyzing(lab, action):
    gw = lab.gateway()
    gw.analysis_start(str(lab.sample()))
    with pytest.raises(StateViolation) as ei:
        gw.vm_power(action)
    assert ei.value.details["op"] == "power_stop"
    assert lab.vm.power == PowerState.RUNNING


@pytest.mark.parametrize("action", ["stop", "suspend", "reset"])
def test_stop_suspend_and_reset_are_allowed_once_collected(lab, action):
    gw = lab.gateway()
    gw.analysis_start(str(lab.sample()))
    gw.analysis_collect()
    gw.vm_power(action)


def test_start_is_refused_while_collecting(lab):
    gw = lab.gateway()
    job_id = gw.analysis_start(str(lab.sample()))["job_id"]
    gw._jobs().transition(job_id, JobState.COLLECTING, reason="test: collection in progress")
    lab.vm.power = PowerState.SUSPENDED
    with pytest.raises(StateViolation) as ei:
        gw.vm_power("start")
    assert ei.value.details["op"] == "power_start"
    assert lab.vm.power == PowerState.SUSPENDED
