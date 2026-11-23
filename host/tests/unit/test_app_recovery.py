"""Gateway restart recovery, in-progress VM operations and the bounded result replay."""

from __future__ import annotations

import threading
import time

import pytest

from tests.fakes.fake_runtime import GUEST_ROOT, make_lab
from x64dbg_vm_gateway.contracts import JobState
from x64dbg_vm_gateway.errors import BackendRestarted, StateViolation


@pytest.fixture
def lab(tmp_path):
    lab = make_lab(tmp_path)
    yield lab
    lab.close()


def wait_until(pred, timeout_s: float = 10.0) -> None:
    end = time.monotonic() + timeout_s
    while time.monotonic() < end:
        if pred():
            return
        time.sleep(0.01)
    raise AssertionError("condition not reached")


def reverts(lab) -> int:
    return sum(1 for c in lab.vm.calls if c[0] == "revert_snapshot")


def crash_in(gw, job_id: str, *path: JobState) -> None:
    """Move the job along ``path`` and stop the gateway, as if the process died there."""
    store = gw._jobs()
    for state in path:
        store.transition(job_id, state, reason="test: simulated crash")
    gw.close()


def gate_guest_ip_wait(lab) -> threading.Event:
    """Block ``getGuestIPAddress -wait`` (the last step of the VM ready procedure) until released."""
    release = threading.Event()
    real = lab.vm.guest_ip

    def guest_ip(*, wait=False, timeout_s=60.0):
        if wait:
            assert release.wait(10), "test gate never opened"
        return real(wait=wait, timeout_s=timeout_s)

    lab.vm.guest_ip = guest_ip  # type: ignore[method-assign]
    return release


# ── restart recovery from states other than ANALYZING ───────────────
def test_job_left_in_reverting_is_finished_after_a_restart(lab):
    gw1 = lab.gateway()
    job_id = gw1.analysis_start(str(lab.sample()))["job_id"]
    gw1.analysis_collect()
    crash_in(gw1, job_id, JobState.REVERTING)

    gw2 = lab.gateway()
    status = gw2.session_status()
    (rec,) = status["needs_recovery"]
    assert rec["job_id"] == job_id and rec["state"] == JobState.REVERTING
    assert "analysis_finish" in rec["recovery_hint"]
    # VM tools point at the interrupted finish instead of "wait until the job leaves this step"
    with pytest.raises(StateViolation) as ei:
        gw2.vm_snapshot_revert()
    assert ei.value.next_tool == "analysis_finish"
    before = reverts(lab)
    fin = gw2.analysis_finish(job_id)
    assert fin["state"] == JobState.DONE and fin["reverted"] is True and fin["resumed"] is True
    assert reverts(lab) == before + 1
    assert gw2.session_status()["needs_recovery"] == [] and gw2.session_status()["job"] is None


def test_job_left_in_reverting_is_not_finished_without_a_revert(lab):
    # J-integ review: revert=False no longer passes REVERTING, so a job left there was being
    # reverted; its VM state is unknown and only redoing the revert may close it
    gw1 = lab.gateway()
    job_id = gw1.analysis_start(str(lab.sample()))["job_id"]
    gw1.analysis_collect()
    crash_in(gw1, job_id, JobState.REVERTING)
    gw2 = lab.gateway()
    before = reverts(lab)
    with pytest.raises(StateViolation):
        gw2.analysis_finish(job_id, revert=False)
    assert reverts(lab) == before
    assert gw2._jobs().get(job_id).state == JobState.REVERTING


def test_job_left_in_collecting_is_collected_again_after_a_restart(lab):
    gw1 = lab.gateway()
    job_id = gw1.analysis_start(str(lab.sample()))["job_id"]
    crash_in(gw1, job_id, JobState.COLLECTING)

    gw2 = lab.gateway()
    (rec,) = gw2.session_status()["needs_recovery"]
    assert rec["state"] == JobState.COLLECTING and "analysis_collect" in rec["recovery_hint"]
    lab.guest.write(f"{GUEST_ROOT}\\{job_id}\\out\\late.bin", b"late")
    col = gw2.analysis_collect(job_id)
    assert col["state"] == JobState.COLLECTED
    assert any(f["original_path"] == "late.bin" for f in col["files"])
    assert gw2.analysis_finish(job_id)["state"] == JobState.DONE


@pytest.mark.parametrize("path", [
    (JobState.PREPARING_VM,),
    (JobState.PREPARING_VM, JobState.VM_READY, JobState.UPLOADING),
    (JobState.PREPARING_VM, JobState.VM_READY, JobState.UPLOADING, JobState.UPLOADED, JobState.LOADING),
])
def test_job_interrupted_during_start_needs_a_human_discard(lab, path):
    gw1 = lab.gateway()
    job = gw1._jobs().create("lab", GUEST_ROOT)
    crash_in(gw1, job.id, *path)

    gw2 = lab.gateway()
    (rec,) = gw2.session_status()["needs_recovery"]
    assert rec["state"] == path[-1] and "discard" in rec["recovery_hint"]
    with pytest.raises(StateViolation):
        gw2.analysis_start(str(lab.sample()))
    with pytest.raises(StateViolation):
        gw2.analysis_collect(job.id)
    assert gw2.discard_job(job.id, "human-cli")["state"] == JobState.DISCARDED
    assert gw2.analysis_finish(job.id)["state"] == JobState.DONE
    assert gw2.analysis_start(str(lab.sample()))["state"] == JobState.ANALYZING


# ── in-progress VM operations ───────────────────────────────────────
def test_slow_revert_is_in_progress_idempotent_and_not_replayed_after_status(lab):
    gw = lab.gateway()
    gw.session_status()
    release = gate_guest_ip_wait(lab)
    try:
        first = gw.vm_snapshot_revert(wait_s=0.05)
        assert first["state"] == "in_progress" and first["op"] == "vm_snapshot_revert"
        again = gw.vm_snapshot_revert(wait_s=0.05)
        assert again["op_id"] == first["op_id"]
        assert reverts(lab) == 1
        status = gw.session_status()
        assert status["operation"]["state"] == "running"
        # polling during the revert does not acknowledge the new epoch
        b = status["backends"]["x64"]
        assert b["health"] == "PAUSED" and b["epoch"] == 1 and b["acked_epoch"] == 0
    finally:
        release.set()
    wait_until(lambda: gw.session_status()["operation"]["state"] != "running")
    op = gw.session_status()["operation"]
    assert op["state"] == "done" and op["result"]["snapshot"] == "MCP_CLEAN"
    # the outcome was reported by session_status: the same call later is a new revert
    gw.vm_snapshot_revert(wait_s=5)
    assert reverts(lab) == 2


def test_repeating_a_slow_revert_after_it_finished_returns_its_result(lab):
    gw = lab.gateway()
    release = gate_guest_ip_wait(lab)
    try:
        first = gw.vm_snapshot_revert(wait_s=0.05)
        assert first["state"] == "in_progress"
    finally:
        release.set()
    gw._ops(gw.runtime()).wait_idle(10)
    out = gw.vm_snapshot_revert(wait_s=5)  # the client polls by repeating the call
    assert out["snapshot"] == "MCP_CLEAN" and reverts(lab) == 1


def test_other_activity_drops_an_unreported_revert_result(lab):
    gw = lab.gateway()
    release = gate_guest_ip_wait(lab)
    try:
        assert gw.vm_snapshot_revert(wait_s=0.05)["state"] == "in_progress"
    finally:
        release.set()
    gw._ops(gw.runtime()).wait_idle(10)
    gw.debugger_call("GetDebugState")  # the guest may have changed since the revert
    gw.vm_snapshot_revert(wait_s=5)
    assert reverts(lab) == 2


def test_status_polled_during_a_revert_does_not_hide_backend_restarted(lab):
    gw = lab.gateway()
    assert gw.call_mirrored("StepOver")["epoch"] == 0
    release = gate_guest_ip_wait(lab)
    try:
        assert gw.vm_snapshot_revert(wait_s=0.05)["state"] == "in_progress"
        gw.session_status()
    finally:
        release.set()
    gw._ops(gw.runtime()).wait_idle(10)
    with pytest.raises(BackendRestarted):
        gw.call_mirrored("StepOver")
    gw.session_status()
    assert gw.call_mirrored("StepOver")["epoch"] == 1


def test_slow_power_start_is_in_progress_and_idempotent(lab):
    from x64dbg_vm_gateway.contracts import PowerState

    gw = lab.gateway()
    lab.vm.power = PowerState.OFF
    release = gate_guest_ip_wait(lab)
    try:
        first = gw.vm_power("start", wait_s=0.05)
        assert first["state"] == "in_progress" and first["op"] == "vm_power"
        assert gw.vm_power("start", wait_s=0.05)["op_id"] == first["op_id"]
        with pytest.raises(StateViolation):
            gw.vm_power("stop", wait_s=0.05)
    finally:
        release.set()
    gw._ops(gw.runtime()).wait_idle(10)
    assert sum(1 for c in lab.vm.calls if c[0] == "start") == 1


def test_slow_finish_is_in_progress_and_idempotent(lab):
    gw = lab.gateway()
    job_id = gw.analysis_start(str(lab.sample()))["job_id"]
    gw.analysis_collect()
    release = gate_guest_ip_wait(lab)
    try:
        first = gw.analysis_finish(wait_s=0.05)
        assert first["state"] == "in_progress" and first["job_id"] == job_id
        assert gw.session_status()["job"]["state"] == JobState.REVERTING
        # repeating the call while it runs is idempotent (the job is REVERTING by then)
        again = gw.analysis_finish(job_id, wait_s=0.05)
        assert again["state"] == "in_progress" and again["op_id"] == first["op_id"]
    finally:
        release.set()
    gw._ops(gw.runtime()).wait_idle(10)
    assert gw.analysis_finish(job_id, wait_s=5)["state"] == JobState.DONE
    assert reverts(lab) == 2  # analysis_start + analysis_finish


def test_recovered_job_being_finished_here_is_not_reported_as_interrupted(lab):
    gw1 = lab.gateway()
    job_id = gw1.analysis_start(str(lab.sample()))["job_id"]
    gw1.close()
    gw2 = lab.gateway()
    gw2.discard_job(job_id, "human-cli")  # keeps the needs_recovery flag of the restart scan
    release = gate_guest_ip_wait(lab)
    try:
        assert gw2.analysis_finish(job_id, wait_s=0.05)["state"] == "in_progress"
        status = gw2.session_status()
        assert status["job"]["state"] == JobState.REVERTING and status["needs_recovery"] == []
        with pytest.raises(StateViolation) as ei:
            gw2.vm_snapshot_revert()
        assert ei.value.next_tool != "analysis_finish"
    finally:
        release.set()
    gw2._ops(gw2.runtime()).wait_idle(10)
    assert gw2.analysis_finish(job_id, wait_s=5)["state"] == JobState.DONE
