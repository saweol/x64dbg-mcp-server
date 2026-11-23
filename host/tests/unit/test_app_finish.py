"""analysis_finish edges (J-integ): revert=False goes straight to DONE, and an interrupted
revert is redone as REVERTING -> REVERTING (no longer reported as interrupted meanwhile)."""

from __future__ import annotations

import threading

import pytest

from tests.fakes.fake_runtime import make_lab
from x64dbg_vm_gateway.contracts import JobState
from x64dbg_vm_gateway.errors import StateViolation


@pytest.fixture
def lab(tmp_path):
    lab = make_lab(tmp_path)
    yield lab
    lab.close()


def reverts(lab) -> int:
    return sum(1 for c in lab.vm.calls if c[0] == "revert_snapshot")


def history(gw, job_id: str) -> list[tuple[str, str]]:
    return [(h["from"], h["to"]) for h in gw._jobs().get(job_id).history]


def crash_in(gw, job_id: str, *path: JobState) -> None:
    store = gw._jobs()
    for state in path:
        store.transition(job_id, state, reason="test: simulated crash")
    gw.close()


def gate_guest_ip_wait(lab) -> threading.Event:
    release = threading.Event()
    real = lab.vm.guest_ip

    def guest_ip(*, wait=False, timeout_s=60.0):
        if wait:
            assert release.wait(10), "test gate never opened"
        return real(wait=wait, timeout_s=timeout_s)

    lab.vm.guest_ip = guest_ip  # type: ignore[method-assign]
    return release


def test_finish_without_revert_goes_straight_from_collected_to_done(lab):
    gw = lab.gateway()
    job_id = gw.analysis_start(str(lab.sample()))["job_id"]
    gw.analysis_collect()
    before = reverts(lab)
    fin = gw.analysis_finish(revert=False)
    assert fin["state"] == JobState.DONE and fin["reverted"] is False and fin["resumed"] is False
    assert reverts(lab) == before
    edges = history(gw, job_id)
    assert edges[-1] == ("COLLECTED", "DONE")
    assert all("REVERTING" not in edge for edge in edges)


def test_discarded_job_finished_without_revert_skips_reverting(lab):
    gw = lab.gateway()
    job_id = gw.analysis_start(str(lab.sample()))["job_id"]
    gw.discard_job(job_id, "human-cli")
    fin = gw.analysis_finish(job_id, revert=False)
    assert fin["state"] == JobState.DONE
    assert history(gw, job_id)[-1] == ("DISCARDED", "DONE")
    assert gw.session_status()["job"] is None


def test_interrupted_revert_is_redone_as_a_retry_and_not_reported_meanwhile(lab):
    gw1 = lab.gateway()
    job_id = gw1.analysis_start(str(lab.sample()))["job_id"]
    gw1.analysis_collect()
    crash_in(gw1, job_id, JobState.REVERTING)

    gw2 = lab.gateway()
    before = reverts(lab)
    release = gate_guest_ip_wait(lab)
    try:
        assert gw2.analysis_finish(job_id, wait_s=0.05)["state"] == "in_progress"
        status = gw2.session_status()
        # this process is redoing it now: not "interrupted" any more
        assert status["job"]["state"] == JobState.REVERTING and status["needs_recovery"] == []
    finally:
        release.set()
    gw2._ops(gw2.runtime()).wait_idle(10)
    fin = gw2.analysis_finish(job_id, wait_s=5)
    assert fin["state"] == JobState.DONE and fin["resumed"] is True and fin["reverted"] is True
    assert reverts(lab) == before + 1
    assert history(gw2, job_id)[-2:] == [("REVERTING", "REVERTING"), ("REVERTING", "DONE")]


def test_status_points_an_interrupted_revert_at_analysis_finish(lab):
    gw1 = lab.gateway()
    job_id = gw1.analysis_start(str(lab.sample()))["job_id"]
    gw1.analysis_collect()
    crash_in(gw1, job_id, JobState.REVERTING)
    gw2 = lab.gateway()
    (rec,) = gw2.session_status()["needs_recovery"]
    assert rec["job_id"] == job_id and rec["state"] == JobState.REVERTING
    assert rec["next_tool"] == "analysis_finish"
    assert "analysis_finish" in rec["recovery_hint"]


def test_interrupted_revert_crashing_again_is_flagged_again(lab):
    gw1 = lab.gateway()
    job_id = gw1.analysis_start(str(lab.sample()))["job_id"]
    gw1.analysis_collect()
    crash_in(gw1, job_id, JobState.REVERTING)
    gw2 = lab.gateway()
    gw2._jobs().transition(job_id, JobState.REVERTING, reason="test: retry started",
                           clear_flags=["needs_recovery"])
    gw2.close()  # crashed again in the middle of the retry
    gw3 = lab.gateway()
    (rec,) = gw3.session_status()["needs_recovery"]
    assert rec["job_id"] == job_id and rec["next_tool"] == "analysis_finish"
    assert gw3.analysis_finish(job_id)["state"] == JobState.DONE


def test_interrupted_revert_cannot_be_finished_without_reverting(lab):
    # The interrupted revert may have half-applied: the VM state is unknown and may still hold
    # the sample. revert=False would close the job as "VM left as is" without redoing it.
    gw1 = lab.gateway()
    job_id = gw1.analysis_start(str(lab.sample()))["job_id"]
    gw1.analysis_collect()
    crash_in(gw1, job_id, JobState.REVERTING)
    gw2 = lab.gateway()
    before = reverts(lab)
    with pytest.raises(StateViolation) as ei:
        gw2.analysis_finish(job_id, revert=False)
    err = ei.value
    assert err.next_tool == "analysis_finish" and "revert=true" in (err.hint or "")
    assert err.details["state"] == JobState.REVERTING
    job = gw2._jobs().get(job_id)
    assert job.state == JobState.REVERTING and job.flags.get("needs_recovery") is True
    assert reverts(lab) == before
    # still recoverable the documented way
    fin = gw2.analysis_finish(job_id)
    assert fin["state"] == JobState.DONE and fin["reverted"] is True and fin["resumed"] is True
