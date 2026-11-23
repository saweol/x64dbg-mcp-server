"""Failure paths of the orchestrator: fail-closed revert, debugger death, bad tokens,
isolation, in-progress operations and gateway restart recovery."""

from __future__ import annotations

import threading
import time

import pytest

from tests.fakes.fake_runtime import GUEST_ROOT, make_lab
from x64dbg_vm_gateway.contracts import IsolationReport, JobState
from x64dbg_vm_gateway.errors import (
    BackendAuthError,
    BackendRestarted,
    IntegrityError,
    IsolationRequired,
    PathNotAllowed,
    StateViolation,
)
from x64dbg_vm_gateway.wiring import PROVISION_HINT


@pytest.fixture
def lab(tmp_path):
    lab = make_lab(tmp_path)
    yield lab
    lab.close()


def jobs(lab):
    """Jobs as the (latest) gateway sees them; a second JobStore could not open the locked root."""
    return lab.gateways[-1].list_jobs()


def wait_until(pred, timeout_s: float = 10.0) -> None:
    end = time.monotonic() + timeout_s
    while time.monotonic() < end:
        if pred():
            return
        time.sleep(0.01)
    raise AssertionError("condition not reached")


# ── fail-closed revert ──────────────────────────────────────────────
def test_revert_is_refused_before_collect(lab):
    gw = lab.gateway()
    gw.analysis_start(str(lab.sample()))
    reverts = sum(1 for c in lab.vm.calls if c[0] == "revert_snapshot")
    with pytest.raises(StateViolation) as ei:
        gw.analysis_finish()
    assert ei.value.next_tool == "analysis_collect"
    with pytest.raises(StateViolation):
        gw.vm_snapshot_revert()
    with pytest.raises(StateViolation):
        gw.vm_power("reset")
    assert sum(1 for c in lab.vm.calls if c[0] == "revert_snapshot") == reverts
    assert gw.session_status()["job"]["state"] == JobState.ANALYZING


def test_finish_without_revert_also_needs_a_collection(lab):
    gw = lab.gateway()
    gw.analysis_start(str(lab.sample()))
    with pytest.raises(StateViolation):
        gw.analysis_finish(revert=False)


# ── debugger death ──────────────────────────────────────────────────
def test_debugger_death_mid_analysis_surfaces_backend_restarted(lab):
    gw = lab.gateway()
    res = gw.analysis_start(str(lab.sample()))
    assert res["epoch"] == 1
    lab.kill_debugger("x64")
    with pytest.raises(BackendRestarted) as ei:
        gw.call_mirrored("StepOver")
    d = ei.value.details
    assert d["epoch"] == 2 and d["previous_epoch"] == 1
    assert lab.launches == ["x64"]  # relaunched through the scheduled task
    # still gated until the client acknowledges with session_status
    with pytest.raises(BackendRestarted):
        gw.call_mirrored("StepInto")
    status = gw.session_status()
    b = status["backends"]["x64"]
    assert b["epoch"] == 2 and b["acked_epoch"] == 2 and b["health"] == "HEALTHY"
    assert status["job"]["epoch"] == 2 and status["job"]["restarts"] == 1
    assert gw.call_mirrored("StepInto")["epoch"] == 2


def test_debugger_restart_tool_kills_and_relaunches(lab):
    gw = lab.gateway()
    gw.analysis_start(str(lab.sample()))
    pid_before = [p.pid for p in lab.guest.processes if p.image_name == "x64dbg.exe"]
    lab.servers["x64"].stop()  # the kill below takes the plugin down with the process

    out = gw.debugger_restart(reason="hung UI")
    assert out["backend_id"] == "x64" and out["epoch"] == 2 and out["previous_epoch"] == 1
    assert out["killed"] == pid_before
    assert ("kill_process", (pid_before[0],), {}) in lab.guest.calls
    assert lab.launches == ["x64"]


# ── tokens ──────────────────────────────────────────────────────────
def test_corrupt_guest_token_config_fails_the_job_with_a_provision_hint(lab):
    lab.write_guest_token_config("x64", b"\x00" * 101)
    gw = lab.gateway()
    with pytest.raises(BackendAuthError) as ei:
        gw.analysis_start(str(lab.sample()))
    err = ei.value
    assert PROVISION_HINT in err.hint
    job_id = err.details["job_id"]
    assert [s["name"] for s in err.details["steps"]][-1] == "debugger"
    (job,) = jobs(lab)
    assert job["job_id"] == job_id and job["state"] == JobState.FAILED
    assert job["error"]["code"] == "BACKEND_AUTH"
    # the profile is free again
    assert gw.session_status()["job"] is None


# ── isolation ───────────────────────────────────────────────────────
def test_isolation_violation_refuses_before_any_job_or_vm_change(lab):
    lab.vm.isolation = IsolationReport(True, True, ("bridged",))
    gw = lab.gateway()
    with pytest.raises(IsolationRequired) as ei:
        gw.analysis_start(str(lab.sample()))
    assert "shared folders are enabled" in ei.value.details["violations"]
    assert jobs(lab) == []
    assert not [c for c in lab.vm.calls if c[0] == "revert_snapshot"]


def test_isolation_warnings_when_not_required(lab):
    lab.vm.isolation = IsolationReport(True, True, ("bridged",))
    lab.set_profile(require_isolation=False)
    gw = lab.gateway()
    res = gw.analysis_start(str(lab.sample()))
    assert any("shared folders" in w for w in res["warnings"])
    assert gw.session_status()["isolation_warnings"]


# ── in-progress / idempotency ───────────────────────────────────────
def test_slow_start_returns_in_progress_and_is_idempotent(lab):
    gate = threading.Event()
    lab.ps.gate = gate
    gw = lab.gateway()
    sample = str(lab.sample())
    try:
        first = gw.analysis_start(sample, wait_s=0.05)
        assert first["state"] == "in_progress" and first["op"] == "analysis_start"
        assert lab.ps.hashing.wait(10)
        second = gw.analysis_start(sample, wait_s=0.05)
        assert second["op_id"] == first["op_id"] and second["state"] == "in_progress"
        status = gw.session_status()
        op = status["operation"]
        assert op["op_id"] == first["op_id"] and op["state"] == "running" and op["stage"] == "upload"
        assert op["job_id"] and status["job"]["state"] == JobState.UPLOADING
        job_id = op["job_id"]
        # another sample, or a VM operation, must wait
        with pytest.raises(StateViolation) as ei:
            gw.analysis_start(str(lab.sample("other.exe")), wait_s=0.05)
        assert "analysis_start" in ei.value.hint
        with pytest.raises(StateViolation):
            gw.vm_snapshot_take("manual")
    finally:
        gate.set()
    wait_until(lambda: gw.session_status()["operation"]["state"] != "running")
    assert gw.session_status()["operation"]["state"] == "done"
    # the repeated call now gets the final result of the same run
    final = gw.analysis_start(sample, wait_s=5)
    assert final["state"] == JobState.ANALYZING and final["job_id"] == job_id
    assert len(jobs(lab)) == 1


def test_second_start_while_a_job_is_live_is_refused(lab):
    gw = lab.gateway()
    job_id = gw.analysis_start(str(lab.sample()))["job_id"]
    with pytest.raises(StateViolation) as ei:
        gw.analysis_start(str(lab.sample("second.exe")))
    assert ei.value.details["job_id"] == job_id


def test_upload_integrity_failure_marks_the_job_failed(lab):
    lab.ps.hash_results = ["0" * 64] * 3
    gw = lab.gateway()
    with pytest.raises(IntegrityError) as ei:
        gw.analysis_start(str(lab.sample()))
    (job,) = jobs(lab)
    assert job["state"] == JobState.FAILED and job["error"]["code"] == "INTEGRITY_MISMATCH"
    assert ei.value.details["job_id"] == job["job_id"]
    # a new job may start right away
    assert gw.analysis_start(str(lab.sample("again.exe")))["state"] == JobState.ANALYZING


def test_sample_outside_upload_roots_is_refused(lab, tmp_path):
    outside = tmp_path / "secret.key"
    outside.write_bytes(b"MZ secret")
    gw = lab.gateway()
    with pytest.raises(PathNotAllowed):
        gw.analysis_start(str(outside))
    assert jobs(lab) == []


def test_missing_sample_is_refused(lab):
    gw = lab.gateway()
    with pytest.raises(PathNotAllowed):
        gw.analysis_start(str(lab.samples / "nope.exe"))


# ── gateway restart ─────────────────────────────────────────────────
def test_gateway_restart_reports_unfinished_jobs_for_recovery(lab):
    gw1 = lab.gateway()
    job_id = gw1.analysis_start(str(lab.sample()))["job_id"]
    gw1.close()

    gw2 = lab.gateway()
    status = gw2.session_status()
    rec = status["needs_recovery"]
    assert [r["job_id"] for r in rec] == [job_id]
    assert rec[0]["state"] == JobState.ANALYZING
    assert status["job"]["job_id"] == job_id
    # nothing was resumed automatically, and a new start is refused
    with pytest.raises(StateViolation):
        gw2.analysis_start(str(lab.sample("next.exe")))
    # a human discards it; the AI can then revert and finish
    assert gw2.discard_job(job_id, "human-cli")["state"] == JobState.DISCARDED
    assert gw2.analysis_finish(job_id)["state"] == JobState.DONE
    assert gw2.session_status()["needs_recovery"] == []


def test_recovered_job_can_still_be_collected(lab):
    gw1 = lab.gateway()
    job_id = gw1.analysis_start(str(lab.sample()))["job_id"]
    gw1.close()
    gw2 = lab.gateway()
    lab.guest.write(f"{GUEST_ROOT}\\{job_id}\\out\\x.bin", b"x")
    assert gw2.analysis_collect(job_id)["state"] == JobState.COLLECTED
    assert gw2.session_status()["needs_recovery"] == []


def test_discard_requires_the_human_actor(lab):
    gw = lab.gateway()
    job_id = gw.analysis_start(str(lab.sample()))["job_id"]
    with pytest.raises(StateViolation):
        gw.discard_job(job_id, "mcp")
