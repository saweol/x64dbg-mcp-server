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
    return lab.gateways[-1].list_jobs()["jobs"]


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
    op = gw.session_status()["operation"]
    # the final result is reported by session_status ...
    assert op["state"] == "done" and op["result"]["state"] == JobState.ANALYZING
    assert op["result"]["job_id"] == job_id
    # ... so a repeated call afterwards is a new request, refused while the job is live
    with pytest.raises(StateViolation) as ei:
        gw.analysis_start(sample, wait_s=5)
    assert ei.value.details["job_id"] == job_id
    assert len(jobs(lab)) == 1


def test_repeating_a_slow_start_without_polling_status_returns_its_result(lab):
    gate = threading.Event()
    lab.ps.gate = gate
    gw = lab.gateway()
    sample = str(lab.sample())
    try:
        first = gw.analysis_start(sample, wait_s=0.05)
        assert first["state"] == "in_progress"
    finally:
        gate.set()
    gw._ops(gw.runtime()).wait_idle(10)
    final = gw.analysis_start(sample, wait_s=5)  # the client polls by repeating the call
    assert final["state"] == JobState.ANALYZING and final["job_id"]
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


def test_sample_outside_upload_roots_names_the_roots_and_the_setting(lab, tmp_path):
    outside = tmp_path / "elsewhere.exe"
    outside.write_bytes(b"MZ")
    with pytest.raises(PathNotAllowed) as ei:
        lab.gateway().analysis_start(str(outside))
    assert str(lab.samples.resolve()) in ei.value.message
    assert "gateway.upload_roots" in ei.value.message and "gateway.upload_roots" in (ei.value.hint or "")


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


# ── fail-closed collection of the debugger state (review findings) ──
def test_failed_save_database_makes_the_collection_partial_and_blocks_the_revert(lab):
    from tests.fakes.fake_plugin_server import ToolError

    gw = lab.gateway()
    gw.analysis_start(str(lab.sample()))

    def broken_save(args):
        raise ToolError("SaveDatabase failed: disk full")

    working_save = lab.servers["x64"]._handler_for("SaveDatabase")
    lab.servers["x64"].on_tool("SaveDatabase", broken_save)
    col = gw.analysis_collect()
    assert col["state"] == JobState.COLLECTED_PARTIAL and col["partial"] is True
    assert any(e.get("step") == "save_database" for e in col["errors"])
    reverts = sum(1 for c in lab.vm.calls if c[0] == "revert_snapshot")
    with pytest.raises(StateViolation):
        gw.analysis_finish()
    assert sum(1 for c in lab.vm.calls if c[0] == "revert_snapshot") == reverts
    # fixed: the retry completes the collection
    lab.servers["x64"].on_tool("SaveDatabase", working_save)
    assert gw.analysis_collect()["state"] == JobState.COLLECTED


def test_save_database_after_an_unacknowledged_restart_is_partial(lab):
    gw = lab.gateway()
    gw.analysis_start(str(lab.sample()))
    lab.kill_debugger("x64")
    with pytest.raises(BackendRestarted):
        gw.call_mirrored("StepOver")  # relaunched; the client has not acknowledged yet
    col = gw.analysis_collect()
    assert col["state"] == JobState.COLLECTED_PARTIAL
    gw.session_status()
    assert gw.analysis_collect()["state"] == JobState.COLLECTED


def test_failed_module_list_makes_the_collection_partial(lab):
    from tests.fakes.fake_plugin_server import ToolError

    gw = lab.gateway()
    gw.analysis_start(str(lab.sample()))

    def broken(args):
        raise ToolError("ListModules failed")

    lab.servers["x64"].on_tool("ListModules", broken)
    col = gw.analysis_collect()
    assert col["state"] == JobState.COLLECTED_PARTIAL
    assert any(e.get("step") == "module_map" for e in col["errors"])


def test_no_debug_session_means_nothing_to_save(lab):
    """A sample that exited (or was never loaded) leaves no database to lose."""
    gw = lab.gateway()
    gw.analysis_start(str(lab.sample()), load=False)
    srv = lab.servers["x64"]
    srv.debugging = False
    srv.on_tool("SaveDatabase", None)  # back to the plugin's own "requires an active debug session"
    srv.on_tool("ListModules", None)
    col = gw.analysis_collect()
    assert col["state"] == JobState.COLLECTED and col["partial"] is False
    steps = {s["name"]: s for s in col["steps"]}
    assert steps["save_database"]["ok"] and "no debug session" in steps["save_database"]["detail"]


def test_exception_during_collect_leaves_the_job_collected_partial(lab, monkeypatch):
    from x64dbg_vm_gateway import transfer
    from x64dbg_vm_gateway.errors import TransferError

    gw = lab.gateway()
    job_id = gw.analysis_start(str(lab.sample()))["job_id"]
    real = transfer.collect_artifacts

    def boom(*a, **kw):
        raise TransferError("host disk vanished", stage="host_fs")

    monkeypatch.setattr(transfer, "collect_artifacts", boom)
    with pytest.raises(TransferError) as ei:
        gw.analysis_collect()
    assert ei.value.details["job_id"] == job_id
    (job,) = jobs(lab)
    assert job["state"] == JobState.COLLECTED_PARTIAL and job["error"]["code"] == "TRANSFER_FAILED"
    with pytest.raises(StateViolation):
        gw.analysis_finish()
    monkeypatch.setattr(transfer, "collect_artifacts", real)
    assert gw.analysis_collect()["state"] == JobState.COLLECTED


def test_failed_finish_revert_marks_the_job_failed_with_a_revert_hint(lab):
    from x64dbg_vm_gateway.errors import VmrunError

    gw = lab.gateway()
    job_id = gw.analysis_start(str(lab.sample()))["job_id"]
    gw.analysis_collect()

    def broken_revert(name):
        raise VmrunError("vmrun revertToSnapshot failed")

    lab.vm.revert_snapshot = broken_revert  # type: ignore[method-assign]
    with pytest.raises(VmrunError) as ei:
        gw.analysis_finish()
    assert "vm_snapshot_revert" in ei.value.hint
    (job,) = [j for j in jobs(lab) if j["job_id"] == job_id]
    assert job["state"] == JobState.FAILED and job["error"]["code"] == "VMRUN_ERROR"


@pytest.mark.parametrize(("system", "extracted"), [("Windows", False), ("Linux", True), ("Darwin", True)])
def test_collect_extracts_by_default_except_on_windows_hosts(lab, system, extracted):
    gw = lab.gateway(host_system=system)
    job_id = gw.analysis_start(str(lab.sample()))["job_id"]
    lab.guest.write(f"{GUEST_ROOT}\\{job_id}\\out\\a.bin", b"a")
    assert gw.analysis_collect()["extracted"] is extracted


# ── loading ─────────────────────────────────────────────────────────
def test_wait_for_pause_failure_is_reported(lab):
    from tests.fakes.fake_plugin_server import ToolError

    def timeout(args):
        raise ToolError("Timeout waiting for pause")

    lab.servers["x64"].on_tool("WaitForPause", timeout)
    res = lab.gateway().analysis_start(str(lab.sample()))
    load = [s for s in res["steps"] if s["name"] == "load"][0]
    assert load["ok"] is False and "WaitForPause" in load["detail"]
    assert res["paused"] is False
    assert any("WaitForPause" in w and "GetDebugState" in w for w in res["warnings"])
    assert res["state"] == JobState.ANALYZING


def test_snapshot_without_revert_is_rejected(lab):
    from x64dbg_vm_gateway.app import InvalidArgument

    with pytest.raises(InvalidArgument):
        lab.gateway().analysis_start(str(lab.sample()), snapshot="BASE", revert=False)
    assert jobs(lab) == []


# ── crash loops and debugger_restart ────────────────────────────────
def test_crash_loop_records_debugger_killed_by_target(lab):
    from x64dbg_vm_gateway.errors import CrashLoop

    gw = lab.gateway()
    job_id = gw.analysis_start(str(lab.sample()))["job_id"]
    for _ in range(3):
        lab.kill_debugger("x64")
        with pytest.raises(BackendRestarted):
            gw.call_mirrored("StepOver")
        gw.session_status()
    lab.kill_debugger("x64")
    with pytest.raises(CrashLoop):
        gw.call_mirrored("StepOver")
    (job,) = [j for j in jobs(lab) if j["job_id"] == job_id]
    assert job["flags"]["debugger_killed_by_target"] == 3


def test_debugger_restart_checks_the_relaunch_config_before_killing(lab):
    from dataclasses import replace

    from x64dbg_vm_gateway.errors import ConfigError

    lab.set_profile(backends=tuple(replace(b, launch_task=None) for b in lab.profile.backends))
    gw = lab.gateway()
    before = [p.pid for p in lab.guest.processes if p.image_name == "x64dbg.exe"]
    with pytest.raises(ConfigError):
        gw.debugger_restart()
    assert [p.pid for p in lab.guest.processes if p.image_name == "x64dbg.exe"] == before
    assert not lab.guest.calls_of("kill_process")


def test_manual_restarts_do_not_use_the_jobs_crash_budget(lab):
    gw = lab.gateway()
    job_id = gw.analysis_start(str(lab.sample()))["job_id"]
    for _ in range(2):
        lab.servers["x64"].stop()
        gw.debugger_restart(reason="user asked")
    assert gw.runtime().supervisor.restarts(job_id) == 0
    # the sample may still kill the debugger the full number of times
    for _ in range(3):
        lab.kill_debugger("x64")
        with pytest.raises(BackendRestarted):
            gw.call_mirrored("StepOver")
        gw.session_status()


def test_manual_restart_limit_never_leaves_the_debugger_dead(lab):
    from x64dbg_vm_gateway.errors import CrashLoop

    gw = lab.gateway()
    for _ in range(3):
        lab.servers["x64"].stop()
        gw.debugger_restart()
    alive = [p.pid for p in lab.guest.processes if p.image_name == "x64dbg.exe"]
    kills = len(lab.guest.calls_of("kill_process"))
    with pytest.raises(CrashLoop) as ei:
        gw.debugger_restart()
    assert "debugger_restart" in ei.value.message
    assert [p.pid for p in lab.guest.processes if p.image_name == "x64dbg.exe"] == alive
    assert len(lab.guest.calls_of("kill_process")) == kills


# ── reload_on_restart ───────────────────────────────────────────────
def test_reload_on_restart_reloads_the_sample_after_a_relaunch(lab):
    gw = lab.gateway()
    res = gw.analysis_start(str(lab.sample()), reload_on_restart=True, args="-x")
    srv = lab.servers["x64"]
    lab.kill_debugger("x64")
    with pytest.raises(BackendRestarted) as ei:
        gw.call_mirrored("StepOver")
    assert ei.value.details["reload"]["ok"] is True
    loads = srv.tool_calls("LoadBinary")
    assert len(loads) == 2 and loads[-1].arguments["filePath"] == res["sample"]["guest_path"]
    assert loads[-1].arguments["arguments"] == "-x"
    # repeated refusals before the acknowledgement do not load it again
    with pytest.raises(BackendRestarted):
        gw.call_mirrored("StepOver")
    assert len(srv.tool_calls("LoadBinary")) == 2
    gw.session_status()
    gw.call_mirrored("StepOver")


def test_without_reload_on_restart_the_sample_is_not_reloaded(lab):
    gw = lab.gateway()
    gw.analysis_start(str(lab.sample()))
    lab.kill_debugger("x64")
    with pytest.raises(BackendRestarted) as ei:
        gw.call_mirrored("StepOver")
    assert "reload" not in ei.value.details
    assert len(lab.servers["x64"].tool_calls("LoadBinary")) == 1


def test_debugger_restart_reloads_when_asked(lab):
    gw = lab.gateway()
    gw.analysis_start(str(lab.sample()), reload_on_restart=True)
    lab.servers["x64"].stop()
    out = gw.debugger_restart()
    assert out["reload"]["ok"] is True
    assert len(lab.servers["x64"].tool_calls("LoadBinary")) == 2
