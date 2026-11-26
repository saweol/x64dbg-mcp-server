"""Several VMs (profiles) behind one gateway process: concurrent jobs, routing, isolation.

One ``Gateway`` serves every configured profile (one MCP registration). Each profile has its
own runtime (VM, VM lock, supervisor and epochs, proxy) and operation runner, and each may
have its own live job. Mirrored x64dbg tools and debugger_* tools carry no profile: they go
to the current target of the client session (``app_api.client_session``), which
``analysis_start`` and ``debugger_select(profile=...)`` set; with live jobs on several VMs and
no target the gateway refuses instead of guessing (TARGET_AMBIGUOUS).
"""

from __future__ import annotations

import json
import threading

import pytest
from starlette.testclient import TestClient

from tests.fakes.fake_runtime import make_labs
from tests.unit.test_http_server import ADMIN_TOKEN, BASE, ENV, LOCAL, cfg, open_session, rpc
from x64dbg_vm_gateway import app as app_module
from x64dbg_vm_gateway.app_api import STATELESS_SESSION, client_session
from x64dbg_vm_gateway.contracts import JobState, PowerState
from x64dbg_vm_gateway.errors import (
    BackendRestarted,
    GatewayError,
    InvalidArgument,
    StateViolation,
    TargetAmbiguous,
)
from x64dbg_vm_gateway.frontends import http_server, mcp_server


@pytest.fixture
def labs(tmp_path):
    labs = make_labs(tmp_path)
    yield labs
    labs.close()


def calls(labs, profile: str, tool: str) -> int:
    return len(labs[profile].servers["x64"].tool_calls(tool))


def start(gw, labs, profile: str, name: str = "sample.exe", **kw):
    return gw.analysis_start(str(labs[profile].sample(name)), profile=profile, **kw)


def reverts(labs, profile: str) -> int:
    return sum(1 for c in labs[profile].vm.calls if c[0] == "revert_snapshot")


# ── concurrent jobs ─────────────────────────────────────────────────
def test_each_profile_has_its_own_live_job(labs):
    gw = labs.gateway()
    a = start(gw, labs, "lab", "a.exe")
    b = start(gw, labs, "lab2", "b.exe")
    assert a["state"] == b["state"] == JobState.ANALYZING
    assert (a["profile"], b["profile"]) == ("lab", "lab2") and a["job_id"] != b["job_id"]
    # each sample went into its own VM only
    assert labs["lab"].servers["x64"].tool_calls("LoadBinary")[-1].arguments["filePath"] == \
        a["sample"]["guest_path"]
    assert labs["lab2"].servers["x64"].tool_calls("LoadBinary")[-1].arguments["filePath"] == \
        b["sample"]["guest_path"]
    assert calls(labs, "lab", "LoadBinary") == calls(labs, "lab2", "LoadBinary") == 1
    # one profile still refuses a second job of its own
    with pytest.raises(StateViolation) as ei:
        start(gw, labs, "lab", "c.exe")
    assert ei.value.details["job_id"] == a["job_id"]


def test_a_vm_operation_of_one_profile_never_blocks_the_other(labs):
    gw = labs.gateway()
    entered, release = threading.Event(), threading.Event()
    original = labs["lab"].vm.revert_snapshot

    def slow_revert(name: str) -> None:
        entered.set()
        release.wait(10)
        original(name)

    labs["lab"].vm.revert_snapshot = slow_revert  # type: ignore[method-assign]
    first = start(gw, labs, "lab", "a.exe", wait_s=0)  # holds lab's VM write lock in the revert
    assert first["state"] == "in_progress" and entered.wait(5)
    try:
        assert gw.runtime("lab").lock.state()["writer"]
        b = start(gw, labs, "lab2", "b.exe")  # not held up by lab's revert
        assert b["state"] == JobState.ANALYZING
        out = gw.debugger_call("GetDebugState", profile="lab2")
        assert out["is_error"] is False and out["profile"] == "lab2"
        assert gw.session_status("lab2")["backends"]["x64"]["health"] == "HEALTHY"
    finally:
        release.set()
    assert gw._ops(gw.runtime("lab")).wait_idle(10)


def test_finishing_one_job_reverts_only_its_own_vm(labs):
    gw = labs.gateway()
    a = start(gw, labs, "lab", "a.exe")
    b = start(gw, labs, "lab2", "b.exe")
    lab2_calls = list(labs["lab2"].vm.calls)
    epochs2 = gw.session_status("lab2")["backends"]["x64"]["epoch"]
    gw.analysis_collect(a["job_id"])
    done = gw.analysis_finish(a["job_id"])
    assert done["state"] == JobState.DONE and reverts(labs, "lab") == 2  # start + finish
    assert reverts(labs, "lab2") == 1  # only its own start
    assert not [c for c in labs["lab2"].vm.calls[len(lab2_calls):]
                if c[0] in ("revert_snapshot", "start", "stop", "suspend", "take_snapshot")]
    # the other job goes on in the same epoch: no BACKEND_RESTARTED for a mutating call
    assert gw.get_job(b["job_id"])["state"] == JobState.ANALYZING
    out = gw.debugger_call("SetBreakpoint", {"address": "0x401000"}, profile="lab2")
    assert out["is_error"] is False and out["epoch"] == epochs2


def test_epochs_and_restarts_are_per_profile(labs):
    gw = labs.gateway()
    start(gw, labs, "lab", "a.exe")
    start(gw, labs, "lab2", "b.exe")
    before = {p: gw.session_status(p)["backends"]["x64"]["epoch"] for p in ("lab", "lab2")}
    labs["lab"].servers["x64"].stop()  # the kill below takes the plugin down with the process
    out = gw.debugger_restart(profile="lab")
    assert out["epoch"] == before["lab"] + 1 and out["profile"] == "lab"
    assert gw.session_status("lab2")["backends"]["x64"]["epoch"] == before["lab2"]
    assert labs["lab"].launches == ["x64"] and labs["lab2"].launches == []  # lab2's debugger untouched
    # a VM revert bumps only the reverted profile's epochs
    job = gw.session_status("lab")["job"]["job_id"]
    gw.analysis_collect(job)
    gw.analysis_finish(job)
    assert gw.session_status("lab")["backends"]["x64"]["epoch"] == before["lab"] + 2
    assert gw.session_status("lab2")["backends"]["x64"]["epoch"] == before["lab2"]


def test_a_vm_down_in_one_profile_leaves_the_other_usable(labs):
    gw = labs.gateway()
    start(gw, labs, "lab2", "b.exe")
    labs["lab"].vm.power = PowerState.OFF
    st = gw.session_status()
    assert st["profiles"]["lab"]["vm"]["power"] == "off"
    assert st["profiles"]["lab2"]["backends"]["x64"]["health"] == "HEALTHY"
    assert gw.call_mirrored("GetDebugState")["profile"] == "lab2"


# ── routing of mirrored and debugger_* tools ────────────────────────
def test_analysis_start_makes_its_profile_the_session_target(labs):
    gw = labs.gateway()
    start(gw, labs, "lab", "a.exe")
    start(gw, labs, "lab2", "b.exe")
    out = gw.call_mirrored("SetBreakpoint", {"address": "0x401000"})
    assert out["profile"] == "lab2" and out["backend_id"] == "x64"
    assert "profile=lab2" in out["texts"][-1]
    assert calls(labs, "lab2", "SetBreakpoint") == 1 and calls(labs, "lab", "SetBreakpoint") == 0


def test_debugger_select_with_a_profile_switches_the_target(labs):
    gw = labs.gateway()
    start(gw, labs, "lab", "a.exe")
    start(gw, labs, "lab2", "b.exe")
    sel = gw.debugger_select(profile="lab")
    assert sel["profile"] == "lab" and sel["selected"] == "x64"
    out = gw.call_mirrored("SetBreakpoint", {"address": "0x401000"})
    assert out["profile"] == "lab" and calls(labs, "lab", "SetBreakpoint") == 1
    assert calls(labs, "lab2", "SetBreakpoint") == 0
    assert gw.debugger_call("GetDebugState")["profile"] == "lab"


def test_debugger_select_needs_a_backend_or_a_profile(labs):
    with pytest.raises(InvalidArgument):
        labs.gateway().debugger_select()


def test_debugger_select_refuses_unknown_profiles_and_backends(labs):
    gw = labs.gateway()
    with pytest.raises(GatewayError) as ei:
        gw.debugger_select(profile="nope")
    assert ei.value.code == "CONFIG_INVALID"
    with pytest.raises(InvalidArgument):
        gw.debugger_select("arm64", profile="lab")


def test_two_live_jobs_without_a_target_refuse_mirrored_calls(labs):
    gw = labs.gateway()
    with client_session("one"):
        a = start(gw, labs, "lab", "a.exe")
    with client_session("two"):
        b = start(gw, labs, "lab2", "b.exe")
    with client_session("three"), pytest.raises(TargetAmbiguous) as ei:
        gw.call_mirrored("SetBreakpoint", {"address": "0x401000"})
    err = ei.value
    assert isinstance(err, StateViolation) and err.code == "TARGET_AMBIGUOUS"
    assert err.next_tool == "debugger_select"
    assert {j["job_id"] for j in err.details["active_jobs"]} == {a["job_id"], b["job_id"]}
    assert {j["profile"] for j in err.details["active_jobs"]} == {"lab", "lab2"}
    assert "debugger_select(profile=" in err.hint
    assert calls(labs, "lab", "SetBreakpoint") == calls(labs, "lab2", "SetBreakpoint") == 0
    # the sessions that started the jobs keep their own targets
    with client_session("one"):
        assert gw.call_mirrored("GetDebugState")["profile"] == "lab"
    with client_session("two"):
        assert gw.call_mirrored("GetDebugState")["profile"] == "lab2"
    # an explicit profile always works, and selecting one ends the refusal for that session
    with client_session("three"):
        assert gw.debugger_call("GetDebugState", profile="lab2")["profile"] == "lab2"
        with pytest.raises(TargetAmbiguous):
            gw.debugger_restart()
        gw.debugger_select(profile="lab")
        assert gw.call_mirrored("GetDebugState")["profile"] == "lab"


def test_a_single_live_job_is_followed_only_by_reading_tools(labs):
    """Another session's only live job is where its mirrored calls and reads go, but collecting,
    finishing (a revert) and uploading into it need job_id, a target or a default profile."""
    gw = labs.gateway()
    with client_session("one"):
        b = start(gw, labs, "lab2", "b.exe")
    with client_session("two"):
        out = gw.call_mirrored("GetDebugState")
        assert out["profile"] == "lab2"
        assert gw.static_rebase("0x401000", direction="runtime_to_rva")["job_id"] == b["job_id"]
        assert gw.analysis_report()["job_id"] == b["job_id"]
        for call in (gw.analysis_collect, gw.analysis_finish, gw.static_export_annotations,
                     lambda: gw.static_import_annotations([{"rva": "0x10", "name": "f"}], module="b.exe"),
                     lambda: gw.file_download(f"C:\\mcp\\jobs\\{b['job_id']}\\out\\x.bin"),
                     lambda: gw.file_upload(str(labs["lab2"].sample("extra.bin")))):
            with pytest.raises(TargetAmbiguous):
                call()
        assert gw.analysis_collect(b["job_id"])["job_id"] == b["job_id"]  # naming the job is enough
        with pytest.raises(TargetAmbiguous):
            gw.analysis_finish()  # collected now, but still another client's job
    assert reverts(labs, "lab2") == 1 and gw.get_job(b["job_id"])["state"] == JobState.COLLECTED


def test_job_changing_tools_without_job_id_use_the_default_profile_not_another_job(tmp_path):
    labs = make_labs(tmp_path, default_profile="lab")
    try:
        gw = labs.gateway()
        with client_session("one"):
            b = start(gw, labs, "lab2", "b.exe")
            gw.analysis_collect()
        with client_session("nine"):
            with pytest.raises(StateViolation) as ei:
                gw.analysis_finish()
            assert not isinstance(ei.value, TargetAmbiguous) and ei.value.next_tool == "analysis_start"
        assert reverts(labs, "lab2") == 1 and gw.get_job(b["job_id"])["state"] == JobState.COLLECTED
    finally:
        labs.close()


def test_without_jobs_or_a_default_the_gateway_asks_which_vm(labs):
    gw = labs.gateway()
    with pytest.raises(TargetAmbiguous) as ei:
        gw.call_mirrored("GetDebugState")
    assert set(ei.value.details["profiles"]) == {"lab", "lab2"}
    with pytest.raises(TargetAmbiguous):
        gw.vm_snapshot_revert()
    assert reverts(labs, "lab") == reverts(labs, "lab2") == 0


def test_without_jobs_the_default_profile_is_used(tmp_path):
    labs = make_labs(tmp_path, default_profile="lab2")
    try:
        gw = labs.gateway()
        assert gw.call_mirrored("GetDebugState")["profile"] == "lab2"
        assert calls(labs, "lab2", "GetDebugState") == 1 and calls(labs, "lab", "GetDebugState") == 0
    finally:
        labs.close()


def test_vm_tools_follow_the_session_target_and_refuse_when_ambiguous(labs):
    gw = labs.gateway()
    with client_session("one"):
        start(gw, labs, "lab", "a.exe")
    with client_session("two"):
        start(gw, labs, "lab2", "b.exe")
    with client_session("one"):
        shot = gw.vm_screenshot()
        assert shot["job_id"] == gw.session_status("lab")["job"]["job_id"]
        assert sum(1 for c in labs["lab"].vm.calls if c[0] == "screenshot") == 1
        assert not [c for c in labs["lab2"].vm.calls if c[0] == "screenshot"]
    with client_session("three"), pytest.raises(TargetAmbiguous):
        gw.vm_screenshot()


def test_vm_changing_tools_never_pick_a_vm_from_another_sessions_job(labs):
    """Only reading tools and job work follow the only live job; a revert, power change or snapshot
    without a profile needs the session's target or a default profile."""
    gw = labs.gateway()
    with client_session("one"):
        b = start(gw, labs, "lab2", "b.exe")
        gw.analysis_collect()  # collected: the policy would let a revert of lab2 through
    with client_session("nine"):
        for call in (gw.vm_snapshot_revert, lambda: gw.vm_power("stop"),
                     lambda: gw.vm_snapshot_take("gw-x"), lambda: gw.vm_snapshot_delete("gw-x")):
            with pytest.raises(TargetAmbiguous):
                call()
        assert gw.vm_screenshot()["profile"] == "lab2"  # observing follows the live job
    assert reverts(labs, "lab2") == 1 and labs["lab2"].vm.power == PowerState.RUNNING
    assert gw.get_job(b["job_id"])["state"] == JobState.COLLECTED


def test_vm_changing_tools_without_a_target_use_the_default_profile(tmp_path):
    labs = make_labs(tmp_path, default_profile="lab")
    try:
        gw = labs.gateway()
        with client_session("one"):
            start(gw, labs, "lab2", "b.exe")
            gw.analysis_collect()
        with client_session("nine"):
            assert gw.vm_snapshot_revert()["snapshot"] == "MCP_CLEAN"
        assert reverts(labs, "lab") == 1 and reverts(labs, "lab2") == 1
    finally:
        labs.close()


def test_analysis_start_without_profile_is_refused_while_several_vms_have_jobs(tmp_path):
    labs = make_labs(tmp_path, names=("lab", "lab2", "lab3"), default_profile="lab3")
    try:
        gw = labs.gateway()
        with client_session("one"):
            start(gw, labs, "lab", "a.exe")
        with client_session("two"):
            start(gw, labs, "lab2", "b.exe")
        with client_session("nine"), pytest.raises(TargetAmbiguous) as ei:
            gw.analysis_start(str(labs["lab3"].sample("c.exe")))
        assert len(ei.value.details["active_jobs"]) == 2
        assert reverts(labs, "lab3") == 0
        with client_session("nine"):  # naming the VM is always enough
            assert start(gw, labs, "lab3", "c.exe")["profile"] == "lab3"
    finally:
        labs.close()


def test_polling_analysis_finish_answers_only_for_the_finish_this_session_started(labs):
    gw = labs.gateway()
    with client_session("one"):
        a = start(gw, labs, "lab", "a.exe")
        gw.analysis_collect()
    with client_session("two"):
        b = start(gw, labs, "lab2", "b.exe")
    entered, release = threading.Event(), threading.Event()
    original = labs["lab"].vm.revert_snapshot

    def slow_revert(name: str) -> None:
        entered.set()
        release.wait(10)
        original(name)

    labs["lab"].vm.revert_snapshot = slow_revert  # type: ignore[method-assign]
    with client_session("one"):
        assert gw.analysis_finish(wait_s=0)["state"] == "in_progress" and entered.wait(5)
    try:
        with client_session("nine"), pytest.raises(TargetAmbiguous):
            gw.analysis_finish()  # two live jobs (lab REVERTING, lab2 ANALYZING); not lab's finish
    finally:
        release.set()
    assert gw._ops(gw.runtime("lab")).wait_idle(10)
    with client_session("nine"), pytest.raises(TargetAmbiguous) as ei:
        gw.analysis_finish()  # neither lab's finished job nor lab2's live one: it named no job
    assert [j["job_id"] for j in ei.value.details["active_jobs"]] == [b["job_id"]]
    with client_session("one"):  # the session that started it gets the outcome
        done = gw.analysis_finish()
        assert done["job_id"] == a["job_id"] and done["state"] == JobState.DONE
    assert gw.get_job(b["job_id"])["state"] == JobState.ANALYZING


def test_selecting_the_same_vm_again_keeps_its_backend(tmp_path):
    labs = make_labs(tmp_path, backends=("x64", "x32"))
    try:
        gw = labs.gateway()
        gw.debugger_select("x32", profile="lab2")
        assert gw.debugger_select(profile="lab2")["selected"] == "x32"
        assert gw.debugger_select(profile="lab")["selected"] == "x64"
    finally:
        labs.close()


def test_screenshots_without_a_job_name_their_vm(labs):
    gw = labs.gateway()
    one, two = gw.vm_screenshot(profile="lab"), gw.vm_screenshot(profile="lab2")
    assert (one["profile"], two["profile"]) == ("lab", "lab2") and one["job_id"] is None
    assert "-lab-" in one["host_path"].rsplit("/", 1)[-1] and "-lab2-" in two["host_path"].rsplit("/", 1)[-1]
    assert sum(1 for c in labs["lab"].vm.calls if c[0] == "screenshot") == 1
    assert sum(1 for c in labs["lab2"].vm.calls if c[0] == "screenshot") == 1


def test_the_backend_selection_is_per_profile_and_session(tmp_path):
    labs = make_labs(tmp_path, backends=("x64", "x32"))
    try:
        gw = labs.gateway()
        with client_session("one"):
            sel = gw.debugger_select("x32", profile="lab2")
            assert sel["profile"] == "lab2" and sel["selected"] == "x32"
            out = gw.call_mirrored("GetDebugState")
            assert (out["profile"], out["backend_id"]) == ("lab2", "x32")
        with client_session("two"):
            gw.debugger_select(profile="lab2")
            assert gw.call_mirrored("GetDebugState")["backend_id"] == "x64"
    finally:
        labs.close()


# ── job-scoped tools ────────────────────────────────────────────────
def test_job_tools_use_the_profile_of_the_job_they_are_given(labs):
    gw = labs.gateway()
    a = start(gw, labs, "lab", "a.exe")
    start(gw, labs, "lab2", "b.exe")  # the session target is lab2 now
    reb = gw.static_rebase("0x401000", direction="runtime_to_rva", job_id=a["job_id"])
    assert reb["job_id"] == a["job_id"]
    lists_before = calls(labs, "lab", "ListModules")
    col = gw.analysis_collect(a["job_id"])
    assert col["job_id"] == a["job_id"] and calls(labs, "lab", "ListModules") > lists_before
    assert gw.analysis_finish(a["job_id"])["state"] == JobState.DONE
    assert reverts(labs, "lab2") == 1


def test_job_tools_without_job_id_use_the_targets_job_or_refuse(labs):
    gw = labs.gateway()
    with client_session("one"):
        a = start(gw, labs, "lab", "a.exe")
    with client_session("two"):
        b = start(gw, labs, "lab2", "b.exe")
        assert gw.static_rebase("0x401000", direction="runtime_to_rva")["job_id"] == b["job_id"]
    with client_session("one"):
        assert gw.analysis_collect()["job_id"] == a["job_id"]
    with client_session("three"):
        for call in (gw.analysis_collect, gw.analysis_finish, gw.static_export_annotations,
                     lambda: gw.static_rebase("0x401000", direction="runtime_to_rva"),
                     lambda: gw.file_download("C:\\mcp\\jobs\\x\\out\\a.bin")):
            with pytest.raises(TargetAmbiguous):
                call()
    assert gw.get_job(a["job_id"])["state"] == JobState.COLLECTED
    assert gw.get_job(b["job_id"])["state"] == JobState.ANALYZING


def test_a_target_without_a_job_does_not_borrow_another_profiles_job(labs):
    gw = labs.gateway()
    with client_session("one"):
        b = start(gw, labs, "lab2", "b.exe")
    with client_session("two"):
        gw.debugger_select(profile="lab")
        with pytest.raises(StateViolation) as ei:
            gw.analysis_collect()
        assert ei.value.code == "STATE_VIOLATION" and b["job_id"] in (ei.value.hint or "")


def test_analysis_finish_polling_without_job_id_finds_its_profiles_finish(labs):
    gw = labs.gateway()
    with client_session("one"):
        a = start(gw, labs, "lab", "a.exe")
        gw.analysis_collect()
    with client_session("two"):
        b = start(gw, labs, "lab2", "b.exe")
    with client_session("one"):
        out = gw.analysis_finish()
        assert out["job_id"] == a["job_id"] and out["state"] == JobState.DONE
    assert gw.get_job(b["job_id"])["state"] == JobState.ANALYZING


# ── status, instructions, tool list, warm-up ────────────────────────
def test_session_status_without_profile_lists_every_profile(labs):
    gw = labs.gateway()
    with client_session("one"):
        b = start(gw, labs, "lab2", "b.exe")
        st = gw.session_status()
    assert st["profile"] is None and set(st["profiles"]) == {"lab", "lab2"}
    lab, lab2 = st["profiles"]["lab"], st["profiles"]["lab2"]
    assert lab["vm"]["power"] == "running" and lab["job"] is None
    assert lab2["job"]["job_id"] == b["job_id"] and lab2["job"]["state"] == "ANALYZING"
    assert lab2["backends"]["x64"]["health"] == "HEALTHY"
    assert set(lab2["backends"]["x64"]) >= {"health", "epoch", "acked_epoch", "selected"}
    assert "health_details" not in lab2["backends"]["x64"]  # compact
    assert st["target"] == {"profile": "lab2", "backend": None, "source": "analysis_start"}
    assert st["active_jobs"] == [{"job_id": b["job_id"], "profile": "lab2", "state": "ANALYZING",
                                  "backend_id": "x64"}]
    # with a profile: only that one, in the full single-profile form
    one = gw.session_status("lab2")
    assert one["profile"] == "lab2" and one["job"]["job_id"] == b["job_id"] and "profiles" not in one


def test_session_status_without_profile_acknowledges_only_the_vm_this_session_works_on(labs):
    """Another client's VM keeps its restart guard: its client still learns of the restart."""
    gw = labs.gateway()
    with client_session("one"):
        start(gw, labs, "lab", "a.exe")
    with client_session("two"):
        start(gw, labs, "lab2", "b.exe")
    for p in ("lab", "lab2"):
        gw.runtime(p).supervisor.bump_epoch("x64", "test restart")
    with client_session("one"):
        st = gw.session_status()
        lab2 = st["profiles"]["lab2"]["backends"]["x64"]
        assert lab2["acked_epoch"] < lab2["epoch"]
        assert gw.call_mirrored("SetBreakpoint", {"address": "0x401000"})["profile"] == "lab"
        with pytest.raises(BackendRestarted) as ei:
            gw.debugger_call("SetBreakpoint", {"address": "0x401000"}, profile="lab2")
        assert ei.value.details["profile"] == "lab2" and "session_status(profile='lab2')" in ei.value.hint
    with client_session("two"):
        with pytest.raises(BackendRestarted):
            gw.call_mirrored("SetBreakpoint", {"address": "0x401000"})
        gw.session_status()
        assert gw.call_mirrored("SetBreakpoint", {"address": "0x401000"})["profile"] == "lab2"


def test_session_status_without_a_routed_vm_acknowledges_nothing(labs):
    gw = labs.gateway()
    with client_session("one"):
        start(gw, labs, "lab", "a.exe")
    with client_session("two"):
        start(gw, labs, "lab2", "b.exe")
    for p in ("lab", "lab2"):
        gw.runtime(p).supervisor.bump_epoch("x64", "test restart")
    with client_session("three"):
        st = gw.session_status()
        assert st["routing"]["profile"] is None
        assert all(e["backends"]["x64"]["acked_epoch"] < e["backends"]["x64"]["epoch"]
                   for e in st["profiles"].values())
        gw.session_status("lab2")  # an explicit profile acknowledges that VM
        assert gw.debugger_call("SetBreakpoint", {"address": "0x1"}, profile="lab2")["is_error"] is False


def test_session_status_reports_a_profile_that_cannot_be_built(labs):
    gw = labs.gateway()

    def broken(name):
        if name == "lab":
            raise GatewayError("vmrun is missing")
        return labs.runtime(name)

    gw._factory = broken
    st = gw.session_status()
    assert st["profiles"]["lab"]["error"]["code"] == "GATEWAY_ERROR"
    assert st["profiles"]["lab2"]["vm"]["power"] == "running"


def test_instructions_name_the_multi_vm_rule(labs):
    text = labs.gateway().instructions()
    assert "lab, lab2" in text and "debugger_select(profile=" in text and "TARGET_AMBIGUOUS" in text


def test_single_profile_instructions_have_no_multi_vm_rule(tmp_path):
    labs = make_labs(tmp_path, names=("solo",))
    try:
        assert "debugger_select(profile=" not in labs.gateway().instructions()
    finally:
        labs.close()


def test_instructions_carry_the_plugin_notes_of_every_profile_once(labs):
    gw = labs.gateway()
    start(gw, labs, "lab", "a.exe")
    start(gw, labs, "lab2", "b.exe")
    text = gw.instructions()
    assert text.count("ALWAYS call GetDebugState first") == 1  # the same plugin build in both VMs
    assert "lab/x64" in text and "lab2/x64" in text


V110_TOOLS = {"GetServerInfo", "SetArtifactDir", "ProbeFile"}


def test_mirrored_tool_list_covers_every_profile(tmp_path):
    """One tools/list for every VM: a tool that only the newer plugin build has is listed too
    (a call to a VM whose plugin lacks it is answered by that plugin)."""
    labs = make_labs(tmp_path, names=("old", "new"), overrides={"new": {"plugin_version": "1.10"}})
    try:
        gw = labs.gateway()
        assert not V110_TOOLS & {t.name for t in gw.list_mirrored_tools()}  # control: nothing learnt yet
        gw.warm_up(timeout_s=5)
        names = [t.name for t in gw.list_mirrored_tools()]
        assert V110_TOOLS <= set(names) and "LoadBinary" in names
        assert len(names) == len(set(names))
    finally:
        labs.close()


def test_warm_up_learns_every_profile(labs):
    out = labs.gateway().warm_up(timeout_s=5)
    assert set(out["profiles"]) == {"lab", "lab2"}
    for p in ("lab", "lab2"):
        assert out["profiles"][p]["backends"]["x64"]["source"] == "live", out
        assert labs[p].servers["x64"].requests  # each VM's plugin was asked


# ── through the HTTP front-end: one target per MCP session ──────────
def test_each_http_session_routes_to_the_vm_it_started(labs, tmp_path):
    """Two MCP clients of one gateway, one VM each: each session's mirrored calls reach its own
    VM, and a third session without a target is refused."""
    gw = labs.gateway()
    asgi = http_server.build_asgi_app(gw, cfg(), audit_dir=tmp_path / "_audit", environ=ENV)

    def call(c, sid, name, arguments):
        res = rpc(c, ADMIN_TOKEN, sid, "tools/call", {"name": name, "arguments": arguments})["result"]
        return res, [item["text"] for item in res["content"]]

    with TestClient(asgi, base_url=BASE, client=LOCAL) as c:
        one, two, three = (open_session(c, ADMIN_TOKEN) for _ in range(3))
        for sid, profile in ((one, "lab"), (two, "lab2")):
            sample = str(labs[profile].sample(f"{profile}.exe"))
            res, texts = call(c, sid, "analysis_start", {"sample_path": sample, "profile": profile})
            assert res["isError"] is False and json.loads(texts[0])["state"] == "ANALYZING", texts
        for sid, profile in ((one, "lab"), (two, "lab2"), (one, "lab")):
            res, texts = call(c, sid, "SetBreakpoint", {"address": "0x401000"})
            assert res["isError"] is False and f"profile={profile}" in texts[-1], texts
        res, texts = call(c, three, "SetBreakpoint", {"address": "0x401000"})
        assert res["isError"] is True and json.loads(texts[0])["code"] == "TARGET_AMBIGUOUS"
    assert calls(labs, "lab", "SetBreakpoint") == 2 and calls(labs, "lab2", "SetBreakpoint") == 1


# ── the same VM under two profiles ──────────────────────────────────
def test_two_profiles_of_the_same_vm_never_run_jobs_at_once(labs):
    labs.set_profile("lab2", vmx=labs.config.profile("lab").vmx)
    gw = labs.gateway()
    a = start(gw, labs, "lab", "a.exe")
    with pytest.raises(StateViolation) as ei:
        start(gw, labs, "lab2", "b.exe")
    assert a["job_id"] in ei.value.message and "lab" in ei.value.message
    with pytest.raises(StateViolation):
        gw.vm_snapshot_revert(profile="lab2")
    assert reverts(labs, "lab2") == 0


def test_two_profiles_of_the_same_vm_cannot_start_jobs_at_the_same_moment(labs):
    """The check of the other profile's job and the creation of this one's must not interleave:
    the profiles of one VM share one operation runner."""
    labs.set_profile("lab2", vmx=labs.config.profile("lab").vmx)
    gw = labs.gateway()
    entered, release = threading.Event(), threading.Event()
    original = labs["lab"].vm.isolation_report

    def slow_isolation():
        entered.set()
        release.wait(10)
        return original()

    labs["lab"].vm.isolation_report = slow_isolation  # type: ignore[method-assign]
    assert start(gw, labs, "lab", "a.exe", wait_s=0)["state"] == "in_progress" and entered.wait(5)
    try:
        with pytest.raises(StateViolation):
            start(gw, labs, "lab2", "b.exe")
        with pytest.raises(StateViolation):
            gw.vm_snapshot_revert(profile="lab2")
    finally:
        release.set()
    assert gw._ops(gw.runtime("lab")).wait_idle(10)
    assert [j["profile"] for j in gw.list_jobs()["jobs"] if j["state"] != "FAILED"] == ["lab"]
    assert reverts(labs, "lab2") == 0


def same_vm(labs) -> None:
    """lab2 names lab's .vmx: two profiles of one VM (one x64dbg in it)."""
    labs.set_profile("lab2", vmx=labs.config.profile("lab").vmx)


def test_a_restart_through_the_other_profile_of_the_vm_never_kills_its_jobs_debugger(labs):
    same_vm(labs)
    gw = labs.gateway()
    a = start(gw, labs, "lab", "a.exe")
    labs["lab2"].servers["x64"].stop()
    with client_session("two"), pytest.raises(StateViolation) as ei:
        gw.debugger_restart(profile="lab2")
    assert a["job_id"] in ei.value.message and "debugger_select(profile='lab')" in (ei.value.hint or "")
    assert labs["lab2"].guest.calls_of("kill_process") == [] and labs["lab2"].launches == []
    assert gw.get_job(a["job_id"])["state"] == JobState.ANALYZING


def test_a_restart_rechecks_the_other_profile_right_before_the_kill(labs):
    """A job the other profile creates after the first check still stops the kill."""
    same_vm(labs)
    gw = labs.gateway()
    labs["lab2"].servers["x64"].stop()
    original = labs["lab2"].guest.list_processes

    def job_appears_meanwhile():
        if not gw.list_jobs()["jobs"]:
            gw._jobs().create("lab", "C:\\mcp\\jobs")  # as if lab's analysis_start got there first
        return original()

    labs["lab2"].guest.list_processes = job_appears_meanwhile  # type: ignore[method-assign]
    with pytest.raises(StateViolation):
        gw.debugger_restart(profile="lab2")
    assert labs["lab2"].guest.calls_of("kill_process") == []


def test_debugger_calls_through_the_other_profile_of_the_vm_only_read(labs):
    """The other profile's debugger is the job's debugger: mutating tools only via the job's
    profile, where the job's epoch guard and crash-loop count apply."""
    same_vm(labs)
    gw = labs.gateway()
    a = start(gw, labs, "lab", "a.exe")
    with client_session("two"):
        for call in (lambda: gw.debugger_call("SetBreakpoint", {"address": "0x401000"}, profile="lab2"),
                     lambda: gw.debugger_call("NoSuchTool", {}, profile="lab2")):  # unknown: mutating
            with pytest.raises(StateViolation) as ei:
                call()
            assert a["job_id"] in ei.value.message and ei.value.next_tool == "debugger_select"
        assert calls(labs, "lab2", "SetBreakpoint") == 0
        gw.debugger_select(profile="lab2")
        with pytest.raises(StateViolation):
            gw.call_mirrored("run")
        assert gw.debugger_call("GetDebugState", profile="lab2")["is_error"] is False  # read-only
    with client_session("one"):
        assert gw.call_mirrored("SetBreakpoint", {"address": "0x401000"})["profile"] == "lab"


def test_a_revert_starts_a_new_epoch_in_every_profile_of_the_vm(labs):
    same_vm(labs)
    gw = labs.gateway()
    before = gw.session_status("lab2")["backends"]["x64"]["epoch"]  # lab2's runtime is built
    gw.vm_snapshot_revert(profile="lab")
    assert gw.session_status("lab2")["backends"]["x64"]["epoch"] == before + 1
    assert gw.session_status("lab")["backends"]["x64"]["epoch"] == before + 1


def test_a_revert_bumps_the_other_profile_of_the_vm_before_any_ack(labs):
    same_vm(labs)
    gw = labs.gateway()
    gw.debugger_call("GetDebugState", profile="lab2")  # lab2 known, epoch acknowledged
    gw.vm_snapshot_revert(profile="lab")
    with pytest.raises(BackendRestarted):
        gw.debugger_call("SetBreakpoint", {"address": "0x1"}, profile="lab2")


def test_the_status_of_one_profile_neither_shows_nor_consumes_the_other_profiles_operation(labs):
    same_vm(labs)
    gw = labs.gateway()
    started = start(gw, labs, "lab", "a.exe", wait_s=0)
    assert started["state"] == "in_progress"
    assert gw._ops(gw.runtime("lab")).wait_idle(10)
    other = gw.session_status("lab2")["operation"]
    assert other["profile"] == "lab" and "result" not in other and "lab" in other["note"]
    replay = start(gw, labs, "lab", "a.exe", wait_s=0)  # repeating the call still gets the outcome
    assert replay["job_id"] == gw.session_status("lab")["job"]["job_id"]
    assert gw.session_status("lab")["operation"]["profile"] == "lab"


def test_the_other_profile_of_the_vm_never_joins_this_profiles_operation(labs):
    same_vm(labs)
    gw = labs.gateway()
    entered, release = threading.Event(), threading.Event()
    original = labs["lab"].vm.revert_snapshot

    def slow_revert(name: str) -> None:
        entered.set()
        release.wait(10)
        original(name)

    labs["lab"].vm.revert_snapshot = slow_revert  # type: ignore[method-assign]
    assert gw.vm_snapshot_revert(profile="lab", wait_s=0)["state"] == "in_progress" and entered.wait(5)
    try:
        with pytest.raises(StateViolation):  # same op and key, other profile: refused, not joined
            gw.vm_snapshot_revert(profile="lab2", wait_s=0)
    finally:
        release.set()
    assert gw._ops(gw.runtime("lab")).wait_idle(10)


def test_a_finish_pending_for_another_vm_never_answers_a_finish_of_the_target(labs):
    gw = labs.gateway()
    a = start(gw, labs, "lab", "a.exe")
    gw.analysis_collect()
    assert gw.analysis_finish(wait_s=0)["state"] == "in_progress"
    assert gw._ops(gw.runtime("lab")).wait_idle(10)  # its outcome is not delivered yet
    b = start(gw, labs, "lab2", "b.exe")  # the target is lab2 now
    gw.analysis_collect()
    done = gw.analysis_finish()
    assert done["job_id"] == b["job_id"] and done["state"] == JobState.DONE
    assert gw.get_job(a["job_id"])["state"] == JobState.DONE


def test_a_forgotten_target_is_refused_not_guessed(labs, monkeypatch):
    monkeypatch.setattr(app_module, "MAX_SESSION_TARGETS", 2)
    gw = labs.gateway()
    with client_session("old"):
        start(gw, labs, "lab2", "b.exe")
    for other in ("a", "b"):
        with client_session(other):
            gw.debugger_select(profile="lab")
    with client_session("old"):
        with pytest.raises(TargetAmbiguous) as ei:
            gw.call_mirrored("SetBreakpoint", {"address": "0x401000"})
        assert "forgot" in ei.value.message and ei.value.next_tool == "debugger_select"
        assert gw.session_status()["routing"]["profile"] is None
        gw.debugger_select(profile="lab2")
        assert gw.call_mirrored("GetDebugState")["profile"] == "lab2"
    assert calls(labs, "lab", "SetBreakpoint") == calls(labs, "lab2", "SetBreakpoint") == 0


def test_a_forgotten_target_with_a_single_profile_needs_no_choice(tmp_path, monkeypatch):
    monkeypatch.setattr(app_module, "MAX_SESSION_TARGETS", 1)
    labs = make_labs(tmp_path, names=("solo",))
    try:
        gw = labs.gateway()
        with client_session("old"):
            gw.debugger_select(profile="solo")
        with client_session("new"):
            gw.debugger_select(profile="solo")
        with client_session("old"):
            assert gw.call_mirrored("GetDebugState")["profile"] == "solo"
    finally:
        labs.close()


def test_analysis_report_follows_the_session_target(tmp_path):
    labs = make_labs(tmp_path, default_profile="lab")
    try:
        gw = labs.gateway()
        with client_session("one"):
            b = start(gw, labs, "lab2", "b.exe")
            assert gw.analysis_report()["job_id"] == b["job_id"]
        with client_session("two"):  # no target: the only live job (reading only)
            assert gw.analysis_report()["job_id"] == b["job_id"]
            gw.debugger_select(profile="lab")
            with pytest.raises(StateViolation):
                gw.analysis_report()  # lab has no jobs yet
    finally:
        labs.close()


def test_doctor_without_profile_checks_every_vm_when_there_is_no_default(labs):
    rep = labs.gateway().doctor()
    names = [c["name"] for c in rep["checks"]]
    assert rep["profile"] is None and set(rep["profiles"]) == {"lab", "lab2"}
    assert "lab: vmx" in names and "lab2: vmx" in names
    assert names.count("host_jobs_root") == 1 and names.count("static_tools") == 1
    assert rep["ok"] == all(c["ok"] for c in rep["checks"])


def test_doctor_without_profile_uses_the_default_when_there_is_one(tmp_path):
    labs = make_labs(tmp_path, default_profile="lab2")
    try:
        rep = labs.gateway().doctor()
        assert rep["profile"] == "lab2" and "profiles" not in rep
    finally:
        labs.close()


def test_a_vm_whose_job_state_is_unknown_counts_as_busy(labs):
    """Fail closed: a job directory that cannot be read may hold a live job, so it can make a call
    ambiguous but never leaves another VM's job as "the only one"."""
    gw = labs.gateway()
    with client_session("one"):
        start(gw, labs, "lab2", "b.exe")
    gw.close()
    corrupt = labs.tmp / "jobs" / "20261123-000000-abcdef"
    corrupt.mkdir()
    (corrupt / "state.json").write_text("{not json", encoding="utf-8")
    (corrupt / "intent.log").write_text(json.dumps({"op": "create", "profile": "lab", "job_id": corrupt.name})
                                        + "\n", encoding="utf-8")
    gw = labs.gateway()
    with client_session("two"), pytest.raises(TargetAmbiguous) as ei:
        gw.call_mirrored("GetDebugState")
    states = {j["profile"]: j["state"] for j in ei.value.details["active_jobs"]}
    assert states["lab"] == "UNKNOWN" and states["lab2"] == "ANALYZING"


# ── front-end session keys ──────────────────────────────────────────
class _Req:
    def __init__(self, headers: dict[str, str]) -> None:
        self.headers = headers


class _Ctx:
    def __init__(self, request: object, protocol_version: str) -> None:
        self.request = request
        self.protocol_version = protocol_version


def test_session_keys_trust_only_sessions_the_sdk_validated():
    sid = {"mcp-session-id": "abc123"}
    assert mcp_server.session_key("analyze", _Ctx(None, "2025-06-18")) is None  # stdio / in memory
    assert mcp_server.session_key("analyze", _Ctx(_Req(sid), "2025-06-18")) == "http:analyze:abc123"
    assert mcp_server.session_key("admin", _Ctx(_Req(sid), "2025-06-18")) == "http:admin:abc123"
    # the 2026 protocol has no sessions: its header is the client's own word and keeps nothing
    assert mcp_server.session_key("analyze", _Ctx(_Req(sid), "2026-07-28")) == STATELESS_SESSION
    assert mcp_server.session_key("analyze", _Ctx(_Req({}), "2025-06-18")) == STATELESS_SESSION


def test_a_stateless_client_keeps_no_target(labs):
    gw = labs.gateway()
    with client_session("one"):
        start(gw, labs, "lab", "a.exe")
    with client_session(STATELESS_SESSION):
        start(gw, labs, "lab2", "b.exe")
        sel = gw.debugger_select(profile="lab2")
        assert "not kept" in sel["scope"]
        with pytest.raises(TargetAmbiguous):
            gw.call_mirrored("GetDebugState")
        assert gw.debugger_call("GetDebugState", profile="lab2")["profile"] == "lab2"
    with client_session("one"):
        assert gw.call_mirrored("GetDebugState")["profile"] == "lab"
