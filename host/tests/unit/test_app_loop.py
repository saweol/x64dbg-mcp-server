"""End-to-end analysis loop through app.Gateway on the fake lab (plan section 7)."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

import pytest

from tests.fakes.fake_runtime import EXE, GUEST_ROOT, make_lab
from x64dbg_vm_gateway.app import Gateway
from x64dbg_vm_gateway.app_api import GatewayApp
from x64dbg_vm_gateway.contracts import JobState, Snapshot
from x64dbg_vm_gateway.errors import StateViolation

POSIX = os.name == "posix"
STEP_NAMES = ["check_job", "isolation", "create_job", "copy_sample", "prepare_vm", "debugger", "upload",
              "load"]


@pytest.fixture
def lab(tmp_path):
    lab = make_lab(tmp_path)
    yield lab
    lab.close()


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def test_gateway_satisfies_the_facade_protocol(lab):
    assert isinstance(lab.gateway(), GatewayApp)


def test_full_loop_start_mirror_collect_finish(lab):
    gw = lab.gateway()
    sample = lab.sample("calc.exe")
    digest = sha(sample)

    # ── analysis_start ─────────────────────────────────────────────
    res = gw.analysis_start(str(sample))
    job_id = res["job_id"]
    assert res["state"] == JobState.ANALYZING
    assert res["backend_id"] == "x64" and res["arch"] == "x64"
    assert res["sample"]["sha256"] == digest and res["sample"]["kind"] == "exe"
    guest_path = res["sample"]["guest_path"]
    assert guest_path.lower() == f"{GUEST_ROOT}\\{job_id}\\in\\{digest[:12]}.exe".lower()
    assert [s["name"] for s in res["steps"]] == STEP_NAMES
    assert all(s["ok"] for s in res["steps"]) and all(isinstance(s["ms"], int | float) for s in res["steps"])
    assert any("system breakpoint" in t for t in res["debugger_state"])
    assert res["epoch"] == 1  # the revert to the clean snapshot bumped it

    # the VM went back to the clean snapshot and was resumed (revert leaves it suspended)
    assert ("revert_snapshot", ("MCP_CLEAN",)) in lab.vm.calls
    assert ("start", (False,)) in lab.vm.calls
    # the sample sits in the guest under its sha12 name and was loaded + waited for
    assert lab.guest.read(guest_path) == sample.read_bytes()
    srv = lab.servers["x64"]
    assert srv.tool_calls("LoadBinary")[-1].arguments["filePath"] == guest_path
    assert srv.tool_calls("WaitForPause")[-1].arguments == {"timeoutMs": 30000}
    assert not srv.tool_calls("SetArtifactDir")  # the v1.9 tool list has no SetArtifactDir

    # host copy of the sample: input/sample.bin, private and not executable
    host_copy = Path(lab.config.jobs_root) / job_id / "input" / "sample.bin"
    assert host_copy.read_bytes() == sample.read_bytes()
    if POSIX:
        assert stat.S_IMODE(host_copy.stat().st_mode) == 0o600

    # ── mirrored calls ─────────────────────────────────────────────
    out = gw.call_mirrored("SetBreakpoint", {"address": "0x401000"})
    assert out["is_error"] is False and out["epoch"] == 1 and out["backend_id"] == "x64"
    assert out["texts"][0].startswith("<untrusted_guest_output>")
    assert out["texts"][-1].startswith("[gateway] epoch=1")
    assert srv.tool_calls("SetBreakpoint")[-1].arguments == {"address": "0x401000"}
    gen = gw.debugger_call("GetDebugState")
    assert gen["is_error"] is False

    # the sample "dumps" something into the job out dir
    lab.guest.write(f"{GUEST_ROOT}\\{job_id}\\out\\dump_401000.bin", b"MZ dumped")

    # ── analysis_collect ───────────────────────────────────────────
    col = gw.analysis_collect()
    assert col["job_id"] == job_id and col["state"] == JobState.COLLECTED and col["partial"] is False
    manifest = Path(col["manifest_path"])
    assert manifest.is_file()
    doc = json.loads(manifest.read_text())
    assert doc["module_map"]["raw"].startswith("0x00400000")
    by_name = {f["original_path"].replace("\\", "/").rsplit("/", 1)[-1]: f for f in col["files"]}
    dump = by_name["dump_401000.bin"]
    assert Path(dump["host_path"]).read_bytes() == b"MZ dumped"
    assert Path(dump["host_path"]).is_absolute()
    # v1.9: SaveDatabase without a path; the default database file is collected as an extra file
    assert srv.tool_calls("SaveDatabase")[-1].arguments == {}
    db_name = f"{digest[:12]}.exe.dd64"
    assert by_name[db_name]["status"] == "ok"
    assert Path(by_name[db_name]["host_path"]).read_bytes() == b"x64dbg database"
    assert col["screenshot"] is not None

    # ── analysis_finish ────────────────────────────────────────────
    reverts_before = sum(1 for c in lab.vm.calls if c[0] == "revert_snapshot")
    fin = gw.analysis_finish()
    assert fin["job_id"] == job_id and fin["state"] == JobState.DONE and fin["reverted"] is True
    assert sum(1 for c in lab.vm.calls if c[0] == "revert_snapshot") == reverts_before + 1
    status = gw.session_status()
    assert status["job"] is None


def test_plugin_v110_features_are_used_when_the_live_tool_list_has_them(tmp_path):
    lab = make_lab(tmp_path, plugin_version="1.10")
    try:
        gw = lab.gateway()
        sample = lab.sample("app.exe")
        digest = sha(sample)
        res = gw.analysis_start(str(sample), args="--flag", cwd="C:\\Users\\Public")
        job_root = f"{GUEST_ROOT}\\{res['job_id']}"
        srv = lab.servers["x64"]
        assert srv.tool_calls("SetArtifactDir")[-1].arguments == {"path": f"{job_root}\\out"}
        load = srv.tool_calls("LoadBinary")[-1].arguments
        assert load["filePath"] == res["sample"]["guest_path"]
        assert load["arguments"] == "--flag" and load["workingDir"] == "C:\\Users\\Public"
        col = gw.analysis_collect()
        db_path = f"{job_root}\\out\\{digest[:12]}.dd64"
        assert srv.tool_calls("SaveDatabase")[-1].arguments == {"filePath": db_path}
        names = [f["original_path"] for f in col["files"]]
        assert f"{digest[:12]}.dd64" in names  # collected with the out dir
        assert col["state"] == JobState.COLLECTED
        # the live tool list replaced the builtin one
        assert len(gw.list_mirrored_tools()) == 82
    finally:
        lab.close()


def test_working_dir_is_not_sent_to_plugins_that_do_not_know_it(lab):
    gw = lab.gateway()
    res = gw.analysis_start(str(lab.sample()), cwd="C:\\Users\\Public")
    assert "workingDir" not in lab.servers["x64"].tool_calls("LoadBinary")[-1].arguments
    assert any("workingDir" in w for w in res["warnings"])


def test_x32_sample_is_routed_to_x32dbg(tmp_path):
    lab = make_lab(tmp_path, backends=("x64", "x32"))
    try:
        gw = lab.gateway()
        res = gw.analysis_start(str(lab.sample("old.exe", machine=0x14C)))
        assert res["arch"] == "x32" and res["backend_id"] == "x32"
        assert lab.servers["x32"].tool_calls("LoadBinary")
        assert not lab.servers["x64"].tool_calls("LoadBinary")
        out = gw.call_mirrored("StepOver")
        assert out["backend_id"] == "x32"
        assert lab.servers["x32"].tool_calls("StepOver")
    finally:
        lab.close()


def test_explicit_arch_overrides_detection(tmp_path):
    lab = make_lab(tmp_path, backends=("x64", "x32"))
    try:
        res = lab.gateway().analysis_start(str(lab.sample()), arch="x32")
        assert res["backend_id"] == "x32"
    finally:
        lab.close()


def test_dll_is_uploaded_with_dll_extension(lab):
    gw = lab.gateway()
    res = gw.analysis_start(str(lab.sample("lib.dll", dll=True)))
    assert res["sample"]["kind"] == "dll" and res["sample"]["guest_path"].endswith(".dll")


def test_non_pe_is_uploaded_only_with_a_warning(lab):
    gw = lab.gateway()
    res = gw.analysis_start(str(lab.sample("notes.txt", data=b"just some text")))
    assert res["sample"]["kind"] == "non-pe" and res["arch"] is None
    assert res["state"] == JobState.ANALYZING
    assert res["warnings"] and not lab.servers["x64"].tool_calls("LoadBinary")
    assert res["sample"]["guest_path"].endswith(".bin")
    load_step = [s for s in res["steps"] if s["name"] == "load"][0]
    assert load_step["ok"] and "skipped" in load_step["detail"]


def test_load_false_uploads_without_loading(lab):
    gw = lab.gateway()
    res = gw.analysis_start(str(lab.sample()), load=False)
    assert res["state"] == JobState.ANALYZING
    assert not lab.servers["x64"].tool_calls("LoadBinary")


def test_revert_false_keeps_the_running_vm(lab):
    gw = lab.gateway()
    res = gw.analysis_start(str(lab.sample()), revert=False)
    assert not [c for c in lab.vm.calls if c[0] in ("revert_snapshot", "start")]
    assert res["epoch"] == 0


def test_snapshot_argument_selects_the_revert_target(lab):
    gw = lab.gateway()
    gw.analysis_start(str(lab.sample()), snapshot="BASE")
    assert ("revert_snapshot", ("BASE",)) in lab.vm.calls


def test_finish_with_keep_snapshot_takes_a_job_snapshot_and_applies_retention(lab):
    old = "gw-job-20200101-000000-aaaaaa"
    lab.vm.snapshots.append(Snapshot(old))
    lab.set_profile(retention=type(lab.profile.retention)(max_gateway_snapshots=5, max_age_days=30))
    gw = lab.gateway()
    job_id = gw.analysis_start(str(lab.sample()))["job_id"]
    gw.analysis_collect()
    fin = gw.analysis_finish(keep_snapshot=True)
    name = f"gw-job-{job_id}"
    assert fin["snapshot"] == name
    names = [s.name for s in lab.vm.snapshots]
    assert name in names and old not in names  # the 2020 snapshot is past max_age_days
    assert fin["deleted_snapshots"] == [old]
    assert "MCP_CLEAN" in names and "BASE" in names


def test_finish_without_revert(lab):
    gw = lab.gateway()
    gw.analysis_start(str(lab.sample()))
    gw.analysis_collect()
    reverts = sum(1 for c in lab.vm.calls if c[0] == "revert_snapshot")
    fin = gw.analysis_finish(revert=False)
    assert fin["state"] == JobState.DONE and fin["reverted"] is False
    assert sum(1 for c in lab.vm.calls if c[0] == "revert_snapshot") == reverts


def test_collect_twice_then_finish(lab):
    gw = lab.gateway()
    job_id = gw.analysis_start(str(lab.sample()))["job_id"]
    gw.analysis_collect()
    lab.guest.write(f"{GUEST_ROOT}\\{job_id}\\out\\later.bin", b"later")
    col = gw.analysis_collect(job_id)
    assert any(f["original_path"] == "later.bin" for f in col["files"])
    assert gw.analysis_finish(job_id)["state"] == JobState.DONE


def test_collect_extra_guest_paths_are_limited_to_allowed_roots(lab):
    gw = lab.gateway()
    job_id = gw.analysis_start(str(lab.sample()))["job_id"]
    lab.guest.write(f"{GUEST_ROOT}\\{job_id}\\note.txt", b"note")
    lab.guest.write("C:\\Windows\\System32\\config\\SAM", b"nope")
    col = gw.analysis_collect(extra_guest_paths=[f"{GUEST_ROOT}\\{job_id}\\note.txt",
                                                 "C:\\Windows\\System32\\config\\SAM"])
    statuses = {f["original_path"].rsplit("\\", 1)[-1]: f["status"] for f in col["files"]}
    assert statuses["note.txt"] == "ok"
    assert statuses["SAM"].startswith("failed:")
    assert col["state"] == JobState.COLLECTED_PARTIAL
    # a partial collection blocks the revert (fail closed)
    with pytest.raises(StateViolation):
        gw.analysis_finish()


def test_gateway_is_constructed_without_disk_io(lab, tmp_path):
    Gateway(lab.config, runtime_factory=lambda name: lab.runtime(), clock=lab.clock)
    assert not (tmp_path / "jobs").exists()


def test_debugger_exe_dir_db_path_for_x32(tmp_path):
    lab = make_lab(tmp_path, backends=("x32",))
    try:
        gw = lab.gateway()
        res = gw.analysis_start(str(lab.sample("a.exe", machine=0x14C)))
        col = gw.analysis_collect()
        name = res["sample"]["guest_path"].rsplit("\\", 1)[-1] + ".dd32"
        entry = [f for f in col["files"] if f["original_path"].endswith(name)][0]
        assert entry["original_path"].lower().startswith(EXE["x32"].rsplit("\\", 1)[0].lower() + "\\db\\")
        assert entry["status"] == "ok"
    finally:
        lab.close()


def test_gateway_subclasses_the_facade_with_matching_signatures():
    import inspect

    assert GatewayApp in Gateway.__mro__
    for name, proto in inspect.getmembers(GatewayApp, inspect.isfunction):
        if name.startswith("_"):
            continue
        impl = getattr(Gateway, name)
        assert impl is not proto, f"{name} is not implemented"
        want = [(p.name, p.kind, p.default) for p in inspect.signature(proto).parameters.values()]
        got = [(p.name, p.kind, p.default) for p in inspect.signature(impl).parameters.values()]
        assert got == want, name
