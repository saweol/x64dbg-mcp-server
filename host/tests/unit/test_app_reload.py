"""reload_on_restart (plan 4.2, J-integ): after a relaunch the gateway reloads the job sample
(SetArtifactDir when supported, LoadBinary, WaitForPause) before it reports
BACKEND_RESTARTED, and ``details.reloaded`` says whether the sample is loaded again."""

from __future__ import annotations

import pytest

from tests.fakes.fake_plugin_server import ToolError
from tests.fakes.fake_runtime import GUEST_ROOT, make_lab
from x64dbg_vm_gateway.errors import BackendRestarted


@pytest.fixture
def lab(tmp_path):
    lab = make_lab(tmp_path)
    yield lab
    lab.close()


def restarted(gw, tool: str = "StepOver") -> BackendRestarted:
    with pytest.raises(BackendRestarted) as ei:
        gw.call_mirrored(tool)
    return ei.value


def test_without_reload_on_restart_reloaded_is_false(lab):
    gw = lab.gateway()
    gw.analysis_start(str(lab.sample()))
    lab.kill_debugger("x64")
    err = restarted(gw)
    assert err.details["reloaded"] is False
    assert len(lab.servers["x64"].tool_calls("LoadBinary")) == 1


def test_reload_happens_before_the_error_and_reloaded_is_true(lab):
    gw = lab.gateway()
    res = gw.analysis_start(str(lab.sample()), reload_on_restart=True)
    srv = lab.servers["x64"]
    srv.clear_log()
    lab.kill_debugger("x64")
    err = restarted(gw)
    assert err.details["reloaded"] is True and err.details["reload"]["ok"] is True
    calls = [r.tool for r in srv.tool_calls() if r.tool in ("LoadBinary", "WaitForPause", "StepOver")]
    assert calls == ["LoadBinary", "WaitForPause"]  # reloaded; StepOver itself was not executed
    assert srv.tool_calls("LoadBinary")[-1].arguments["filePath"] == res["sample"]["guest_path"]
    assert "reloaded" in (err.hint or "")
    # refused again before the acknowledgement: still loaded, not loaded twice
    again = restarted(gw)
    assert again.details["reloaded"] is True
    assert len(srv.tool_calls("LoadBinary")) == 1
    gw.session_status()
    assert gw.call_mirrored("StepOver")["is_error"] is False


def test_reload_sets_the_artifact_dir_first_on_a_v110_plugin(tmp_path):
    lab = make_lab(tmp_path, plugin_version="1.10")
    try:
        gw = lab.gateway()
        job_id = gw.analysis_start(str(lab.sample()), reload_on_restart=True)["job_id"]
        srv = lab.servers["x64"]
        srv.clear_log()
        lab.kill_debugger("x64")
        err = restarted(gw)
        assert err.details["reloaded"] is True
        wanted = ("SetArtifactDir", "LoadBinary", "WaitForPause")
        assert [r.tool for r in srv.tool_calls() if r.tool in wanted] == list(wanted)
        assert srv.tool_calls("SetArtifactDir")[-1].arguments == {"path": f"{GUEST_ROOT}\\{job_id}\\out"}
    finally:
        lab.close()


def test_failed_reload_says_reloaded_false(lab):
    gw = lab.gateway()
    gw.analysis_start(str(lab.sample()), reload_on_restart=True)
    srv = lab.servers["x64"]
    lab.kill_debugger("x64")
    srv.on_tool("LoadBinary", ToolError("cannot open file"))
    err = restarted(gw)
    assert err.details["reloaded"] is False and err.details["reload"]["ok"] is False
    assert restarted(gw).details["reloaded"] is False  # no retry loop either
    assert len(srv.tool_calls("LoadBinary")) == 2


def test_debugger_restart_reports_reloaded(lab):
    gw = lab.gateway()
    gw.analysis_start(str(lab.sample()), reload_on_restart=True)
    lab.servers["x64"].stop()
    assert gw.debugger_restart()["reloaded"] is True


def test_debugger_restart_without_reload_on_restart_reports_not_reloaded(lab):
    gw = lab.gateway()
    gw.analysis_start(str(lab.sample()))
    lab.servers["x64"].stop()
    assert gw.debugger_restart()["reloaded"] is False
