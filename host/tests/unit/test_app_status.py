"""session_status, doctor, instructions, tool list, debugger routing and stubs."""

from __future__ import annotations

import json

import pytest

from tests.fakes.fake_plugin_server import FakePluginServer
from tests.fakes.fake_runtime import make_lab
from x64dbg_vm_gateway.app import Gateway, InvalidArgument
from x64dbg_vm_gateway.config import BackendConfig, GatewayConfig, ProfileConfig
from x64dbg_vm_gateway.contracts import IsolationReport, PowerState
from x64dbg_vm_gateway.errors import ConfigError, GatewayError, VmrunNotFound
from x64dbg_vm_gateway.wiring import PROVISION_HINT, build_runtime


@pytest.fixture
def lab(tmp_path):
    lab = make_lab(tmp_path)
    yield lab
    lab.close()


def checks(report: dict) -> dict[str, dict]:
    return {c["name"]: c for c in report["checks"]}


# ── session_status ──────────────────────────────────────────────────
def test_status_of_an_idle_lab(lab):
    st = lab.gateway().session_status()
    assert st["profile"] == "lab" and st["mode"] == "vmware"
    assert st["vm"] == {"power": "running", "tools": "running", "ip": "127.0.0.1"}
    b = st["backends"]["x64"]
    assert b["health"] == "HEALTHY" and b["epoch"] == 0 and b["acked_epoch"] == 0
    assert b["url"].startswith("http://127.0.0.1:") and b["arch"] == "x64" and b["selected"] is True
    assert st["job"] is None and st["operation"] is None
    assert st["needs_recovery"] == [] and st["isolation_warnings"] == []
    json.dumps(st)  # JSON-serialisable


def test_status_with_the_vm_off_does_not_touch_the_guest(lab):
    lab.vm.power = PowerState.OFF
    st = lab.gateway().session_status()
    assert st["vm"]["power"] == "off" and st["vm"]["tools"] == "unknown"
    assert st["backends"]["x64"]["health"] == "VM_DOWN"
    assert not lab.guest.calls_of("copy_from_guest")


def test_status_reports_isolation_warnings(lab):
    lab.vm.isolation = IsolationReport(True, True, ("nat",))
    st = lab.gateway().session_status()
    assert any("shared folders" in w for w in st["isolation_warnings"])
    assert any("nat" in w for w in st["isolation_warnings"])


def test_status_reports_backend_token_problems_without_raising(lab):
    lab.write_guest_token_config("x64", b"\x00" * 101)
    st = lab.gateway().session_status()
    b = st["backends"]["x64"]
    assert b["error"]["code"] == "BACKEND_AUTH" and PROVISION_HINT in b["error"]["hint"]


def test_status_shows_the_active_job(lab):
    gw = lab.gateway()
    res = gw.analysis_start(str(lab.sample()))
    st = gw.session_status()
    job = st["job"]
    assert job["job_id"] == res["job_id"] and job["state"] == "ANALYZING" and job["backend_id"] == "x64"
    assert job["sample"]["sha256"] == res["sample"]["sha256"]
    assert st["operation"]["op"] == "analysis_start" and st["operation"]["state"] == "done"


# ── doctor ──────────────────────────────────────────────────────────
def test_doctor_all_green(lab):
    rep = lab.gateway().doctor()
    c = checks(rep)
    assert rep["ok"] is True, [x for x in rep["checks"] if not x["ok"]]
    for name in ("vmrun", "vmx", "clean_snapshot", "vm_power", "tools", "guest_credentials", "guest_ip",
                 "backend:x64:reachable", "backend:x64:token", "isolation", "host_jobs_root",
                 "guest_job_root", "catalog:x64"):
        assert c[name]["ok"], name
    assert "1.17.0" in c["vmrun"]["detail"]
    assert "1.9" in c["catalog:x64"]["detail"]


def test_doctor_reports_failures_without_raising(lab):
    lab.write_guest_token_config("x64", b"\x00" * 101)
    lab.vm.isolation = IsolationReport(True, True, ("bridged",))
    lab.vm.snapshots = [s for s in lab.vm.snapshots if s.name != "MCP_CLEAN"]
    rep = lab.gateway().doctor()
    c = checks(rep)
    assert rep["ok"] is False
    assert not c["backend:x64:token"]["ok"] and PROVISION_HINT in c["backend:x64:token"]["hint"]
    assert not c["isolation"]["ok"] and "bridged" in c["isolation"]["detail"]
    assert not c["clean_snapshot"]["ok"]
    assert c["guest_credentials"]["ok"]


def test_doctor_isolation_only_warns_when_not_required(lab):
    lab.vm.isolation = IsolationReport(True, True, ("bridged",))
    lab.set_profile(require_isolation=False)
    c = checks(lab.gateway().doctor())
    assert c["isolation"]["ok"] and "bridged" in c["isolation"]["detail"]


def test_doctor_guest_credentials_failure(lab):
    from x64dbg_vm_gateway.errors import GuestAuthFailed

    lab.guest.fail_next("list_processes", GuestAuthFailed("bad password"), times=10)
    c = checks(lab.gateway().doctor())
    assert not c["guest_credentials"]["ok"]


def test_doctor_without_vmrun(lab):
    def missing(configured="auto", **_kw):
        raise VmrunNotFound("vmrun not found", hint="install VMware")

    rep = lab.gateway(find_vmrun=missing).doctor()
    c = checks(rep)
    assert rep["ok"] is False and not c["vmrun"]["ok"] and c["vmrun"]["hint"] == "install VMware"


def test_doctor_vm_off(lab):
    lab.vm.power = PowerState.OFF
    c = checks(lab.gateway().doctor())
    assert not c["vm_power"]["ok"] and c["vm_power"]["hint"]
    assert not c["tools"]["ok"]


def test_doctor_unknown_profile_raises(lab):
    with pytest.raises(ConfigError):
        lab.gateway().doctor("nope")


def test_doctor_endpoint_profile(tmp_path):
    srv = FakePluginServer(token="t" * 32).start()
    try:
        prof = ProfileConfig(name="remote", mode="endpoint", token_source="env", require_isolation=False,
                             backends=(BackendConfig(id="x64", arch="x64", url=srv.url, token_env="T"),))
        cfg = GatewayConfig(jobs_root=str(tmp_path / "jobs"), profiles={"remote": prof})
        rt = build_runtime(cfg, "remote", environ={"T": "t" * 32}, cache_dir=tmp_path / "c")
        gw = Gateway(cfg, runtime_factory=lambda name: rt)
        rep = gw.doctor()
        c = checks(rep)
        assert rep["ok"] is True, rep
        assert "vmrun" not in c and c["backend:x64:token"]["ok"]
        gw.close()
    finally:
        srv.stop()


# ── instructions / tools ────────────────────────────────────────────
def test_instructions_contain_the_loop_rules(lab):
    text = lab.gateway().instructions()
    for needle in ("analysis_start", "analysis_collect", "BACKEND_RESTARTED", "<untrusted_guest_output>",
                   "never execute", "approval"):
        assert needle in text, needle


def test_instructions_include_cached_backend_instructions(lab):
    gw = lab.gateway()
    gw.analysis_start(str(lab.sample()))
    assert "ALWAYS call GetDebugState first" in gw.instructions()


def test_mirrored_tools_fall_back_to_the_builtin_catalog(lab):
    tools = lab.gateway().list_mirrored_tools()
    assert len(tools) == 80 and "LoadBinary" in {t.name for t in tools}


def test_mirrored_tools_without_a_usable_runtime_still_list_the_builtin(lab, tmp_path):
    def broken(name):
        raise VmrunNotFound("vmrun not found")

    gw = Gateway(lab.config, runtime_factory=broken)
    assert len(gw.list_mirrored_tools()) == 80
    assert "analysis_start" in gw.instructions()


# ── debugger routing ────────────────────────────────────────────────
def test_debugger_select_routes_calls_without_a_job(tmp_path):
    lab = make_lab(tmp_path, backends=("x64", "x32"))
    try:
        gw = lab.gateway()
        assert gw.call_mirrored("GetDebugState")["backend_id"] == "x64"
        out = gw.debugger_select("x32")
        assert out["selected"] == "x32"
        assert gw.call_mirrored("GetDebugState")["backend_id"] == "x32"
        assert gw.debugger_call("GetDebugState", backend_id="x64")["backend_id"] == "x64"
        assert gw.session_status()["backends"]["x32"]["selected"] is True
    finally:
        lab.close()


def test_debugger_select_unknown_backend(lab):
    with pytest.raises(InvalidArgument):
        lab.gateway().debugger_select("arm64")


def test_debugger_call_unknown_tool_is_an_error_result(lab):
    out = lab.gateway().debugger_call("NoSuchTool", {})
    assert out["is_error"] is True and "Tool not found." in out["texts"][0]


def test_debugger_call_validates_the_tool_name(lab):
    with pytest.raises(InvalidArgument):
        lab.gateway().debugger_call("", {})


# ── stubs / misc ────────────────────────────────────────────────────
@pytest.mark.parametrize("call", [
    lambda gw: gw.static_rebase("0x401000", direction="runtime_to_static"),
    lambda gw: gw.static_export_annotations(),
    lambda gw: gw.static_import_annotations([], module="a.exe"),
])
def test_static_tools_need_a_job(lab, call):
    # The static tools are wired now (J-integ, see test_app_ida); this pinned the old stub.
    with pytest.raises(GatewayError) as ei:
        call(lab.gateway())
    assert ei.value.code == "STATE_VIOLATION" and ei.value.next_tool == "analysis_start"


def test_close_is_idempotent(lab):
    gw = lab.gateway()
    gw.session_status()
    gw.close()
    gw.close()
