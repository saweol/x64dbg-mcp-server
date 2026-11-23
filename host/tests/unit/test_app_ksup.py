"""Orchestrator fixes from the spike-VM E2E run.

E4  analysis_start resolves the backend (re-reading the token while VMware Tools are
    still starting) before it asks the supervisor; a healthy x64dbg is never killed.
E1  never start a second instance of the VM: vmware-vmx processes of this .vmx that
    vmrun does not list are waited for (normal revert transition, <= 15 s) and then
    refused with VM_LOCKED; a duplicate after the start is refused too; gateway_doctor
    has a ``single_vm_instance`` check.
E5  ``Gateway.warm_up`` learns the live plugin version before the first tools/list.
E6  session_status answers from short-lived VM observations, checks the backends in
    parallel and lists guest processes only when L1 fails.
"""

from __future__ import annotations

import json
import time
from importlib import resources
from typing import Any

import pytest

from tests.fakes.fake_runtime import PROFILE, make_lab
from tests.fakes.fake_vm_instances import InstanceVm, PidsOnlyVm
from x64dbg_vm_gateway.app import Gateway
from x64dbg_vm_gateway.catalog import ToolCatalog
from x64dbg_vm_gateway.contracts import PowerState, ToolInfo, ToolsState, VmrunResult
from x64dbg_vm_gateway.errors import ToolsNotRunning, VmLocked, VmrunError
from x64dbg_vm_gateway.vmrun import VmrunProvider
from x64dbg_vm_gateway.wiring import VM_STATE_TTL_S, Runtime, build_runtime

TOOLS_DOWN = "Error: The VMware Tools are not running in the virtual machine"
V110_TOOLS = {"GetServerInfo", "SetArtifactDir", "ProbeFile"}


@pytest.fixture
def lab(tmp_path):
    lab = make_lab(tmp_path)
    yield lab
    lab.close()


def checks(report: dict) -> dict[str, dict]:
    return {c["name"]: c for c in report["checks"]}


def gateway_over(lab, rt: Runtime, **kwargs: Any) -> Gateway:
    kwargs.setdefault("host_system", "Linux")
    kwargs.setdefault("find_vmrun", lambda configured="auto", **_kw: lab.vmrun_path)
    kwargs.setdefault("vmrun_version", lambda path: "1.17.0 build-24583834")
    gw = Gateway(lab.config, runtime_factory=lambda name: rt, clock=lab.clock, **kwargs)
    lab.gateways.append(gw)
    return gw


# ════════════════════════════════════════════════════════════════════
# E4: tools still starting after the revert
def test_e4_analysis_start_survives_vmware_tools_starting_after_the_revert(lab):
    gw = lab.gateway()
    state: dict[str, int] = {"tools_down_polls": 0}
    real_revert, real_tools = lab.vm.revert_snapshot, lab.vm.tools_state

    def revert(name: str) -> None:
        real_revert(name)
        state["tools_down_polls"] = 3
        # checkToolsState may already say "running" while guest operations still fail
        lab.guest.fail_next("copy_from_guest", ToolsNotRunning(TOOLS_DOWN), times=5)

    def tools() -> ToolsState:
        if state["tools_down_polls"] > 0:
            state["tools_down_polls"] -= 1
            return ToolsState.INSTALLED
        return real_tools()

    lab.vm.revert_snapshot = revert  # type: ignore[method-assign]
    lab.vm.tools_state = tools  # type: ignore[method-assign]
    res = gw.analysis_start(str(lab.sample()))
    assert res["state"] == "ANALYZING" and res["loaded"] is True and res["paused"] is True
    assert lab.guest.calls_of("kill_process") == [] and lab.launches == []
    assert gw.call_mirrored("StepOver")["is_error"] is False  # no BACKEND_RESTARTED
    assert gw.session_status()["backends"]["x64"]["epoch"] == res["epoch"]


def test_e4_status_during_the_unresolved_window_never_kills(lab):
    gw = lab.gateway()
    gw.session_status()
    gw.vm_snapshot_revert()
    lab.guest.fail_next("copy_from_guest", ToolsNotRunning(TOOLS_DOWN), times=10_000)
    for _ in range(5):
        st = gw.session_status()
        assert st["backends"]["x64"]["health"] == "UNRESOLVED"
        lab.clock.advance(60)
    assert lab.guest.calls_of("kill_process") == [] and lab.launches == []


# ════════════════════════════════════════════════════════════════════
# E1: one VM instance only
def instance_lab(tmp_path, vm_cls: type[InstanceVm] = InstanceVm):
    lab = make_lab(tmp_path)
    vm = vm_cls()
    vm.ip = "127.0.0.1"
    vm.snapshots = list(lab.vm.snapshots)
    lab.vm = vm
    return lab


@pytest.fixture
def ilab(tmp_path):
    lab = instance_lab(tmp_path)
    yield lab
    lab.close()


def starts(lab) -> int:
    return sum(1 for c in lab.vm.calls if c[0] == "start")


def test_an_orphan_vmx_process_blocks_the_start_after_a_revert(ilab):
    orphan = ilab.vm.add_orphan(exit_after_polls=None)  # E1: an older vmware-vmx that never exits
    gw = ilab.gateway()
    with pytest.raises(VmLocked) as ei:
        gw.analysis_start(str(ilab.sample()))
    err = ei.value
    assert err.code == "VM_LOCKED" and str(orphan) in err.message
    assert "refusing to start a second instance" in err.message
    assert "orphan" in (err.hint or "")
    assert err.details["pids"] == [orphan]
    assert starts(ilab) == 0  # never a second instance
    waited = sum(ilab.clock.sleeps)
    assert 15 <= waited <= 20


def test_the_old_instance_of_a_revert_is_waited_for(ilab):
    ilab.vm.add_orphan(exit_after_polls=3)  # the reverted instance takes a few seconds to exit
    gw = ilab.gateway()
    res = gw.analysis_start(str(ilab.sample()))
    assert res["state"] == "ANALYZING"
    assert starts(ilab) == 1
    assert ilab.vm.vm_process_ids() == ilab.vm.registered


def test_a_second_instance_after_the_start_is_refused(ilab):
    ilab.vm.start_duplicates = True
    gw = ilab.gateway()
    with pytest.raises(VmLocked) as ei:
        gw.analysis_start(str(ilab.sample()))
    assert len(ei.value.details["pids"]) == 2
    assert starts(ilab) == 1


def test_vm_power_start_refuses_to_start_next_to_an_orphan(ilab):
    gw = ilab.gateway()
    ilab.vm.stop()
    orphan = ilab.vm.add_orphan(exit_after_polls=None)
    with pytest.raises(VmLocked) as ei:
        gw.vm_power("start")
    assert str(orphan) in ei.value.message
    assert starts(ilab) == 0


def test_vm_power_start_without_orphans_starts(ilab):
    gw = ilab.gateway()
    ilab.vm.stop()
    out = gw.vm_power("start")
    assert out["started"] is True and starts(ilab) == 1


def test_a_provider_with_only_vm_process_ids_is_guarded_too(tmp_path):
    lab = instance_lab(tmp_path, PidsOnlyVm)
    try:
        assert getattr(lab.vm, "instance_report", None) is None
        orphan = lab.vm.add_orphan(exit_after_polls=None)
        lab.vm.stop()
        with pytest.raises(VmLocked) as ei:
            lab.gateway().vm_power("start")
        assert str(orphan) in ei.value.message and starts(lab) == 0
    finally:
        lab.close()


def test_an_unusable_instance_report_does_not_block_the_start(ilab):
    ilab.vm.report_error = VmrunError("pgrep is not available")
    ilab.vm.stop()
    out = ilab.gateway().vm_power("start")
    assert out["started"] is True and starts(ilab) == 1


def test_doctor_single_vm_instance_ok(ilab):
    rep = ilab.gateway().doctor()
    c = checks(rep)["single_vm_instance"]
    assert c["ok"] is True and str(ilab.vm.registered[0]) in c["detail"]
    assert rep["ok"] is True, [x for x in rep["checks"] if not x["ok"]]


def test_doctor_single_vm_instance_reports_an_orphan(ilab):
    orphan = ilab.vm.add_orphan(exit_after_polls=None)
    c = checks(ilab.gateway().doctor())["single_vm_instance"]
    assert c["ok"] is False and str(orphan) in c["detail"]
    assert "orphan" in c["hint"]


def test_doctor_single_vm_instance_reports_an_orphan_of_a_stopped_vm(ilab):
    ilab.vm.stop()
    orphan = ilab.vm.add_orphan(exit_after_polls=None)
    c = checks(ilab.gateway().doctor())["single_vm_instance"]
    assert c["ok"] is False and str(orphan) in c["detail"]


def test_doctor_single_vm_instance_without_provider_support(lab):
    c = checks(lab.gateway().doctor())["single_vm_instance"]
    assert c["ok"] is True and "not checked" in c["detail"]


# ════════════════════════════════════════════════════════════════════
# E5: live tool list at start-up
def mirrored_names(gw: Gateway) -> set[str]:
    return {t.name for t in gw.list_mirrored_tools()}


def test_warm_up_learns_the_live_plugin_version(tmp_path):
    lab = make_lab(tmp_path, plugin_version="1.10")
    try:
        gw = lab.gateway()
        assert not (V110_TOOLS & mirrored_names(gw))  # control: nothing contacted yet (E5)
        out = gw.warm_up()
        assert V110_TOOLS <= mirrored_names(gw)
        assert out["backends"]["x64"]["version"] == "1.10" and out["backends"]["x64"]["source"] == "live"
    finally:
        lab.close()


def test_warm_up_replaces_a_stale_cached_list_of_an_older_plugin(tmp_path):
    lab = make_lab(tmp_path, plugin_version="1.10")
    try:
        data = json.loads(resources.files("x64dbg_vm_gateway").joinpath("data/tools-v1.9.json")
                          .read_text(encoding="utf-8"))
        old = [ToolInfo(t["name"], t["description"], t["inputSchema"], t["read_only"]) for t in data["tools"]]
        ToolCatalog("data/tools-v1.9.json", cache_dir=tmp_path / "cache" / PROFILE).update_from_live(
            "x64", "1.3", old)  # written by a session against the old v1.3 plugin
        gw = lab.gateway()
        assert not (V110_TOOLS & mirrored_names(gw))
        gw.warm_up()
        assert V110_TOOLS <= mirrored_names(gw)
    finally:
        lab.close()


def test_warm_up_with_the_vm_off_contacts_nothing(lab):
    lab.vm.power = PowerState.OFF
    gw = lab.gateway()
    out = gw.warm_up()
    assert lab.guest.calls_of("copy_from_guest") == []
    assert lab.servers["x64"].requests == []
    assert out["backends"]["x64"]["source"] == "builtin"


def test_warm_up_is_bounded(lab):
    lab.servers["x64"].set_delay("GET", 3.0)
    gw = lab.gateway()
    t0 = time.monotonic()
    gw.warm_up(timeout_s=0.5)
    assert time.monotonic() - t0 < 2.0


def test_warm_up_never_raises(lab):
    lab.guest.fail_next("copy_from_guest", VmrunError("vmrun exploded"))
    out = lab.gateway().warm_up()
    assert out["backends"]["x64"]["error"] == "VMRUN_ERROR"


# ════════════════════════════════════════════════════════════════════
# E6: session_status fast path
class SlowRunner:
    """VmrunRunner fake for a running VM: every vmrun call costs ``cost_s`` of fake time."""

    def __init__(self, clock, vmx: str, cost_s: float = 0.5) -> None:
        self.clock, self.vmx, self.cost_s = clock, vmx, cost_s
        self.calls: list[str] = []

    def run(self, command: str, *params: str, guest: bool = False, timeout_s: float = 120.0,
            vmx: bool = True) -> VmrunResult:
        self.calls.append(command)
        self.clock.advance(self.cost_s)
        answers = {"list": f"Total running VMs: 1\n{self.vmx}\n", "checkToolsState": "running\n",
                   "getGuestIPAddress": "127.0.0.1\n"}
        if command not in answers:
            raise AssertionError(f"unexpected vmrun {command} {params}")
        return VmrunResult(0, answers[command], "")


def slow_gateway(lab, cost_s: float = 0.5) -> tuple[Gateway, SlowRunner]:
    vmx = str(lab.profile.vmx)
    runner = SlowRunner(lab.clock, vmx, cost_s)
    rt = build_runtime(lab.config, PROFILE, environ=lab.environ, clock=lab.clock,
                       vm=VmrunProvider(runner, vmx, clock=lab.clock), channel=lab.guest,
                       cache_dir=lab.tmp / "cache")
    return gateway_over(lab, rt), runner


def test_session_status_on_a_healthy_vm_is_fast(lab):
    gw, runner = slow_gateway(lab)
    gw.session_status()  # first contact: resolves the backend (token, version)
    lab.clock.advance(VM_STATE_TTL_S + 1)
    runner.calls.clear()
    t0 = lab.clock.monotonic()
    st = gw.session_status()
    assert st["backends"]["x64"]["health"] == "HEALTHY"
    assert st["vm"] == {"power": "running", "tools": "running", "ip": "127.0.0.1"}
    assert sorted(runner.calls) == ["checkToolsState", "list"]  # once each, not once per backend
    assert lab.clock.monotonic() - t0 < 2.0


def test_session_status_reuses_fresh_vm_observations(lab):
    gw, runner = slow_gateway(lab)
    gw.session_status()
    runner.calls.clear()
    gw.session_status()
    gw.session_status()
    assert runner.calls == []  # within the TTL


def test_a_vm_operation_makes_the_next_status_ask_again(lab):
    gw, runner = slow_gateway(lab)
    gw.session_status()
    runner.calls.clear()
    with gw.runtime().lock.write(timeout_s=5):
        pass
    gw.session_status()
    assert sorted(runner.calls) == ["checkToolsState", "list"]


def test_session_status_lists_guest_processes_only_when_l1_fails(lab):
    gw = lab.gateway()
    for _ in range(3):
        assert gw.session_status()["backends"]["x64"]["health"] == "HEALTHY"
    assert lab.guest.calls_of("list_processes") == []
    lab.servers["x64"].stop()  # plugin gone, x64dbg.exe still listed: LOADING
    assert gw.session_status()["backends"]["x64"]["health"] == "LOADING"
    assert len(lab.guest.calls_of("list_processes")) == 1


def test_session_status_checks_the_backends_in_parallel(tmp_path):
    lab = make_lab(tmp_path, backends=("x64", "x32"))
    try:
        gw = lab.gateway()
        gw.session_status()  # resolve both first
        for srv in lab.servers.values():
            srv.set_delay("GET", 0.75)
            srv.set_delay("GetDebugState", 0.75)
        t0 = time.monotonic()
        st = gw.session_status()
        elapsed = time.monotonic() - t0
        assert {b["health"] for b in st["backends"].values()} == {"HEALTHY"}
        assert elapsed < 2.4, elapsed  # sequential: 2 x (0.75 + 0.75) = 3.0 s
    finally:
        lab.close()
