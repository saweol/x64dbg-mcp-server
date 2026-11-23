"""VM tools of app.Gateway: snapshots, power, screenshots, epochs after VM operations."""

from __future__ import annotations

import os
import stat
import threading
from pathlib import Path

import pytest
from x64dbg_vm_gateway.app import Gateway, InvalidArgument
from x64dbg_vm_gateway.wiring import build_runtime

from tests.fakes.fake_runtime import make_lab
from x64dbg_vm_gateway.config import BackendConfig, GatewayConfig, ProfileConfig
from x64dbg_vm_gateway.contracts import PowerState, Snapshot, ToolsState
from x64dbg_vm_gateway.errors import (
    BackendRestarted,
    ConfigError,
    ProtectedSnapshotError,
    SnapshotNotFound,
    StateViolation,
    VmNotReady,
)

POSIX = os.name == "posix"


@pytest.fixture
def lab(tmp_path):
    lab = make_lab(tmp_path)
    yield lab
    lab.close()


def test_snapshots_list_marks_protected_and_gateway_owned(lab):
    lab.vm.snapshots.append(Snapshot("gw-job-20261101-000000-abcdef", depth=1, parent="MCP_CLEAN"))
    out = lab.gateway().vm_snapshots_list()
    by = {s["name"]: s for s in out["snapshots"]}
    assert by["MCP_CLEAN"]["protected"] is True and by["MCP_CLEAN"]["clean"] is True
    assert by["BASE"]["protected"] is True and by["BASE"]["gateway_owned"] is False
    g = by["gw-job-20261101-000000-abcdef"]
    assert g["gateway_owned"] is True and g["protected"] is False
    assert g["depth"] == 1 and g["parent"] == "MCP_CLEAN"
    assert out["clean_snapshot"] == "MCP_CLEAN"


def test_revert_without_a_job_restarts_the_vm_and_bumps_epochs(lab):
    gw = lab.gateway()
    assert gw.call_mirrored("StepOver")["epoch"] == 0
    out = gw.vm_snapshot_revert()
    assert out["snapshot"] == "MCP_CLEAN" and out["power"] == "running"
    assert ("revert_snapshot", ("MCP_CLEAN",)) in lab.vm.calls
    assert lab.vm.power == PowerState.RUNNING  # suspended after revert, then resumed
    with pytest.raises(BackendRestarted):
        gw.call_mirrored("StepOver")
    gw.session_status()
    assert gw.call_mirrored("StepOver")["epoch"] == 1


def test_revert_drops_cached_tokens(lab):
    gw = lab.gateway()
    gw.session_status()
    before = len(lab.guest.calls_of("copy_from_guest"))
    gw.vm_snapshot_revert()
    gw.session_status()
    assert len(lab.guest.calls_of("copy_from_guest")) == before + 1


def test_revert_to_a_named_snapshot(lab):
    gw = lab.gateway()
    gw.vm_snapshot_revert("BASE")
    assert ("revert_snapshot", ("BASE",)) in lab.vm.calls


def test_revert_to_an_unknown_snapshot(lab):
    with pytest.raises(SnapshotNotFound):
        lab.gateway().vm_snapshot_revert("nope")


def test_revert_waits_for_vmware_tools(lab):
    gw = lab.gateway()
    real_tools_state = lab.vm.tools_state
    answers = iter([ToolsState.INSTALLED, ToolsState.INSTALLED])

    def tools_state():
        return next(answers, None) or real_tools_state()

    lab.vm.tools_state = tools_state  # type: ignore[method-assign]
    gw.vm_snapshot_revert()
    assert lab.clock.sleeps  # polled with the injected clock


def test_revert_fails_when_tools_never_start(lab):
    gw = lab.gateway()
    lab.vm.tools = ToolsState.INSTALLED
    with pytest.raises(VmNotReady):
        gw.vm_snapshot_revert()
    assert gw.session_status()["operation"]["state"] == "failed"


def test_revert_refreshes_the_guest_ip(lab):
    gw = lab.gateway()
    gw.session_status()
    lab.vm.ip = "127.0.0.2"
    gw.vm_snapshot_revert()
    rt = gw.runtime()
    assert rt.guest_ip() == "127.0.0.2"


def test_snapshot_take(lab):
    gw = lab.gateway()
    out = gw.vm_snapshot_take("before-unpack")
    assert out["snapshot"] == "before-unpack"
    assert "before-unpack" in [s.name for s in lab.vm.snapshots]


@pytest.mark.parametrize("name", ["", "  ", "a/b", "a\\b", "x\ny", "MCP_CLEAN", "base", "x" * 200])
def test_snapshot_take_validates_the_name(lab, name):
    with pytest.raises((InvalidArgument, ProtectedSnapshotError)):
        lab.gateway().vm_snapshot_take(name)


def test_snapshot_take_refuses_duplicates(lab):
    gw = lab.gateway()
    gw.vm_snapshot_take("once")
    with pytest.raises(InvalidArgument):
        gw.vm_snapshot_take("once")


def test_snapshot_take_is_allowed_while_analyzing(lab):
    gw = lab.gateway()
    gw.analysis_start(str(lab.sample()))
    gw.vm_snapshot_take("mid-analysis")
    assert "mid-analysis" in [s.name for s in lab.vm.snapshots]


def test_snapshot_delete_only_gateway_snapshots(lab):
    lab.vm.snapshots.append(Snapshot("gw-job-20261101-000000-abcdef"))
    gw = lab.gateway()
    with pytest.raises(ProtectedSnapshotError):
        gw.vm_snapshot_delete("MCP_CLEAN")
    with pytest.raises(ProtectedSnapshotError):
        gw.vm_snapshot_delete("BASE")
    out = gw.vm_snapshot_delete("gw-job-20261101-000000-abcdef")
    assert out["deleted"] == "gw-job-20261101-000000-abcdef"
    assert "gw-job-20261101-000000-abcdef" not in [s.name for s in lab.vm.snapshots]


@pytest.mark.parametrize(("action", "power"), [("stop", PowerState.OFF), ("suspend", PowerState.SUSPENDED)])
def test_power_down(lab, action, power):
    out = lab.gateway().vm_power(action)
    assert lab.vm.power == power and out["power"] == power.value


def test_power_start_from_off_bumps_epochs(lab):
    gw = lab.gateway()
    gw.session_status()
    lab.vm.power = PowerState.OFF
    out = gw.vm_power("start")
    assert out["power"] == "running" and lab.vm.power == PowerState.RUNNING
    assert gw.session_status()["backends"]["x64"]["epoch"] >= 1


def test_power_reset_is_hard_stop_then_start(lab):
    gw = lab.gateway()
    gw.vm_power("reset")
    names = [c for c in lab.vm.calls if c[0] in ("stop", "start")]
    assert names[-2:] == [("stop", (True,)), ("start", (False,))]


def test_power_invalid_action(lab):
    with pytest.raises(InvalidArgument):
        lab.gateway().vm_power("explode")


def test_power_refused_while_analyzing(lab):
    gw = lab.gateway()
    gw.analysis_start(str(lab.sample()))
    with pytest.raises(StateViolation):
        gw.vm_power("stop")


def test_start_blocking_vmrun_is_bounded_by_power_polling(lab):
    """``vmrun start`` may block for minutes although the VM already runs (phase 0)."""
    release = threading.Event()
    real_start = lab.vm.start

    def slow_start(*, gui=False):
        real_start(gui=gui)  # the VM is running right away ...
        release.wait(10)  # ... but vmrun does not return

    lab.vm.start = slow_start  # type: ignore[method-assign]
    lab.vm.power = PowerState.OFF
    gw = lab.gateway(start_join_s=0.05)
    try:
        assert gw.vm_power("start")["power"] == "running"
    finally:
        release.set()


def test_screenshot_without_a_job(lab):
    out = lab.gateway().vm_screenshot()
    p = Path(out["host_path"])
    assert p.is_file() and p.parent == Path(lab.config.jobs_root) / "_screens"
    if POSIX:
        assert stat.S_IMODE(p.stat().st_mode) == 0o600


def test_screenshot_goes_into_the_active_job(lab):
    gw = lab.gateway()
    job_id = gw.analysis_start(str(lab.sample()))["job_id"]
    p = Path(gw.vm_screenshot()["host_path"])
    assert p.is_relative_to(Path(lab.config.jobs_root) / job_id)
    assert gw.vm_screenshot()["host_path"] != str(p)  # never overwritten


def test_vm_tools_in_endpoint_mode_raise_config_error(tmp_path):
    prof = ProfileConfig(name="remote", mode="endpoint", token_source="env", require_isolation=False,
                         backends=(BackendConfig(id="x64", arch="x64", url="http://127.0.0.1:1/",
                                                 token_env="T"),))
    cfg = GatewayConfig(jobs_root=str(tmp_path / "jobs"), profiles={"remote": prof})
    rt = build_runtime(cfg, "remote", environ={"T": "0" * 32}, cache_dir=tmp_path / "c")
    gw = Gateway(cfg, runtime_factory=lambda name: rt)
    try:
        for call in (gw.vm_snapshots_list, gw.vm_snapshot_revert, lambda: gw.vm_power("start"),
                     gw.vm_screenshot, lambda: gw.vm_snapshot_take("x")):
            with pytest.raises(ConfigError):
                call()
    finally:
        gw.close()
