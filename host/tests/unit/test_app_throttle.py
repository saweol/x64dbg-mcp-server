"""A plugin that locked the gateway out (HTTP 429, plugin v1.10) is THROTTLED, never relaunched."""

from __future__ import annotations

import pytest

from tests.fakes.fake_runtime import make_lab
from x64dbg_vm_gateway.errors import BackendThrottled


@pytest.fixture
def lab(tmp_path):
    lab = make_lab(tmp_path)
    yield lab
    lab.close()


def test_status_reports_a_locked_out_backend_as_throttled_without_relaunching(lab):
    gw = lab.gateway()
    gw.session_status()
    lab.servers["x64"].lock_out(60)
    backend = gw.session_status()["backends"]["x64"]
    assert backend["health"] == "THROTTLED"
    assert backend["health_details"]["retry_after_s"] == 60
    assert lab.launches == [] and lab.guest.calls_of("kill_process") == []


def test_mirrored_calls_against_a_locked_out_backend_surface_the_throttling(lab):
    gw = lab.gateway()
    gw.analysis_start(str(lab.sample()))
    srv = lab.servers["x64"]
    srv.lock_out(30)
    with pytest.raises(BackendThrottled) as ei:
        gw.call_mirrored("GetDebugState")  # read-only: still not retried
    assert ei.value.details["retry_after_s"] == 30
    assert ei.value.to_dict()["retryable"] is True
    with pytest.raises(BackendThrottled):
        gw.call_mirrored("StepOver")
    assert lab.launches == [] and lab.guest.calls_of("kill_process") == []
    srv.unlock()
    out = gw.call_mirrored("StepOver")
    assert out["is_error"] is False and out["epoch"] == 1  # no epoch change: nothing was lost


def test_doctor_reports_the_lockout_with_a_wait_hint(lab):
    gw = lab.gateway()
    lab.servers["x64"].lock_out(45)
    checks = {c["name"]: c for c in gw.doctor()["checks"]}
    reach = checks["backend:x64:reachable"]
    assert reach["ok"] is True and "locked" in reach["detail"]
    token = checks["backend:x64:token"]
    assert token["ok"] is False and "BACKEND_THROTTLED" in token["detail"]
    assert "45" in (token["hint"] or "")
    assert lab.launches == []
