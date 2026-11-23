"""GatewayApp.list_jobs / get_job (J-integ): read-only job views of the serving gateway."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.fakes.fake_app import FakeApp
from tests.fakes.fake_runtime import make_lab
from x64dbg_vm_gateway.app_api import GatewayApp
from x64dbg_vm_gateway.contracts import JobState
from x64dbg_vm_gateway.errors import ConfigError, InvalidJobId, JobNotFound


@pytest.fixture
def lab(tmp_path):
    lab = make_lab(tmp_path)
    yield lab
    lab.close()


def test_protocol_has_the_job_views():
    assert callable(GatewayApp.list_jobs) and callable(GatewayApp.get_job)
    assert isinstance(FakeApp(), GatewayApp)


def test_list_jobs_and_get_job(lab):
    gw = lab.gateway()
    assert gw.list_jobs() == {"profile": None, "jobs": [], "corrupt": []}
    job_id = gw.analysis_start(str(lab.sample()))["job_id"]
    listed = gw.list_jobs()
    assert [j["job_id"] for j in listed["jobs"]] == [job_id]
    assert listed["jobs"][0]["state"] == JobState.ANALYZING
    assert gw.list_jobs("lab")["profile"] == "lab"
    assert [j["job_id"] for j in gw.list_jobs("lab")["jobs"]] == [job_id]
    job = gw.get_job(job_id)
    assert job["job_id"] == job_id and job["state"] == JobState.ANALYZING
    assert job["history"][-1]["to"] == "ANALYZING"
    assert job["needs_recovery"] is False and job["recovery_hint"] is None and job["next_tool"] is None
    json.dumps(listed)
    json.dumps(job)


def test_job_views_change_nothing(lab):
    gw = lab.gateway()
    job_id = gw.analysis_start(str(lab.sample()))["job_id"]
    state = Path(lab.config.jobs_root) / job_id / "state.json"
    before = state.read_bytes()
    gw.list_jobs()
    gw.get_job(job_id)
    assert state.read_bytes() == before


def test_get_job_errors(lab):
    gw = lab.gateway()
    with pytest.raises(InvalidJobId):
        gw.get_job("../../etc/passwd")
    with pytest.raises(JobNotFound):
        gw.get_job("20261123-101010-abcdef")


def test_list_jobs_of_an_unknown_profile(lab):
    with pytest.raises(ConfigError):
        lab.gateway().list_jobs("nope")


def test_get_job_of_an_interrupted_job_says_how_to_recover(lab):
    gw1 = lab.gateway()
    job_id = gw1.analysis_start(str(lab.sample()))["job_id"]
    gw1.close()
    job = lab.gateway().get_job(job_id)
    assert job["needs_recovery"] is True
    assert "analysis_collect" in job["recovery_hint"] and job["next_tool"] == "analysis_collect"


# ── debuggers restarted outside a gateway (CLI install-plugin / provision) ──
def test_debuggers_restarted_by_the_cli_are_recorded_on_the_live_job(lab):
    # the CLI's epoch bump dies with its process: the job record keeps that the debuggee is gone
    gw1 = lab.gateway()
    job_id = gw1.analysis_start(str(lab.sample()))["job_id"]
    assert gw1.note_debuggers_restarted(None, "plugin reinstalled") == [job_id]
    assert gw1.get_job(job_id)["flags"]["debuggee_lost"] == "plugin reinstalled"
    gw1.close()
    gw2 = lab.gateway()  # the next gateway process
    (rec,) = gw2.session_status()["needs_recovery"]
    assert rec["job_id"] == job_id and rec["state"] == JobState.ANALYZING
    assert "plugin reinstalled" in rec["recovery_hint"] and "no longer loaded" in rec["recovery_hint"]
    shown = gw2.get_job(job_id)
    assert shown["needs_recovery"] is True and "no longer loaded" in shown["recovery_hint"]


def test_jobs_without_a_debuggee_are_not_marked(lab):
    gw = lab.gateway()
    job_id = gw.analysis_start(str(lab.sample()))["job_id"]
    gw.analysis_collect()
    gw.analysis_finish()
    assert gw.note_debuggers_restarted("lab", "guest rebooted by provision") == []
    assert "debuggee_lost" not in gw.get_job(job_id)["flags"]
