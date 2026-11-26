"""``x64dbg-vm-gateway demo``: the installation self-test, driven through ``cli.main`` on the
FakeLab (real gateway, fake VM / guest / plugin servers).

The demo copies a bundled benign sample into a private directory of its own, builds its own
gateway whose upload_roots hold only that directory (the config the MCP clients use is never
changed), refuses to run next to a serving gateway or a live job, and runs
analysis_start -> SetBreakpoint kernel32.Sleep -> run (until paused in kernel32, at most 4)
-> GetCallStack -> analysis_collect -> analysis_finish(revert=true), cleaning up its own job
when a step fails."""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path
from typing import Any

import pytest

from tests.fakes.fake_app import FakeApp
from tests.fakes.fake_runtime import make_lab, make_pe
from tests.unit.test_cli import run
from x64dbg_vm_gateway import sample_bundle
from x64dbg_vm_gateway.contracts import JobState
from x64dbg_vm_gateway.frontends import cli, demo
from x64dbg_vm_gateway.jobs import JobStore

KERNEL32 = 0x7FFC12340000


def state_text(module: str, address: int = 0x401000) -> str:
    return (f"isDebugging: true\nisRunning: false\npid: 4321\nstatus: PAUSED\ncurrentAddress: 0x{address:X}\n"
            f"currentModule: {module}\nstackPointer: 0x14FE00")


class DemoLab:
    """A FakeLab wired into the CLI: ``wiring.build_app`` builds a lab gateway from the config the
    demo passes, the bundled samples and the demo's work directory live under tmp_path."""

    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, backends: tuple[str, ...]) -> None:
        self.lab = make_lab(tmp_path, backends=backends)
        self.bundle = tmp_path / "bundle"
        self.bundle.mkdir()
        (self.bundle / "e2e_sample_x86_64.exe").write_bytes(make_pe(machine=0x8664, pad=b"x64 demo"))
        (self.bundle / "e2e_sample_x86.exe").write_bytes(make_pe(machine=0x14C, pad=b"x86 demo"))
        self.work = tmp_path / "cache" / "demo"
        self.configs: list[Any] = []
        self.kernel32_after = {b: 2 for b in backends}  # GetDebugState says kernel32 from this run on
        monkeypatch.setattr(sample_bundle, "bundle_root", lambda: self.bundle)
        monkeypatch.setattr(demo, "demo_root", lambda: self.work)
        monkeypatch.setattr(cli, "_load_config", lambda args: self.lab.config)
        monkeypatch.setattr(demo, "POLL_S", 0.0)
        wiring = types.SimpleNamespace(build_app=self.build_app)
        monkeypatch.setitem(sys.modules, "x64dbg_vm_gateway.wiring", wiring)
        for bid in backends:
            self.lab.servers[bid].on_tool("GetDebugState", self._debug_state(bid))

    def _debug_state(self, bid: str) -> Any:
        srv = self.lab.servers[bid]

        def answer(_args: dict[str, Any]) -> str:
            runs = len(srv.tool_calls("run"))
            if runs >= self.kernel32_after[bid]:
                return state_text("kernel32.dll", KERNEL32 + 0x1234)
            loaded = srv.tool_calls("LoadBinary")
            name = str(loaded[-1].arguments.get("filePath", "")).rsplit("\\", 1)[-1] if loaded else "?"
            return state_text(name)

        return answer

    def build_app(self, config: Any, profile: str | None = None, environ: Any = None) -> Any:
        self.configs.append(config)
        original = self.lab.config
        self.lab.config = config
        try:
            return self.lab.gateway()
        finally:
            self.lab.config = original

    def jobs(self) -> list[Any]:
        with JobStore(Path(self.lab.config.jobs_root)) as store:
            return store.list()

    def reverts(self) -> int:
        return sum(1 for c in self.lab.vm.calls if c[0] == "revert_snapshot")


@pytest.fixture
def dlab(tmp_path, monkeypatch):
    d = DemoLab(tmp_path, monkeypatch, ("x64", "x32"))
    yield d
    d.lab.close()


@pytest.fixture
def dlab64(tmp_path, monkeypatch):
    d = DemoLab(tmp_path, monkeypatch, ("x64",))
    yield d
    d.lab.close()


# ── the happy path ──────────────────────────────────────────────────
def test_demo_x64_passes_and_leaves_a_reverted_vm(dlab64, capsys):
    before = dlab64.reverts()
    assert run(["demo", "--arch", "x64"]) == 0
    out = capsys.readouterr().out
    for step in ("analysis_start", "SetBreakpoint", "run 1/4", "run 2/4", "GetCallStack", "analysis_collect",
                 "analysis_finish"):
        assert step in out, step
    assert "run 3/4" not in out
    assert "kernel32.dll" in out and "demo x64: PASS" in out and out.rstrip().endswith("demo: PASS (x64)")
    srv = dlab64.lab.servers["x64"]
    assert [c.arguments for c in srv.tool_calls("SetBreakpoint")] == [{"target": "kernel32.Sleep"}]
    assert len(srv.tool_calls("run")) == 2 and len(srv.tool_calls("GetCallStack")) == 1
    (job,) = dlab64.jobs()
    assert job.state == JobState.DONE and job.flags["reverted"] is True
    assert job.sample.original_name == "e2e_sample_x86_64.exe"
    assert dlab64.reverts() == before + 2  # analysis_start and analysis_finish


def test_demo_uses_a_private_upload_root_of_its_own(dlab64, capsys):
    mcp_roots = dlab64.lab.config.upload_roots
    assert run(["demo", "--arch", "x64"]) == 0
    (config,) = dlab64.configs
    (root,) = config.upload_roots
    assert Path(root).parent == dlab64.work  # a fresh directory below the demo's work dir
    assert dlab64.lab.config.upload_roots == mcp_roots  # the clients' config is untouched
    assert not Path(root).exists()  # removed after the run
    (job,) = dlab64.jobs()
    assert job.sample.host_path.startswith(str(dlab64.lab.config.jobs_root))  # the job's own copy


def test_demo_both_architectures_by_default(dlab, capsys):
    assert run(["demo"]) == 0  # default: every architecture the profile has a backend for
    out = capsys.readouterr().out
    assert "demo x64: PASS" in out and "demo x32: PASS" in out and "demo: PASS (x64, x32)" in out
    jobs = dlab.jobs()
    assert sorted((j.backend_id, j.state.value) for j in jobs) == [("x32", "DONE"), ("x64", "DONE")]
    assert dlab.lab.servers["x32"].tool_calls("LoadBinary")
    assert run(["demo", "--arch", "both"]) == 0


def test_demo_json(dlab64, capsys):
    assert run(["--json", "demo", "--arch", "x64"]) == 0
    data = json.loads(capsys.readouterr().out)  # one document, no step lines around it
    assert data["ok"] is True and data["profile"] == "lab" and [r["arch"] for r in data["results"]] == ["x64"]
    (res,) = data["results"]
    assert res["ok"] is True and res["failed_step"] is None and res["job_id"]
    names = [s["step"] for s in res["steps"]]
    assert names == ["analysis_start", "SetBreakpoint", "run 1/4", "run 2/4", "GetCallStack",
                     "analysis_collect", "analysis_finish"]
    assert all(s["ok"] and isinstance(s["seconds"], float) for s in res["steps"])
    assert res["sample"]["name"] == "e2e_sample_x86_64.exe" and len(res["sample"]["sha256"]) == 64


# ── failures: FAIL, hints, cleanup of the demo's own job ────────────
def test_demo_fails_when_kernel32_is_never_reached_and_cleans_up(dlab64, capsys):
    dlab64.kernel32_after["x64"] = 99
    assert run(["demo", "--arch", "x64"]) == 1
    out = capsys.readouterr().out
    assert "run 4/4" in out and "run 5/4" not in out
    assert "demo x64: FAIL" in out and "demo: FAIL" in out
    assert "kernel32.Sleep" in out.split("demo: FAIL", 1)[1]  # the hint says what was expected
    assert "cleanup: analysis_collect" in out and "cleanup: analysis_finish" in out
    (job,) = dlab64.jobs()
    assert job.state == JobState.DONE  # the VM was reverted, the profile is free again


def test_demo_fails_on_a_breakpoint_error_and_cleans_up(dlab64, capsys):
    failure = {"content": [{"type": "text", "text": "no such symbol"}], "isError": True}
    dlab64.lab.servers["x64"].on_tool("SetBreakpoint", failure)
    assert run(["--json", "demo", "--arch", "x64"]) == 1
    data = json.loads(capsys.readouterr().out)
    (res,) = data["results"]
    assert data["ok"] is False and res["failed_step"] == "SetBreakpoint"
    bp = next(s for s in res["steps"] if s["step"] == "SetBreakpoint")
    assert bp["ok"] is False and "no such symbol" in bp["detail"]
    cleanup = [s for s in res["steps"] if s.get("cleanup")]
    assert [s["step"] for s in cleanup] == ["cleanup: analysis_collect", "cleanup: analysis_finish"]
    assert res["hints"]
    (job,) = dlab64.jobs()
    assert job.state == JobState.DONE


def test_demo_a_start_without_a_pause_fails_and_cleans_up(dlab64, capsys):
    dlab64.lab.servers["x64"].on_tool("WaitForPause", {"content": [{"type": "text", "text": "timeout"}],
                                                       "isError": True})
    assert run(["--json", "demo", "--arch", "x64"]) == 1
    (res,) = json.loads(capsys.readouterr().out)["results"]
    assert res["failed_step"] == "analysis_start" and "pause" in res["steps"][0]["detail"]
    assert [s["step"] for s in res["steps"][1:]] == ["cleanup: analysis_collect", "cleanup: analysis_finish"]
    (job,) = dlab64.jobs()
    assert job.state == JobState.DONE and job.id == res["job_id"]


def test_demo_discards_its_own_job_when_the_cleanup_collection_stays_partial(dlab64, capsys):
    dlab64.kernel32_after["x64"] = 99
    dlab64.lab.servers["x64"].on_tool("SaveDatabase", {"content": [{"type": "text", "text": "disk full"}],
                                                       "isError": True})
    assert run(["--json", "demo", "--arch", "x64"]) == 1
    (res,) = json.loads(capsys.readouterr().out)["results"]
    cleanup = [s["step"] for s in res["steps"] if s.get("cleanup")]
    assert cleanup == ["cleanup: analysis_collect", "cleanup: discard", "cleanup: analysis_finish"]
    assert all(s["ok"] for s in res["steps"] if s.get("cleanup"))
    (job,) = dlab64.jobs()
    assert job.state == JobState.DONE and job.flags.get("reverted") is True
    assert any(h["to"] == "DISCARDED" for h in job.history)


def test_demo_a_failed_start_reports_the_gateway_error(dlab64, capsys):
    dlab64.lab.set_profile(clean_snapshot="NO_SUCH_SNAPSHOT")
    assert run(["demo", "--arch", "x64"]) == 1
    out = capsys.readouterr().out
    assert "[FAIL]" in out and "analysis_start" in out and "doctor" in out  # the hint names doctor


def test_demo_x32_without_an_x32_backend_is_refused(dlab64, capsys):
    assert run(["demo", "--arch", "x32"]) == 1
    err = capsys.readouterr().err
    assert "x32" in err and "backend" in err
    assert dlab64.jobs() == []


def test_demo_unknown_arch_is_a_usage_error(dlab64, capsys):
    assert run(["demo", "--arch", "arm64"]) == 2


# ── refusals: before anything reaches the VM ────────────────────────
def test_demo_refuses_while_a_job_is_live(dlab64, capsys):
    with JobStore(Path(dlab64.lab.config.jobs_root)) as store:
        live = store.create("lab", "C:\\mcp\\jobs")
    before = len(dlab64.lab.vm.calls)
    assert run(["demo", "--arch", "x64"]) == 1
    err = capsys.readouterr().err
    assert live.id in err and "STATE_VIOLATION" in err and "discard" in err
    assert len(dlab64.lab.vm.calls) == before  # nothing was reverted
    assert not dlab64.lab.servers["x64"].tool_calls("LoadBinary")


def test_a_live_job_of_another_profile_does_not_block_the_demo(dlab64, capsys):
    with JobStore(Path(dlab64.lab.config.jobs_root)) as store:
        other = store.create("other-vm", "C:\\mcp\\jobs")  # another profile: another VM
    assert run(["demo", "--arch", "x64"]) == 0
    states = {j.id: j.state for j in dlab64.jobs()}
    assert states[other.id] == JobState.CREATED  # untouched


def test_demo_refuses_while_another_gateway_serves_the_jobs_root(dlab64, capsys):
    with JobStore(Path(dlab64.lab.config.jobs_root)):  # stands in for a serving gateway (this pid)
        rc = run(["demo", "--arch", "x64"])
    assert rc == 1
    err = capsys.readouterr().err
    assert "LOCK_TIMEOUT" in err and "`demo` cannot run next to it" in err and "stop" in err
    assert not dlab64.lab.servers["x64"].tool_calls("LoadBinary")


def test_demo_without_bundled_samples_says_how_to_build_them(dlab64, capsys):
    for p in dlab64.bundle.iterdir():
        p.unlink()
    assert run(["demo", "--arch", "x64"]) == 1
    err = capsys.readouterr().err
    assert "e2e_sample_x86_64.exe" in err and "build.sh" in err
    assert dlab64.configs == []  # no gateway was built


def test_demo_needs_a_vmware_profile(dlab64, capsys):
    dlab64.lab.set_profile(mode="endpoint")
    assert run(["demo", "--arch", "x64"]) == 1
    assert "vmware" in capsys.readouterr().err
    assert dlab64.configs == []


def test_demo_is_listed_in_the_help(capsys):
    assert run(["--help"]) == 0
    assert "demo" in capsys.readouterr().out
    assert run(["demo", "--help"]) == 0
    out = capsys.readouterr().out
    assert "--arch" in out and "x64" in out and "both" in out and "reverts" in out


# ── long operations answer in_progress: the demo polls session_status ─
def test_demo_polls_operations_that_answer_in_progress():
    app = FakeApp()
    statuses = iter([
        {"operation": {"op_id": "op-1", "state": "running"}},
        {"operation": {"op_id": "op-1", "state": "done", "result": {"job_id": "20261126-101010-abcdef",
                                                                    "state": "ANALYZING", "loaded": True,
                                                                    "paused": True, "backend_id": "x64",
                                                                    "epoch": 1}}},
    ])
    app.results["session_status"] = lambda **_kw: next(statuses)
    app.results["analysis_start"] = {"state": "in_progress", "op_id": "op-1", "op": "analysis_start"}
    sleeps: list[float] = []
    runner = demo.DemoRun(app, sleep=sleeps.append, poll_s=0.5)
    result = runner.wait(app.analysis_start("/s/a.exe"), "analysis_start")
    assert result["state"] == "ANALYZING" and sleeps == [0.5, 0.5]


def test_demo_poll_reports_a_failed_operation():
    app = FakeApp()
    app.results["session_status"] = {"operation": {"op_id": "op-2", "state": "failed",
                                                   "error": {"code": "VM_NOT_READY", "message": "no tools",
                                                             "hint": "check VMware Tools"}}}
    runner = demo.DemoRun(app, sleep=lambda s: None, poll_s=0.0)
    with pytest.raises(demo.OperationFailed) as ei:
        runner.wait({"state": "in_progress", "op_id": "op-2", "op": "analysis_collect"}, "analysis_collect")
    assert ei.value.code == "VM_NOT_READY" and ei.value.hint == "check VMware Tools"
