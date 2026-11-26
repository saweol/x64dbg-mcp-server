"""Human-only clean-snapshot maintenance (no MCP tool): ``snapshot refresh --name NEW
[--set-clean]`` takes a new clean snapshot of the guest as it is now, after the readiness
checks; ``snapshot prune --keep N [--yes]`` lists the gateway's ``gw-*`` snapshots and the old
clean snapshots (``snapshot_ledger``) and deletes them only with --yes. Protected snapshots and
the current clean snapshot are never deleted.

Two harnesses: a FakeApp (flow, refusals, the config edit) and the fake lab (the real Gateway,
the real ``provision.take_clean_snapshot``, a FakeVm, fake plugin servers on 127.0.0.1)."""

from __future__ import annotations

import json
import sys
import tomllib
import types
from pathlib import Path
from typing import Any

import pytest

from tests.fakes.fake_app import FakeApp
from tests.fakes.fake_runtime import PROFILE, make_lab
from tests.unit.test_cli import run, write_config
from x64dbg_vm_gateway import config as gw_config
from x64dbg_vm_gateway import platform as gw_platform
from x64dbg_vm_gateway import provision as real_provision
from x64dbg_vm_gateway import snapshot_ledger
from x64dbg_vm_gateway.contracts import Snapshot
from x64dbg_vm_gateway.errors import LockTimeout, ProtectedSnapshotError, StateViolation, VmNotReady
from x64dbg_vm_gateway.frontends import cli
from x64dbg_vm_gateway.frontends.tool_defs import RESERVED_TOOL_NAMES
from x64dbg_vm_gateway.ps import DEFAULT_GUEST_TMP_DIR

READY = {"ok": True, "checks": [{"name": "vmrun", "ok": True, "detail": "/usr/bin/vmrun", "hint": None}]}
JOB_A = "20261101-101010-aaaaaa"
JOB_B = "20261110-101010-bbbbbb"
JOB_C = "20261120-101010-cccccc"


@pytest.fixture(autouse=True)
def posix_host(monkeypatch) -> None:
    monkeypatch.setattr(cli, "_windows_host", lambda: False)


# ── FakeApp harness ─────────────────────────────────────────────────
@pytest.fixture
def cfg_path(tmp_path: Path) -> Path:
    return write_config(tmp_path)


@pytest.fixture
def fake() -> FakeApp:
    app = FakeApp()
    app.results["doctor"] = READY
    app.results["vm_snapshots_list"] = {"snapshots": [{"name": "MCP_CLEAN", "protected": True}]}
    return app


@pytest.fixture
def wiring(monkeypatch, fake) -> types.SimpleNamespace:
    calls: list[dict[str, Any]] = []

    def build_app(config: Any, profile: str | None = None, environ: Any = None) -> FakeApp:
        calls.append({"config": config, "profile": profile})
        return fake

    mod = types.SimpleNamespace(build_app=build_app, calls=calls)
    monkeypatch.setitem(sys.modules, "x64dbg_vm_gateway.wiring", mod)
    return mod


@pytest.fixture
def provision(monkeypatch) -> types.SimpleNamespace:
    calls: list[dict[str, Any]] = []

    def take_clean_snapshot(runtime: Any, name: str, **kw: Any) -> dict[str, Any]:
        calls.append({"name": name, **kw})
        runtime.log.append("take_clean_snapshot")
        return {"snapshot": {"name": name, "replaced": False}, "ready_s": 0.0, "readiness": {"x64": 401},
                "cleaned_guest_tmp": 0}

    mod = types.SimpleNamespace(take_clean_snapshot=take_clean_snapshot, calls=calls)
    monkeypatch.setitem(sys.modules, "x64dbg_vm_gateway.provision", mod)
    return mod


def json_run(argv: list[str], capsys) -> tuple[int, dict[str, Any]]:
    rc = run(argv)
    return rc, json.loads(capsys.readouterr().out)


def test_snapshot_is_listed_in_the_help_and_is_no_mcp_tool(capsys):
    assert run(["--help"]) == 0
    assert "snapshot" in capsys.readouterr().out
    assert run(["snapshot", "refresh", "--help"]) == 0
    out = capsys.readouterr().out
    assert "--name" in out and "--set-clean" in out and "--wait-ready" in out
    assert run(["snapshot", "prune", "--help"]) == 0
    out = capsys.readouterr().out
    assert "--keep" in out and "--yes" in out
    assert not any("refresh" in n or "prune" in n for n in RESERVED_TOOL_NAMES)


def test_snapshot_needs_an_action_and_refresh_a_name(cfg_path, wiring):
    assert run(["--config", str(cfg_path), "snapshot"]) == 2
    assert run(["--config", str(cfg_path), "snapshot", "refresh"]) == 2
    assert run(["--config", str(cfg_path), "snapshot", "prune"]) == 2
    assert wiring.calls == []


@pytest.mark.parametrize("name", ["a/b", "a\\b", " lead", "trail ", "gw-mine", "MCP_CLEAN", "mcp_clean",
                                  "tab\there"])
def test_refresh_refuses_unusable_names_before_contacting_anything(cfg_path, wiring, name, capsys):
    assert run(["--config", str(cfg_path), "snapshot", "refresh", "--name", name]) == 2
    assert wiring.calls == []


def test_refresh_takes_the_snapshot_holding_the_vm(cfg_path, wiring, provision, fake, capsys):
    rc, data = json_run(["--config", str(cfg_path), "--json", "snapshot", "refresh", "--name", "MCP_CLEAN_2"],
                        capsys)
    assert rc == 0, data
    names = [m for m, _ in fake.calls]
    assert names.index("open") < names.index("doctor") < names.index("runtime")  # jobs root claimed first
    assert fake.called("list_jobs")
    assert fake.runtimes[0].log == ["supervisor.pause", "lock.write", "take_clean_snapshot", "lock.release",
                                    "supervisor.resume"]
    (call,) = provision.calls
    assert call["name"] == "MCP_CLEAN_2" and call["wait_ready_s"] == 60.0
    assert data["ok"] is True and data["snapshot"] == "MCP_CLEAN_2"
    assert data["config"]["updated"] is False
    assert data["config"]["lines"] == ["clean_snapshot = 'MCP_CLEAN_2'",
                                       "protected_snapshots = ['MCP_CLEAN_2']"]


def test_refresh_without_set_clean_only_prints_the_lines(cfg_path, wiring, provision, capsys):
    before = cfg_path.read_text(encoding="utf-8")
    assert run(["--config", str(cfg_path), "snapshot", "refresh", "--name", "MCP_CLEAN_2"]) == 0
    out = capsys.readouterr().out
    assert cfg_path.read_text(encoding="utf-8") == before
    assert "clean_snapshot = 'MCP_CLEAN_2'" in out and "--set-clean" in out and "[profiles.win10]" in out


@pytest.mark.parametrize("state", ["ANALYZING", "COLLECTED", "DISCARDED", "CREATED"])
def test_refresh_refuses_while_a_job_is_live(cfg_path, wiring, provision, fake, capsys, state):
    jobs = [{"job_id": JOB_A, "state": state}]
    fake.results["list_jobs"] = {"profile": "win10", "jobs": jobs, "corrupt": []}
    rc, data = json_run(["--config", str(cfg_path), "--json", "snapshot", "refresh", "--name", "NEW"], capsys)
    assert rc == 1 and data["error"]["code"] == "STATE_VIOLATION" and JOB_A in data["error"]["message"]
    assert provision.calls == []


def test_refresh_ignores_finished_jobs(cfg_path, wiring, provision, fake, capsys):
    jobs = [{"job_id": JOB_A, "state": "DONE"}, {"job_id": JOB_B, "state": "FAILED"}]
    fake.results["list_jobs"] = {"profile": "win10", "jobs": jobs, "corrupt": []}
    assert run(["--config", str(cfg_path), "snapshot", "refresh", "--name", "NEW"]) == 0, capsys.readouterr()
    assert len(provision.calls) == 1


def test_refresh_refuses_a_corrupt_job(cfg_path, wiring, provision, fake, capsys):
    fake.results["list_jobs"] = {"profile": "win10", "jobs": [],
                                 "corrupt": [{"job_id": JOB_A, "profile": None, "corrupt": True}]}
    assert run(["--config", str(cfg_path), "snapshot", "refresh", "--name", "NEW"]) == 1
    assert JOB_A in capsys.readouterr().err and provision.calls == []


@pytest.mark.parametrize("check", ["single_vm_instance", "vm_power", "tools", "guest_credentials",
                                   "backend:x64:reachable", "backend:x64:token", "isolation"])
def test_refresh_refuses_a_guest_that_is_not_ready(cfg_path, wiring, provision, fake, capsys, check):
    fake.results["doctor"] = {"ok": False, "checks": [
        # a missing clean snapshot does not matter for a refresh
        {"name": "clean_snapshot", "ok": False, "detail": "MCP_CLEAN missing", "hint": None},
        {"name": check, "ok": False, "detail": "broken", "hint": f"fix {check}"}]}
    assert run(["--config", str(cfg_path), "snapshot", "refresh", "--name", "NEW"]) == 1
    captured = capsys.readouterr()
    assert check in captured.err and f"fix {check}" in captured.out + captured.err
    assert "clean_snapshot" not in captured.err.split("not ready", 1)[1].splitlines()[0]
    assert provision.calls == []


def test_refresh_does_not_mind_a_missing_clean_snapshot(cfg_path, wiring, provision, fake, capsys):
    fake.results["doctor"] = {"ok": False, "checks": [
        {"name": "clean_snapshot", "ok": False, "detail": "MCP_CLEAN missing", "hint": None}]}
    assert run(["--config", str(cfg_path), "snapshot", "refresh", "--name", "NEW"]) == 0, capsys.readouterr()


def test_refresh_refuses_an_existing_snapshot_name(cfg_path, wiring, provision, fake, capsys):
    fake.results["vm_snapshots_list"] = {"snapshots": [{"name": "new", "protected": False}]}
    rc, data = json_run(["--config", str(cfg_path), "--json", "snapshot", "refresh", "--name", "NEW"], capsys)
    assert rc == 1 and data["error"]["code"] == "STATE_VIOLATION" and provision.calls == []


def test_refresh_while_a_gateway_serves_names_its_pid(cfg_path, wiring, provision, fake, capsys):
    fake.fail["open"] = LockTimeout("jobs root is in use", details={"lock": "/j/.lock", "owner_pid": 4242})
    assert run(["--config", str(cfg_path), "snapshot", "refresh", "--name", "NEW"]) == 1
    err = capsys.readouterr().err
    assert "pid 4242" in err and "snapshot" in err and provision.calls == []


def test_refresh_records_the_old_and_the_new_clean_snapshot(cfg_path, wiring, provision, capsys):
    assert run(["--config", str(cfg_path), "snapshot", "refresh", "--name", "MCP_CLEAN_2"]) == 0
    conf = gw_config.load_config(cfg_path, environ={})
    entries = snapshot_ledger.entries(conf.jobs_root_path, profile="win10", vmx="/vms/win10/win10.vmx")
    # the replaced one was the clean snapshot; the new one is not, until the config says so
    assert [(e.name, e.source, e.was_clean) for e in entries] == [("MCP_CLEAN", "clean_snapshot", True),
                                                                  ("MCP_CLEAN_2", "refresh", False)]


def test_refresh_with_set_clean_records_the_new_one_as_clean(init_config, wiring, provision, capsys):
    assert run(["--config", str(init_config), "snapshot", "refresh", "--name", "C2", "--set-clean"]) == 0
    conf = gw_config.load_config(init_config, environ={})
    entries = snapshot_ledger.entries(conf.jobs_root_path, profile="win10", vmx="/vms/w10/w10.vmx")
    assert [(e.name, e.was_clean) for e in entries] == [("MCP_CLEAN", True), ("C2", True)]


# ── --set-clean ─────────────────────────────────────────────────────
@pytest.fixture
def init_config(tmp_path, monkeypatch) -> Path:
    """A config written by `init` (the only kind --set-clean edits)."""
    monkeypatch.setattr(gw_platform, "find_vmrun", lambda configured="auto", **kw: "/usr/bin/vmrun")
    path = tmp_path / "init.toml"
    assert run(["--config", str(path), "init", "--non-interactive", "--vmx", "/vms/w10/w10.vmx",
                "--guest-user", "analyst", "--x64dbg-root", "C:\\x64dbg\\release",
                "--jobs-root", str(tmp_path / "jobs")]) == 0
    return path


def test_set_clean_updates_a_config_written_by_init(init_config, wiring, provision, capsys):
    before = init_config.read_text(encoding="utf-8")
    rc, data = json_run(["--config", str(init_config), "--json", "snapshot", "refresh",
                         "--name", "MCP_CLEAN_2", "--set-clean"], capsys)
    assert rc == 0, data
    assert data["config"]["updated"] is True and data["config"]["unprotected"] == "MCP_CLEAN"
    prof = gw_config.load_config(init_config, environ={}).profile()
    assert prof.clean_snapshot == "MCP_CLEAN_2" and prof.protected_snapshots == ("MCP_CLEAN_2",)
    after = init_config.read_text(encoding="utf-8")
    changed = [(a, b) for a, b in zip(before.splitlines(), after.splitlines(), strict=True) if a != b]
    assert changed == [("clean_snapshot = 'MCP_CLEAN'", "clean_snapshot = 'MCP_CLEAN_2'"),
                       ("protected_snapshots = ['MCP_CLEAN']", "protected_snapshots = ['MCP_CLEAN_2']")]


def test_set_clean_keeps_other_protected_snapshots(init_config, wiring, provision, capsys):
    text = init_config.read_text(encoding="utf-8").replace("protected_snapshots = ['MCP_CLEAN']",
                                                           "protected_snapshots = ['BASE', 'MCP_CLEAN']")
    init_config.write_text(text, encoding="utf-8")
    assert run(["--config", str(init_config), "snapshot", "refresh", "--name", "C2", "--set-clean"]) == 0
    prof = gw_config.load_config(init_config, environ={}).profile()
    assert prof.clean_snapshot == "C2" and prof.protected_snapshots == ("BASE", "C2")


def test_set_clean_never_edits_a_hand_written_config(cfg_path, wiring, provision, capsys):
    before = cfg_path.read_text(encoding="utf-8")
    rc, data = json_run(["--config", str(cfg_path), "--json", "snapshot", "refresh", "--name", "C2",
                         "--set-clean"], capsys)
    assert rc == 0 and data["config"]["updated"] is False and "init" in data["config"]["reason"]
    assert cfg_path.read_text(encoding="utf-8") == before


def test_set_clean_gives_up_when_the_edit_would_change_more(init_config, wiring, provision, capsys):
    """The generated lines are gone (hand-edited into another shape): nothing is rewritten."""
    text = init_config.read_text(encoding="utf-8").replace(
        "protected_snapshots = ['MCP_CLEAN']", "protected_snapshots = [\n  'MCP_CLEAN',\n]")
    init_config.write_text(text, encoding="utf-8")
    rc, data = json_run(["--config", str(init_config), "--json", "snapshot", "refresh", "--name", "C2",
                         "--set-clean"], capsys)
    assert rc == 0 and data["config"]["updated"] is False
    assert init_config.read_text(encoding="utf-8") == text


# ── the clean snapshot ledger ───────────────────────────────────────
def test_ledger_keeps_each_snapshot_once_per_profile_and_vm(tmp_path):
    root = tmp_path / "jobs"
    kw = {"profile": "p", "vmx": "/v/a.vmx"}
    assert snapshot_ledger.record_taken(root, **kw, name="C1", source="provision", clean=True) is True
    assert snapshot_ledger.record_taken(root, profile="p", vmx="/v/b.vmx", name="C1", source="provision",
                                        clean=False) is True
    assert snapshot_ledger.record_taken(root, profile="q", vmx="/v/a.vmx", name="C2", source="provision",
                                        clean=False) is True
    assert [e.name for e in snapshot_ledger.entries(root, **kw)] == ["C1"]
    assert [e.name for e in snapshot_ledger.entries(root, profile="q", vmx="/v/a.vmx")] == ["C2"]
    data = json.loads(snapshot_ledger.path_for(root).read_text(encoding="utf-8"))
    assert data["version"] == 1 and len(data["snapshots"]) == 3


def test_ledger_a_snapshot_taken_again_under_an_old_name_is_a_new_one(tmp_path):
    """Review finding: a re-used name must not keep the old entry's place (prune would call the
    snapshot just taken 'old')."""
    root = tmp_path / "jobs"
    kw = {"profile": "p", "vmx": "/v/a.vmx"}
    snapshot_ledger.mark_clean(root, **kw, name="A")
    snapshot_ledger.record_taken(root, **kw, name="B", source="refresh", clean=True)
    snapshot_ledger.record_taken(root, **kw, name="a", source="refresh", clean=False)
    assert [(e.name, e.was_clean) for e in snapshot_ledger.entries(root, **kw)] == [("B", True), ("a", False)]


def test_ledger_mark_clean_adds_or_flags_and_forget_removes(tmp_path):
    root = tmp_path / "jobs"
    kw = {"profile": "p", "vmx": "/v/a.vmx"}
    snapshot_ledger.record_taken(root, **kw, name="C1", source="refresh", clean=False)
    assert snapshot_ledger.mark_clean(root, **kw, name="c1") is True
    assert snapshot_ledger.mark_clean(root, **kw, name="C1") is False  # already flagged
    assert snapshot_ledger.mark_clean(root, **kw, name="C0") is True
    rows = [(e.name, e.was_clean) for e in snapshot_ledger.entries(root, **kw)]
    assert rows == [("C1", True), ("C0", True)]
    snapshot_ledger.forget(root, **kw, names=["c0"])
    assert [e.name for e in snapshot_ledger.entries(root, **kw)] == ["C1"]


def test_ledger_that_cannot_be_read_counts_as_empty_and_is_not_overwritten(tmp_path):
    root = tmp_path / "jobs"
    root.mkdir()
    snapshot_ledger.path_for(root).write_text("{not json", encoding="utf-8")
    kw = {"profile": "p", "vmx": "/v/a.vmx"}
    assert snapshot_ledger.entries(root, **kw) == []
    assert snapshot_ledger.record_taken(root, **kw, name="C1", source="provision", clean=True) is False
    assert snapshot_ledger.mark_clean(root, **kw, name="C1") is False
    snapshot_ledger.forget(root, **kw, names=["C1"])
    assert snapshot_ledger.path_for(root).read_text(encoding="utf-8") == "{not json"


def test_provision_records_the_clean_snapshot_it_took(cfg_path, wiring, fake, monkeypatch, capsys):
    monkeypatch.setenv("GW_TEST_GUEST_PW", "pw")
    mod = types.SimpleNamespace(provision_guest=lambda runtime, **kw: {
        "status": "ok", "rebooted": False, "snapshot": {"name": "MCP_CLEAN", "replaced": False}})
    monkeypatch.setitem(sys.modules, "x64dbg_vm_gateway.provision", mod)
    assert run(["--config", str(cfg_path), "provision", "--x64dbg-root", "C:\\x", "--no-reboot",
                "--snapshot", "MCP_CLEAN"]) == 0, capsys.readouterr()
    conf = gw_config.load_config(cfg_path, environ={})
    entries = snapshot_ledger.entries(conf.jobs_root_path, profile="win10", vmx="/vms/win10/win10.vmx")
    assert [(e.name, e.source, e.was_clean) for e in entries] == [("MCP_CLEAN", "provision", True)]


# ── the fake lab: real Gateway, FakeVm, real take_clean_snapshot ────
@pytest.fixture
def lab(tmp_path, monkeypatch):
    lab = make_lab(tmp_path / "lab", protected_snapshots=("MCP_CLEAN", "BASE"))
    gw = lab.gateway()
    monkeypatch.setitem(sys.modules, "x64dbg_vm_gateway.wiring",
                        types.SimpleNamespace(build_app=lambda *a, **kw: gw))
    monkeypatch.setitem(sys.modules, "x64dbg_vm_gateway.provision", real_provision)
    lab.gw = gw
    yield lab
    lab.close()


def lab_config(lab, tmp_path: Path, other: dict[str, Any] | None = None) -> Path:
    """The config file the CLI reads: the lab's profile, as `init` would write it; ``other`` adds
    a second profile ("other") on the same VM."""
    prof = lab.profile
    doc = {"gateway": {"jobs_root": str(lab.tmp / "jobs"), "default_profile": PROFILE},
           "profiles": {PROFILE: {"mode": "vmware", "vmx": prof.vmx, "clean_snapshot": prof.clean_snapshot,
                                  "protected_snapshots": list(prof.protected_snapshots), "guest_user": "mcp",
                                  "guest_password_env": "GW_TEST_GUEST_PW",
                                  "backends": {"x64": {"port": 9094,
                                                       "config": "C:\\dbg\\x64\\mcp_config.json"}}}}}
    if other is not None:
        doc["profiles"]["other"] = {"mode": "vmware", "vmx": prof.vmx, "guest_user": "mcp",
                                    "guest_password_env": "GW_TEST_GUEST_PW", **other}
    path = tmp_path / "lab.toml"
    header = f"x64dbg-vm-gateway configuration (written by `{cli.PROG} init`)."
    path.write_text(cli.to_toml(doc, header=header), encoding="utf-8")
    return path


def snapshot_names(lab) -> list[str]:
    return [s.name for s in lab.vm.snapshots]


def test_lab_refresh_takes_a_new_clean_snapshot(lab, tmp_path, capsys):
    path = lab_config(lab, tmp_path)
    lab.guest.write(f"{DEFAULT_GUEST_TMP_DIR}\\ps-0123456789abcdef.out", b"stale")
    rc, data = json_run(["--config", str(path), "--json", "snapshot", "refresh", "--name", "MCP_CLEAN_2",
                         "--set-clean"], capsys)
    assert rc == 0, data
    assert snapshot_names(lab) == ["MCP_CLEAN", "BASE", "MCP_CLEAN_2"]
    assert ("take_snapshot", ("MCP_CLEAN_2",)) in lab.vm.calls
    assert data["result"]["cleaned_guest_tmp"] == 1 and data["result"]["readiness"]["x64"] in (200, 401)
    prof = gw_config.load_config(path, environ={}).profile()
    assert prof.clean_snapshot == "MCP_CLEAN_2" and prof.protected_snapshots == ("BASE", "MCP_CLEAN_2")


def test_lab_refresh_refuses_a_live_job(lab, tmp_path, capsys):
    lab.gw.analysis_start(str(lab.sample()))  # the CLI gets this gateway object, its store open
    path = lab_config(lab, tmp_path)
    rc, data = json_run(["--config", str(path), "--json", "snapshot", "refresh", "--name", "NEW"], capsys)
    assert rc == 1 and data["error"]["code"] == "STATE_VIOLATION"
    assert "NEW" not in snapshot_names(lab)


def _lab_snapshots(lab, *names: str) -> None:
    lab.vm.snapshots = [Snapshot(n) for n in names]


def _ledger(lab, path: Path, *clean: str, taken: tuple[str, ...] = ()) -> None:
    """Record ``clean`` as snapshots that were the profile's clean snapshot, ``taken`` as ones a
    refresh took without making them clean."""
    conf = gw_config.load_config(path, environ={})
    kw = {"profile": PROFILE, "vmx": lab.profile.vmx}
    for name in clean:
        snapshot_ledger.mark_clean(conf.jobs_root_path, **kw, name=name)
    for name in taken:
        snapshot_ledger.record_taken(conf.jobs_root_path, **kw, name=name, source="refresh", clean=False)


def test_lab_prune_is_a_dry_run_by_default(lab, tmp_path, capsys):
    path = lab_config(lab, tmp_path)
    _lab_snapshots(lab, "BASE", "OLD_CLEAN", "MCP_CLEAN", f"gw-job-{JOB_A}", f"gw-job-{JOB_B}", "mine")
    _ledger(lab, path, "OLD_CLEAN", "MCP_CLEAN")
    rc, data = json_run(["--config", str(path), "--json", "snapshot", "prune", "--keep", "1"], capsys)
    assert rc == 0, data
    assert data["dry_run"] is True and data["deleted"] == []
    assert data["delete"] == [f"gw-job-{JOB_A}"]  # one old clean snapshot is within --keep 1
    actions = {s["name"]: s["action"] for s in data["snapshots"]}
    assert actions == {f"gw-job-{JOB_A}": "delete", f"gw-job-{JOB_B}": "keep", "OLD_CLEAN": "keep",
                       "MCP_CLEAN": "keep", "BASE": "keep"}
    assert "mine" not in actions and data["untouched"] == 1
    assert not any(c[0] == "delete_snapshot" for c in lab.vm.calls)


def test_lab_prune_yes_deletes_only_what_it_listed(lab, tmp_path, capsys):
    path = lab_config(lab, tmp_path)
    _lab_snapshots(lab, "BASE", "C0", "C1", "MCP_CLEAN", f"gw-job-{JOB_A}", f"gw-pre-revert-{JOB_B}",
                   f"gw-job-{JOB_C}", "gw-manual", "mine")
    _ledger(lab, path, "C0", "C1", "BASE", "MCP_CLEAN")  # BASE is protected, MCP_CLEAN is current
    rc, data = json_run(["--config", str(path), "--json", "snapshot", "prune", "--keep", "1", "--yes"],
                        capsys)
    assert rc == 0, data
    assert sorted(data["deleted"]) == sorted(["C0", f"gw-job-{JOB_A}", f"gw-pre-revert-{JOB_B}"])
    assert snapshot_names(lab) == ["BASE", "C1", "MCP_CLEAN", f"gw-job-{JOB_C}", "gw-manual", "mine"]
    reasons = {s["name"]: s["reason"] for s in data["snapshots"]}
    assert "protected" in reasons["BASE"] and "current clean" in reasons["MCP_CLEAN"]
    assert "not a job snapshot" in reasons["gw-manual"]


def test_lab_prune_keep_zero_still_spares_protected_and_current(lab, tmp_path, capsys):
    path = lab_config(lab, tmp_path)
    _lab_snapshots(lab, "BASE", "MCP_CLEAN", "C0", f"gw-job-{JOB_A}")
    _ledger(lab, path, "C0", "BASE", "MCP_CLEAN")
    rc, data = json_run(["--config", str(path), "--json", "snapshot", "prune", "--keep", "0", "--yes"],
                        capsys)
    assert rc == 0, data
    assert snapshot_names(lab) == ["BASE", "MCP_CLEAN"]


def test_lab_prune_keeps_a_refreshed_snapshot_that_never_was_the_clean_one(lab, tmp_path, capsys):
    """A refresh without --set-clean: the new snapshot is not in use yet, so it is no "old"
    clean snapshot, not even with --keep 0."""
    path = lab_config(lab, tmp_path)
    _lab_snapshots(lab, "MCP_CLEAN", "BASE", "C_OLD", "C_NEXT")
    _ledger(lab, path, "C_OLD", "MCP_CLEAN", taken=("C_NEXT",))
    rc, data = json_run(["--config", str(path), "--json", "snapshot", "prune", "--keep", "0", "--yes"],
                        capsys)
    assert rc == 0, data
    assert data["deleted"] == ["C_OLD"] and "C_NEXT" in snapshot_names(lab)
    assert "never the clean snapshot" in {s["name"]: s["reason"] for s in data["snapshots"]}["C_NEXT"]


def test_lab_refresh_with_the_clean_snapshot_missing_is_not_pruned_afterwards(lab, tmp_path, capsys):
    """Review finding: the configured clean snapshot is gone from the VM (refresh allows that);
    the snapshot a refresh takes then must not count as old."""
    path = lab_config(lab, tmp_path)
    _lab_snapshots(lab, "BASE")
    rc = run(["--config", str(path), "snapshot", "refresh", "--name", "V2"])
    assert rc == 0, capsys.readouterr()
    capsys.readouterr()
    lab.gw = lab.gateway()
    sys.modules["x64dbg_vm_gateway.wiring"] = types.SimpleNamespace(build_app=lambda *a, **kw: lab.gw)
    rc, data = json_run(["--config", str(path), "--json", "snapshot", "prune", "--keep", "0", "--yes"],
                        capsys)
    assert rc == 0, data
    assert data["deleted"] == [] and snapshot_names(lab) == ["BASE", "V2"]


def test_lab_prune_forgets_what_it_deleted(lab, tmp_path, capsys):
    path = lab_config(lab, tmp_path)
    _lab_snapshots(lab, "MCP_CLEAN", "BASE", "C0")
    _ledger(lab, path, "C0", "MCP_CLEAN")
    rc, data = json_run(["--config", str(path), "--json", "snapshot", "prune", "--keep", "0", "--yes"],
                        capsys)
    assert rc == 0 and data["deleted"] == ["C0"]
    conf = gw_config.load_config(path, environ={})
    names = [e.name for e in snapshot_ledger.entries(conf.jobs_root_path, profile=PROFILE,
                                                     vmx=lab.profile.vmx)]
    assert names == ["MCP_CLEAN"]


def test_lab_prune_never_deletes_what_the_plan_should_not_have_listed(lab, tmp_path, monkeypatch, capsys):
    """The last guard before each delete: protected and clean names, whatever the plan says."""
    path = lab_config(lab, tmp_path)
    _lab_snapshots(lab, "MCP_CLEAN", "BASE", "C0")
    rows = [cli._PruneRow("MCP_CLEAN", "delete", "bad plan"), cli._PruneRow("base", "delete", "bad plan"),
            cli._PruneRow("C0", "delete", "fine")]
    monkeypatch.setattr(cli, "_prune_plan", lambda *a, **kw: (rows, 0))
    rc, data = json_run(["--config", str(path), "--json", "snapshot", "prune", "--keep", "0", "--yes"],
                        capsys)
    assert rc == 0 and data["deleted"] == ["C0"] and snapshot_names(lab) == ["MCP_CLEAN", "BASE"]


def test_lab_prune_compares_names_without_case(lab, tmp_path, capsys):
    path = lab_config(lab, tmp_path)
    _lab_snapshots(lab, "mcp_clean", "base", "C0")
    _ledger(lab, path, "C0", "mcp_clean", "base")
    rc, data = json_run(["--config", str(path), "--json", "snapshot", "prune", "--keep", "0", "--yes"],
                        capsys)
    assert rc == 0 and data["deleted"] == ["C0"] and snapshot_names(lab) == ["mcp_clean", "base"]


def test_lab_prune_spares_the_clean_snapshot_of_another_profile_on_the_same_vm(lab, tmp_path, capsys):
    """Review finding: snapshots belong to the VM, so every profile on it protects its own."""
    path = lab_config(lab, tmp_path, other={"clean_snapshot": "OTHER_CLEAN", "protected_snapshots": ["KEEP"]})
    _lab_snapshots(lab, "MCP_CLEAN", "BASE", "OTHER_CLEAN", "KEEP", "C0")
    _ledger(lab, path, "C0", "OTHER_CLEAN", "KEEP", "MCP_CLEAN")
    rc, data = json_run(["--config", str(path), "--json", "snapshot", "prune", "--keep", "0", "--yes"],
                        capsys)
    assert rc == 0, data
    assert data["deleted"] == ["C0"]
    reasons = {s["name"]: s["reason"] for s in data["snapshots"]}
    assert "other" in reasons["OTHER_CLEAN"] and "other" in reasons["KEEP"]


def test_refresh_refuses_an_unfinished_job_of_another_profile_on_the_same_vm(tmp_path, wiring, provision,
                                                                            fake, capsys):
    cfg = write_config(tmp_path)
    text = cfg.read_text(encoding="utf-8") + """
[profiles.second]
mode = "vmware"
vmx = "/vms/win10/win10.vmx"
clean_snapshot = "SECOND_CLEAN"
guest_user = "analyst"
guest_password_env = "GW_TEST_GUEST_PW"
"""
    cfg.write_text(text, encoding="utf-8")
    fake.results["list_jobs"] = {"profile": None, "corrupt": [],
                                 "jobs": [{"job_id": JOB_A, "profile": "second", "state": "ANALYZING"},
                                          {"job_id": JOB_B, "profile": "elsewhere", "state": "ANALYZING"}]}
    rc, data = json_run(["--config", str(cfg), "--json", "snapshot", "refresh", "--name", "NEW"], capsys)
    assert rc == 1 and JOB_A in data["error"]["message"] and JOB_B not in data["error"]["message"]
    assert provision.calls == []


def test_lab_refresh_refuses_a_second_vm_instance(tmp_path, monkeypatch, capsys):
    """The real doctor's single_vm_instance check (an orphan vmware-vmx process) stops a refresh."""
    from tests.fakes.fake_vm_instances import InstanceVm

    lab = make_lab(tmp_path / "lab", protected_snapshots=("MCP_CLEAN", "BASE"))
    try:
        vm = InstanceVm()
        vm.ip, vm.snapshots = lab.vm.ip, list(lab.vm.snapshots)
        vm.add_orphan()
        lab.vm = vm
        gw = lab.gateway()
        wiring_mod = types.SimpleNamespace(build_app=lambda *a, **kw: gw)
        monkeypatch.setitem(sys.modules, "x64dbg_vm_gateway.wiring", wiring_mod)
        monkeypatch.setitem(sys.modules, "x64dbg_vm_gateway.provision", real_provision)
        path = lab_config(lab, tmp_path)
        rc = run(["--config", str(path), "snapshot", "refresh", "--name", "NEW"])
        err = capsys.readouterr().err
        assert rc == 1 and "single_vm_instance" in err and "NEW" not in snapshot_names(lab)
    finally:
        lab.close()


def test_lab_prune_spares_the_live_jobs_snapshots(lab, tmp_path, capsys):
    job_id = lab.gw.analysis_start(str(lab.sample()))["job_id"]
    path = lab_config(lab, tmp_path)
    _lab_snapshots(lab, "MCP_CLEAN", "BASE", f"gw-job-{JOB_A}", f"gw-job-{job_id}")
    rc, data = json_run(["--config", str(path), "--json", "snapshot", "prune", "--keep", "0", "--yes"],
                        capsys)
    assert rc == 0, data
    assert data["deleted"] == [f"gw-job-{JOB_A}"] and f"gw-job-{job_id}" in snapshot_names(lab)


def test_lab_prune_human_output(lab, tmp_path, capsys):
    path = lab_config(lab, tmp_path)
    _lab_snapshots(lab, "MCP_CLEAN", "BASE", f"gw-job-{JOB_A}")
    assert run(["--config", str(path), "snapshot", "prune", "--keep", "0"]) == 0
    out = capsys.readouterr().out
    assert f"delete  gw-job-{JOB_A}" in out and "keep    MCP_CLEAN" in out and "--yes" in out


def test_prune_keep_must_not_be_negative(cfg_path, wiring):
    assert run(["--config", str(cfg_path), "snapshot", "prune", "--keep", "-1"]) == 2
    assert wiring.calls == []


# ── provision.take_clean_snapshot ───────────────────────────────────
@pytest.fixture
def lab_rt(tmp_path):
    lab = make_lab(tmp_path / "lab")
    yield lab, lab.runtime()
    lab.close()


def test_take_clean_snapshot_waits_for_the_backends_and_takes_it(lab_rt):
    lab, rt = lab_rt
    probes: list[int] = []

    def probe(ip: str, port: int, timeout: float) -> int:
        probes.append(port)
        return 401

    res = real_provision.take_clean_snapshot(rt, "C2", http_probe=probe)
    assert res["snapshot"] == {"name": "C2", "replaced": False} and probes == [lab.servers["x64"].port]
    assert snapshot_names(lab)[-1] == "C2"


def test_take_clean_snapshot_never_replaces_a_snapshot(lab_rt):
    lab, rt = lab_rt
    with pytest.raises(StateViolation):
        real_provision.take_clean_snapshot(rt, "BASE", http_probe=lambda *a: 401)
    with pytest.raises((StateViolation, ProtectedSnapshotError)):
        real_provision.take_clean_snapshot(rt, "MCP_CLEAN", http_probe=lambda *a: 401)
    assert not any(c[0] in ("take_snapshot", "delete_snapshot") for c in lab.vm.calls)


def test_take_clean_snapshot_refuses_when_a_backend_does_not_answer(lab_rt):
    lab, rt = lab_rt
    with pytest.raises(VmNotReady):
        real_provision.take_clean_snapshot(rt, "C2", http_probe=lambda *a: None, wait_ready_s=10.0)
    assert not any(c[0] == "take_snapshot" for c in lab.vm.calls)


def test_the_lab_config_is_valid_toml(lab, tmp_path):
    assert tomllib.loads(lab_config(lab, tmp_path).read_text(encoding="utf-8"))["profiles"][PROFILE]
