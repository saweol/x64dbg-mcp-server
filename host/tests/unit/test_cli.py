"""`x64dbg-vm-gateway` command line (plan 5.1): driven through ``cli.main([...])``
with a FakeApp. ``wiring`` and ``provision`` are replaced in ``sys.modules`` so
the CLI never builds a real gateway."""

from __future__ import annotations

import io
import json
import os
import stat
import sys
import types
from pathlib import Path
from typing import Any

import pytest

from tests.fakes.fake_app import FakeApp
from x64dbg_vm_gateway import config as gw_config
from x64dbg_vm_gateway import platform as gw_platform
from x64dbg_vm_gateway.contracts import Secret
from x64dbg_vm_gateway.errors import BackendAuthError, LockTimeout, StateViolation, VmrunNotFound
from x64dbg_vm_gateway.frontends import cli
from x64dbg_vm_gateway.jobs import JobStore

JOB_ID = "20261123-101010-abcdef"
ANY_ADDR = "0.0.0.0"  # noqa: S104 - a value under test, nothing binds


def write_config(tmp_path: Path, *, http_enabled: bool = False) -> Path:
    jobs = tmp_path / "jobs"
    text = f"""
[gateway]
jobs_root = "{jobs.as_posix()}"
default_profile = "win10"

[http]
enabled = {"true" if http_enabled else "false"}
token_envs = {{ admin = "GW_ADMIN" }}

[profiles.win10]
mode = "vmware"
vmx = "/vms/win10/win10.vmx"
clean_snapshot = "MCP_CLEAN"
guest_user = "analyst"
guest_password_env = "GW_TEST_GUEST_PW"

[profiles.win10.backends.x64]
port = 9094
config = 'C:\\x64dbg\\release\\x64\\mcp_config.json'
"""
    path = tmp_path / "config.toml"
    path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture
def cfg_path(tmp_path: Path) -> Path:
    return write_config(tmp_path)


@pytest.fixture
def fake() -> FakeApp:
    return FakeApp()


@pytest.fixture
def wiring(monkeypatch, fake) -> types.SimpleNamespace:
    calls: list[dict[str, Any]] = []

    def build_app(config: Any, profile: str | None = None, environ: Any = None) -> FakeApp:
        calls.append({"config": config, "profile": profile, "environ": environ})
        return fake

    mod = types.SimpleNamespace(build_app=build_app, calls=calls)
    monkeypatch.setitem(sys.modules, "x64dbg_vm_gateway.wiring", mod)
    return mod


@pytest.fixture
def provision(monkeypatch) -> types.SimpleNamespace:
    calls: list[tuple[str, Any, dict[str, Any]]] = []
    results: dict[str, Any] = {"provision_guest": {"ok": True, "steps": ["copied", "ran"]},
                               "install_plugin": {"ok": True, "installed": ["x64", "x32"]}}

    def answer(name: str, runtime: Any, kw: dict[str, Any]) -> Any:
        calls.append((name, runtime, kw))
        log = getattr(runtime, "log", None)
        if isinstance(log, list):
            log.append(name)  # proves where in the lock/pause sequence the call ran
        res = results[name]
        if isinstance(res, BaseException):
            raise res
        return res

    def provision_guest(runtime: Any, **kw: Any) -> dict[str, Any]:
        return answer("provision_guest", runtime, kw)

    def install_plugin(runtime: Any, **kw: Any) -> dict[str, Any]:
        return answer("install_plugin", runtime, kw)

    mod = types.SimpleNamespace(provision_guest=provision_guest, install_plugin=install_plugin, calls=calls,
                                results=results)
    monkeypatch.setitem(sys.modules, "x64dbg_vm_gateway.provision", mod)
    return mod


def run(argv: list[str]) -> int:
    return cli.main(argv)


# ── usage ───────────────────────────────────────────────────────────
def test_no_command_is_usage_error(capsys):
    assert run([]) == 2


def test_unknown_command_is_usage_error(capsys):
    assert run(["frobnicate"]) == 2


def test_help_exits_zero(capsys):
    assert run(["--help"]) == 0
    out = capsys.readouterr().out
    for cmd in ("serve", "doctor", "status", "init", "jobs", "discard", "provision", "install-plugin"):
        assert cmd in out


def test_missing_config_is_failure_with_hint(tmp_path, capsys, wiring):
    rc = run(["--config", str(tmp_path / "nope.toml"), "doctor"])
    assert rc == 1
    err = capsys.readouterr().err
    assert "CONFIG_INVALID" in err and "init" in err


# ── doctor / status ─────────────────────────────────────────────────
def test_doctor_ok(cfg_path, wiring, fake, capsys):
    assert run(["--config", str(cfg_path), "doctor"]) == 0
    out = capsys.readouterr().out
    assert "vmrun" in out
    assert fake.called("doctor") == [{"profile": None}]
    assert fake.closed
    assert wiring.calls[0]["config"].default_profile == "win10"


def test_doctor_failing_check_exits_1_and_shows_hint(cfg_path, wiring, fake, capsys):
    fake.results["doctor"] = {"ok": False, "checks": [
        {"name": "guest_credentials", "ok": False, "detail": "login failed",
         "hint": "check the password env"}]}
    assert run(["--config", str(cfg_path), "doctor", "--profile", "win10"]) == 1
    out = capsys.readouterr().out
    assert "guest_credentials" in out and "check the password env" in out
    assert fake.called("doctor") == [{"profile": "win10"}]
    assert wiring.calls[0]["profile"] == "win10"


def test_doctor_json_output(cfg_path, wiring, fake, capsys):
    assert run(["--config", str(cfg_path), "--json", "doctor"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["ok"] is True and data["checks"][0]["name"] == "vmrun"


def test_global_options_after_the_subcommand(cfg_path, wiring, fake, capsys):
    assert run(["doctor", "--config", str(cfg_path), "--json", "--profile", "win10"]) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True
    assert fake.called("doctor") == [{"profile": "win10"}]


def test_doctor_tolerates_malformed_checks(cfg_path, wiring, fake, capsys):
    fake.results["doctor"] = {"ok": False, "checks": ["not-a-dict", {"name": "vmx", "ok": False}]}
    assert run(["--config", str(cfg_path), "doctor"]) == 1
    assert "vmx" in capsys.readouterr().out


def test_status_prints_json(cfg_path, wiring, fake, capsys):
    fake.results["session_status"] = {"vm": {"power": "running"}, "job": {"id": JOB_ID}}
    assert run(["--config", str(cfg_path), "--json", "status"]) == 0
    assert json.loads(capsys.readouterr().out)["job"]["id"] == JOB_ID
    assert fake.closed


def test_gateway_error_prints_code_message_hint(cfg_path, wiring, fake, capsys):
    fake.fail["session_status"] = BackendAuthError("token rejected",
                                                   hint="re-run provision to rewrite the token")
    assert run(["--config", str(cfg_path), "status"]) == 1
    err = capsys.readouterr().err
    assert "BACKEND_AUTH" in err and "token rejected" in err and "re-run provision" in err
    assert fake.closed


def test_gateway_error_json(cfg_path, wiring, fake, capsys):
    fake.fail["session_status"] = LockTimeout("jobs root is locked", hint="stop the other gateway")
    assert run(["--config", str(cfg_path), "--json", "status"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["ok"] is False and data["error"]["code"] == "LOCK_TIMEOUT"


def test_unexpected_error_is_internal_without_details(cfg_path, wiring, fake, capsys):
    fake.fail["session_status"] = RuntimeError("password=hunter2")
    assert run(["--config", str(cfg_path), "status"]) == 1
    captured = capsys.readouterr()
    assert "INTERNAL" in captured.err
    assert "hunter2" not in captured.err + captured.out


# ── discard ─────────────────────────────────────────────────────────
def test_discard_with_yes(cfg_path, wiring, fake, capsys):
    assert run(["--config", str(cfg_path), "discard", JOB_ID, "--yes"]) == 0
    assert fake.called("discard_job") == [{"job_id": JOB_ID, "actor": "human-cli"}]
    assert fake.closed


def test_discard_asks_and_aborts(cfg_path, wiring, fake, monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda _prompt="": "n")
    assert run(["--config", str(cfg_path), "discard", JOB_ID]) == 1
    assert fake.called("discard_job") == []


def _input_like_the_builtin(answers: list[str]) -> Any:
    """Stand-in for input(): like the real one it writes its prompt argument to stdout."""
    it = iter(answers)

    def _input(prompt: str = "") -> str:
        sys.stdout.write(prompt)
        return next(it)

    return _input


def test_discard_asks_and_confirms(cfg_path, wiring, fake, monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", _input_like_the_builtin(["yes"]))
    assert run(["--config", str(cfg_path), "discard", JOB_ID]) == 0
    assert JOB_ID in capsys.readouterr().err  # the question goes to stderr
    assert fake.called("discard_job") == [{"job_id": JOB_ID, "actor": "human-cli"}]


def test_discard_prompt_keeps_json_stdout_clean(cfg_path, wiring, fake, monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", _input_like_the_builtin(["y"]))
    assert run(["--config", str(cfg_path), "--json", "discard", JOB_ID]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["state"] == "DISCARDED"
    assert JOB_ID in captured.err


def test_discard_eof_aborts(cfg_path, wiring, fake, monkeypatch, capsys):
    def eof(_prompt: str = "") -> str:
        raise EOFError

    monkeypatch.setattr("builtins.input", eof)
    assert run(["--config", str(cfg_path), "discard", JOB_ID]) == 1
    assert fake.called("discard_job") == []


def test_discard_refused_by_app(cfg_path, wiring, fake, capsys):
    fake.fail["discard_job"] = StateViolation("job is REVERTING", hint="wait")
    assert run(["--config", str(cfg_path), "discard", JOB_ID, "--yes"]) == 1
    assert "STATE_VIOLATION" in capsys.readouterr().err


def test_discard_requires_job_id(cfg_path, wiring):
    assert run(["--config", str(cfg_path), "discard"]) == 2


# ── jobs ────────────────────────────────────────────────────────────
def _make_job(tmp_path: Path) -> str:
    with JobStore(tmp_path / "jobs", id_factory=lambda: JOB_ID) as store:
        store.create("win10", "C:\\mcp\\jobs")
    return JOB_ID


def test_jobs_list_and_show(cfg_path, tmp_path, capsys):
    _make_job(tmp_path)
    (tmp_path / "jobs" / "20261123-111111-000000").mkdir()  # no state.json -> reported, not fatal
    assert run(["--config", str(cfg_path), "--json", "jobs", "list"]) == 0
    rows = json.loads(capsys.readouterr().out)
    by = {r["id"]: r for r in rows}
    assert by[JOB_ID]["state"] == "CREATED" and by[JOB_ID]["profile"] == "win10"
    assert by["20261123-111111-000000"]["state"] == "CORRUPT"

    assert run(["--config", str(cfg_path), "jobs"]) == 0  # default action: list (human table)
    assert JOB_ID in capsys.readouterr().out

    assert run(["--config", str(cfg_path), "--json", "jobs", "show", JOB_ID]) == 0
    job = json.loads(capsys.readouterr().out)
    assert job["id"] == JOB_ID and job["guest_root"] == "C:\\mcp\\jobs\\" + JOB_ID


def test_jobs_list_while_another_process_holds_the_store(cfg_path, tmp_path, capsys):
    _make_job(tmp_path)
    with JobStore(tmp_path / "jobs"):
        assert run(["--config", str(cfg_path), "--json", "jobs", "list"]) == 0
    assert JOB_ID in capsys.readouterr().out


def test_jobs_list_empty_root(cfg_path, capsys):
    assert run(["--config", str(cfg_path), "--json", "jobs", "list"]) == 0
    assert json.loads(capsys.readouterr().out) == []


def test_jobs_show_invalid_and_missing(cfg_path, tmp_path, capsys):
    assert run(["--config", str(cfg_path), "jobs", "show", "../../etc"]) == 1
    assert "INVALID_JOB_ID" in capsys.readouterr().err
    assert run(["--config", str(cfg_path), "jobs", "show", JOB_ID]) == 1
    assert "JOB_NOT_FOUND" in capsys.readouterr().err


def test_jobs_list_profile_filter_keeps_corrupt_rows(cfg_path, tmp_path, capsys):
    """A corrupt job's profile is unknown, so it is shown under every profile filter
    (the job store likewise lets it block every profile)."""
    _make_job(tmp_path)
    (tmp_path / "jobs" / "20261123-111111-000000").mkdir()
    assert run(["--config", str(cfg_path), "--json", "--profile", "other", "jobs", "list"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert [(r["id"], r["state"]) for r in rows] == [("20261123-111111-000000", "CORRUPT")]


def test_jobs_show_requires_id(cfg_path):
    assert run(["--config", str(cfg_path), "jobs", "show"]) == 2


# ── serve ───────────────────────────────────────────────────────────
def test_serve_stdio(cfg_path, wiring, fake, monkeypatch):
    from x64dbg_vm_gateway.frontends import mcp_server

    seen: list[Any] = []
    monkeypatch.setattr(mcp_server, "run_stdio", lambda app: seen.append(app))
    assert run(["--config", str(cfg_path), "serve"]) == 0
    assert seen == [fake] and fake.closed


def test_serve_http_requires_http_enabled(cfg_path, wiring, fake, monkeypatch, capsys):
    from x64dbg_vm_gateway.frontends import http_server

    monkeypatch.setattr(http_server, "serve_http", lambda *a, **k: pytest.fail("must not start"))
    assert run(["--config", str(cfg_path), "serve", "--transport", "http"]) == 1
    assert "http.enabled" in capsys.readouterr().err


def test_serve_http(tmp_path, wiring, fake, monkeypatch):
    from x64dbg_vm_gateway.frontends import http_server

    path = write_config(tmp_path, http_enabled=True)
    monkeypatch.setenv("GW_ADMIN", "admin-token-" + "x" * 20)
    seen: list[tuple[Any, ...]] = []

    def fake_serve(app: Any, http_cfg: Any, *, environ: Any = None, jobs_root: Any = None) -> None:
        seen.append((app, http_cfg, jobs_root))

    monkeypatch.setattr(http_server, "serve_http", fake_serve)
    assert run(["--config", str(path), "serve", "--transport", "http", "--profile", "win10"]) == 0
    app, http_cfg, jobs_root = seen[0]
    assert app is fake and http_cfg.enabled is True and Path(jobs_root) == tmp_path / "jobs"
    assert wiring.calls[0]["profile"] == "win10" and fake.closed


def test_serve_http_without_tokens_fails_before_building_the_app(tmp_path, wiring, monkeypatch, capsys):
    from x64dbg_vm_gateway.frontends import http_server

    path = write_config(tmp_path, http_enabled=True)
    monkeypatch.delenv("GW_ADMIN", raising=False)
    monkeypatch.setattr(http_server, "serve_http", lambda *a, **k: pytest.fail("must not start"))
    assert run(["--config", str(path), "serve", "--transport", "http"]) == 1
    assert "GW_ADMIN" not in capsys.readouterr().out
    assert wiring.calls == []


def test_serve_rejects_bad_transport(cfg_path, wiring):
    assert run(["--config", str(cfg_path), "serve", "--transport", "carrier-pigeon"]) == 2


# ── provision / install-plugin ──────────────────────────────────────
def test_provision_passes_runtime_and_options(cfg_path, wiring, provision, fake, monkeypatch, capsys):
    monkeypatch.setenv("GW_TEST_GUEST_PW", "guest-pass")
    rc = run(["--config", str(cfg_path), "provision", "--x64dbg-root", "C:\\x64dbg\\release",
              "--bind", ANY_ADDR, "--snapshot", "MCP_CLEAN", "--no-reboot"])
    assert rc == 0, capsys.readouterr()
    name, runtime, kw = provision.calls[0]
    assert name == "provision_guest" and runtime is fake.runtimes[0]
    assert kw["x64dbg_root"] == "C:\\x64dbg\\release"
    assert kw["user"] == "analyst"  # from the profile
    assert isinstance(kw["password"], Secret) and kw["password"].reveal() == "guest-pass"
    assert kw["autologon"] is True and kw["reboot"] is False and kw["bind"] == ANY_ADDR
    assert kw["clean_snapshot"] == "MCP_CLEAN" and kw["wait_ready_s"] > 0
    out = capsys.readouterr()
    assert "guest-pass" not in out.out + out.err
    assert fake.closed


def test_provision_autologon_needs_password(cfg_path, wiring, provision, monkeypatch, capsys):
    monkeypatch.delenv("GW_TEST_GUEST_PW", raising=False)
    assert run(["--config", str(cfg_path), "provision", "--x64dbg-root", "C:\\x"]) == 1
    assert "GW_TEST_GUEST_PW" in capsys.readouterr().err
    assert provision.calls == []


def test_provision_without_autologon_and_user_override(cfg_path, wiring, provision, monkeypatch):
    monkeypatch.delenv("GW_TEST_GUEST_PW", raising=False)
    assert run(["--config", str(cfg_path), "provision", "--x64dbg-root", "C:\\x", "--user", "mcp",
                "--no-autologon"]) == 0
    _, _, kw = provision.calls[0]
    assert kw["user"] == "mcp" and kw["autologon"] is False and kw["password"] is None
    assert kw["reboot"] is True and kw["clean_snapshot"] is None


def test_provision_requires_x64dbg_root(cfg_path, wiring, provision):
    assert run(["--config", str(cfg_path), "provision"]) == 2


def test_install_plugin(cfg_path, wiring, provision, fake, tmp_path, capsys):
    dist = _fake_dist(tmp_path / "dist")
    assert run(["--config", str(cfg_path), "--json", "install-plugin", "--dist", str(dist)]) == 0
    name, runtime, kw = provision.calls[0]
    assert name == "install_plugin" and runtime is fake.runtimes[0]
    # the root comes from the profile's backends (<root>\x64\mcp_config.json)
    assert Path(kw["dist_dir"]) == dist and kw["x64dbg_root"] == "C:\\x64dbg\\release"
    assert kw["relaunch"] is True
    data = json.loads(capsys.readouterr().out)
    assert data["ok"] is True and data["plugin"] == {"source": "dist", "path": str(dist)}


def _fake_dist(root: Path) -> Path:
    """A folder laid out like ``zig build --prefix``."""
    for arch, name in (("x64", "x64dbg-MCP-Server.dp64"), ("x32", "x64dbg-MCP-Server.dp32")):
        (root / arch / "plugins").mkdir(parents=True, exist_ok=True)
        (root / arch / "plugins" / name).write_bytes(b"MZ-" + arch.encode())
    return root


def test_install_plugin_missing_dist_is_usage_error(cfg_path, wiring, provision, tmp_path):
    assert run(["--config", str(cfg_path), "install-plugin", "--dist", str(tmp_path / "nope")]) == 2
    assert provision.calls == []


def test_install_plugin_dist_without_the_build_fails_before_the_vm(cfg_path, wiring, provision, tmp_path,
                                                                  capsys):
    dist = tmp_path / "dist"
    (dist / "x64" / "plugins").mkdir(parents=True)
    (dist / "x64" / "plugins" / "x64dbg-MCP-Server.dp64").write_bytes(b"MZ")
    assert run(["--config", str(cfg_path), "--json", "install-plugin", "--dist", str(dist)]) == 1
    error = json.loads(capsys.readouterr().out)["error"]
    assert error["code"] == "TRANSFER_FAILED"
    assert error["details"]["missing"] == ["x32/plugins/x64dbg-MCP-Server.dp32"]
    assert provision.calls == [] and wiring.calls == []


@pytest.mark.parametrize("value", ["nan", "inf", "0"])
def test_provision_wait_ready_must_be_a_positive_finite_number(cfg_path, wiring, provision, value):
    assert run(["--config", str(cfg_path), *PROVISION_ARGS, "--wait-ready", value]) == 2
    assert provision.calls == []


def test_install_plugin_explicit_root_wins(cfg_path, wiring, provision, tmp_path):
    dist = _fake_dist(tmp_path / "dist")
    assert run(["--config", str(cfg_path), "install-plugin", "--dist", str(dist),
                "--x64dbg-root", "D:/tools/x64dbg"]) == 0
    assert provision.calls[0][2]["x64dbg_root"] == "D:\\tools\\x64dbg"


def test_install_plugin_root_not_derivable_is_usage_error(tmp_path, wiring, provision, capsys):
    path = write_config(tmp_path)
    path.write_text(path.read_text(encoding="utf-8").replace(
        "config = 'C:\\x64dbg\\release\\x64\\mcp_config.json'", "config = 'C:\\elsewhere\\mcp_config.json'"),
        encoding="utf-8")
    dist = _fake_dist(tmp_path / "dist")
    assert run(["--config", str(path), "install-plugin", "--dist", str(dist)]) == 2
    assert "--x64dbg-root" in capsys.readouterr().err
    assert provision.calls == [] and wiring.calls == []


def _fake_bundle(root: Path, version: str = "1.10.0") -> Path:
    for arch, name in (("x64", "x64dbg-MCP-Server.dp64"), ("x32", "x64dbg-MCP-Server.dp32")):
        (root / arch).mkdir(parents=True, exist_ok=True)
        (root / arch / name).write_bytes(b"MZ-" + arch.encode())
    (root / "VERSION").write_text(version + "\n", encoding="utf-8")
    return root


def test_install_plugin_without_dist_uses_the_bundled_build(cfg_path, wiring, provision, fake, tmp_path,
                                                            monkeypatch, capsys):
    from x64dbg_vm_gateway import plugin_bundle

    bundle = _fake_bundle(tmp_path / "bundle")
    monkeypatch.setattr(plugin_bundle, "bundle_root", lambda: bundle)
    seen: dict[str, Any] = {}

    def install_plugin(runtime: Any, **kw: Any) -> dict[str, Any]:
        dist = Path(kw["dist_dir"])
        seen.update(dist=dist, x64=(dist / "x64" / "plugins" / "x64dbg-MCP-Server.dp64").read_bytes(),
                    x32=(dist / "x32" / "plugins" / "x64dbg-MCP-Server.dp32").read_bytes(), kw=kw)
        return {"ok": True, "installed": {"x64": {}, "x32": {}}}

    provision.install_plugin = install_plugin
    assert run(["--config", str(cfg_path), "--json", "install-plugin"]) == 0, capsys.readouterr()
    assert seen["x64"] == b"MZ-x64" and seen["x32"] == b"MZ-x32"
    assert not seen["dist"].exists()  # the temporary copy is gone
    assert seen["kw"]["relaunch"] is True and seen["kw"]["x64dbg_root"] == "C:\\x64dbg\\release"
    data = json.loads(capsys.readouterr().out)
    assert data["plugin"] == {"source": "bundled", "version": "1.10.0"}


def test_install_plugin_without_dist_or_bundle_fails_with_a_hint(cfg_path, wiring, provision, tmp_path,
                                                                 monkeypatch, capsys):
    from x64dbg_vm_gateway import plugin_bundle

    monkeypatch.setattr(plugin_bundle, "bundle_root", lambda: tmp_path / "no-bundle")
    assert run(["--config", str(cfg_path), "install-plugin"]) == 1
    err = capsys.readouterr().err
    assert "bundled" in err and "scripts/build-release.sh" in err and "--dist" in err
    assert provision.calls == [] and wiring.calls == []  # nothing was built or touched

    assert run(["--config", str(cfg_path), "--json", "install-plugin"]) == 1
    error = json.loads(capsys.readouterr().out)["error"]
    assert error["code"] == "TRANSFER_FAILED" and "--dist" in error["hint"]
    assert error["details"]["missing"] == ["x64/x64dbg-MCP-Server.dp64", "x32/x64dbg-MCP-Server.dp32"]


# ── provisioning holds the VM (J-integ) ─────────────────────────────
PROVISION_ARGS = ["provision", "--x64dbg-root", "C:\\x64dbg\\release", "--no-autologon", "--user", "mcp"]


def test_provision_claims_the_jobs_root_pauses_supervision_and_holds_the_vm_lock(
        cfg_path, wiring, provision, fake):
    assert run(["--config", str(cfg_path), *PROVISION_ARGS, "--no-reboot"]) == 0
    names = [m for m, _ in fake.calls]
    assert names.index("open") < names.index("runtime")  # a serving gateway is detected first
    rt = fake.runtimes[0]
    assert rt.log == ["supervisor.pause", "lock.write", "provision_guest", "lock.release",
                      "supervisor.resume"]
    assert rt.lock.write_timeouts and all(t is not None and t > 0 for t in rt.lock.write_timeouts)


def test_provision_with_a_reboot_starts_new_epochs(cfg_path, wiring, provision, fake):
    provision.results["provision_guest"] = {"status": "ok", "rebooted": True}
    assert run(["--config", str(cfg_path), *PROVISION_ARGS]) == 0
    rt = fake.runtimes[0]
    assert rt.log == ["supervisor.pause", "lock.write", "provision_guest", "bump:x64", "bump:x32",
                      "invalidate_clients", "lock.release", "supervisor.resume"]


def test_install_plugin_bumps_the_backend_epochs_after_success(cfg_path, wiring, provision, fake, tmp_path):
    dist = _fake_dist(tmp_path / "dist")
    assert run(["--config", str(cfg_path), "install-plugin", "--dist", str(dist)]) == 0
    rt = fake.runtimes[0]
    assert rt.log == ["supervisor.pause", "lock.write", "install_plugin", "bump:x64", "bump:x32",
                      "invalidate_clients", "lock.release", "supervisor.resume"]
    # the bump dies with this process: the job store keeps that the debuggee is gone
    assert fake.called("note_debuggers_restarted") == [
        {"profile": None, "reason": "plugin reinstalled (debuggers killed and relaunched)"}]


def test_provision_reboot_records_the_lost_debuggee(cfg_path, wiring, provision, fake):
    provision.results["provision_guest"] = {"status": "ok", "rebooted": True}
    assert run(["--config", str(cfg_path), "--profile", "win10", *PROVISION_ARGS]) == 0
    assert fake.called("note_debuggers_restarted") == [
        {"profile": "win10", "reason": "guest rebooted by provision"}]


def test_provision_without_a_reboot_records_nothing(cfg_path, wiring, provision, fake):
    assert run(["--config", str(cfg_path), *PROVISION_ARGS, "--no-reboot"]) == 0
    assert fake.called("note_debuggers_restarted") == []


def test_install_plugin_names_the_jobs_that_lost_their_debuggee(cfg_path, wiring, provision, fake, tmp_path,
                                                                capsys):
    fake.results["note_debuggers_restarted"] = [JOB_ID]
    dist = _fake_dist(tmp_path / "dist")
    assert run(["--config", str(cfg_path), "--json", "install-plugin", "--dist", str(dist)]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["debuggee_lost_jobs"] == [JOB_ID]
    assert JOB_ID in captured.err and "no longer loaded" in captured.err


def test_failed_install_plugin_keeps_the_epochs_and_releases_everything(
        cfg_path, wiring, provision, fake, tmp_path, capsys):
    from x64dbg_vm_gateway.errors import GuestOperationError

    provision.results["install_plugin"] = GuestOperationError("schtasks /run failed")
    dist = _fake_dist(tmp_path / "dist")
    assert run(["--config", str(cfg_path), "install-plugin", "--dist", str(dist)]) == 1
    assert "GUEST_OP_FAILED" in capsys.readouterr().err
    assert fake.runtimes[0].log == ["supervisor.pause", "lock.write", "install_plugin", "lock.release",
                                    "supervisor.resume"]
    assert fake.called("note_debuggers_restarted") == []


def test_provision_with_the_real_runtime_runs_paused_and_locked(tmp_path, cfg_path, provision, monkeypatch):
    from tests.fakes.fake_runtime import make_lab

    lab = make_lab(tmp_path / "lab")
    try:
        gw = lab.gateway()
        monkeypatch.setitem(sys.modules, "x64dbg_vm_gateway.wiring",
                            types.SimpleNamespace(build_app=lambda *a, **kw: gw))
        rt = gw.runtime()
        seen: dict[str, Any] = {}

        def install_plugin(runtime: Any, **kw: Any) -> dict[str, Any]:
            seen.update(writer=runtime.lock.state()["writer"], paused=runtime.supervisor.is_paused(),
                        same=runtime is rt)
            return {"ok": True}

        provision.install_plugin = install_plugin
        dist = _fake_dist(tmp_path / "dist")
        assert run(["--config", str(cfg_path), "install-plugin", "--dist", str(dist)]) == 0
        assert seen == {"writer": True, "paused": True, "same": True}
        assert rt.supervisor.epoch("x64") == 1
        assert not rt.lock.state()["writer"] and not rt.supervisor.is_paused()
    finally:
        lab.close()


def test_install_plugin_marks_the_live_job_in_the_real_store(tmp_path, cfg_path, provision, monkeypatch):
    from tests.fakes.fake_runtime import make_lab

    lab = make_lab(tmp_path / "lab")
    try:
        gw = lab.gateway()
        job_id = gw.analysis_start(str(lab.sample()))["job_id"]
        monkeypatch.setitem(sys.modules, "x64dbg_vm_gateway.wiring",
                            types.SimpleNamespace(build_app=lambda *a, **kw: gw))
        provision.install_plugin = lambda runtime, **kw: {"ok": True}
        dist = _fake_dist(tmp_path / "dist")
        assert run(["--config", str(cfg_path), "install-plugin", "--dist", str(dist)]) == 0
        later = lab.gateway()  # the CLI closed its gateway; the next process reads the record
        flags = later.get_job(job_id)["flags"]
        assert flags["debuggee_lost"] == "plugin reinstalled (debuggers killed and relaunched)"
    finally:
        lab.close()


# ── a serving gateway holds the jobs root (J-integ) ─────────────────
LOCKED = LockTimeout("jobs root is in use by another gateway process",
                     details={"lock": "/jobs/.lock", "owner_pid": 4242, "owner_host": "lab-host"},
                     hint="stop the other gateway")


def test_discard_while_a_gateway_serves_names_its_pid(cfg_path, wiring, fake, capsys):
    fake.fail["discard_job"] = LOCKED
    assert run(["--config", str(cfg_path), "discard", JOB_ID, "--yes"]) == 1
    err = capsys.readouterr().err
    assert "LOCK_TIMEOUT" in err and "pid 4242" in err and "lab-host" in err
    assert "stop" in err and "discard" in err


def test_locked_jobs_root_in_json_keeps_code_and_owner(cfg_path, wiring, fake, capsys):
    fake.fail["discard_job"] = LOCKED
    assert run(["--config", str(cfg_path), "--json", "discard", JOB_ID, "--yes"]) == 1
    err = json.loads(capsys.readouterr().out)["error"]
    assert err["code"] == "LOCK_TIMEOUT" and "4242" in err["message"]
    assert err["details"]["owner_pid"] == 4242 and "stop" in err["hint"]


def test_status_while_a_gateway_serves_points_at_its_mcp_tools(cfg_path, wiring, fake, capsys):
    fake.fail["session_status"] = LOCKED
    assert run(["--config", str(cfg_path), "status"]) == 1
    err = capsys.readouterr().err
    assert "pid 4242" in err and "session_status" in err


def test_provision_refuses_while_a_gateway_serves(cfg_path, wiring, provision, fake, capsys):
    fake.fail["open"] = LOCKED
    assert run(["--config", str(cfg_path), *PROVISION_ARGS]) == 1
    assert provision.calls == []
    assert "pid 4242" in capsys.readouterr().err


def test_other_lock_timeouts_are_reported_unchanged(cfg_path, wiring, fake, capsys):
    fake.fail["discard_job"] = LockTimeout("VmOpLock write timed out", hint="retry")
    assert run(["--config", str(cfg_path), "discard", JOB_ID, "--yes"]) == 1
    err = capsys.readouterr().err
    assert "VmOpLock write timed out" in err and "pid" not in err


def test_discard_against_a_really_locked_jobs_root(cfg_path, tmp_path, capsys):
    _make_job(tmp_path)
    with JobStore(tmp_path / "jobs"):  # stands in for a serving gateway (this process' pid)
        rc = run(["--config", str(cfg_path), "discard", JOB_ID, "--yes"])
    assert rc == 1
    err = capsys.readouterr().err
    assert "LOCK_TIMEOUT" in err and f"pid {os.getpid()}" in err


# ── init ────────────────────────────────────────────────────────────
@pytest.fixture
def vmrun_found(monkeypatch) -> None:
    monkeypatch.setattr(gw_platform, "find_vmrun", lambda configured="auto", **kw: "/usr/bin/vmrun")


INIT_ARGS = ["init", "--non-interactive", "--vmx", "/vms/w10/w10.vmx", "--guest-user", "analyst",
             "--x64dbg-root", "C:\\Users\\analyst\\Desktop\\x64dbg\\release"]


def test_init_non_interactive_writes_loadable_private_config(tmp_path, vmrun_found, capsys):
    path = tmp_path / "cfgdir" / "config.toml"
    assert run(["--config", str(path), *INIT_ARGS, "--profile-name", "lab.1"]) == 0
    if sys.platform != "win32":
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    conf = gw_config.load_config(path, environ={})
    prof = conf.profile()
    assert conf.default_profile == "lab.1" and prof.mode == "vmware"
    assert prof.vmx == "/vms/w10/w10.vmx" and prof.clean_snapshot == "MCP_CLEAN"
    assert prof.guest_user == "analyst" and prof.guest_password_env == "X64DBG_GW_GUEST_PW"
    assert "MCP_CLEAN" in prof.protected_snapshots
    by = {b.id: b for b in prof.backends}
    assert set(by) == {"x64", "x32"}
    assert by["x64"].port == 9094 and by["x32"].port == 9095
    assert by["x64"].exe == "C:\\Users\\analyst\\Desktop\\x64dbg\\release\\x64\\x64dbg.exe"
    assert by["x32"].config == "C:\\Users\\analyst\\Desktop\\x64dbg\\release\\x32\\mcp_config.json"
    assert by["x64"].launch_task == "MCP-x64dbg" and by["x32"].launch_task == "MCP-x32dbg"
    out = capsys.readouterr().out
    assert str(path) in out and "/usr/bin/vmrun" in out


def test_init_custom_values(tmp_path, vmrun_found):
    path = tmp_path / "c.toml"
    assert run(["--config", str(path), *INIT_ARGS, "--clean-snapshot", "CLEAN \"2\"",
                "--guest-password-env", "MY_PW", "--profile-name", "w11"]) == 0
    prof = gw_config.load_config(path, environ={}).profile("w11")
    assert prof.clean_snapshot == "CLEAN \"2\"" and prof.guest_password_env == "MY_PW"


def test_init_refuses_to_overwrite_without_force(tmp_path, vmrun_found, capsys):
    path = tmp_path / "config.toml"
    path.write_text("# mine\n", encoding="utf-8")
    assert run(["--config", str(path), *INIT_ARGS]) == 1
    assert "--force" in capsys.readouterr().err
    assert path.read_text(encoding="utf-8") == "# mine\n"
    assert run(["--config", str(path), *INIT_ARGS, "--force"]) == 0
    assert gw_config.load_config(path, environ={}).profile().vmx == "/vms/w10/w10.vmx"


def test_init_force_is_not_blocked_by_a_stale_temp_file(tmp_path, vmrun_found, capsys):
    """A crashed earlier init may leave its temp file behind; PIDs repeat (containers)."""
    path = tmp_path / "config.toml"
    path.write_text("# mine\n", encoding="utf-8")
    (tmp_path / f".config.toml.{os.getpid()}.tmp").write_text("stale", encoding="utf-8")
    assert run(["--config", str(path), *INIT_ARGS, "--force"]) == 0, capsys.readouterr().err
    assert gw_config.load_config(path, environ={}).profile().vmx == "/vms/w10/w10.vmx"


def test_init_default_path(tmp_path, vmrun_found, monkeypatch):
    target = tmp_path / "xdg" / "x64dbg-vm-gateway" / "config.toml"
    monkeypatch.setattr(gw_config, "default_config_path", lambda **kw: target)
    monkeypatch.delenv(gw_config.ENV_CONFIG_PATH, raising=False)
    assert run(INIT_ARGS) == 0
    assert target.exists()


@pytest.mark.parametrize("drop", ["--vmx", "--guest-user", "--x64dbg-root"])
def test_init_non_interactive_missing_required_flag_is_usage_error(tmp_path, vmrun_found, drop):
    args = list(INIT_ARGS)
    i = args.index(drop)
    del args[i:i + 2]
    assert run(["--config", str(tmp_path / "c.toml"), *args]) == 2
    assert not (tmp_path / "c.toml").exists()


def test_init_rejects_invalid_values(tmp_path, vmrun_found, capsys):
    rc = run(["--config", str(tmp_path / "c.toml"), *INIT_ARGS, "--guest-password-env", "not a name!"])
    assert rc in (1, 2)
    assert not (tmp_path / "c.toml").exists()
    rc = run(["--config", str(tmp_path / "c.toml"), "init", "--non-interactive", "--vmx", "/v.vmx",
              "--guest-user", "u", "--x64dbg-root", "relative\\path"])
    assert rc == 2


def test_init_warns_when_vmrun_is_missing(tmp_path, monkeypatch, capsys):
    def missing(configured: str = "auto", **kw: Any) -> str:
        raise VmrunNotFound("vmrun not found", hint="install VMware Workstation")

    monkeypatch.setattr(gw_platform, "find_vmrun", missing)
    assert run(["--config", str(tmp_path / "c.toml"), *INIT_ARGS]) == 0
    assert "vmrun" in capsys.readouterr().err.lower()
    assert gw_config.load_config(tmp_path / "c.toml", environ={}).profile().vmrun == "auto"


def test_init_endpoint_mode(tmp_path, vmrun_found):
    path = tmp_path / "c.toml"
    assert run(["--config", str(path), "init", "--non-interactive", "--mode", "endpoint",
                "--profile-name", "remote", "--x64-url", "http://10.0.0.20:9094",
                "--x64-token-env", "REMOTE_X64_TOKEN"]) == 0
    prof = gw_config.load_config(path, environ={}).profile("remote")
    assert prof.mode == "endpoint" and prof.token_source == "env"
    (b,) = prof.backends
    assert b.id == "x64" and b.url == "http://10.0.0.20:9094" and b.token_env == "REMOTE_X64_TOKEN"


def test_init_interactive(tmp_path, vmrun_found, monkeypatch, capsys):
    answers = iter([
        "",                                   # mode [vmware]
        "lab",                                # profile name
        "/vms/lab/lab.vmx",                   # vmx
        "",                                   # clean snapshot [MCP_CLEAN]
        "analyst",                            # guest user
        "",                                   # password env [X64DBG_GW_GUEST_PW]
        "C:\\tools\\x64dbg\\release",        # x64dbg root
        "",                                   # jobs root [default]
    ])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))
    path = tmp_path / "c.toml"
    assert run(["--config", str(path), "init"]) == 0
    prof = gw_config.load_config(path, environ={}).profile("lab")
    assert prof.vmx == "/vms/lab/lab.vmx" and prof.guest_user == "analyst"
    assert prof.backends[0].exe.startswith("C:\\tools\\x64dbg\\release\\")


def test_init_interactive_prompts_keep_json_stdout_clean(tmp_path, vmrun_found, monkeypatch, capsys):
    answers = ["", "lab", "/vms/lab/lab.vmx", "", "analyst", "", "C:\\tools\\x64dbg\\release", ""]
    monkeypatch.setattr("builtins.input", _input_like_the_builtin(answers))
    path = tmp_path / "c.toml"
    assert run(["--config", str(path), "--json", "init"]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["path"] == str(path)
    assert "Profile name" in captured.err


def test_init_interactive_eof_is_usage_error(tmp_path, vmrun_found, monkeypatch):
    def eof(_prompt: str = "") -> str:
        raise EOFError

    monkeypatch.setattr("builtins.input", eof)
    assert run(["--config", str(tmp_path / "c.toml"), "init"]) == 2
    assert not (tmp_path / "c.toml").exists()


# ── output encoding ─────────────────────────────────────────────────
def _narrow_stream(encoding: str = "cp1252") -> io.TextIOWrapper:
    """Like a redirected stdout/stderr on a Windows host: the locale code page, strict errors."""
    return io.TextIOWrapper(io.BytesIO(), encoding=encoding, errors="strict", write_through=True)


def _text_of(stream: io.TextIOWrapper) -> str:
    return stream.buffer.getvalue().decode(stream.encoding)  # type: ignore[attr-defined]


def test_json_output_survives_a_narrow_stdout_encoding(cfg_path, wiring, fake, monkeypatch):
    status = {"vm": {"power": "running"}, "snapshots": ["깨끗한-스냅샷", "\U0001F600"]}
    fake.results["session_status"] = status
    out = _narrow_stream()
    monkeypatch.setattr(sys, "stdout", out)
    assert run(["--config", str(cfg_path), "--json", "status"]) == 0
    assert json.loads(_text_of(out)) == status  # lossless: escaped JSON is still the same data


def test_human_output_survives_a_narrow_stdout_encoding(cfg_path, wiring, fake, monkeypatch):
    fake.results["doctor"] = {"ok": True, "checks": [{"name": "vmx", "ok": True, "detail": "경로 OK"}]}
    out = _narrow_stream()
    monkeypatch.setattr(sys, "stdout", out)
    assert run(["--config", str(cfg_path), "doctor"]) == 0
    assert "vmx" in _text_of(out)


def test_error_output_survives_a_narrow_stderr_encoding(cfg_path, wiring, fake, monkeypatch):
    fake.fail["session_status"] = StateViolation("작업이 아직 수집되지 않았습니다", hint="analysis_collect")
    err = _narrow_stream()
    monkeypatch.setattr(sys, "stderr", err)
    assert run(["--config", str(cfg_path), "status"]) == 1
    text = _text_of(err)
    assert "STATE_VIOLATION" in text and "analysis_collect" in text


def test_lone_surrogates_do_not_break_json_output(cfg_path, wiring, fake, monkeypatch):
    fake.results["session_status"] = {"warning": "bad \ud800 text"}
    out = _narrow_stream("utf-8")
    monkeypatch.setattr(sys, "stdout", out)
    assert run(["--config", str(cfg_path), "--json", "status"]) == 0
    assert json.loads(_text_of(out)) == {"warning": "bad \ud800 text"}


# ── provision with the QUICKSTART config shape (real-VM finding) ───
def _env_file_config(tmp_path: Path) -> Path:
    """guest_user_env + guest_password_env resolved from gateway.env_file (docs/QUICKSTART_KO.md)."""
    env = tmp_path / "lab.env"
    env.write_text("GW_QS_USER=labuser\nGW_QS_PW=from-env-file\n", encoding="utf-8")
    env.chmod(0o600)
    text = f"""
[gateway]
jobs_root = "{(tmp_path / 'jobs').as_posix()}"
default_profile = "lab"
env_file = "{env.as_posix()}"

[profiles.lab]
mode = "vmware"
vmx = "/vms/lab/lab.vmx"
clean_snapshot = "MCP_CLEAN"
guest_user_env = "GW_QS_USER"
guest_password_env = "GW_QS_PW"

[profiles.lab.backends.x64]
port = 9094
config = 'C:\\x64dbg\\release\\x64\\mcp_config.json'
"""
    path = tmp_path / "qs.toml"
    path.write_text(text, encoding="utf-8")
    return path


def test_provision_takes_user_and_password_from_the_env_file(
    tmp_path, wiring, provision, monkeypatch, capsys
):
    monkeypatch.delenv("GW_QS_USER", raising=False)
    monkeypatch.delenv("GW_QS_PW", raising=False)
    cfg = _env_file_config(tmp_path)
    rc = run(["--config", str(cfg), "provision", "--x64dbg-root", "C:\\x64dbg\\release", "--no-reboot"])
    out = capsys.readouterr()
    assert rc == 0, out
    _, _, kw = provision.calls[0]
    assert kw["user"] == "labuser"
    assert isinstance(kw["password"], Secret) and kw["password"].reveal() == "from-env-file"
    assert "from-env-file" not in out.out + out.err


def test_provision_real_environment_wins_over_the_env_file(tmp_path, wiring, provision, monkeypatch):
    monkeypatch.setenv("GW_QS_USER", "shelluser")
    monkeypatch.setenv("GW_QS_PW", "from-shell")
    cfg = _env_file_config(tmp_path)
    rc = run(["--config", str(cfg), "provision", "--x64dbg-root", "C:\\x", "--no-reboot"])
    assert rc == 0
    _, _, kw = provision.calls[0]
    assert kw["user"] == "shelluser" and kw["password"].reveal() == "from-shell"


def test_serve_http_takes_the_access_tokens_from_the_env_file(tmp_path, wiring, fake, monkeypatch):
    # review (F4): http.token_envs are *_env names too, resolved through gateway.env_file
    from x64dbg_vm_gateway.frontends import http_server

    env = tmp_path / "gw.env"
    env.write_text("GW_ADMIN=admin-token-from-file-" + "y" * 20 + "\n", encoding="utf-8")
    env.chmod(0o600)
    path = write_config(tmp_path, http_enabled=True)
    path.write_text(path.read_text(encoding="utf-8").replace(
        'default_profile = "win10"', f'default_profile = "win10"\nenv_file = "{env.as_posix()}"', 1),
        encoding="utf-8")
    monkeypatch.delenv("GW_ADMIN", raising=False)
    seen: list[Any] = []

    def fake_serve(app: Any, http_cfg: Any, *, environ: Any = None, jobs_root: Any = None) -> None:
        seen.append(http_server.resolve_tokens(http_cfg, environ))

    monkeypatch.setattr(http_server, "serve_http", fake_serve)
    assert run(["--config", str(path), "serve", "--transport", "http"]) == 0
    assert seen[0]["admin"].reveal().startswith("admin-token-from-file-")


def test_provision_an_empty_shell_variable_does_not_hide_the_env_file(
    tmp_path, wiring, provision, monkeypatch
):
    # review (F7): GW_QS_PW="" exported in the shell must not mask the value in the env file
    monkeypatch.setenv("GW_QS_USER", "")
    monkeypatch.setenv("GW_QS_PW", "")
    cfg = _env_file_config(tmp_path)
    assert run(["--config", str(cfg), "provision", "--x64dbg-root", "C:\\x", "--no-reboot"]) == 0
    _, _, kw = provision.calls[0]
    assert kw["user"] == "labuser" and kw["password"].reveal() == "from-env-file"


def test_doctor_text_shows_a_warning_check_as_warn_with_its_hint():
    """A check with level "warn" passes (doctor still succeeds) but must not look like [ ok ]."""
    text = cli._format_doctor({"ok": True, "checks": [
        {"name": "vm_power", "ok": True, "detail": "running"},
        {"name": "static_tools", "ok": True, "level": "warn",
         "detail": "WARN ghidra: none of ghidraRun on PATH",
         "hint": "install Ghidra or set [static.servers.ghidra]"},
    ]})
    lines = text.splitlines()
    assert lines[0].startswith("[ ok ] vm_power")
    assert lines[1].startswith("[WARN] static_tools")
    assert lines[2].strip() == "hint: install Ghidra or set [static.servers.ghidra]"
    assert lines[-1] == "doctor: all checks passed (1 warning)"
