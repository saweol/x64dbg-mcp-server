"""`x64dbg-vm-gateway` command line (plan 5.1): driven through ``cli.main([...])``
with a FakeApp. ``wiring`` and ``provision`` are replaced in ``sys.modules`` so
the CLI never builds a real gateway."""

from __future__ import annotations

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

    def provision_guest(runtime: Any, **kw: Any) -> dict[str, Any]:
        calls.append(("provision_guest", runtime, kw))
        return {"ok": True, "steps": ["copied", "ran"]}

    def install_plugin(runtime: Any, **kw: Any) -> dict[str, Any]:
        calls.append(("install_plugin", runtime, kw))
        return {"ok": True, "installed": ["x64", "x32"]}

    mod = types.SimpleNamespace(provision_guest=provision_guest, install_plugin=install_plugin, calls=calls)
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


def test_discard_asks_and_confirms(cfg_path, wiring, fake, monkeypatch, capsys):
    prompts: list[str] = []

    def answer(prompt: str = "") -> str:
        prompts.append(prompt)
        return "yes"

    monkeypatch.setattr("builtins.input", answer)
    assert run(["--config", str(cfg_path), "discard", JOB_ID]) == 0
    assert JOB_ID in prompts[0]
    assert fake.called("discard_job") == [{"job_id": JOB_ID, "actor": "human-cli"}]


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
    dist = tmp_path / "dist"
    dist.mkdir()
    assert run(["--config", str(cfg_path), "--json", "install-plugin", "--dist", str(dist)]) == 0
    name, runtime, kw = provision.calls[0]
    assert name == "install_plugin" and runtime is fake.runtimes[0]
    assert Path(kw["dist_dir"]) == dist and kw["x64dbg_root"] is None and kw["relaunch"] is True
    assert json.loads(capsys.readouterr().out)["ok"] is True


def test_install_plugin_missing_dist_is_usage_error(cfg_path, wiring, provision, tmp_path):
    assert run(["--config", str(cfg_path), "install-plugin", "--dist", str(tmp_path / "nope")]) == 2
    assert provision.calls == []


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


def test_init_interactive_eof_is_usage_error(tmp_path, vmrun_found, monkeypatch):
    def eof(_prompt: str = "") -> str:
        raise EOFError

    monkeypatch.setattr("builtins.input", eof)
    assert run(["--config", str(tmp_path / "c.toml"), "init"]) == 2
    assert not (tmp_path / "c.toml").exists()
