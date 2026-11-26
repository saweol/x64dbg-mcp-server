"""`x64dbg-vm-gateway setup`: init (when there is no config) -> doctor precheck ->
install-plugin -> provision -> doctor -> the MCP client registration command.
Driven through ``cli.main([...])`` with a FakeApp; ``wiring`` and ``provision``
are replaced in ``sys.modules`` so nothing reaches a VM."""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
import sys
import types
from pathlib import Path
from typing import Any

import pytest

from tests.fakes.fake_app import FakeApp
from tests.unit.test_cli import _fake_bundle, run, write_config
from x64dbg_vm_gateway import config as gw_config
from x64dbg_vm_gateway import platform as gw_platform
from x64dbg_vm_gateway import plugin_bundle
from x64dbg_vm_gateway import provision as real_provision
from x64dbg_vm_gateway.contracts import Secret
from x64dbg_vm_gateway.errors import GuestOperationError, LockTimeout
from x64dbg_vm_gateway.frontends import cli

PW_ENV = "GW_TEST_GUEST_PW"
REGISTER = "claude mcp add x64dbg-vm -- x64dbg-vm-gateway serve"
IDA_LINE = "  claude mcp add ida-multi-mcp -- python3 -m ida_multi_mcp"
ANY_ADDR = "0.0.0.0"  # noqa: S104 - a value under test, nothing binds
ROOT = "C:\\x64dbg\\release"  # what write_config's backend paths imply

FRESH_GUEST = {"ok": False, "checks": [  # a guest before setup: no plugin answers, no clean snapshot
    {"name": "vmrun", "ok": True, "detail": "/usr/bin/vmrun", "hint": None},
    {"name": "clean_snapshot", "ok": False, "detail": "MCP_CLEAN missing (0 snapshots)",
     "hint": "create the clean snapshot (plan 5.7)"},
    {"name": "vm_power", "ok": True, "detail": "VM is running", "hint": None},
    {"name": "backend:x64:reachable", "ok": False, "detail": "does not accept connections",
     "hint": "is x64dbg running with the plugin started? (debugger_restart)"},
    {"name": "backend:x64:token", "ok": False, "detail": "skipped: backend not reachable", "hint": None},
    {"name": "catalog:x64", "ok": True, "detail": "builtin list", "hint": None},
]}
ALL_GREEN = {"ok": True, "checks": [{"name": "vmrun", "ok": True, "detail": "/usr/bin/vmrun", "hint": None}]}


@pytest.fixture(autouse=True)
def posix_host(monkeypatch) -> None:
    """The printed commands follow the host's shell: the tests pin a POSIX host (CI runs them on
    Windows too); the Windows tests set ``_windows_host`` to True themselves."""
    monkeypatch.setattr(cli, "_windows_host", lambda: False)


@pytest.fixture
def cfg_path(tmp_path: Path) -> Path:
    return write_config(tmp_path)


@pytest.fixture
def fake() -> FakeApp:
    app = FakeApp()
    answers = iter([FRESH_GUEST, ALL_GREEN])
    app.results["doctor"] = lambda **kw: next(answers)
    app.results["vm_snapshots_list"] = {"snapshots": [{"name": "base", "protected": False}]}
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
    calls: list[tuple[str, Any, dict[str, Any]]] = []
    results: dict[str, Any] = {
        "provision_guest": {"status": "ok", "rebooted": True,
                            "snapshot": {"name": "MCP_CLEAN", "replaced": False}},
        "install_plugin": {"x64dbg_root": ROOT, "installed": {"x64": {}, "x32": {}}, "relaunched": False},
    }

    def answer(name: str, runtime: Any, kw: dict[str, Any]) -> Any:
        if name == "install_plugin":  # the build must be there while install_plugin runs
            dist = Path(kw["dist_dir"])
            kw = {**kw, "files_present": all((dist / a / "plugins" / f).is_file()
                                             for a, f in plugin_bundle.PLUGIN_FILES.items())}
        calls.append((name, runtime, kw))
        runtime.log.append(name)
        res = results[name]
        if isinstance(res, BaseException):
            raise res
        return res

    mod = types.SimpleNamespace(
        provision_guest=lambda runtime, **kw: answer("provision_guest", runtime, kw),
        install_plugin=lambda runtime, **kw: answer("install_plugin", runtime, kw),
        check_provision_arguments=real_provision.check_provision_arguments,
        calls=calls, results=results)
    monkeypatch.setitem(sys.modules, "x64dbg_vm_gateway.provision", mod)
    return mod


@pytest.fixture
def bundle(tmp_path, monkeypatch) -> Path:
    root = _fake_bundle(tmp_path / "bundle")
    monkeypatch.setattr(plugin_bundle, "bundle_root", lambda: root)
    return root


@pytest.fixture
def no_bundle(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(plugin_bundle, "bundle_root", lambda: tmp_path / "no-bundle")


@pytest.fixture
def password(monkeypatch) -> None:
    monkeypatch.setenv(PW_ENV, "guest-pass")


@pytest.fixture
def ready(bundle, password) -> None:
    """A bundled plugin build and the guest password: what a full run needs locally."""


@pytest.fixture
def vmrun_found(monkeypatch) -> None:
    monkeypatch.setattr(gw_platform, "find_vmrun", lambda configured="auto", **kw: "/usr/bin/vmrun")


def calls_named(provision: types.SimpleNamespace, name: str) -> list[dict[str, Any]]:
    return [kw for n, _, kw in provision.calls if n == name]


def json_run(argv: list[str], capsys) -> tuple[int, dict[str, Any]]:
    rc = run(argv)
    return rc, json.loads(capsys.readouterr().out)


def steps_of(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {s["step"]: s for s in data["steps"]}


def register_argv(path: Path) -> list[str]:
    return ["claude", "mcp", "add", "x64dbg-vm", "-e", f"X64DBG_VM_GATEWAY_CONFIG={path.absolute()}",
            "--", "x64dbg-vm-gateway", "serve"]


# ── help ────────────────────────────────────────────────────────────
def test_setup_is_listed_in_the_help(capsys):
    assert run(["--help"]) == 0
    assert "setup" in capsys.readouterr().out


def test_setup_help_lists_its_options(capsys):
    assert run(["setup", "--help"]) == 0
    out = capsys.readouterr().out
    for flag in ("--dry-run", "--skip-plugin", "--skip-provision", "--dist", "--snapshot",
                 "--non-interactive", "--vmx", "--guest-user", "--x64dbg-root", "--user", "--no-autologon",
                 "--bind", "--wait-ready"):
        assert flag in out, flag


def test_shell_join_quotes_for_the_host_shell():
    argv = ["claude", "-e", "X=/a b/c.toml", "--", "serve"]
    assert cli.shell_join(argv, windows=False) == "claude -e 'X=/a b/c.toml' -- serve"
    assert cli.shell_join(argv, windows=True) == "claude -e 'X=/a b/c.toml' '--' serve"


#: arguments a shell must not interpret: (argument, POSIX form, PowerShell form)
SHELL_METACHARACTERS = [
    ("a&b", "'a&b'", "'a&b'"),
    ("a;b", "'a;b'", "'a;b'"),
    ("50%", "50%", "'50%'"),  # %VAR% in cmd; POSIX shells leave % alone
    ("%PATH%", "%PATH%", "'%PATH%'"),
    ("$HOME", "'$HOME'", "'$HOME'"),
    ("$(whoami)", "'$(whoami)'", "'$(whoami)'"),
    ("x^y", "'x^y'", "'x^y'"),
    ('say "hi"', "'say \"hi\"'", "'say \"hi\"'"),
    ("it's", "'it'\"'\"'s'", "'it''s'"),
    ("it\u2019s", "'it\u2019s'", "'it\u2019\u2019s'"),  # PowerShell also ends a string at typographic quotes
    ("<in>", "'<in>'", "'<in>'"),
    ("a>b", "'a>b'", "'a>b'"),
    ("a|b", "'a|b'", "'a|b'"),
    ("a b", "'a b'", "'a b'"),
    ("back`tick", "'back`tick'", "'back`tick'"),
    ("#comment", "'#comment'", "'#comment'"),
    ("@scope/pkg", "@scope/pkg", "'@scope/pkg'"),  # @name splats a variable in PowerShell
    ("a,b", "a,b", "'a,b'"),  # an array in PowerShell
    ("{x}", "'{x}'", "'{x}'"),
    ("(x)", "'(x)'", "'(x)'"),
    ("1kb", "1kb", "'1kb'"),  # a number (1024) in PowerShell
    ("-Dfoo.bar=1", "-Dfoo.bar=1", "'-Dfoo.bar=1'"),  # Windows PowerShell splits it at the dot
    ("--", "--", "'--'"),  # PowerShell's end-of-parameters token, eaten by .ps1 shims
    ("--%", "--%", "'--%'"),  # PowerShell's stop-parsing token
]


@pytest.mark.parametrize(("arg", "posix", "powershell"), SHELL_METACHARACTERS)
def test_shell_join_quotes_shell_metacharacters(arg, posix, powershell):
    argv = ["claude", "mcp", "add", "x", arg]
    assert cli.shell_join(argv, windows=False) == "claude mcp add x " + posix
    assert cli.shell_join(argv, windows=True) == "claude mcp add x " + powershell


@pytest.mark.parametrize("arg", ["-e", "--project-path", "ida-multi-mcp", "X=/a/b.toml", "python3",
                                 "C:\\x64dbg\\release", "C:\\PROGRA~1\\x.exe", "/opt/ghidra",
                                 "\\\\server\\share\\m.exe", "a+b", "host:9100"])
def test_plain_words_stay_unquoted_for_powershell(arg):
    assert cli.shell_join(["claude", arg], windows=True) == f"claude {arg}"


def test_a_program_that_needs_quotes_is_called_with_the_call_operator():
    argv = ["C:\\Program Files\\x\\x.exe", "serve"]
    assert cli.shell_join(argv, windows=True) == "& 'C:\\Program Files\\x\\x.exe' serve"


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="needs PowerShell 7 (pwsh)")
def test_powershell_passes_every_argument_unchanged():
    values = [arg for arg, _posix, _ps in SHELL_METACHARACTERS] + [
        "C:\\x64dbg\\release", "X=C:\\a b\\c.toml", "<project-dir>", "-e", "0x10"]
    code = "import json, sys; print(json.dumps(sys.argv[1:]))"
    line = cli.shell_join([sys.executable, "-c", code, *values], windows=True)
    encoded = base64.b64encode(line.encode("utf-16-le")).decode("ascii")
    res = subprocess.run([shutil.which("pwsh"), "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                         capture_output=True, text=True, timeout=120, check=False)
    assert res.returncode == 0, res.stdout + res.stderr
    assert json.loads(res.stdout) == values


# ── the full run ────────────────────────────────────────────────────
@pytest.mark.usefixtures("ready")
def test_setup_runs_every_step_in_order(cfg_path, wiring, provision, fake, capsys):
    rc = run(["--config", str(cfg_path), "setup"])
    captured = capsys.readouterr()
    assert rc == 0, captured
    names = [m for m, _ in fake.calls]
    assert names[:3] == ["open", "doctor", "vm_snapshots_list"]  # the jobs root is claimed first
    assert names.count("doctor") == 2 and fake.closed
    (inst,) = calls_named(provision, "install_plugin")
    assert inst["files_present"] and inst["x64dbg_root"] == ROOT
    assert inst["relaunch"] is False  # the provisioning reboot starts the debuggers through the new tasks
    (prov,) = calls_named(provision, "provision_guest")
    assert prov["x64dbg_root"] == ROOT and prov["user"] == "analyst"
    assert isinstance(prov["password"], Secret) and prov["password"].reveal() == "guest-pass"
    assert prov["autologon"] is True and prov["reboot"] is True and prov["bind"] == ANY_ADDR
    assert prov["clean_snapshot"] == "MCP_CLEAN" and prov["wait_ready_s"] == 300.0
    rt = fake.runtimes[0]
    assert rt.log == ["supervisor.pause", "lock.write", "install_plugin", "bump:x64", "bump:x32",
                      "invalidate_clients", "lock.release", "supervisor.resume",
                      "supervisor.pause", "lock.write", "provision_guest", "bump:x64", "bump:x32",
                      "invalidate_clients", "lock.release", "supervisor.resume"]
    # the config is not at the default location, so the registration names it
    assert cli.shell_join(register_argv(cfg_path)) in captured.out
    assert IDA_LINE in captured.out.splitlines() and "setup complete" in captured.out
    assert "guest-pass" not in captured.out + captured.err


@pytest.mark.usefixtures("wiring", "provision", "ready")
def test_setup_json_report(cfg_path, capsys):
    rc, data = json_run(["--config", str(cfg_path), "--json", "setup"], capsys)
    assert rc == 0 and data["ok"] is True and data["dry_run"] is False
    assert data["config"] == {"path": str(cfg_path), "created": False, "profile": "win10"}
    assert [s["step"] for s in data["steps"]] == ["init", "precheck", "install-plugin", "provision", "doctor"]
    steps = steps_of(data)
    assert steps["init"]["status"] == "skipped"
    assert steps["precheck"]["status"] == "done"
    assert set(steps["precheck"]["fixable"]) == {"clean_snapshot", "backend:x64:reachable",
                                                 "backend:x64:token"}
    assert steps["install-plugin"]["status"] == "done"
    assert steps["install-plugin"]["result"]["plugin"] == {"source": "bundled", "version": "1.10.0"}
    assert steps["provision"]["status"] == "done" and steps["provision"]["result"]["rebooted"] is True
    assert steps["doctor"]["status"] == "done" and steps["doctor"]["result"]["ok"] is True
    assert data["register"]["command"] == cli.shell_join(register_argv(cfg_path))
    assert data["register"]["argv"] == register_argv(cfg_path)
    # the same block as `mcp-config --json` (servers): the gateway first, then the static tools
    assert [s["id"] for s in data["mcp_config"]] == ["gateway", "ida"]
    assert data["mcp_config"][0]["argv"] == register_argv(cfg_path)
    assert data["mcp_config"][1]["argv"] == ["claude", "mcp", "add", "ida-multi-mcp", "--", "python3", "-m",
                                             "ida_multi_mcp"]
    assert "static_tools" not in data


@pytest.mark.usefixtures("wiring", "provision", "ready")
def test_setup_register_command_at_the_default_location(tmp_path, monkeypatch, capsys):
    target = tmp_path / "xdg" / "x64dbg-vm-gateway" / "config.toml"
    target.parent.mkdir(parents=True)
    write_config(tmp_path).rename(target)
    monkeypatch.setattr(gw_config, "default_config_path", lambda **kw: target)
    monkeypatch.delenv(gw_config.ENV_CONFIG_PATH, raising=False)
    rc, data = json_run(["--json", "setup"], capsys)
    assert rc == 0 and data["register"]["command"] == REGISTER


@pytest.mark.usefixtures("wiring", "provision", "ready")
def test_setup_register_command_names_an_explicit_profile(cfg_path, fake, capsys):
    rc, data = json_run(["--config", str(cfg_path), "--json", "--profile", "win10", "setup"], capsys)
    assert rc == 0 and data["register"]["argv"][-3:] == ["serve", "--profile", "win10"]
    assert fake.called("doctor") == [{"profile": "win10"}, {"profile": "win10"}]


@pytest.mark.usefixtures("wiring", "bundle")
def test_setup_passes_the_provision_options(cfg_path, provision, monkeypatch, capsys):
    monkeypatch.delenv(PW_ENV, raising=False)  # not needed without auto-logon
    rc = run(["--config", str(cfg_path), "setup", "--user", "mcp", "--no-autologon", "--bind", "127.0.0.1",
              "--wait-ready", "90", "--snapshot", "MCP_CLEAN_2", "--x64dbg-root", "D:\\dbg"])
    assert rc == 0, capsys.readouterr()
    (prov,) = calls_named(provision, "provision_guest")
    assert prov["user"] == "mcp" and prov["autologon"] is False and prov["password"] is None
    assert prov["bind"] == "127.0.0.1" and prov["wait_ready_s"] == 90.0
    assert prov["clean_snapshot"] == "MCP_CLEAN_2" and prov["x64dbg_root"] == "D:\\dbg"
    assert calls_named(provision, "install_plugin")[0]["x64dbg_root"] == "D:\\dbg"


@pytest.mark.usefixtures("wiring", "provision", "ready")
def test_setup_says_when_the_snapshot_is_not_the_profiles_clean_snapshot(cfg_path, capsys):
    _, data = json_run(["--config", str(cfg_path), "--json", "setup", "--snapshot", "MCP_CLEAN_2"], capsys)
    assert any("clean_snapshot" in n and "MCP_CLEAN_2" in n for n in data["notes"])


@pytest.mark.usefixtures("wiring", "no_bundle", "password")
def test_setup_with_dist(cfg_path, provision, tmp_path, capsys):
    dist = tmp_path / "dist"
    for arch, name in plugin_bundle.PLUGIN_FILES.items():
        (dist / arch / "plugins").mkdir(parents=True)
        (dist / arch / "plugins" / name).write_bytes(b"MZ")
    rc, data = json_run(["--config", str(cfg_path), "--json", "setup", "--dist", str(dist)], capsys)
    assert rc == 0
    (inst,) = calls_named(provision, "install_plugin")
    assert Path(inst["dist_dir"]) == dist
    assert steps_of(data)["install-plugin"]["result"]["plugin"] == {"source": "dist", "path": str(dist)}


# ── partial runs ────────────────────────────────────────────────────
@pytest.mark.usefixtures("wiring", "no_bundle", "password")
def test_setup_skip_plugin(cfg_path, provision, capsys):
    rc, data = json_run(["--config", str(cfg_path), "--json", "setup", "--skip-plugin"], capsys)
    assert rc == 0  # no bundle needed
    assert calls_named(provision, "install_plugin") == []
    assert len(calls_named(provision, "provision_guest")) == 1
    assert steps_of(data)["install-plugin"]["status"] == "skipped"


@pytest.mark.usefixtures("wiring", "bundle")
def test_setup_skip_provision_relaunches_the_debuggers(cfg_path, provision, fake, monkeypatch, capsys):
    monkeypatch.delenv(PW_ENV, raising=False)  # provisioning is skipped: no password needed
    answers = iter([{"ok": False, "checks": FRESH_GUEST["checks"][2:]}, ALL_GREEN])
    fake.results["doctor"] = lambda **kw: next(answers)
    rc, data = json_run(["--config", str(cfg_path), "--json", "setup", "--skip-provision"], capsys)
    assert rc == 0, data
    (inst,) = calls_named(provision, "install_plugin")
    assert inst["relaunch"] is True  # nothing reboots afterwards
    assert calls_named(provision, "provision_guest") == []
    assert fake.called("vm_snapshots_list") == []
    assert steps_of(data)["provision"]["status"] == "skipped"


@pytest.mark.usefixtures("wiring", "bundle")
def test_setup_skip_provision_cannot_fix_a_rejected_token(cfg_path, provision, fake, capsys):
    """Provisioning rewrites the token configs; reinstalling the plugin does not."""
    rejected = {"name": "backend:x64:token", "ok": False, "hint": "run: x64dbg-vm-gateway provision",
                "detail": "BACKEND_AUTH: backend x64 rejects the token"}
    fake.results["doctor"] = {"ok": False, "checks": [FRESH_GUEST["checks"][2], rejected]}
    rc, data = json_run(["--config", str(cfg_path), "--json", "setup", "--skip-provision"], capsys)
    assert rc == 1 and provision.calls == []
    assert steps_of(data)["precheck"]["blockers"] == ["backend:x64:token"]


@pytest.mark.usefixtures("wiring", "ready")
def test_setup_provisioning_fixes_a_rejected_token(cfg_path, provision, fake, capsys):
    rejected = {"name": "backend:x64:token", "ok": False, "detail": "BACKEND_AUTH: rejected", "hint": None}
    answers = iter([{"ok": False, "checks": [rejected]}, ALL_GREEN])
    fake.results["doctor"] = lambda **kw: next(answers)
    assert run(["--config", str(cfg_path), "setup"]) == 0, capsys.readouterr()
    assert len(calls_named(provision, "provision_guest")) == 1


@pytest.mark.usefixtures("wiring", "bundle")
def test_setup_skip_provision_cannot_fix_a_missing_clean_snapshot(cfg_path, provision, capsys):
    rc, data = json_run(["--config", str(cfg_path), "--json", "setup", "--skip-provision"], capsys)
    assert rc == 1
    pre = steps_of(data)["precheck"]
    assert pre["status"] == "blocked" and pre["blockers"] == ["clean_snapshot"]
    assert provision.calls == []


@pytest.mark.usefixtures("wiring", "no_bundle")
def test_setup_skip_both_only_checks_and_prints_the_registration(cfg_path, provision, fake, capsys):
    fake.results["doctor"] = ALL_GREEN
    argv = ["--config", str(cfg_path), "--json", "setup", "--skip-plugin", "--skip-provision"]
    rc, data = json_run(argv, capsys)
    assert rc == 0 and provision.calls == []
    assert data["register"]["argv"] == register_argv(cfg_path)


# ── the precheck stops before anything changes ──────────────────────
@pytest.mark.parametrize("check", ["vmrun", "vmx", "runtime", "vm_power", "tools", "guest_credentials",
                                   "guest_ip", "isolation", "single_vm_instance", "guest_job_root",
                                   "host_jobs_root"])
@pytest.mark.usefixtures("wiring", "ready")
def test_setup_stops_on_a_check_it_cannot_fix(cfg_path, provision, fake, capsys, check):
    broken = {"name": check, "ok": False, "detail": "broken", "hint": f"fix {check} by hand"}
    fake.results["doctor"] = {"ok": False, "checks": [*FRESH_GUEST["checks"], broken]}
    rc = run(["--config", str(cfg_path), "setup"])
    captured = capsys.readouterr()
    assert rc == 1
    assert provision.calls == [] and fake.called("vm_snapshots_list") == []
    assert f"fix {check} by hand" in captured.out and f"[blocked] precheck: setup cannot fix: {check}" \
        in captured.out
    assert REGISTER not in captured.out and "setup stopped" in captured.out


@pytest.mark.usefixtures("wiring", "ready")
def test_setup_blocked_json(cfg_path, provision, fake, capsys):
    fake.results["doctor"] = {"ok": False, "checks": [
        {"name": "isolation", "ok": False, "detail": "shared folders enabled", "hint": "disable them"},
        {"name": "backend:x64:reachable", "ok": False, "detail": "down", "hint": None}]}
    rc, data = json_run(["--config", str(cfg_path), "--json", "setup"], capsys)
    assert rc == 1 and data["ok"] is False and "register" not in data
    steps = steps_of(data)
    assert steps["precheck"]["status"] == "blocked" and steps["precheck"]["blockers"] == ["isolation"]
    assert steps["precheck"]["result"]["checks"][0]["hint"] == "disable them"
    assert steps["install-plugin"]["status"] == "not_run" and steps["provision"]["status"] == "not_run"
    assert provision.calls == []


@pytest.mark.usefixtures("wiring", "ready")
def test_setup_unknown_failed_checks_do_not_block(cfg_path, provision, fake, capsys):
    unknown = {"name": "something_new", "ok": False, "detail": "?", "hint": None}
    answers = iter([{"ok": False, "checks": [unknown]}, ALL_GREEN])
    fake.results["doctor"] = lambda **kw: next(answers)
    assert run(["--config", str(cfg_path), "setup"]) == 0, capsys.readouterr()
    assert len(calls_named(provision, "provision_guest")) == 1


@pytest.mark.usefixtures("wiring", "ready")
def test_setup_refuses_an_existing_snapshot_before_changing_anything(cfg_path, provision, fake, capsys):
    fake.results["vm_snapshots_list"] = {"snapshots": [{"name": "mcp_clean", "protected": True}]}
    rc, data = json_run(["--config", str(cfg_path), "--json", "setup"], capsys)
    assert rc == 1 and provision.calls == []
    assert steps_of(data)["precheck"]["status"] == "blocked"
    assert data["error"]["code"] == "STATE_VIOLATION"
    assert "--snapshot" in data["error"]["hint"] and "--skip-provision" in data["error"]["hint"]


@pytest.mark.usefixtures("wiring", "ready")
def test_setup_while_a_gateway_serves_names_its_pid(cfg_path, provision, fake, capsys):
    fake.fail["open"] = LockTimeout("jobs root is in use by another gateway process",
                                    details={"lock": "/jobs/.lock", "owner_pid": 4242}, hint="stop it")
    assert run(["--config", str(cfg_path), "setup"]) == 1
    err = capsys.readouterr().err
    assert "pid 4242" in err and "`setup`" in err
    assert fake.called("doctor") == [] and provision.calls == []


# ── local problems are found before the VM is touched ───────────────
@pytest.mark.usefixtures("bundle")
def test_setup_needs_the_password_before_touching_the_vm(cfg_path, wiring, provision, monkeypatch, capsys):
    monkeypatch.delenv(PW_ENV, raising=False)
    assert run(["--config", str(cfg_path), "setup"]) == 1
    err = capsys.readouterr().err
    assert PW_ENV in err and "--no-autologon" in err
    assert wiring.calls == [] and provision.calls == []


@pytest.mark.usefixtures("no_bundle", "password")
def test_setup_without_a_plugin_build_fails_before_touching_the_vm(cfg_path, wiring, capsys):
    assert run(["--config", str(cfg_path), "setup"]) == 1
    err = capsys.readouterr().err
    assert "scripts/build-release.sh" in err and "--dist" in err and "--skip-plugin" in err
    assert wiring.calls == []


@pytest.mark.usefixtures("ready")
def test_setup_root_not_derivable_is_usage_error(tmp_path, wiring, capsys):
    path = write_config(tmp_path)
    path.write_text(path.read_text(encoding="utf-8").replace(
        "config = 'C:\\x64dbg\\release\\x64\\mcp_config.json'", "config = 'C:\\elsewhere\\mcp_config.json'"),
        encoding="utf-8")
    assert run(["--config", str(path), "setup"]) == 2
    assert "--x64dbg-root" in capsys.readouterr().err
    assert wiring.calls == []


# ── failures while changing the guest ───────────────────────────────
@pytest.mark.usefixtures("wiring", "ready")
def test_setup_install_failure_stops_before_provisioning(cfg_path, provision, fake, capsys):
    provision.results["install_plugin"] = GuestOperationError(f"no x64dbg.exe under {ROOT}",
                                                              hint="see discover_x64dbg")
    rc, data = json_run(["--config", str(cfg_path), "--json", "setup"], capsys)
    assert rc == 1 and data["ok"] is False
    assert calls_named(provision, "provision_guest") == []
    steps = steps_of(data)
    assert steps["install-plugin"]["status"] == "failed"
    assert steps["provision"]["status"] == "not_run" and steps["doctor"]["status"] == "not_run"
    assert data["error"]["code"] == "GUEST_OP_FAILED"
    assert fake.runtimes[0].log[-2:] == ["lock.release", "supervisor.resume"] and fake.closed


@pytest.mark.usefixtures("wiring", "ready")
def test_setup_failure_in_human_mode_prints_the_error(cfg_path, provision, capsys):
    provision.results["provision_guest"] = GuestOperationError("provision.ps1 failed",
                                                               hint="see the log tail")
    assert run(["--config", str(cfg_path), "setup"]) == 1
    captured = capsys.readouterr()
    assert "GUEST_OP_FAILED" in captured.err and "see the log tail" in captured.err
    assert "[failed] provision" in captured.out and REGISTER not in captured.out


@pytest.mark.usefixtures("wiring", "provision", "ready")
def test_setup_final_doctor_failure_exits_1(cfg_path, fake, capsys):
    fake.results["doctor"] = FRESH_GUEST  # still failing after provisioning
    rc = run(["--config", str(cfg_path), "setup"])
    captured = capsys.readouterr()
    assert rc == 1
    assert "[failed] doctor" in captured.out and "is x64dbg running" in captured.out
    assert REGISTER not in captured.out


# ── init when there is no config ────────────────────────────────────
INIT_FLAGS = ["--non-interactive", "--vmx", "/vms/w10/w10.vmx", "--guest-user", "analyst",
              "--x64dbg-root", "C:\\tools\\x64dbg\\release", "--guest-password-env", PW_ENV]


@pytest.mark.usefixtures("ready", "vmrun_found")
def test_setup_creates_the_config_first(tmp_path, wiring, provision, capsys):
    path = tmp_path / "new" / "config.toml"
    rc, data = json_run(["--config", str(path), "--json", "setup", *INIT_FLAGS], capsys)
    assert rc == 0, data
    prof = gw_config.load_config(path, environ={}).profile()
    assert prof.vmx == "/vms/w10/w10.vmx" and prof.guest_password_env == PW_ENV
    assert data["config"] == {"path": str(path), "created": True, "profile": "win10"}
    assert steps_of(data)["init"]["status"] == "done"
    assert calls_named(provision, "provision_guest")[0]["x64dbg_root"] == "C:\\tools\\x64dbg\\release"
    assert wiring.calls[0]["config"].profile().vmx == "/vms/w10/w10.vmx"


@pytest.mark.usefixtures("wiring", "provision", "ready", "vmrun_found")
def test_setup_new_config_takes_the_upload_roots(tmp_path, capsys):
    path = tmp_path / "config.toml"
    samples = tmp_path / "samples"
    assert run(["--config", str(path), "setup", *INIT_FLAGS, "--upload-root", str(samples)]) == 0, \
        capsys.readouterr()
    assert gw_config.load_config(path, environ={}).upload_roots == (str(samples),)


@pytest.mark.usefixtures("wiring", "provision", "ready")
def test_setup_upload_root_with_an_existing_config_is_not_used(cfg_path, capsys):
    _, data = json_run(["--config", str(cfg_path), "--json", "setup", "--upload-root", "/x"], capsys)
    assert any("--upload-root" in n and "not used" in n for n in data["notes"]), data["notes"]


@pytest.mark.usefixtures("wiring", "ready", "vmrun_found")
def test_setup_new_config_takes_the_profile_and_snapshot_names(tmp_path, provision, capsys):
    path = tmp_path / "config.toml"
    rc = run(["--config", str(path), "--profile", "lab", "setup", *INIT_FLAGS, "--snapshot", "CLEAN_A"])
    assert rc == 0, capsys.readouterr()
    assert gw_config.load_config(path, environ={}).profile("lab").clean_snapshot == "CLEAN_A"
    assert calls_named(provision, "provision_guest")[0]["clean_snapshot"] == "CLEAN_A"


@pytest.mark.usefixtures("bundle", "vmrun_found")
def test_setup_writes_no_config_while_the_plan_has_a_problem(tmp_path, wiring, monkeypatch, capsys):
    monkeypatch.delenv(PW_ENV, raising=False)
    path = tmp_path / "config.toml"
    assert run(["--config", str(path), "setup", *INIT_FLAGS]) == 1
    assert not path.exists()  # the same command runs again once the password is exported
    assert PW_ENV in capsys.readouterr().err
    assert wiring.calls == []


@pytest.mark.usefixtures("ready", "vmrun_found")
def test_setup_usage_error_in_the_guest_options_writes_no_config(tmp_path, wiring):
    path = tmp_path / "config.toml"
    assert run(["--config", str(path), "setup", *INIT_FLAGS, "--wait-ready", "0"]) == 2
    assert not path.exists() and wiring.calls == []


@pytest.mark.usefixtures("ready", "vmrun_found")
def test_setup_init_usage_error_writes_nothing(tmp_path, wiring):
    path = tmp_path / "config.toml"
    assert run(["--config", str(path), "setup", "--non-interactive", "--vmx", "/v.vmx"]) == 2
    assert not path.exists() and wiring.calls == []


@pytest.mark.usefixtures("wiring", "provision", "ready", "vmrun_found")
def test_setup_interactive_init(tmp_path, monkeypatch, capsys):
    answers = iter(["", "lab", "/vms/lab/lab.vmx", "", "analyst", PW_ENV, "C:\\tools\\x64dbg\\release", ""])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))
    path = tmp_path / "config.toml"
    assert run(["--config", str(path), "setup"]) == 0, capsys.readouterr()
    assert gw_config.load_config(path, environ={}).profile("lab").vmx == "/vms/lab/lab.vmx"


@pytest.mark.usefixtures("wiring", "provision", "ready")
def test_setup_never_overwrites_an_existing_config(cfg_path, capsys):
    before = cfg_path.read_text(encoding="utf-8")
    rc, data = json_run(["--config", str(cfg_path), "--json", "setup", *INIT_FLAGS], capsys)
    assert rc == 0, data
    assert cfg_path.read_text(encoding="utf-8") == before
    assert any("--vmx" in n and "not used" in n for n in data["notes"])


# ── endpoint profiles have no guest to prepare ──────────────────────
@pytest.mark.usefixtures("wiring", "no_bundle")
def test_setup_endpoint_profile_skips_the_guest_steps(tmp_path, provision, fake, capsys):
    path = tmp_path / "ep.toml"
    path.write_text(f"""
[gateway]
jobs_root = "{(tmp_path / 'jobs').as_posix()}"
default_profile = "remote"

[profiles.remote]
mode = "endpoint"
token_source = "env"

[profiles.remote.backends.x64]
url = "http://10.0.0.20:9094"
token_env = "REMOTE_X64_TOKEN"
""", encoding="utf-8")
    fake.results["doctor"] = ALL_GREEN
    rc, data = json_run(["--config", str(path), "--json", "setup"], capsys)
    assert rc == 0, data
    steps = steps_of(data)
    assert steps["install-plugin"]["status"] == "skipped" and steps["provision"]["status"] == "skipped"
    assert "endpoint" in steps["provision"]["detail"]
    assert provision.calls == []


# ── dry run ─────────────────────────────────────────────────────────
@pytest.mark.usefixtures("ready")
def test_setup_dry_run_changes_nothing(cfg_path, wiring, provision, fake, capsys):
    rc = run(["--config", str(cfg_path), "setup", "--dry-run"])
    captured = capsys.readouterr()
    assert rc == 0, captured
    assert wiring.calls == [] and provision.calls == [] and fake.calls == []
    out = captured.out
    assert "[planned] install-plugin" in out and "bundled build v1.10.0" in out
    assert "[planned] provision" in out and "MCP_CLEAN" in out and ROOT in out
    assert cli.shell_join(register_argv(cfg_path)) in out and IDA_LINE in out.splitlines()
    assert "dry run: nothing was changed" in out


@pytest.mark.usefixtures("wiring", "provision", "ready")
def test_setup_dry_run_json_plan(cfg_path, capsys):
    rc, data = json_run(["--config", str(cfg_path), "--json", "setup", "--dry-run"], capsys)
    assert rc == 0 and data["dry_run"] is True and data["problems"] == []
    assert all(s["status"] in ("planned", "skipped") for s in data["steps"])
    steps = steps_of(data)
    # quoted for the host's shell, like the registration command
    install = cli.shell_join(["x64dbg-vm-gateway", "install-plugin", "--x64dbg-root", ROOT, "--no-relaunch"])
    assert steps["install-plugin"]["command"].startswith(install)
    provision = cli.shell_join(["x64dbg-vm-gateway", "provision", "--x64dbg-root", ROOT,
                                "--snapshot", "MCP_CLEAN"])
    assert steps["provision"]["command"].startswith(provision)
    assert steps["provision"]["command"].endswith(" " + cli.shell_join(["--config", str(cfg_path)]))
    assert f"install-plugin --x64dbg-root '{ROOT}' --no-relaunch" in steps["install-plugin"]["command"]
    assert data["shell"] == "posix"


@pytest.mark.usefixtures("wiring", "provision", "ready")
def test_setup_dry_run_commands_are_powershell_commands_on_windows(cfg_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_windows_host", lambda: True)
    _, data = json_run(["--config", str(cfg_path), "--json", "setup", "--dry-run"], capsys)
    assert data["shell"] == "powershell"
    install = steps_of(data)["install-plugin"]["command"]
    assert install == cli.shell_join(["x64dbg-vm-gateway", "install-plugin", "--x64dbg-root", ROOT,
                                      "--no-relaunch", "--config", str(cfg_path)], windows=True)
    assert f"--x64dbg-root {ROOT} --no-relaunch" in install  # a Windows path needs no quotes there
    register = data["register"]["command"]
    assert register == cli.shell_join(register_argv(cfg_path), windows=True)
    assert register.endswith(" '--' x64dbg-vm-gateway serve")
    assert data["mcp_config"][1]["command"] == "claude mcp add ida-multi-mcp '--' python3 -m ida_multi_mcp"


@pytest.mark.usefixtures("wiring", "provision", "ready")
def test_setup_dry_run_says_the_commands_are_for_powershell_on_windows(cfg_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_windows_host", lambda: True)
    assert run(["--config", str(cfg_path), "setup", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert out.splitlines()[0] == cli.POWERSHELL_NOTE and out.count("PowerShell") == 1
    assert "  claude mcp add ida-multi-mcp '--' python3 -m ida_multi_mcp" in out.splitlines()
    assert "    = " + cli.shell_join(["x64dbg-vm-gateway", "install-plugin", "--x64dbg-root", ROOT,
                                      "--no-relaunch", "--config", str(cfg_path)], windows=True) in out


@pytest.mark.usefixtures("wiring", "provision", "ready")
def test_setup_on_a_posix_host_does_not_mention_powershell(cfg_path, capsys):
    assert run(["--config", str(cfg_path), "setup", "--dry-run"]) == 0
    assert "PowerShell" not in capsys.readouterr().out


@pytest.mark.usefixtures("provision", "ready", "vmrun_found")
def test_setup_dry_run_without_a_config_writes_nothing(tmp_path, wiring, capsys):
    path = tmp_path / "config.toml"
    rc, data = json_run(["--config", str(path), "--json", "setup", "--dry-run", *INIT_FLAGS], capsys)
    assert rc == 0, data
    assert not path.exists() and wiring.calls == []
    init = steps_of(data)["init"]
    assert init["status"] == "planned" and str(path) in init["detail"]
    assert init["document"]["profiles"]["win10"]["vmx"] == "/vms/w10/w10.vmx"
    assert data["config"]["created"] is False


@pytest.mark.usefixtures("provision", "no_bundle")
def test_setup_dry_run_lists_the_problems(cfg_path, wiring, monkeypatch, capsys):
    monkeypatch.delenv(PW_ENV, raising=False)
    rc, data = json_run(["--config", str(cfg_path), "--json", "setup", "--dry-run"], capsys)
    assert rc == 1 and data["ok"] is False and wiring.calls == []
    assert sorted(p["code"] for p in data["problems"]) == ["CONFIG_INVALID", "TRANSFER_FAILED"]
    assert "register" in data  # still shows what would be registered


@pytest.mark.usefixtures("wiring", "provision", "no_bundle", "password")
def test_setup_dry_run_human_problems(cfg_path, capsys):
    assert run(["--config", str(cfg_path), "setup", "--dry-run"]) == 1
    out = capsys.readouterr().out
    assert "problem [TRANSFER_FAILED]" in out and "scripts/build-release.sh" in out


# ── review findings: checks before the guest changes ────────────────
@pytest.mark.parametrize("bad", [["--bind", "not-an-ip"], ["--bind", "::1"], ["--user", "bad/user"]])
@pytest.mark.usefixtures("ready")
def test_setup_checks_the_provision_arguments_before_changing_the_guest(cfg_path, wiring, provision, capsys,
                                                                        bad):
    rc, data = json_run(["--config", str(cfg_path), "--json", "setup", *bad], capsys)
    assert rc == 1 and data["error"]["code"] == "CONFIG_INVALID"
    assert provision.calls == [] and wiring.calls == []


@pytest.mark.usefixtures("wiring", "provision", "ready")
def test_setup_dry_run_lists_bad_provision_arguments(cfg_path, capsys):
    rc, data = json_run(["--config", str(cfg_path), "--json", "setup", "--dry-run", "--bind", "nope"], capsys)
    assert rc == 1 and [p["code"] for p in data["problems"]] == ["CONFIG_INVALID"]


@pytest.mark.parametrize("value", ["nan", "inf", "-1"])
@pytest.mark.usefixtures("ready")
def test_setup_wait_ready_must_be_a_positive_finite_number(cfg_path, wiring, value):
    assert run(["--config", str(cfg_path), "setup", "--wait-ready", value]) == 2
    assert wiring.calls == []


@pytest.mark.usefixtures("ready")
def test_setup_dist_without_the_build_fails_before_the_vm(cfg_path, wiring, provision, tmp_path, capsys):
    (tmp_path / "empty").mkdir()
    argv = ["--config", str(cfg_path), "--json", "setup", "--dist", str(tmp_path / "empty")]
    rc, data = json_run(argv, capsys)
    assert rc == 1 and data["error"]["code"] == "TRANSFER_FAILED"
    assert wiring.calls == [] and provision.calls == []


@pytest.mark.usefixtures("wiring", "provision", "bundle")
def test_setup_without_autologon_says_someone_must_log_on(cfg_path, capsys):
    _, data = json_run(["--config", str(cfg_path), "--json", "setup", "--dry-run", "--no-autologon"], capsys)
    assert any("log on" in n and "analyst" in n and "300" in n for n in data["notes"]), data["notes"]


@pytest.mark.usefixtures("ready", "vmrun_found")
def test_setup_profile_and_profile_name_must_agree_for_a_new_config(tmp_path, wiring):
    path = tmp_path / "config.toml"
    rc = run(["--config", str(path), "--profile", "a", "setup", *INIT_FLAGS, "--profile-name", "b"])
    assert rc == 2 and not path.exists() and wiring.calls == []


@pytest.mark.usefixtures("wiring", "provision", "ready")
def test_setup_notes_an_x64dbg_root_the_profile_does_not_use(cfg_path, capsys):
    argv = ["--config", str(cfg_path), "--json", "setup", "--dry-run", "--x64dbg-root", "D:\\dbg"]
    _, data = json_run(argv, capsys)
    assert any("D:\\dbg" in n and ROOT in n for n in data["notes"]), data["notes"]


@pytest.mark.usefixtures("wiring", "provision", "ready")
def test_setup_registration_says_where_serve_gets_the_guest_password(cfg_path, capsys):
    _, data = json_run(["--config", str(cfg_path), "--json", "setup"], capsys)
    note = data["register"]["note"]
    assert PW_ENV in note and "env_file" in note and "-e" in note


def test_every_check_the_real_doctor_emits_is_classified_by_setup(tmp_path):
    """A check added to Gateway.doctor must be sorted into blocking / fixable on purpose."""
    from tests.fakes.fake_runtime import make_lab

    lab = make_lab(tmp_path / "lab")
    try:
        names = [c["name"] for c in lab.gateway().doctor()["checks"]]
    finally:
        lab.close()
    assert "vm_power" in names and any(n.startswith("backend:") for n in names)
    assert [n for n in names if cli.setup_check_kind(n) == "unknown"] == []
    assert cli.setup_check_kind("runtime") == "blocking"  # emitted only when the runtime cannot be built


def test_the_static_tools_check_is_advisory_and_never_stops_setup():
    """static_tools only reports which static tools and MCP servers are found (WARN, never FAIL)."""
    assert cli.setup_check_kind("static_tools") == "advisory"
    assert "static_tools" not in cli.SETUP_BLOCKING_CHECKS


# ── help texts (first-time usability) ───────────────────────────────
def _setup_parser() -> Any:
    from tests.unit.test_cli import _subparser

    return _subparser("setup")


def test_setup_help_shows_a_first_run_example(capsys):
    assert run(["setup", "--help"]) == 0
    out = capsys.readouterr().out
    lines = out.splitlines()
    (i,) = [n for n, line in enumerate(lines) if line.strip().startswith("x64dbg-vm-gateway setup --vmx")]
    example = " ".join(lines[i:i + 2])
    assert "--guest-user" in example and "--x64dbg-root" in example
    flat = " ".join(out.split())
    assert "three values" in flat and "--dry-run" in flat and "--non-interactive" in flat


def test_setup_help_groups_have_short_titles(capsys):
    assert run(["setup", "--help"]) == 0
    out = capsys.readouterr().out.splitlines()
    groups = {g.title: g for g in _setup_parser()._action_groups if g._group_actions}
    assert {"config creation", "plugin", "provisioning"} <= set(groups), groups
    assert all(len(t or "") <= 30 for t in groups), list(groups)
    assert all(f"{t}:" in out for t in groups)  # each title stands on its own line
    assert "no config file" in (groups["config creation"].description or "")


@pytest.mark.parametrize(("option", "other"), [
    ("--user", "--guest-user"), ("--guest-user", "--user"),
    ("--snapshot", "--clean-snapshot"), ("--clean-snapshot", "--snapshot"),
    ("--profile-name", "--profile"), ("--profile", "--profile-name"),
])
def test_setup_help_tells_the_option_pairs_apart(option, other):
    from tests.unit.test_cli import _option_help

    words = _option_help("setup", option).replace(",", " ").replace(")", " ").replace("(", " ").split()
    assert other in words, (option, words)
