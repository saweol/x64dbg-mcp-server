"""`setup` on a terminal: it asks for the VM, the guest user, the guest password (getpass) and
the x64dbg folder (offering a search in the guest), and offers to save the credentials in a
0600 env file (``--save-password-file`` does that without asking). Without a terminal, or with
--non-interactive, it asks nothing and names the missing flags.

Driven through ``cli.main``; ``wiring`` and ``provision`` are replaced in ``sys.modules``,
``cli._open_guest`` (the guest channel of the x64dbg search) by a fake, and
``vm_inventory.running_vms`` (``vmrun list``) by a stub, so nothing reaches vmrun or a VM."""

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
from tests.fakes.fake_vm import FakeVm
from tests.unit.test_cli import _fake_bundle, run, write_config
from x64dbg_vm_gateway import config as gw_config
from x64dbg_vm_gateway import envfile, plugin_bundle, vm_inventory
from x64dbg_vm_gateway import platform as gw_platform
from x64dbg_vm_gateway import provision as real_provision
from x64dbg_vm_gateway.contracts import PowerState, Secret
from x64dbg_vm_gateway.errors import GuestAuthFailed, VmNotRunning
from x64dbg_vm_gateway.frontends import cli

PASSWORD = "lab-only pw'1"  # noqa: S105 - a test value (a space and a quote: the env file must keep both)
PW_ENV = cli.DEFAULT_PASSWORD_ENV
USER_ENV = cli.DEFAULT_USER_ENV
ROOT = "C:\\Users\\analyst\\Desktop\\x64dbg\\release"
#: a vmware doctor always reports guest_credentials: only a pass lets setup save the password
CREDENTIALS_OK = {"name": "guest_credentials", "ok": True, "detail": "1 guest processes listed", "hint": None}
ALL_GREEN = {"ok": True, "checks": [{"name": "vmrun", "ok": True, "detail": "/usr/bin/vmrun", "hint": None},
                                   CREDENTIALS_OK]}
REFUSED = {"ok": False, "checks": [{"name": "guest_credentials", "ok": False,
                                    "detail": "GUEST_AUTH_FAILED: invalid user name or password",
                                    "hint": "x"}]}
VM_OFF = {"ok": False, "checks": [
    {"name": "vm_power", "ok": False, "detail": "VM is off", "hint": "start it"},
    {"name": "guest_credentials", "ok": False, "detail": "skipped: the VM is not running", "hint": None}]}
FOUND = [{"root": ROOT,
          "x64": {"exe": True, "plugin": {"present": False}, "config": {"state": "missing"}, "ready": False},
          "x32": {"exe": True, "plugin": {"present": False}, "config": {"state": "missing"}, "ready": False}}]


@pytest.fixture(autouse=True)
def posix_host(monkeypatch) -> None:
    monkeypatch.setattr(cli, "_windows_host", lambda: False)


@pytest.fixture(autouse=True)
def no_vmrun_list(monkeypatch) -> None:
    """``vmrun list`` is never run by these tests."""
    monkeypatch.setattr(vm_inventory, "running_vms", lambda runner: [])
    monkeypatch.setattr(vm_inventory, "inventory_files", lambda **kw: [])


@pytest.fixture(autouse=True)
def environment(monkeypatch, tmp_path) -> Path:
    """No guest password exported; the per-user config folder is a temporary one."""
    monkeypatch.delenv(PW_ENV, raising=False)
    monkeypatch.delenv(USER_ENV, raising=False)
    monkeypatch.delenv(gw_config.ENV_CONFIG_PATH, raising=False)
    home = tmp_path / "home" / ".config" / "x64dbg-vm-gateway"
    monkeypatch.setattr(gw_config, "default_config_path", lambda **kw: home / "config.toml")
    monkeypatch.setattr(gw_platform, "find_vmrun", lambda configured="auto", **kw: "/usr/bin/vmrun")
    return home


@pytest.fixture
def fake() -> FakeApp:
    app = FakeApp()
    app.results["doctor"] = ALL_GREEN
    app.results["vm_snapshots_list"] = {"snapshots": []}
    return app


@pytest.fixture
def wiring(monkeypatch, fake) -> types.SimpleNamespace:
    calls: list[dict[str, Any]] = []

    def build_app(config: Any, profile: str | None = None, environ: Any = None) -> FakeApp:
        calls.append({"config": config, "profile": profile, "environ": dict(environ or {})})
        return fake

    mod = types.SimpleNamespace(build_app=build_app, calls=calls)
    monkeypatch.setitem(sys.modules, "x64dbg_vm_gateway.wiring", mod)
    return mod


@pytest.fixture
def provision(monkeypatch) -> types.SimpleNamespace:
    calls: list[tuple[str, dict[str, Any]]] = []
    results: dict[str, Any] = {
        "provision_guest": {"status": "ok", "rebooted": True,
                            "snapshot": {"name": "MCP_CLEAN", "replaced": False}},
        "install_plugin": {"x64dbg_root": ROOT, "installed": {"x64": {}, "x32": {}}, "relaunched": False},
        "discover_x64dbg": FOUND,
    }

    def answer(name: str, kw: dict[str, Any]) -> Any:
        """``results[name]``: a value, an exception to raise, or a callable giving either."""
        calls.append((name, kw))
        res = results[name]
        if callable(res):
            res = res(**kw)
        if isinstance(res, BaseException):
            raise res
        return res

    mod = types.SimpleNamespace(
        provision_guest=lambda runtime, **kw: answer("provision_guest", kw),
        install_plugin=lambda runtime, **kw: answer("install_plugin", kw),
        discover_x64dbg=lambda channel, **kw: answer("discover_x64dbg", {"channel": channel, **kw}),
        check_provision_arguments=real_provision.check_provision_arguments,
        calls=calls, results=results)
    monkeypatch.setitem(sys.modules, "x64dbg_vm_gateway.provision", mod)
    return mod


def called(provision: types.SimpleNamespace, name: str) -> list[dict[str, Any]]:
    return [kw for n, kw in provision.calls if n == name]


@pytest.fixture
def bundle(tmp_path, monkeypatch) -> Path:
    root = _fake_bundle(tmp_path / "bundle")
    monkeypatch.setattr(plugin_bundle, "bundle_root", lambda: root)
    return root


@pytest.fixture
def guest(monkeypatch) -> types.SimpleNamespace:
    """The guest the x64dbg search opens (``cli._open_guest``): a running FakeVm."""
    state = types.SimpleNamespace(vm=FakeVm(), channel=object(), opened=[])

    def open_guest(vmx: str, *, vmrun: str, vmrun_type: str, user: str, password: Secret) -> tuple[Any, Any]:
        state.opened.append({"vmx": vmx, "vmrun": vmrun, "user": user, "password": password.reveal()})
        return state.vm, state.channel

    monkeypatch.setattr(cli, "_open_guest", open_guest)
    return state


@pytest.fixture
def terminal(monkeypatch) -> types.SimpleNamespace:
    """stdin is a terminal. ``answers`` feed input() (echoed to stderr, as a terminal shows what is
    typed), ``passwords`` feed getpass (nothing echoed). Running out of answers is end of input."""
    state = types.SimpleNamespace(answers=[], passwords=[], password_prompts=[], asked=0)
    monkeypatch.setattr(cli, "_stdin_is_tty", lambda: True)

    def fake_input(prompt: str = "") -> str:
        state.asked += 1
        if not state.answers:
            raise EOFError
        answer = state.answers.pop(0)
        sys.stderr.write(answer + "\n")
        return answer

    def fake_getpass(prompt: str = "Password: ", stream: Any = None) -> str:
        state.password_prompts.append(prompt)
        (stream or sys.stderr).write(prompt + "\n")
        if not state.passwords:
            raise EOFError
        return state.passwords.pop(0)

    monkeypatch.setattr("builtins.input", fake_input)
    monkeypatch.setattr("getpass.getpass", fake_getpass)
    return state


@pytest.fixture
def vm_file(tmp_path) -> Path:
    vmx = tmp_path / "vms" / "win10" / "win10.vmx"
    vmx.parent.mkdir(parents=True)
    vmx.write_text('displayName = "win10"\n', encoding="utf-8")
    return vmx


def env_values(path: Path) -> dict[str, str]:
    return envfile.read_env_file(path)


def mode(path: Path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


POSIX = sys.platform != "win32"


# ── a first run on a terminal ───────────────────────────────────────
@pytest.mark.usefixtures("bundle")
def test_first_run_asks_for_the_four_values_and_saves_the_credentials(
        tmp_path, environment, terminal, guest, wiring, provision, vm_file, monkeypatch, capsys):
    monkeypatch.setattr(vm_inventory, "running_vms", lambda runner: [str(vm_file)])
    terminal.answers = ["1", "analyst", "", "1", ""]  # VM, user, search the guest, x64dbg folder, save
    terminal.passwords = [PASSWORD]
    path = tmp_path / "cfg" / "config.toml"
    rc = run(["--config", str(path), "setup"])
    captured = capsys.readouterr()
    assert rc == 0, captured
    # the config: the chosen VM, the credentials through the env file
    conf = gw_config.load_config(path, environ={})
    prof = conf.profile()
    # the profile names the user itself: the password file is written only once the guest accepts it
    assert prof.vmx == str(vm_file) and prof.guest_user == "analyst" and prof.guest_user_env is None
    assert prof.guest_password_env == PW_ENV
    assert prof.backends[0].exe == f"{ROOT}\\x64\\x64dbg.exe"
    env_file = environment / "win10.env"
    assert Path(conf.env_file) == env_file
    assert env_values(env_file) == {USER_ENV: "analyst", PW_ENV: PASSWORD}
    if POSIX:
        assert mode(env_file) == 0o600
    # what a later `serve` resolves from the config alone (no environment): user and password
    later = envfile.resolve_environ(conf, {})
    assert later[USER_ENV] == "analyst" and later[PW_ENV] == PASSWORD
    # the search used the typed credentials; this run's provisioning got them too
    assert guest.opened == [{"vmx": str(vm_file), "vmrun": "auto", "user": "analyst", "password": PASSWORD}]
    (prov,) = called(provision, "provision_guest")
    assert prov["user"] == "analyst" and prov["password"].reveal() == PASSWORD
    assert prov["x64dbg_root"] == ROOT
    # what the terminal showed
    err = captured.err
    assert "1) " + str(vm_file) in err and "running" in err
    assert "Guest user" in err and "Password of guest user analyst" in err
    assert "Search the guest for x64dbg" in err and ROOT in err
    assert f"Save the guest user and password in {env_file}" in err
    assert PASSWORD not in captured.out + captured.err
    assert terminal.answers == [] and terminal.passwords == []
    # the end of the run says where the password went
    lines = captured.out.splitlines()
    assert any(line.startswith("warning:") and "auto-logon" in line and "lab-only" in line for line in lines)
    assert lines[-1] == "setup complete"


@pytest.mark.usefixtures("bundle")
def test_the_flags_skip_their_questions(tmp_path, terminal, guest, wiring, provision, vm_file, capsys):
    terminal.passwords = [PASSWORD]
    terminal.answers = ["n"]  # only the save question is left
    path = tmp_path / "config.toml"
    rc = run(["--config", str(path), "setup", "--vmx", str(vm_file), "--guest-user", "analyst",
              "--x64dbg-root", ROOT])
    captured = capsys.readouterr()
    assert rc == 0, captured
    assert terminal.asked == 1 and guest.opened == []  # no search: the folder was given
    prof = gw_config.load_config(path, environ={}).profile()
    assert prof.guest_user == "analyst" and prof.guest_user_env is None  # nothing saved
    # the typed password reaches this run's gateway, but no file
    assert wiring.calls[0]["environ"][PW_ENV] == PASSWORD
    assert not list(tmp_path.glob("home/.config/x64dbg-vm-gateway/*.env"))
    assert "not saved" in captured.out and PW_ENV in captured.out


@pytest.mark.usefixtures("bundle")
def test_an_exported_password_is_not_asked_for(tmp_path, terminal, wiring, provision, vm_file, monkeypatch,
                                               capsys):
    monkeypatch.setenv(PW_ENV, PASSWORD)
    path = tmp_path / "config.toml"
    rc = run(["--config", str(path), "setup", "--vmx", str(vm_file), "--guest-user", "analyst",
              "--x64dbg-root", ROOT])
    assert rc == 0, capsys.readouterr()
    assert terminal.password_prompts == [] and terminal.asked == 0


@pytest.mark.usefixtures("bundle")
def test_the_search_asks_again_when_the_guest_refuses_the_password(
        tmp_path, terminal, guest, wiring, provision, vm_file, capsys):
    answers = iter([GuestAuthFailed("invalid user name or password"), FOUND])
    provision.results["discover_x64dbg"] = lambda **kw: next(answers)
    terminal.answers = ["analyst", "", "1", "n"]
    terminal.passwords = ["wrong", PASSWORD]
    path = tmp_path / "config.toml"
    rc = run(["--config", str(path), "setup", "--vmx", str(vm_file)])
    captured = capsys.readouterr()
    assert rc == 0, captured
    assert [o["password"] for o in guest.opened] == ["wrong", PASSWORD]
    assert "refused" in captured.err
    assert called(provision, "provision_guest")[0]["password"].reveal() == PASSWORD


@pytest.mark.usefixtures("bundle")
def test_a_stopped_vm_cannot_be_searched_so_the_folder_is_typed(
        tmp_path, terminal, guest, wiring, provision, vm_file, capsys):
    guest.vm.power = PowerState.OFF
    terminal.answers = ["analyst", "", ROOT, "n"]
    terminal.passwords = [PASSWORD]
    path = tmp_path / "config.toml"
    rc = run(["--config", str(path), "setup", "--vmx", str(vm_file)])
    captured = capsys.readouterr()
    assert rc == 0, captured
    assert called(provision, "discover_x64dbg") == []
    assert "not running" in captured.err
    assert gw_config.load_config(path, environ={}).profile().backends[0].exe == f"{ROOT}\\x64\\x64dbg.exe"


@pytest.mark.usefixtures("bundle")
def test_a_failed_search_falls_back_to_typing(tmp_path, terminal, guest, wiring, provision, vm_file, capsys):
    provision.results["discover_x64dbg"] = VmNotRunning("the VM is not powered on")
    terminal.answers = ["analyst", "y", "not a path", ROOT, "n"]
    terminal.passwords = [PASSWORD]
    rc = run(["--config", str(tmp_path / "config.toml"), "setup", "--vmx", str(vm_file)])
    captured = capsys.readouterr()
    assert rc == 0, captured
    assert "VM_NOT_RUNNING" in captured.err and "absolute guest path" in captured.err


@pytest.mark.usefixtures("bundle")
def test_dry_run_asks_but_searches_and_writes_nothing(tmp_path, environment, terminal, guest, wiring,
                                                      provision, vm_file, capsys):
    terminal.answers = ["analyst", ROOT, ""]
    terminal.passwords = [PASSWORD]
    path = tmp_path / "config.toml"
    rc = run(["--config", str(path), "--json", "setup", "--dry-run", "--vmx", str(vm_file)])
    captured = capsys.readouterr()
    assert rc == 0, captured
    data = json.loads(captured.out)
    assert guest.opened == [] and wiring.calls == [] and not path.exists()
    assert not (environment / "win10.env").exists()
    assert data["password_file"]["status"] == "planned"
    assert data["password_file"]["path"] == str(environment / "win10.env")
    assert data["password_file"]["variables"] == [USER_ENV, PW_ENV]
    assert PASSWORD not in captured.out + captured.err
    assert "Search the guest" not in captured.err


def test_a_vm_path_that_does_not_exist_is_asked_again(tmp_path, terminal, guest, wiring, provision, vm_file,
                                                      capsys):
    terminal.answers = [str(tmp_path / "nope.vmx"), str(vm_file)]  # then end of input
    rc = run(["--config", str(tmp_path / "config.toml"), "setup"])
    err = capsys.readouterr().err
    assert rc == 2 and "no such file" in err and "cancelled" in err
    assert not (tmp_path / "config.toml").exists() and wiring.calls == []


def test_end_of_input_while_asking_writes_nothing(tmp_path, terminal, wiring, vm_file, capsys):
    terminal.answers = []
    assert run(["--config", str(tmp_path / "config.toml"), "setup", "--vmx", str(vm_file)]) == 2
    assert not (tmp_path / "config.toml").exists() and wiring.calls == []


# ── no terminal / --non-interactive ─────────────────────────────────
def test_without_a_terminal_setup_names_the_missing_flags(tmp_path, wiring, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_stdin_is_tty", lambda: False)
    monkeypatch.setattr("builtins.input", lambda *_a: pytest.fail("must not ask"))
    path = tmp_path / "config.toml"
    assert run(["--config", str(path), "setup"]) == 2
    err = capsys.readouterr().err
    assert "--vmx" in err and "--guest-user" in err and "--x64dbg-root" in err
    assert "not a terminal" in err and str(path) in err
    assert not path.exists() and wiring.calls == []


def test_non_interactive_on_a_terminal_asks_nothing(tmp_path, terminal, wiring, vm_file, capsys):
    path = tmp_path / "config.toml"
    assert run(["--config", str(path), "setup", "--non-interactive", "--vmx", str(vm_file)]) == 2
    err = capsys.readouterr().err
    assert "--guest-user" in err and "--x64dbg-root" in err and "--vmx" not in err.split("needs", 1)[1]
    assert "--non-interactive" in err
    assert terminal.asked == 0 and terminal.password_prompts == [] and not path.exists()


@pytest.mark.usefixtures("bundle")
def test_non_interactive_without_the_password_says_how_to_give_it(tmp_path, terminal, wiring, vm_file,
                                                                  capsys):
    rc = run(["--config", str(tmp_path / "config.toml"), "setup", "--non-interactive", "--vmx", str(vm_file),
              "--guest-user", "analyst", "--x64dbg-root", ROOT])
    err = capsys.readouterr().err
    assert rc == 1 and PW_ENV in err and "terminal" in err
    assert terminal.password_prompts == [] and wiring.calls == []


# ── --save-password-file ────────────────────────────────────────────
NEW_CONFIG = ["--vmx", "{vmx}", "--guest-user", "analyst", "--x64dbg-root", ROOT]


def new_config_flags(vm_file: Path) -> list[str]:
    return [a.format(vmx=vm_file) for a in NEW_CONFIG]


@pytest.mark.usefixtures("bundle")
def test_save_password_file_writes_the_exported_password(tmp_path, environment, wiring, provision, vm_file,
                                                         monkeypatch, capsys):
    monkeypatch.setenv(PW_ENV, PASSWORD)
    path = tmp_path / "config.toml"
    rc = run(["--config", str(path), "--json", "setup", *new_config_flags(vm_file), "--save-password-file"])
    captured = capsys.readouterr()
    assert rc == 0, captured
    data = json.loads(captured.out)
    target = environment / "win10.env"
    assert env_values(target) == {USER_ENV: "analyst", PW_ENV: PASSWORD}
    assert data["password_file"] == {"path": str(target), "status": "written",
                                     "variables": [USER_ENV, PW_ENV], "config_line": None}
    assert Path(gw_config.load_config(path, environ={}).env_file) == target
    assert PASSWORD not in captured.out + captured.err


@pytest.mark.usefixtures("bundle")
def test_save_password_file_to_an_explicit_path(tmp_path, wiring, provision, vm_file, monkeypatch, capsys):
    monkeypatch.setenv(PW_ENV, PASSWORD)
    target = tmp_path / "secrets" / "lab.env"
    path = tmp_path / "config.toml"
    rc = run(["--config", str(path), "setup", *new_config_flags(vm_file),
              "--save-password-file", str(target)])
    assert rc == 0, capsys.readouterr()
    assert env_values(target)[PW_ENV] == PASSWORD
    if POSIX:
        assert mode(target) == 0o600 and mode(target.parent) == 0o700
    assert Path(gw_config.load_config(path, environ={}).env_file) == target


@pytest.mark.usefixtures("bundle")
def test_an_existing_password_file_is_kept_without_force(tmp_path, wiring, provision, vm_file, monkeypatch,
                                                         capsys):
    monkeypatch.setenv(PW_ENV, PASSWORD)
    target = tmp_path / "lab.env"
    target.write_text("GW_ADMIN=keep-me\n", encoding="utf-8")
    target.chmod(0o600)
    path = tmp_path / "config.toml"
    argv = ["--config", str(path), "setup", *new_config_flags(vm_file), "--save-password-file", str(target)]
    assert run(argv) == 1
    err = capsys.readouterr().err
    assert str(target) in err and "--force" in err
    assert target.read_text(encoding="utf-8") == "GW_ADMIN=keep-me\n"
    assert not path.exists() and wiring.calls == []  # refused before anything was written or contacted
    assert run([*argv, "--force"]) == 0, capsys.readouterr()
    assert env_values(target) == {"GW_ADMIN": "keep-me", USER_ENV: "analyst", PW_ENV: PASSWORD}


@pytest.mark.usefixtures("bundle")
def test_an_existing_config_is_never_rewritten_setup_prints_the_line(tmp_path, wiring, provision, monkeypatch,
                                                                     capsys):
    cfg = write_config(tmp_path)  # guest_user analyst, guest_password_env GW_TEST_GUEST_PW, no env_file
    before = cfg.read_text(encoding="utf-8")
    monkeypatch.setenv("GW_TEST_GUEST_PW", PASSWORD)
    target = tmp_path / "lab.env"
    rc = run(["--config", str(cfg), "setup", "--save-password-file", str(target)])
    captured = capsys.readouterr()
    assert rc == 0, captured
    assert cfg.read_text(encoding="utf-8") == before
    assert env_values(target) == {"GW_TEST_GUEST_PW": PASSWORD}  # the config names the user itself
    assert f"env_file = '{target}'" in captured.out and "[gateway]" in captured.out


@pytest.mark.usefixtures("bundle")
def test_existing_config_on_a_terminal_asks_only_for_the_password(tmp_path, terminal, wiring, provision,
                                                                  capsys):
    cfg = write_config(tmp_path)
    terminal.passwords = [PASSWORD]
    terminal.answers = ["n"]
    rc = run(["--config", str(cfg), "setup"])
    captured = capsys.readouterr()
    assert rc == 0, captured
    assert terminal.password_prompts and terminal.asked == 1
    assert wiring.calls[0]["environ"]["GW_TEST_GUEST_PW"] == PASSWORD
    assert called(provision, "provision_guest")[0]["password"].reveal() == PASSWORD


def _config_with_env_file(tmp_path: Path, env_file: Path) -> Path:
    cfg = write_config(tmp_path)
    text = cfg.read_text(encoding="utf-8").replace(
        'default_profile = "win10"', f'default_profile = "win10"\nenv_file = "{env_file.as_posix()}"', 1)
    cfg.write_text(text, encoding="utf-8")
    return cfg


@pytest.mark.usefixtures("bundle")
def test_a_configured_env_file_that_is_missing_is_where_the_password_goes(tmp_path, terminal, wiring,
                                                                          provision, capsys):
    """gateway.env_file names a file that is not there yet: setup asks for the password and
    offers to write exactly that file (no config line to change)."""
    env_file = tmp_path / "secrets" / "lab.env"
    cfg = _config_with_env_file(tmp_path, env_file)
    terminal.passwords = [PASSWORD]
    terminal.answers = [""]  # yes, save it
    rc = run(["--config", str(cfg), "--json", "setup"])
    captured = capsys.readouterr()
    assert rc == 0, captured
    assert env_values(env_file) == {"GW_TEST_GUEST_PW": PASSWORD}
    data = json.loads(captured.out)
    assert data["password_file"]["path"] == str(env_file) and data["password_file"]["config_line"] is None
    assert f"Save the guest user and password in {env_file}" in captured.err


@pytest.mark.usefixtures("bundle")
def test_a_password_file_elsewhere_than_the_configured_one_says_to_change_it(tmp_path, wiring, provision,
                                                                             monkeypatch, capsys):
    configured = tmp_path / "old.env"
    configured.write_text("GW_TEST_GUEST_PW=old\n", encoding="utf-8")
    configured.chmod(0o600)
    cfg = _config_with_env_file(tmp_path, configured)
    monkeypatch.setenv("GW_TEST_GUEST_PW", PASSWORD)
    target = tmp_path / "new.env"
    rc = run(["--config", str(cfg), "setup", "--save-password-file", str(target)])
    out = capsys.readouterr().out
    assert rc == 0, out
    assert "change gateway.env_file" in out and f"env_file = '{target}'" in out
    assert configured.read_text(encoding="utf-8") == "GW_TEST_GUEST_PW=old\n"


def test_the_session_never_shows_the_password():
    session = cli._SetupSession(interactive=True, env={PW_ENV: PASSWORD})
    session.password_file = cli._PasswordFile(Path("x.env"), None, [(PW_ENV, PASSWORD)])
    assert PASSWORD not in repr(session) and PASSWORD not in repr(session.password_file)
    assert PASSWORD not in json.dumps(session.password_file.public())


@pytest.mark.usefixtures("bundle")
def test_no_autologon_needs_no_warning(tmp_path, wiring, provision, monkeypatch, capsys):
    cfg = write_config(tmp_path)
    monkeypatch.setenv("GW_TEST_GUEST_PW", PASSWORD)
    rc = run(["--config", str(cfg), "--json", "setup", "--no-autologon"])
    data = json.loads(capsys.readouterr().out)
    assert rc == 0 and "autologon_warning" not in data
    rc = run(["--config", str(cfg), "--json", "setup"])
    assert "registry" in json.loads(capsys.readouterr().out)["autologon_warning"]


# ── the env file writer ─────────────────────────────────────────────
@pytest.mark.parametrize("value", [PASSWORD, " leading and trailing ", "'quoted'", '"dq"', "#hash", "a=b=c",
                                   "export x", "\u00e4\u00f6\u00fc \u2603"])
def test_password_file_values_read_back_unchanged(tmp_path, value):
    target = tmp_path / "x.env"
    cli.write_password_file(target, [(PW_ENV, value)], profile="win10", force=False)
    assert envfile.read_env_file(target) == {PW_ENV: value}


#: every character str.splitlines (the env file reader) ends a line at, and NUL
UNSTORABLE = ["two\nlines", "cr\rhere", "nul\x00", "vt\x0bhere", "ff\x0chere", "fs\x1chere", "gs\x1dhere",
              "rs\x1ehere", "nel\x85here", "ls here", "ps here"]


@pytest.mark.parametrize("value", UNSTORABLE)
def test_password_file_refuses_values_it_cannot_store(tmp_path, value):
    with pytest.raises(cli.UsageError):
        cli.write_password_file(tmp_path / "x.env", [(PW_ENV, value)], profile="win10", force=False)
    assert not (tmp_path / "x.env").exists()


def test_password_file_update_keeps_other_lines_and_comments(tmp_path):
    target = tmp_path / "x.env"
    target.write_text(f"# mine\nexport {PW_ENV}=old\nOTHER=1\n", encoding="utf-8")
    target.chmod(0o600)
    cli.write_password_file(target, [(USER_ENV, "u"), (PW_ENV, "new")], profile="win10", force=True)
    text = target.read_text(encoding="utf-8")
    assert text.startswith("# mine\n") and "OTHER=1" in text and "old" not in text
    assert envfile.read_env_file(target) == {PW_ENV: "new", "OTHER": "1", USER_ENV: "u"}


def test_password_file_on_windows_is_restricted_with_icacls(tmp_path):
    seen: list[list[str]] = []

    def fake_run(argv: list[str], **kw: Any) -> Any:
        seen.append(argv)
        return types.SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    ok = gw_platform.restrict_to_owner(tmp_path / "x.env", system="Windows", run=fake_run,
                                       environ={"USERNAME": "analyst", "USERDOMAIN": "LAB"})
    assert ok is True
    (argv,) = seen
    assert argv[0].lower().endswith("icacls.exe") and argv[1] == str(tmp_path / "x.env")
    assert argv[2:] == ["/inheritance:r", "/grant:r", "LAB\\analyst:F"]


def test_password_file_acl_failure_on_windows_is_reported_not_raised(tmp_path):
    def failing(argv: list[str], **kw: Any) -> Any:
        return types.SimpleNamespace(returncode=5, stdout=b"", stderr=b"denied")

    assert gw_platform.restrict_to_owner(tmp_path / "x.env", system="Windows", run=failing,
                                         environ={"USERNAME": "analyst"}) is False
    assert gw_platform.restrict_to_owner(tmp_path / "x.env", system="Windows", run=failing,
                                         environ={}) is False


# ── review findings: the password is saved only once the guest accepted it ──
@pytest.mark.usefixtures("bundle")
def test_a_password_the_guest_refuses_is_not_saved_and_is_asked_again(
        tmp_path, environment, terminal, guest, wiring, provision, fake, vm_file, capsys):
    fake.results["doctor"] = REFUSED
    terminal.passwords = ["wrong"]
    terminal.answers = [""]  # yes, save it
    path = tmp_path / "config.toml"
    flags = ["--vmx", str(vm_file), "--guest-user", "analyst", "--x64dbg-root", ROOT]
    rc = run(["--config", str(path), "setup", *flags])
    captured = capsys.readouterr()
    assert rc == 1
    target = environment / "win10.env"
    assert not target.exists()  # the precheck refused it before anything was saved
    assert "not saved" in captured.out and "refused" in captured.out
    assert "wrong" not in captured.out + captured.err
    # review finding: no config pointing at a password file that was never written (doctor and
    # serve would fail with "env file not found"); env_file goes in only with the file
    conf = gw_config.load_config(path, environ={})
    assert conf.env_file is None and PW_ENV not in envfile.resolve_environ(conf, {})
    assert called(provision, "provision_guest") == []
    # the next run asks again and saves it once the guest accepts it; the config (existing now)
    # is not edited: setup prints the line
    fake.results["doctor"] = ALL_GREEN
    terminal.passwords = [PASSWORD]
    terminal.answers = [""]
    before = path.read_text(encoding="utf-8")
    rc = run(["--config", str(path), "setup"])
    out = capsys.readouterr().out
    assert rc == 0, out
    assert env_values(target) == {PW_ENV: PASSWORD}  # the config names the user (guest_user)
    assert path.read_text(encoding="utf-8") == before and f"env_file = '{target}'" in out


@pytest.mark.usefixtures("bundle")
def test_a_new_config_gets_env_file_only_once_the_password_file_is_written(
        tmp_path, environment, wiring, provision, vm_file, monkeypatch, capsys):
    monkeypatch.setenv(PW_ENV, PASSWORD)
    seen: list[str | None] = []
    real_build = wiring.build_app

    def build_app(config: Any, profile: str | None = None, environ: Any = None) -> Any:
        seen.append(gw_config.load_config(tmp_path / "config.toml", environ={}).env_file)  # on disk, now
        return real_build(config, profile, environ)

    monkeypatch.setattr(wiring, "build_app", build_app)
    rc = run(["--config", str(tmp_path / "config.toml"), "setup", *new_config_flags(vm_file),
              "--save-password-file"])
    assert rc == 0, capsys.readouterr()
    assert seen == [None]  # while the guest had not accepted the password yet
    conf = gw_config.load_config(tmp_path / "config.toml", environ={})
    assert Path(conf.env_file) == environment / "win10.env"
    assert envfile.resolve_environ(conf, {})[PW_ENV] == PASSWORD


@pytest.mark.usefixtures("bundle")
def test_a_failing_password_file_write_leaves_no_file_and_setup_goes_on(
        tmp_path, environment, wiring, provision, vm_file, monkeypatch, capsys):
    """Review finding: an OSError while writing (a volume without chmod, a full disk) is reported
    like a refused restriction; no empty file stays behind."""
    monkeypatch.setenv(PW_ENV, PASSWORD)

    def full(fd: int, data: bytes) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(cli, "_write_fd", full)
    rc = run(["--config", str(tmp_path / "config.toml"), "setup", *new_config_flags(vm_file),
              "--save-password-file"])
    out = capsys.readouterr().out
    assert rc == 0, out
    assert not (environment / "win10.env").exists()
    assert "warning:" in out and "not saved" in out
    assert gw_config.load_config(tmp_path / "config.toml", environ={}).env_file is None


def test_restrict_to_owner_never_raises(tmp_path):
    def no_chmod(path: Any, mode: int) -> None:
        raise PermissionError(1, "Operation not permitted")

    assert gw_platform.restrict_to_owner(tmp_path / "x.env", system="Linux", chmod=no_chmod) is False


def test_a_forced_update_that_fails_keeps_the_old_file(tmp_path, monkeypatch):
    """Review finding: --force replaces the file atomically (temp file, restricted, renamed)."""
    target = tmp_path / "x.env"
    target.write_text("GW_ADMIN=keep-me\nX64DBG_GW_GUEST_PW='old'\n", encoding="utf-8")
    target.chmod(0o600)

    def full(fd: int, data: bytes) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(cli, "_write_fd", full)
    with pytest.raises(OSError):
        cli.write_password_file(target, [(PW_ENV, PASSWORD)], profile="win10", force=True)
    assert target.read_text(encoding="utf-8") == "GW_ADMIN=keep-me\nX64DBG_GW_GUEST_PW='old'\n"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["x.env"]  # no temp file left


def test_a_forced_update_restricts_the_replacement_before_it_holds_the_secret(tmp_path, monkeypatch):
    target = tmp_path / "x.env"
    target.write_text("A=1\n", encoding="utf-8")
    target.chmod(0o600)
    seen: list[tuple[str, bytes]] = []

    def refuse(path: Path, **kw: Any) -> bool:
        seen.append((Path(path).name, Path(path).read_bytes()))
        return False

    monkeypatch.setattr(gw_platform, "restrict_to_owner", refuse)
    with pytest.raises(cli.ConfigError):
        cli.write_password_file(target, [(PW_ENV, PASSWORD)], profile="win10", force=True)
    assert [data for _name, data in seen] == [b""] and seen[0][0] != "x.env"
    assert target.read_text(encoding="utf-8") == "A=1\n"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["x.env"]


def test_a_numbered_vm_whose_file_is_gone_is_asked_again(tmp_path, terminal, wiring, vm_file, monkeypatch,
                                                         capsys):
    monkeypatch.setattr(vm_inventory, "running_vms", lambda runner: [str(tmp_path / "gone" / "gone.vmx")])
    terminal.answers = ["1"]  # then end of input
    assert run(["--config", str(tmp_path / "config.toml"), "setup"]) == 2
    assert "no such file" in capsys.readouterr().err


@pytest.mark.usefixtures("bundle")
def test_a_password_the_guest_could_not_check_is_not_saved(tmp_path, environment, terminal, wiring, provision,
                                                           fake, vm_file, capsys):
    fake.results["doctor"] = VM_OFF
    terminal.passwords = [PASSWORD]
    terminal.answers = [""]
    rc = run(["--config", str(tmp_path / "config.toml"), "--json", "setup", "--vmx", str(vm_file),
              "--guest-user", "analyst", "--x64dbg-root", ROOT])
    data = json.loads(capsys.readouterr().out)
    assert rc == 1 and not (environment / "win10.env").exists()
    pf = data["password_file"]
    assert pf["status"] == "not_written" and "not running" in pf["reason"]


@pytest.mark.usefixtures("bundle")
def test_the_config_is_written_before_the_password_file(tmp_path, environment, wiring, provision, vm_file,
                                                        monkeypatch, capsys):
    monkeypatch.setenv(PW_ENV, PASSWORD)

    def broken(*a: Any, **kw: Any) -> Any:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(cli, "_write_setup_config", broken)
    rc = run(["--config", str(tmp_path / "config.toml"), "setup", *new_config_flags(vm_file),
              "--save-password-file"])
    assert rc == 1 and not (environment / "win10.env").exists() and wiring.calls == []


@pytest.mark.usefixtures("bundle")
def test_a_configured_env_file_that_is_missing_stops_a_non_interactive_run_early(tmp_path, wiring,
                                                                                 monkeypatch, capsys):
    cfg = _config_with_env_file(tmp_path, tmp_path / "missing.env")
    monkeypatch.setenv("GW_TEST_GUEST_PW", PASSWORD)
    assert run(["--config", str(cfg), "setup"]) == 1
    err = capsys.readouterr().err
    assert "missing.env" in err and "--save-password-file" in err and wiring.calls == []


@pytest.mark.usefixtures("bundle")
def test_the_search_uses_the_password_of_the_env_file(tmp_path, terminal, guest, wiring, provision, capsys):
    env_file = tmp_path / "lab.env"
    env_file.write_text("GW_TEST_GUEST_PW=from-the-file\n", encoding="utf-8")
    env_file.chmod(0o600)
    cfg = _config_with_env_file(tmp_path, env_file)
    cfg.write_text(cfg.read_text(encoding="utf-8").replace(
        "config = 'C:\\x64dbg\\release\\x64\\mcp_config.json'", "config = 'C:\\elsewhere\\mcp_config.json'"),
        encoding="utf-8")  # the root cannot be derived: setup asks for it
    terminal.answers = ["", "1"]  # search, pick the first
    rc = run(["--config", str(cfg), "setup"])
    assert rc == 0, capsys.readouterr()
    assert terminal.password_prompts == []
    assert [o["password"] for o in guest.opened] == ["from-the-file"]


@pytest.mark.usefixtures("bundle")
def test_save_password_file_on_a_terminal_asks_for_a_password_that_is_not_exported(
        tmp_path, terminal, wiring, provision, capsys):
    env_file = tmp_path / "lab.env"
    env_file.write_text("GW_TEST_GUEST_PW=stale\n", encoding="utf-8")
    env_file.chmod(0o600)
    cfg = _config_with_env_file(tmp_path, env_file)
    terminal.passwords = [PASSWORD]
    rc = run(["--config", str(cfg), "setup", "--save-password-file", "--force"])
    assert rc == 0, capsys.readouterr()
    assert terminal.password_prompts and env_values(env_file) == {"GW_TEST_GUEST_PW": PASSWORD}


@pytest.mark.usefixtures("bundle")
def test_run_only_user_is_not_saved_in_the_password_file(tmp_path, wiring, provision, monkeypatch, capsys):
    """--user names the account for this run's provisioning only; the file keeps the profile's."""
    cfg = tmp_path / "qs.toml"
    cfg.write_text(f"""
[gateway]
jobs_root = "{(tmp_path / 'jobs').as_posix()}"
default_profile = "lab"

[profiles.lab]
mode = "vmware"
vmx = "/vms/lab/lab.vmx"
clean_snapshot = "MCP_CLEAN"
guest_user_env = "GW_QS_USER"
guest_password_env = "GW_QS_PW"

[profiles.lab.backends.x64]
port = 9094
config = 'C:\\x64dbg\\release\\x64\\mcp_config.json'
""", encoding="utf-8")
    monkeypatch.setenv("GW_QS_USER", "labuser")
    monkeypatch.setenv("GW_QS_PW", PASSWORD)
    target = tmp_path / "lab.env"
    rc = run(["--config", str(cfg), "setup", "--user", "someone-else", "--save-password-file", str(target)])
    assert rc == 0, capsys.readouterr()
    assert env_values(target) == {"GW_QS_USER": "labuser", "GW_QS_PW": PASSWORD}


@pytest.mark.usefixtures("bundle")
def test_a_password_file_that_cannot_be_restricted_is_not_written(tmp_path, environment, wiring, provision,
                                                                  vm_file, monkeypatch, capsys):
    monkeypatch.setenv(PW_ENV, PASSWORD)
    monkeypatch.setattr(gw_platform, "restrict_to_owner", lambda path, **kw: False)
    rc = run(["--config", str(tmp_path / "config.toml"), "setup", *new_config_flags(vm_file),
              "--save-password-file"])
    out = capsys.readouterr().out
    assert rc == 0, out
    assert not (environment / "win10.env").exists()
    assert "warning:" in out and "not saved" in out


def test_write_password_file_never_puts_the_secret_in_an_unrestricted_file(tmp_path, monkeypatch):
    seen: list[bytes] = []

    def refuse(path: Path, **kw: Any) -> bool:
        seen.append(Path(path).read_bytes())  # what the file holds while it is not restricted yet
        return False

    monkeypatch.setattr(gw_platform, "restrict_to_owner", refuse)
    with pytest.raises(cli.ConfigError):
        cli.write_password_file(tmp_path / "x.env", [(PW_ENV, PASSWORD)], profile="win10", force=False)
    assert seen == [b""] and not (tmp_path / "x.env").exists()


@pytest.mark.usefixtures("bundle")
def test_dry_run_lists_an_existing_password_file_as_a_problem(tmp_path, wiring, provision, vm_file,
                                                              monkeypatch, capsys):
    monkeypatch.setenv(PW_ENV, PASSWORD)
    target = tmp_path / "lab.env"
    target.write_text("X=1\n", encoding="utf-8")
    rc, out = run(["--config", str(tmp_path / "c.toml"), "--json", "setup", "--dry-run",
                   *new_config_flags(vm_file), "--save-password-file", str(target)]), capsys.readouterr().out
    data = json.loads(out)
    assert rc == 1 and any("exists already" in p["message"] for p in data["problems"])
    assert data["steps"][0]["status"] == "planned"  # the rest of the plan is still shown


@pytest.mark.usefixtures("bundle")
def test_a_password_file_path_that_is_a_folder_is_refused(tmp_path, wiring, provision, vm_file, monkeypatch,
                                                          capsys):
    monkeypatch.setenv(PW_ENV, PASSWORD)
    rc = run(["--config", str(tmp_path / "c.toml"), "setup", *new_config_flags(vm_file),
              "--save-password-file", str(tmp_path), "--force"])
    assert rc == 1 and "not a file" in capsys.readouterr().err and wiring.calls == []


def test_password_file_update_of_a_file_that_is_not_utf8_is_refused(tmp_path):
    target = tmp_path / "x.env"
    target.write_bytes(b"A=\xff\n")
    with pytest.raises(cli.ConfigError):
        cli.write_password_file(target, [(PW_ENV, PASSWORD)], profile="win10", force=True)
    assert target.read_bytes() == b"A=\xff\n"


def test_an_empty_upload_root_is_refused(tmp_path, vm_file):
    assert run(["--config", str(tmp_path / "c.toml"), "init", "--non-interactive", "--vmx", str(vm_file),
                "--guest-user", "u", "--x64dbg-root", ROOT, "--upload-root", ""]) == 2
    assert not (tmp_path / "c.toml").exists()


def test_odd_answers_are_asked_again(tmp_path, terminal, guest, wiring, provision, vm_file, monkeypatch,
                                     capsys):
    monkeypatch.setattr(vm_inventory, "running_vms", lambda runner: [str(vm_file)])
    terminal.answers = ["\u00b2", f'"{vm_file}"']  # a superscript two, then a pasted quoted path
    rc = run(["--config", str(tmp_path / "config.toml"), "setup"])
    err = capsys.readouterr().err
    assert rc == 2 and "cancelled" in err and "unexpected" not in err  # end of input at the next question
    assert "Guest user" in err  # the quoted path was taken


def test_a_password_prompt_that_would_echo_is_refused(tmp_path, terminal, wiring, vm_file, monkeypatch,
                                                      capsys):
    import getpass as getpass_module
    import warnings

    def echoing(prompt: str = "", stream: Any = None) -> str:
        warnings.warn("Can not control echo on the terminal.", getpass_module.GetPassWarning, stacklevel=2)
        return PASSWORD

    monkeypatch.setattr("getpass.getpass", echoing)
    terminal.answers = ["analyst"]
    rc = run(["--config", str(tmp_path / "c.toml"), "setup", "--vmx", str(vm_file), "--x64dbg-root", ROOT])
    err = capsys.readouterr().err
    assert rc == 2 and "echo" in err and PW_ENV in err and not (tmp_path / "c.toml").exists()
