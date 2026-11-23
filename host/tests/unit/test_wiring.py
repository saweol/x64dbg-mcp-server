"""Tests for wiring: env files, credentials, guest token parsing, Runtime and build_app."""

from __future__ import annotations

import json
import os
import threading
from dataclasses import replace
from pathlib import Path

import pytest
from x64dbg_vm_gateway.app import Gateway
from x64dbg_vm_gateway.wiring import (
    PROVISION_HINT,
    Runtime,
    UnresolvedClient,
    build_app,
    build_runtime,
    builtin_catalog_for,
    guest_credentials,
    parse_guest_token,
    read_env_file,
    resolve_environ,
)

from tests.fakes.fake_guest import FakeGuest
from tests.fakes.fake_plugin_server import FakePluginServer
from tests.fakes.fake_runtime import CFG, PW_ENV, make_lab, token_for
from tests.fakes.fake_vm import FakeClock, FakeVm
from x64dbg_vm_gateway import wiring
from x64dbg_vm_gateway.backend import HttpBackendClient
from x64dbg_vm_gateway.catalog import ToolCatalog
from x64dbg_vm_gateway.config import BackendConfig, GatewayConfig, ProfileConfig, load_config
from x64dbg_vm_gateway.contracts import Secret
from x64dbg_vm_gateway.errors import BackendAuthError, ConfigError, GuestOperationError, VmNotReady
from x64dbg_vm_gateway.guest import VixChannel
from x64dbg_vm_gateway.vmrun import NullProvider, VmrunCli, VmrunProvider

POSIX = os.name == "posix"
GOOD = "0123456789abcdef0123456789abcdef"


# ── env files ───────────────────────────────────────────────────────
def env_file(tmp_path: Path, text: str, mode: int = 0o600) -> Path:
    p = tmp_path / "gw.env"
    p.write_text(text, encoding="utf-8")
    if POSIX:
        os.chmod(p, mode)
    return p


def test_read_env_file_parses_key_value_lines(tmp_path):
    p = env_file(tmp_path, "# comment\n\nA=1\nB = two words \nC=\"quoted value\"\nD='single'\n"
                           "export E=exported\nF=\nG=a=b\n  # indented comment\n")
    assert read_env_file(p) == {"A": "1", "B": "two words", "C": "quoted value", "D": "single",
                                "E": "exported", "F": "", "G": "a=b"}


def test_read_env_file_does_no_shell_expansion(tmp_path):
    p = env_file(tmp_path, "A=$HOME\nB=`id`\nC=${X:-y}\n")
    assert read_env_file(p) == {"A": "$HOME", "B": "`id`", "C": "${X:-y}"}


@pytest.mark.parametrize("line", ["NOEQUALS", "1BAD=x", "BAD NAME=x", "=x"])
def test_read_env_file_rejects_malformed_lines_without_echoing_values(tmp_path, line):
    p = env_file(tmp_path, f"OK=1\n{line}supersecret\n")
    with pytest.raises(ConfigError) as ei:
        read_env_file(p)
    assert "line 2" in ei.value.message
    assert "supersecret" not in ei.value.message and "supersecret" not in str(ei.value.details)


@pytest.mark.skipif(not POSIX, reason="POSIX permission bits")
@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o620])
def test_read_env_file_refuses_group_or_other_access(tmp_path, mode):
    p = env_file(tmp_path, "A=1\n", mode)
    with pytest.raises(ConfigError) as ei:
        read_env_file(p)
    assert "chmod 600" in (ei.value.hint or "")


def test_read_env_file_missing(tmp_path):
    with pytest.raises(ConfigError):
        read_env_file(tmp_path / "missing.env")


def test_resolve_environ_merges_without_touching_os_environ(tmp_path, monkeypatch):
    p = env_file(tmp_path, "GW_FROM_FILE=file\nGW_BOTH=file\n")
    monkeypatch.delenv("GW_FROM_FILE", raising=False)
    cfg = GatewayConfig(env_file=str(p))
    env = resolve_environ(cfg, {"GW_BOTH": "process", "OTHER": "x"})
    assert env["GW_FROM_FILE"] == "file"
    assert env["GW_BOTH"] == "process"  # the real environment wins over the file
    assert env["OTHER"] == "x"
    assert "GW_FROM_FILE" not in os.environ


def test_resolve_environ_relative_env_file_is_relative_to_the_config_file(tmp_path):
    (tmp_path / "conf").mkdir()
    p = tmp_path / "conf" / "gw.env"
    p.write_text("X=1\n", encoding="utf-8")
    if POSIX:
        os.chmod(p, 0o600)
    cfg = GatewayConfig(env_file="gw.env", config_path=str(tmp_path / "conf" / "config.toml"))
    assert resolve_environ(cfg, {})["X"] == "1"


def test_resolve_environ_without_env_file_copies_the_environment():
    env = {"A": "1"}
    out = resolve_environ(GatewayConfig(), env)
    assert out == env and out is not env


# ── credentials ─────────────────────────────────────────────────────
def test_guest_credentials_from_user_and_password_env():
    prof = ProfileConfig(name="p", guest_user="mcp", guest_password_env="PW")
    creds = guest_credentials(prof, {"PW": "s3cret"})
    assert creds.user == "mcp" and creds.password.reveal() == "s3cret"
    assert "s3cret" not in repr(creds)


def test_guest_credentials_user_from_env():
    prof = ProfileConfig(name="p", guest_user_env="USR", guest_password_env="PW")
    assert guest_credentials(prof, {"USR": "envuser", "PW": "x"}).user == "envuser"


def test_guest_credentials_literal_user_wins_over_env():
    prof = ProfileConfig(name="p", guest_user="mcp", guest_user_env="USR", guest_password_env="PW")
    assert guest_credentials(prof, {"USR": "envuser", "PW": "x"}).user == "mcp"


@pytest.mark.parametrize("env", [{}, {"PW": ""}, {"USR": "u"}])
def test_guest_credentials_missing_parts_give_none(env):
    prof = ProfileConfig(name="p", guest_user_env="USR", guest_password_env="PW")
    assert guest_credentials(prof, env) is None


# ── guest token parsing ─────────────────────────────────────────────
def cfg_bytes(token: object = GOOD, **extra: object) -> bytes:
    return json.dumps({"IpAddress": "0.0.0.0", "Port": 9094, "AutoStart": True,  # noqa: S104
                       "AuthToken": token, **extra}).encode()


def test_parse_guest_token_plain():
    tok = parse_guest_token(cfg_bytes(), "x64")
    assert isinstance(tok, Secret) and tok.reveal() == GOOD


@pytest.mark.parametrize("prefix", [b"\xef\xbb\xbf", b"\x00\x00", b""])
def test_parse_guest_token_tolerates_bom_and_nuls(prefix):
    assert parse_guest_token(prefix + cfg_bytes() + b"\x00" * 7, "x64").reveal() == GOOD


def test_parse_guest_token_utf16():
    data = cfg_bytes().decode().encode("utf-16")
    assert parse_guest_token(data, "x64").reveal() == GOOD


@pytest.mark.parametrize(
    "data",
    [
        b"\x00" * 101,  # seen on the spike VM's x32 config
        b"",
        b"   \r\n",
        b"{not json",
        b"[1, 2]",
        json.dumps({"Port": 9094}).encode(),
        cfg_bytes(""),
        cfg_bytes("short-token"),
        cfg_bytes(12345678901234567890123456789012345),
        cfg_bytes("x" * 65),
        cfg_bytes(" " + GOOD[1:]),
        cfg_bytes(GOOD[:-1] + "\u00e9"),
    ],
    ids=["zero-filled", "empty", "blank", "invalid-json", "not-object", "no-token", "empty-token", "short",
         "number", "too-long", "leading-space", "non-ascii"],
)
def test_parse_guest_token_rejects_unusable_configs(data):
    with pytest.raises(BackendAuthError) as ei:
        parse_guest_token(data, "x32")
    err = ei.value
    assert err.hint and PROVISION_HINT in err.hint
    assert "x32" in err.message
    assert "short-token" not in err.message and "short-token" not in str(err.details)


def test_parse_guest_token_never_echoes_the_token():
    with pytest.raises(BackendAuthError) as ei:
        parse_guest_token(cfg_bytes("tooshortbutsecret"), "x64")
    assert "tooshortbutsecret" not in str(ei.value.to_dict())


def test_parse_guest_token_refuses_huge_files():
    with pytest.raises(BackendAuthError):
        parse_guest_token(b" " * (wiring.MAX_GUEST_CONFIG_BYTES + 1) + cfg_bytes(), "x64")


# ── builtin catalog choice ──────────────────────────────────────────
@pytest.mark.parametrize(
    ("version", "expected"),
    [(None, "data/tools-v1.9.json"), ("1.3", "data/tools-v1.9.json"), ("1.9", "data/tools-v1.9.json"),
     ("1.10", "data/tools-v1.10.json"), ("1.11", "data/tools-v1.10.json"), ("2.0", "data/tools-v1.10.json"),
     ("garbage", "data/tools-v1.9.json"), ("", "data/tools-v1.9.json")],
)
def test_builtin_catalog_for(version, expected):
    assert builtin_catalog_for(version) == expected


def test_build_runtime_uses_the_newer_builtin_when_the_cached_version_is_known(tmp_path):
    lab = make_lab(tmp_path)
    try:
        cache = tmp_path / "cache" / "lab"
        cache.mkdir(parents=True)
        (cache / "tools-x64-1.10.json").write_text(json.dumps({
            "format": 1, "backend_id": "x64", "server_version": "1.10",
            "tools": [{"name": "GetServerInfo", "description": "", "read_only": True,
                       "inputSchema": {"type": "object", "properties": {}}}],
        }), encoding="utf-8")
        rt = lab.runtime()
        # only the v1.10 builtin knows GetServerInfo is read-only
        assert rt.catalog.is_read_only("GetServerInfo", "x64") is True
    finally:
        lab.close()


# ── Runtime (vmware mode, fakes) ────────────────────────────────────
@pytest.fixture
def lab(tmp_path):
    lab = make_lab(tmp_path)
    yield lab
    lab.close()


def test_runtime_fields(lab):
    rt = lab.runtime()
    assert isinstance(rt, Runtime)
    assert rt.profile.name == "lab" and rt.vm is lab.vm and rt.channel is lab.guest and rt.runner is None
    assert set(rt.backends) == {"x64"} and isinstance(rt.backends["x64"], BackendConfig)
    assert isinstance(rt.catalog, ToolCatalog)
    assert rt.clock is lab.clock
    # one mutable dict shared by the supervisor and the proxy
    assert rt.supervisor._clients is rt.clients and rt.proxy._clients is rt.clients
    # nothing is resolved before the first connect
    assert isinstance(rt.clients["x64"], UnresolvedClient)
    assert lab.guest.calls == [c for c in lab.guest.calls if c[0] != "copy_from_guest"]


def test_runtime_repr_hides_secrets(lab):
    rt = lab.runtime()
    rt.connect("x64")
    text = repr(rt)
    assert "guest-pw" not in text and token_for("x64") not in text


def test_guest_ip_auto_waits_for_vmware_tools(lab):
    rt = lab.runtime()
    assert rt.refresh_guest_ip() == "127.0.0.1"
    assert ("guest_ip", (True,)) in lab.vm.calls


def test_guest_ip_is_cached(lab):
    rt = lab.runtime()
    rt.guest_ip()
    n = sum(1 for c in lab.vm.calls if c[0] == "guest_ip")
    rt.guest_ip()
    assert sum(1 for c in lab.vm.calls if c[0] == "guest_ip") == n


def test_fixed_guest_host_never_asks_the_vm(lab):
    lab.set_profile(guest_host="127.0.0.1")
    rt = lab.runtime()
    assert rt.guest_ip() == "127.0.0.1"
    assert not [c for c in lab.vm.calls if c[0] == "guest_ip"]


def test_connect_builds_an_http_client_with_the_guest_token(lab):
    rt = lab.runtime()
    client = rt.connect("x64")
    assert isinstance(client, HttpBackendClient)
    assert rt.clients["x64"] is client
    assert client.endpoint.url == f"http://127.0.0.1:{lab.servers['x64'].port}/"
    assert client.health_l1() is True  # the token read from the guest config works
    assert rt.connect("x64") is client  # cached


def test_guest_token_is_read_once_and_cached(lab):
    rt = lab.runtime()
    rt.connect("x64")
    rt.invalidate_clients()
    rt.connect("x64")
    copies = [a for a, _ in lab.guest.calls_of("copy_from_guest") if a[0].lower() == CFG["x64"].lower()]
    assert len(copies) == 1


def test_guest_token_temp_file_is_removed(lab, tmp_path):
    rt = lab.runtime()
    rt.connect("x64")
    (args, _kw), = lab.guest.calls_of("copy_from_guest")
    assert not Path(args[1]).exists()


def test_token_refresher_rereads_and_updates_the_client(lab):
    rt = lab.runtime()
    client = rt.connect("x64")
    new = "f" * 32
    lab.servers["x64"].token = new
    data = json.loads(lab.guest.read(CFG["x64"]))
    data["AuthToken"] = new
    lab.guest.write(CFG["x64"], json.dumps(data).encode())
    # the supervisor sees 401, refreshes once and the backend is healthy again
    report = rt.supervisor.check("x64")
    assert report.state == "HEALTHY", report
    assert rt.clients["x64"] is client and client.health_l1() is True


def test_corrupt_guest_token_config_raises_backend_auth_with_provision_hint(lab):
    lab.write_guest_token_config("x64", b"\x00" * 101)
    rt = lab.runtime()
    with pytest.raises(BackendAuthError) as ei:
        rt.connect("x64")
    assert PROVISION_HINT in ei.value.hint
    assert isinstance(rt.clients["x64"], UnresolvedClient)


def test_missing_guest_token_config_is_a_backend_auth_error(lab):
    lab.guest.files.pop(CFG["x64"].lower())
    rt = lab.runtime()
    with pytest.raises(BackendAuthError) as ei:
        rt.connect("x64")
    assert PROVISION_HINT in ei.value.hint
    assert isinstance(ei.value.__cause__, GuestOperationError)


def test_connect_without_guest_ip_is_vm_not_ready(lab):
    lab.vm.ip = None
    rt = lab.runtime()
    with pytest.raises(VmNotReady):
        rt.connect("x64")


def test_ip_change_replaces_clients_in_the_shared_dict(lab):
    rt = lab.runtime()
    rt.refresh_guest_ip()
    old = rt.connect("x64")
    shared = rt.clients
    lab.vm.ip = "127.0.0.2"
    assert rt.refresh_guest_ip() == "127.0.0.2"
    assert rt.clients is shared
    new = rt.clients["x64"]
    assert new is not old
    assert isinstance(new, HttpBackendClient)  # token was cached: rebuilt right away
    assert new.endpoint.url == f"http://127.0.0.2:{lab.servers['x64'].port}/"


def test_same_ip_keeps_clients(lab):
    rt = lab.runtime()
    rt.refresh_guest_ip()
    c = rt.connect("x64")
    rt.refresh_guest_ip()
    assert rt.clients["x64"] is c


def test_invalidate_drops_tokens_and_clients(lab):
    rt = lab.runtime()
    rt.connect("x64")
    rt.invalidate_clients(drop_tokens=True)
    placeholder = rt.clients["x64"]
    assert isinstance(placeholder, UnresolvedClient)
    assert placeholder.health_l1() is False and placeholder.health_l2() is False
    with pytest.raises(VmNotReady):
        placeholder.call_tool("GetDebugState", {}, 5)
    rt.connect("x64")
    copies = [a for a, _ in lab.guest.calls_of("copy_from_guest") if a[0].lower() == CFG["x64"].lower()]
    assert len(copies) == 2


def test_unknown_backend_is_a_config_error(lab):
    rt = lab.runtime()
    with pytest.raises(ConfigError):
        rt.connect("nope")


def test_vm_write_lock_cancels_in_flight_backend_calls(lab):
    rt = lab.runtime()

    class Spy:
        endpoint = rt.clients["x64"].endpoint
        cancelled = 0

        def cancel_all(self):
            Spy.cancelled += 1

    rt.clients["x64"] = Spy()  # type: ignore[assignment]
    holding, release = threading.Event(), threading.Event()

    def reader():
        with rt.lock.read():
            holding.set()
            release.wait(5)

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    assert holding.wait(5)
    threading.Timer(0.2, release.set).start()
    with rt.lock.write(timeout_s=5):
        pass
    t.join(5)
    assert Spy.cancelled >= 1


def test_vmware_env_token_source(tmp_path):
    lab = make_lab(tmp_path, token_source="env")
    try:
        rt = lab.runtime()
        assert rt.connect("x64").health_l1() is True
        assert not lab.guest.calls_of("copy_from_guest")
    finally:
        lab.close()


def test_env_token_missing_is_backend_auth(tmp_path):
    lab = make_lab(tmp_path, token_source="env")
    try:
        lab.environ.clear()
        lab.environ[PW_ENV] = "pw"
        rt = lab.runtime()
        with pytest.raises(BackendAuthError) as ei:
            rt.connect("x64")
        assert "GW_TEST_X64_TOKEN" in ei.value.message
    finally:
        lab.close()


# ── endpoint mode ───────────────────────────────────────────────────
def test_endpoint_runtime(tmp_path):
    srv = FakePluginServer(token=GOOD).start()
    try:
        prof = ProfileConfig(name="remote", mode="endpoint", token_source="env", require_isolation=False,
                             backends=(BackendConfig(id="x64", arch="x64", url=srv.url,
                                                     token_env="REMOTE_TOK"),))
        cfg = GatewayConfig(jobs_root=str(tmp_path / "jobs"), profiles={"remote": prof})
        rt = build_runtime(cfg, "remote", environ={"REMOTE_TOK": GOOD}, clock=FakeClock(),
                           cache_dir=tmp_path / "cache")
        assert isinstance(rt.vm, NullProvider) and rt.runner is None and rt.channel is None
        assert rt.guest_ip() is None
        client = rt.connect("x64")
        assert client.endpoint.url == srv.url and client.health_l1()
    finally:
        srv.stop()


# ── build_app ───────────────────────────────────────────────────────
def write_config(tmp_path: Path, vmrun: Path) -> Path:
    text = f"""
[gateway]
jobs_root = "{(tmp_path / 'jobs').as_posix()}"
default_profile = "p"
upload_roots = ["{(tmp_path / 'samples').as_posix()}"]

[profiles.p]
mode = "vmware"
vmx = "{(tmp_path / 'p.vmx').as_posix()}"
vmrun = "{vmrun.as_posix()}"
guest_user = "mcp"
guest_password_env = "GW_PW"

[profiles.p.backends.x64]
port = 9094
exe = 'C:\\dbg\\x64\\x64dbg.exe'
config = 'C:\\dbg\\x64\\mcp_config.json'
launch_task = "MCP-x64dbg"
"""
    p = tmp_path / "config.toml"
    p.write_text(text, encoding="utf-8")
    return p


def test_build_app_is_lazy_and_builds_real_components(tmp_path):
    vmrun = tmp_path / "vmrun"
    vmrun.write_text("#!/bin/sh\nexit 1\n")
    cfg = load_config(write_config(tmp_path, vmrun), environ={})
    gw = build_app(cfg, environ={"GW_PW": "pw"}, clock=FakeClock(), cache_dir=tmp_path / "cache")
    try:
        assert isinstance(gw, Gateway)
        assert not (tmp_path / "jobs").exists()  # no disk I/O until first use
        rt = gw.runtime()
        assert isinstance(rt.runner, VmrunCli) and isinstance(rt.vm, VmrunProvider)
        assert isinstance(rt.channel, VixChannel)
        assert "pw" not in repr(rt.runner)
        assert gw.runtime() is rt  # cached per profile
    finally:
        gw.close()


def test_build_app_reads_the_env_file(tmp_path):
    vmrun = tmp_path / "vmrun"
    vmrun.write_text("")
    path = write_config(tmp_path, vmrun)
    envf = env_file(tmp_path, "GW_PW=from-file\n")
    cfg = replace(load_config(path, environ={}), env_file=str(envf))
    gw = build_app(cfg, environ={}, clock=FakeClock(), cache_dir=tmp_path / "cache")
    try:
        creds = gw.runtime().runner._creds
        assert creds is not None and creds.password.reveal() == "from-file"
    finally:
        gw.close()


@pytest.mark.skipif(not POSIX, reason="POSIX permission bits")
def test_build_app_refuses_a_readable_env_file(tmp_path):
    vmrun = tmp_path / "vmrun"
    vmrun.write_text("")
    cfg = replace(load_config(write_config(tmp_path, vmrun), environ={}),
                  env_file=str(env_file(tmp_path, "GW_PW=x\n", 0o644)))
    with pytest.raises(ConfigError):
        build_app(cfg, environ={}, clock=FakeClock())


def test_build_app_profile_argument_selects_the_default(tmp_path):
    srv_prof = ProfileConfig(name="remote", mode="endpoint", token_source="env", require_isolation=False,
                             backends=(BackendConfig(id="x64", arch="x64", url="http://127.0.0.1:1/",
                                                     token_env="T"),))
    vm_prof = ProfileConfig(name="vm", mode="vmware", vmx=str(tmp_path / "x.vmx"), vmrun="/nonexistent/vmrun")
    cfg = GatewayConfig(jobs_root=str(tmp_path / "jobs"), default_profile="vm",
                        profiles={"remote": srv_prof, "vm": vm_prof})
    gw = build_app(cfg, profile="remote", environ={"T": GOOD}, clock=FakeClock(), cache_dir=tmp_path / "c")
    try:
        assert gw.runtime().profile.name == "remote"
    finally:
        gw.close()


def test_build_runtime_with_injected_vm_and_guest_does_not_need_vmrun(tmp_path):
    prof = ProfileConfig(name="p", mode="vmware", vmx=str(tmp_path / "x.vmx"), vmrun="/nonexistent/vmrun",
                         guest_user="u", guest_password_env="PW",
                         backends=(BackendConfig(id="x64", arch="x64", port=1, config="C:\\c.json"),))
    cfg = GatewayConfig(profiles={"p": prof})
    rt = build_runtime(cfg, "p", environ={}, clock=FakeClock(), vm=FakeVm(), channel=FakeGuest(),
                       cache_dir=tmp_path / "c")
    assert rt.runner is None
