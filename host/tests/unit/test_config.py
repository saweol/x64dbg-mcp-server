"""Tests for config.load_config / default_config_path / validation (feature A, plan 5.1)."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from x64dbg_vm_gateway import config as cfgmod
from x64dbg_vm_gateway.config import (
    BackendConfig,
    GatewayConfig,
    HttpServerConfig,
    ProfileConfig,
    RetentionConfig,
    default_config_path,
    load_config,
)
from x64dbg_vm_gateway.errors import ConfigError

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "config"

# A minimal valid profile used as the base of most negative tests.
BASE = """
[gateway]
default_profile = "p"

[profiles.p]
mode = "vmware"
vmx = "/vm/x.vmx"

[profiles.p.backends.x64]
port = 9094
"""


def write(tmp_path: Path, text: str, name: str = "config.toml") -> Path:
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def load_text(tmp_path: Path, text: str) -> GatewayConfig:
    return load_config(write(tmp_path, text), environ={})


def expect_error(tmp_path: Path, text: str, key: str) -> ConfigError:
    with pytest.raises(ConfigError) as ei:
        load_text(tmp_path, text)
    err = ei.value
    assert key in err.message, f"{key!r} not named in {err.message!r}"
    assert err.details.get("key") == key
    return err


# ── happy paths ─────────────────────────────────────────────────────
def test_full_example_parses_into_dataclasses():
    path = FIXTURES / "full.toml"
    cfg = load_config(path, environ={})

    assert isinstance(cfg, GatewayConfig)
    assert cfg.config_path == str(path)
    assert cfg.jobs_root == "~/mcp-lab/jobs"
    assert cfg.default_profile == "win10"
    assert cfg.max_call_s == 55.0 and isinstance(cfg.max_call_s, float)

    assert cfg.http == HttpServerConfig(
        enabled=True,
        bind="127.0.0.1",
        port=9100,
        allow_clients=("10.0.0.0/24", "192.168.56.1"),
        token_envs={"read": "GW_TOKEN_READ", "admin": "GW_TOKEN_ADMIN"},
    )

    win = cfg.profile()
    assert win.name == "win10"
    assert win.mode == "vmware"
    assert win.vmx == "/vms/analysis_vm/analysis_vm.vmx"
    assert win.protected_snapshots == ("MCP_CLEAN", "MCP_BASE", "remote_base")
    assert win.guest_password_env == "X64DBG_GW_GUEST_PW"
    assert win.job_root_guest == "C:\\mcp\\jobs"
    assert win.retention == RetentionConfig(max_gateway_snapshots=5, max_age_days=7)
    assert win.backends == (
        BackendConfig(id="x64", arch="x64", port=9094,
                      exe="C:\\tools\\x64dbg\\release\\x64\\x64dbg.exe",
                      config="C:\\tools\\x64dbg\\release\\x64\\mcp_config.json",
                      launch_task="MCP-x64dbg"),
        BackendConfig(id="x32", arch="x32", port=9095,
                      exe="C:\\tools\\x64dbg\\release\\x32\\x32dbg.exe",
                      config="C:\\tools\\x64dbg\\release\\x32\\mcp_config.json",
                      launch_task="MCP-x32dbg"),
    )

    remote = cfg.profile("remote-pc")
    assert remote.mode == "endpoint"
    assert remote.vmx is None
    assert remote.backends == (
        BackendConfig(id="x64", arch="x64", url="http://10.0.0.20:9094", token_env="REMOTE_X64DBG_TOKEN"),
    )
    # untouched fields keep dataclass defaults
    assert remote.retention == RetentionConfig()
    assert remote.snapshot_prefix == "gw-"


def test_endpoint_only_config_without_gateway_table():
    cfg = load_config(FIXTURES / "endpoint_only.toml", environ={})
    assert cfg.default_profile is None
    assert cfg.http == HttpServerConfig()
    prof = cfg.profile()  # single profile is selected implicitly
    assert prof.name == "lab"
    assert prof.backends == (
        BackendConfig(id="dbg64", arch="x64", url="https://lab.example:9443/", token_env="LAB_DBG_TOKEN"),
    )


def test_explicit_backend_id_overrides_table_key(tmp_path):
    extra = '\n[profiles.p.backends.second]\nid = "dbg32"\narch = "x32"\nport = 9095\n'
    cfg = load_text(tmp_path, BASE + extra)
    assert [b.id for b in cfg.profile().backends] == ["x64", "dbg32"]
    assert cfg.profile().backends[1].arch == "x32"


def test_integer_max_call_s_is_coerced_to_float(tmp_path):
    cfg = load_text(tmp_path, BASE.replace('default_profile = "p"', 'default_profile = "p"\nmax_call_s = 30'))
    assert cfg.max_call_s == 30.0 and isinstance(cfg.max_call_s, float)


def test_schema_covers_every_dataclass_field():
    """Drift guard: a field added to a dataclass must also be accepted by the loader."""
    for cls, section in ((ProfileConfig, "profile"), (BackendConfig, "backend"),
                         (RetentionConfig, "retention"), (HttpServerConfig, "http"),
                         (GatewayConfig, "gateway")):
        names = {f.name for f in dataclasses.fields(cls)}
        known = cfgmod.schema_field_names(section)
        assert names <= known, (section, names - known)


# ── path resolution ─────────────────────────────────────────────────
def test_explicit_path_beats_env(tmp_path):
    explicit = write(tmp_path, BASE, "explicit.toml")
    other = write(tmp_path, BASE.replace('"p"', '"q"').replace("profiles.p", "profiles.q"), "env.toml")
    cfg = load_config(explicit, environ={cfgmod.ENV_CONFIG_PATH: str(other)})
    assert cfg.config_path == str(explicit)


def test_env_path_beats_default(tmp_path):
    env_file = write(tmp_path, BASE, "env.toml")
    cfg = load_config(None, environ={cfgmod.ENV_CONFIG_PATH: str(env_file), "XDG_CONFIG_HOME": "/nope"},
                      system="Linux")
    assert cfg.config_path == str(env_file)


def test_default_path_used_when_nothing_else(tmp_path):
    xdg = tmp_path / "xdg"
    (xdg / "x64dbg-vm-gateway").mkdir(parents=True)
    write(xdg / "x64dbg-vm-gateway", BASE)
    cfg = load_config(None, environ={"XDG_CONFIG_HOME": str(xdg)}, system="Linux")
    assert cfg.config_path == str(xdg / "x64dbg-vm-gateway" / "config.toml")


def test_missing_file_raises_config_error_with_hint(tmp_path):
    missing = tmp_path / "nope.toml"
    with pytest.raises(ConfigError) as ei:
        load_config(missing, environ={})
    assert str(missing) in ei.value.message
    assert ei.value.hint and "init" in ei.value.hint


def test_invalid_toml_raises_config_error(tmp_path):
    with pytest.raises(ConfigError) as ei:
        load_text(tmp_path, "[gateway\njobs_root = 1\n")
    assert "TOML" in ei.value.message


@pytest.mark.parametrize(
    ("system", "environ", "expected"),
    [
        ("Linux", {"XDG_CONFIG_HOME": "/xdg"}, "/xdg/x64dbg-vm-gateway/config.toml"),
        ("Linux", {"HOME": "/home/u"}, "/home/u/.config/x64dbg-vm-gateway/config.toml"),
        ("Linux", {"HOME": "/home/u", "XDG_CONFIG_HOME": "relative/dir"},
         "/home/u/.config/x64dbg-vm-gateway/config.toml"),
        ("Darwin", {"HOME": "/Users/u"}, "/Users/u/.config/x64dbg-vm-gateway/config.toml"),
        ("Windows", {"APPDATA": "C:\\Users\\u\\AppData\\Roaming"},
         "C:\\Users\\u\\AppData\\Roaming\\x64dbg-vm-gateway\\config.toml"),
        ("Windows", {"USERPROFILE": "C:\\Users\\u"},
         "C:\\Users\\u\\AppData\\Roaming\\x64dbg-vm-gateway\\config.toml"),
    ],
)
def test_default_config_path_per_os(system, environ, expected):
    assert str(default_config_path(system=system, environ=environ)) == expected


# ── validation: each rule names the offending dotted key ────────────
@pytest.mark.parametrize(
    ("text", "key"),
    [
        (BASE + "\n[bogus]\nx = 1\n", "bogus"),
        (BASE.replace('default_profile = "p"', 'default_profile = "p"\nbogus = 1'), "gateway.bogus"),
        (BASE + "\n[http]\nbogus = 1\n", "http.bogus"),
        (BASE.replace('vmx = "/vm/x.vmx"', 'vmx = "/vm/x.vmx"\nbogus = 1'), "profiles.p.bogus"),
        (BASE.replace('vmx = "/vm/x.vmx"', 'vmx = "/vm/x.vmx"\nname = "other"'), "profiles.p.name"),
        (BASE + "bogus = 1\n", "profiles.p.backends.x64.bogus"),
        (BASE + "\n[profiles.p.retention]\nbogus = 1\n", "profiles.p.retention.bogus"),
    ],
    ids=["top", "gateway", "http", "profile", "profile-name", "backend", "retention"],
)
def test_unknown_keys_rejected(tmp_path, text, key):
    err = expect_error(tmp_path, text, key)
    assert "unknown" in err.message.lower()


@pytest.mark.parametrize(
    ("text", "key"),
    [
        (BASE.replace("port = 9094", 'port = "9094"'), "profiles.p.backends.x64.port"),
        (BASE.replace("port = 9094", "port = true"), "profiles.p.backends.x64.port"),
        (BASE.replace("port = 9094", "port = 9094.0"), "profiles.p.backends.x64.port"),
        (BASE.replace('vmx = "/vm/x.vmx"', "vmx = 5"), "profiles.p.vmx"),
        (BASE.replace('vmx = "/vm/x.vmx"', 'vmx = "/vm/x.vmx"\nrequire_isolation = "yes"'),
         "profiles.p.require_isolation"),
        (BASE.replace('vmx = "/vm/x.vmx"', 'vmx = "/vm/x.vmx"\nprotected_snapshots = "MCP_CLEAN"'),
         "profiles.p.protected_snapshots"),
        (BASE.replace('vmx = "/vm/x.vmx"', 'vmx = "/vm/x.vmx"\nprotected_snapshots = ["a", 1]'),
         "profiles.p.protected_snapshots"),
        (BASE.replace('default_profile = "p"', 'default_profile = "p"\nmax_call_s = "fast"'),
         "gateway.max_call_s"),
        (BASE.replace('default_profile = "p"', 'default_profile = "p"\nmax_call_s = true'),
         "gateway.max_call_s"),
        (BASE + "\n[http]\ntoken_envs = \"GW_TOKEN\"\n", "http.token_envs"),
        (BASE + "\n[http]\nallow_clients = \"10.0.0.0/8\"\n", "http.allow_clients"),
        ('[gateway]\nprofiles = 1\n', "gateway.profiles"),
        ('profiles = "x"\n', "profiles"),
        ('[profiles]\np = 1\n', "profiles.p"),
        ('[profiles.p]\nmode = "vmware"\nvmx = "/vm/x.vmx"\nbackends = 1\n', "profiles.p.backends"),
        ('[profiles.p]\nmode = "vmware"\nvmx = "/vm/x.vmx"\nbackends = { x64 = 1 }\n',
         "profiles.p.backends.x64"),
        ('[profiles.p]\nmode = "vmware"\nvmx = "/vm/x.vmx"\nretention = 3\n', "profiles.p.retention"),
    ],
)
def test_wrong_types_rejected(tmp_path, text, key):
    expect_error(tmp_path, text, key)


@pytest.mark.parametrize(
    ("field", "value", "key"),
    [
        ("mode", "hyperv", "profiles.p.mode"),
        ("vmrun_type", "player", "profiles.p.vmrun_type"),
        ("token_source", "env:VAR", "profiles.p.token_source"),
        ("relaunch_mode", "psexec", "profiles.p.relaunch_mode"),
    ],
)
def test_enum_values_validated(tmp_path, field, value, key):
    text = BASE.replace('mode = "vmware"', 'mode = "vmware"' if field != "mode" else f'mode = "{value}"')
    if field != "mode":
        text = text.replace('vmx = "/vm/x.vmx"', f'vmx = "/vm/x.vmx"\n{field} = "{value}"')
    expect_error(tmp_path, text, key)


@pytest.mark.parametrize("port", [0, -1, 65536, 70000])
def test_backend_port_range(tmp_path, port):
    expect_error(tmp_path, BASE.replace("port = 9094", f"port = {port}"), "profiles.p.backends.x64.port")


@pytest.mark.parametrize("port", [0, 65536])
def test_http_port_range(tmp_path, port):
    expect_error(tmp_path, BASE + f"\n[http]\nport = {port}\n", "http.port")


@pytest.mark.parametrize("port", [1, 65535])
def test_port_bounds_inclusive(tmp_path, port):
    cfg = load_text(tmp_path, BASE.replace("port = 9094", f"port = {port}"))
    assert cfg.profile().backends[0].port == port


def test_vmware_mode_requires_vmx(tmp_path):
    expect_error(tmp_path, BASE.replace('vmx = "/vm/x.vmx"\n', ""), "profiles.p.vmx")


def test_endpoint_backend_requires_url(tmp_path):
    text = BASE.replace('mode = "vmware"', 'mode = "endpoint"')
    expect_error(tmp_path, text, "profiles.p.backends.x64.url")


def test_backend_requires_port_or_url(tmp_path):
    text = BASE.replace("port = 9094", 'exe = "C:\\\\x64dbg.exe"')
    err = expect_error(tmp_path, text, "profiles.p.backends.x64")
    assert "port" in err.message and "url" in err.message


@pytest.mark.parametrize("url", ["ftp://h:1/", "not a url", "http://", "http:///path"])
def test_backend_url_must_be_http(tmp_path, url):
    text = BASE.replace("port = 9094", f'url = "{url}"')
    expect_error(tmp_path, text, "profiles.p.backends.x64.url")


def test_duplicate_backend_ids(tmp_path):
    text = BASE + '\n[profiles.p.backends.other]\nid = "x64"\narch = "x64"\nport = 9096\n'
    err = expect_error(tmp_path, text, "profiles.p.backends.other.id")
    assert "duplicate" in err.message.lower()


def test_arch_required_for_custom_backend_id(tmp_path):
    text = BASE + "\n[profiles.p.backends.custom]\nport = 9096\n"
    expect_error(tmp_path, text, "profiles.p.backends.custom.arch")


def test_arch_value_validated(tmp_path):
    expect_error(tmp_path, BASE + 'arch = "arm64"\n', "profiles.p.backends.x64.arch")


def test_default_profile_must_exist(tmp_path):
    expect_error(tmp_path, BASE.replace('default_profile = "p"', 'default_profile = "nope"'),
                 "gateway.default_profile")


def test_empty_snapshot_prefix_rejected(tmp_path):
    # an empty prefix would make every snapshot look gateway-owned (retention/delete policy)
    expect_error(tmp_path, BASE.replace('vmx = "/vm/x.vmx"', 'vmx = "/vm/x.vmx"\nsnapshot_prefix = ""'),
                 "profiles.p.snapshot_prefix")


def test_token_source_env_requires_token_env_on_every_backend(tmp_path):
    text = BASE.replace('vmx = "/vm/x.vmx"', 'vmx = "/vm/x.vmx"\ntoken_source = "env"')
    expect_error(tmp_path, text, "profiles.p.backends.x64.token_env")
    ok = load_text(tmp_path, text + 'token_env = "X64_TOKEN"\n')
    assert ok.profile().backends[0].token_env == "X64_TOKEN"


@pytest.mark.parametrize(
    ("text", "key"),
    [
        (BASE + "\n[http]\nallow_clients = [\"10.0.0.0/33\"]\n", "http.allow_clients[0]"),
        (BASE + "\n[http]\ntoken_envs = { superuser = \"X\" }\n", "http.token_envs.superuser"),
        (BASE + "\n[http]\ntls_cert = \"/c.pem\"\n", "http.tls_key"),
        (BASE + "\n[profiles.p.retention]\nmax_age_days = -1\n", "profiles.p.retention.max_age_days"),
        (BASE.replace('default_profile = "p"', 'default_profile = "p"\nmax_call_s = 0'),
         "gateway.max_call_s"),
        (BASE.replace("[profiles.p.backends.x64]", "[profiles.p.backends.\"bad id\"]"),
         "profiles.p.backends.bad id"),
    ],
)
def test_misc_value_validation(tmp_path, text, key):
    expect_error(tmp_path, text, key)


# ── security: inline secrets are refused ───────────────────────────
SECRET_VALUE = "Sup3r-S3cret-Value!"


@pytest.mark.parametrize(
    ("snippet_target", "secret_key", "dotted"),
    [
        ("profile", "guest_password", "profiles.p.guest_password"),
        ("profile", "password", "profiles.p.password"),
        ("backend", "token", "profiles.p.backends.x64.token"),
        ("backend", "auth_token", "profiles.p.backends.x64.auth_token"),
        ("http", "secret", "http.secret"),
        ("gateway", "token", "gateway.token"),
        ("backend", "bearer_token", "profiles.p.backends.x64.bearer_token"),
    ],
)
def test_inline_secret_keys_rejected_without_echoing_value(tmp_path, snippet_target, secret_key, dotted):
    line = f'{secret_key} = "{SECRET_VALUE}"'
    if snippet_target == "profile":
        text = BASE.replace('vmx = "/vm/x.vmx"', f'vmx = "/vm/x.vmx"\n{line}')
    elif snippet_target == "backend":
        text = BASE + line + "\n"
    elif snippet_target == "http":
        text = BASE + f"\n[http]\n{line}\n"
    else:
        text = BASE.replace('default_profile = "p"', f'default_profile = "p"\n{line}')
    err = expect_error(tmp_path, text, dotted)
    assert "_env" in err.message  # tells the user to store the env var NAME instead
    blob = " ".join([str(err), repr(err), err.message, str(err.hint), json.dumps(err.to_dict())])
    assert SECRET_VALUE not in blob


@pytest.mark.parametrize("field", ["guest_password_env", "token_env"])
def test_env_name_fields_must_look_like_env_var_names(tmp_path, field):
    # catches the mistake of pasting the secret itself into a *_env key, without echoing it
    if field == "token_env":
        text = BASE + f'token_env = "{SECRET_VALUE}"\n'
        key = "profiles.p.backends.x64.token_env"
    else:
        text = BASE.replace('vmx = "/vm/x.vmx"', f'vmx = "/vm/x.vmx"\n{field} = "{SECRET_VALUE}"')
        key = f"profiles.p.{field}"
    err = expect_error(tmp_path, text, key)
    blob = " ".join([str(err), repr(err), json.dumps(err.to_dict())])
    assert SECRET_VALUE not in blob


def test_secret_values_never_in_any_config_error(tmp_path):
    """No validation error ever includes a raw string value from the file."""
    text = BASE.replace('mode = "vmware"', f'mode = "{SECRET_VALUE}"')
    err = expect_error(tmp_path, text, "profiles.p.mode")
    assert SECRET_VALUE not in json.dumps(err.to_dict()) and SECRET_VALUE not in str(err)


def test_config_error_details_include_file_path(tmp_path):
    p = write(tmp_path, BASE.replace('mode = "vmware"', 'mode = "x"'))
    with pytest.raises(ConfigError) as ei:
        load_config(p, environ={})
    assert ei.value.details["path"] == str(p)
