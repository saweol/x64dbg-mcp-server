"""Wave-2 config additions: gateway.env_file, gateway.upload_roots, profiles.<n>.guest_user_env."""

from __future__ import annotations

from pathlib import Path

import pytest

from x64dbg_vm_gateway import config as cfgmod
from x64dbg_vm_gateway.config import GatewayConfig, ProfileConfig, load_config
from x64dbg_vm_gateway.errors import ConfigError

BASE = """
[gateway]
default_profile = "p"
{gateway_extra}

[profiles.p]
mode = "vmware"
vmx = "/vm/x.vmx"
{profile_user}
guest_password_env = "GW_GUEST_PW"

[profiles.p.backends.x64]
port = 9094
config = 'C:\\x64\\mcp_config.json'
"""


def doc(*, gateway_extra: str = "", profile_user: str = 'guest_user = "mcp"') -> str:
    return BASE.format(gateway_extra=gateway_extra, profile_user=profile_user)


def load_text(tmp_path: Path, text: str) -> GatewayConfig:
    p = tmp_path / "config.toml"
    p.write_text(text, encoding="utf-8")
    return load_config(p, environ={})


def expect_error(tmp_path: Path, text: str, key: str) -> ConfigError:
    with pytest.raises(ConfigError) as ei:
        load_text(tmp_path, text)
    assert ei.value.details.get("key") == key, ei.value.message
    return ei.value


def test_defaults():
    cfg = GatewayConfig()
    assert cfg.env_file is None
    assert cfg.upload_roots == ("~",)
    assert ProfileConfig(name="p").guest_user_env is None


def test_defaults_when_loading(tmp_path):
    cfg = load_text(tmp_path, doc())
    assert cfg.env_file is None and cfg.upload_roots == ("~",)
    assert cfg.profile().guest_user_env is None


def test_env_file_and_upload_roots_are_loaded(tmp_path):
    cfg = load_text(tmp_path, doc(gateway_extra='env_file = "~/.config/gw.env"\n'
                                                'upload_roots = ["~/samples", "/srv/malware"]'))
    assert cfg.env_file == "~/.config/gw.env"
    assert cfg.upload_roots == ("~/samples", "/srv/malware")


def test_empty_upload_roots_is_allowed(tmp_path):
    cfg = load_text(tmp_path, doc(gateway_extra="upload_roots = []"))
    assert cfg.upload_roots == ()


@pytest.mark.parametrize(
    ("extra", "key"),
    [
        ('env_file = ""', "gateway.env_file"),
        ("env_file = 3", "gateway.env_file"),
        ('upload_roots = "~"', "gateway.upload_roots"),
        ('upload_roots = ["~", ""]', "gateway.upload_roots[1]"),
        ('upload_roots = ["~", "  "]', "gateway.upload_roots[1]"),
        # relative roots would depend on the gateway's working directory (policy drops them)
        ('upload_roots = ["samples"]', "gateway.upload_roots[0]"),
        ('upload_roots = ["~", "./x"]', "gateway.upload_roots[1]"),
        ('upload_roots = ["~user-without-slash/../x", "~/ok", "rel/x"]', "gateway.upload_roots[2]"),
    ],
)
def test_invalid_gateway_additions(tmp_path, extra, key):
    expect_error(tmp_path, doc(gateway_extra=extra), key)


def test_guest_user_env_replaces_guest_user(tmp_path):
    cfg = load_text(tmp_path, doc(profile_user='guest_user_env = "GW_GUEST_USER"'))
    prof = cfg.profile()
    assert prof.guest_user is None and prof.guest_user_env == "GW_GUEST_USER"


def test_guest_user_env_must_be_an_env_name(tmp_path):
    err = expect_error(tmp_path, doc(profile_user='guest_user_env = "not a name!"'),
                       "profiles.p.guest_user_env")
    assert "not a name" not in err.message  # values are never echoed


def test_guest_config_still_needs_some_guest_user(tmp_path):
    err = expect_error(tmp_path, doc(profile_user=""), "profiles.p.guest_user")
    assert "guest_user_env" in err.message


def test_both_guest_user_forms_may_be_given(tmp_path):
    cfg = load_text(tmp_path, doc(profile_user='guest_user = "mcp"\nguest_user_env = "GW_GUEST_USER"'))
    assert cfg.profile().guest_user == "mcp" and cfg.profile().guest_user_env == "GW_GUEST_USER"


def test_schema_knows_the_new_fields():
    assert {"env_file", "upload_roots"} <= cfgmod.schema_field_names("gateway")
    assert "guest_user_env" in cfgmod.schema_field_names("profile")


def test_env_file_value_is_not_read_by_the_loader(tmp_path):
    # The loader only records the path; wiring reads and checks the file.
    cfg = load_text(tmp_path, doc(gateway_extra='env_file = "/does/not/exist.env"'))
    assert cfg.env_file == "/does/not/exist.env"


@pytest.mark.parametrize("root", ["~", "~/samples", "~other/samples", "HOST_ABSOLUTE"])
def test_absolute_and_home_upload_roots_are_accepted(tmp_path, root):
    if root == "HOST_ABSOLUTE":
        root = str(tmp_path / "samples")  # absolute in this host's syntax
    # TOML literal strings (single quotes) keep backslashes as they are
    cfg = load_text(tmp_path, doc(gateway_extra=f"upload_roots = ['{root}']"))
    assert cfg.upload_roots == (root,)


def test_new_profile_field_is_appended_after_the_wave1_fields():
    """Positional construction of ProfileConfig keeps its wave-1 meaning."""
    import dataclasses

    names = [f.name for f in dataclasses.fields(ProfileConfig)]
    wave1 = ["name", "mode", "vmx", "vmrun", "vmrun_type", "clean_snapshot", "protected_snapshots",
             "guest_user", "guest_password_env", "guest_host", "job_root_guest", "require_isolation",
             "token_source", "snapshot_prefix", "retention", "backends", "relaunch_mode"]
    assert names[: len(wave1)] == wave1
    assert names[len(wave1):] == ["guest_user_env"]
