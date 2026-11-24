"""``[static]``: the static-analysis tools used next to the gateway (IDA, Ghidra, radare2, Cutter)."""

from __future__ import annotations

import dataclasses
import json

import pytest

from x64dbg_vm_gateway import config as cfgmod
from x64dbg_vm_gateway.config import GatewayConfig, StaticConfig, StaticServerConfig
from x64dbg_vm_gateway.errors import ConfigError

from .test_config import BASE, expect_error, load_text


def test_without_a_static_section_ida_is_the_default_tool(tmp_path):
    cfg = load_text(tmp_path, BASE)
    assert cfg.static == StaticConfig()
    assert cfg.static.tools == ("ida",) and cfg.static.servers == {}
    assert cfg.static.default_tool == "ida"
    assert GatewayConfig().static == StaticConfig()


def test_tools_keep_their_order_and_the_first_is_the_default(tmp_path):
    cfg = load_text(tmp_path, BASE + '\n[static]\ntools = ["ghidra", "ida", "radare2", "cutter"]\n')
    assert cfg.static.tools == ("ghidra", "ida", "radare2", "cutter")
    assert cfg.static.default_tool == "ghidra"


def test_server_overrides_are_parsed(tmp_path):
    text = BASE + (
        '\n[static]\ntools = ["cutter", "ghidra", "radare2"]\n'
        '[static.servers.cutter]\ncommand = ["python3", "/tools/cuttermcp/bridge.py"]\n'
        '[static.servers.ghidra]\nurl = "http://127.0.0.1:8089/sse"\ntransport = "sse"\nname = "ghidra-gui"\n'
        '[static.servers.radare2]\nname = "r2"\n'
    )
    s = load_text(tmp_path, text).static
    assert s.servers["cutter"] == StaticServerConfig(command=("python3", "/tools/cuttermcp/bridge.py"),
                                                     transport="stdio")
    assert s.servers["ghidra"] == StaticServerConfig(url="http://127.0.0.1:8089/sse", transport="sse",
                                                     name="ghidra-gui")
    assert s.servers["radare2"] == StaticServerConfig(name="r2")


def test_a_url_override_defaults_to_the_http_transport(tmp_path):
    s = load_text(tmp_path, BASE + '\n[static.servers.ghidra]\nurl = "https://10.0.0.5:8443/mcp"\n').static
    assert s.servers["ghidra"].transport == "http"


def test_overrides_for_tools_that_are_not_listed_are_kept(tmp_path):
    # lets the user prepare a recipe before switching tools
    s = load_text(tmp_path, BASE + '\n[static.servers.ghidra]\nname = "g"\n').static
    assert s.tools == ("ida",) and s.servers["ghidra"].name == "g"


@pytest.mark.parametrize(
    ("snippet", "key", "fragment"),
    [
        ('[static]\ntools = ["binja"]\n', "static.tools[0]", "unknown static tool"),
        ('[static]\ntools = ["ida", "IDA"]\n', "static.tools[1]", "unknown static tool"),
        ('[static]\ntools = ["ghidra", "ida", "ghidra"]\n', "static.tools[2]", "duplicate"),
        ('[static]\ntools = []\n', "static.tools", "at least one"),
        ('[static]\ntools = "ida"\n', "static.tools", "array of strings"),
        ('[static]\ntools = ["ida", 1]\n', "static.tools", "array of strings"),
        ('[static]\nbogus = 1\n', "static.bogus", "unknown key"),
        ('[static]\nservers = 1\n', "static.servers", "table"),
        ('[static.servers]\nghidra = 1\n', "static.servers.ghidra", "table"),
        ('[static.servers.binja]\nname = "b"\n', "static.servers.binja", "unknown static tool"),
        ('[static.servers.ghidra]\nbogus = 1\n', "static.servers.ghidra.bogus", "unknown key"),
        ('[static.servers.ghidra]\ncommand = []\n', "static.servers.ghidra.command", "must not be empty"),
        ('[static.servers.ghidra]\ncommand = "pyghidra-mcp"\n', "static.servers.ghidra.command",
         "array of strings"),
        ('[static.servers.ghidra]\ncommand = ["pyghidra-mcp", " "]\n', "static.servers.ghidra.command[1]",
         "must not be empty"),
        ('[static.servers.ghidra]\nurl = "ftp://h/"\n', "static.servers.ghidra.url", "http"),
        ('[static.servers.ghidra]\nurl = "http://"\n', "static.servers.ghidra.url", "http"),
        ('[static.servers.ghidra]\ncommand = ["x"]\nurl = "http://h:1/"\n', "static.servers.ghidra.url",
         "not both"),
        ('[static.servers.ghidra]\ncommand = ["x"]\ntransport = "carrier-pigeon"\n',
         "static.servers.ghidra.transport", "must be one of"),
        ('[static.servers.ghidra]\ncommand = ["x"]\ntransport = "http"\n',
         "static.servers.ghidra.transport", "stdio"),
        ('[static.servers.ghidra]\nurl = "http://h:1/"\ntransport = "stdio"\n',
         "static.servers.ghidra.transport", "http or sse"),
        ('[static.servers.ghidra]\ntransport = "stdio"\n', "static.servers.ghidra.transport",
         "command or url"),
        ('[static.servers.ghidra]\nname = "my ghidra"\n', "static.servers.ghidra.name", "letters"),
        ('[static.servers.ghidra]\nname = ""\n', "static.servers.ghidra.name", "must not be empty"),
    ],
)
def test_invalid_static_settings_name_the_key(tmp_path, snippet, key, fragment):
    err = expect_error(tmp_path, BASE + "\n" + snippet, key)
    assert fragment in err.message


def test_static_must_be_a_table(tmp_path):
    err = expect_error(tmp_path, "static = 1\n" + BASE, "static")
    assert "table" in err.message


def test_unknown_tool_ids_carry_a_hint_with_the_choices(tmp_path):
    for snippet in ('[static]\ntools = ["binja"]\n', '[static.servers.binja]\nname = "b"\n'):
        err = expect_error(tmp_path, BASE + "\n" + snippet,
                           "static.tools[0]" if "tools" in snippet else "static.servers.binja")
        assert "ida, ghidra, radare2, cutter" in (err.hint or "")


def test_configured_tools_need_distinct_server_names(tmp_path):
    text = BASE + ('\n[static]\ntools = ["ghidra", "radare2"]\n'
                   '[static.servers.radare2]\nname = "ghidra"\n')
    err = expect_error(tmp_path, text, "static.servers.radare2.name")
    assert "ghidra" in err.message and "already" in err.message


def test_inline_secrets_are_refused_in_server_overrides(tmp_path):
    err = expect_error(tmp_path, BASE + '\n[static.servers.ghidra]\ntoken = "s3cr3t-value"\n',
                       "static.servers.ghidra.token")
    assert "inline secrets" in err.message and "s3cr3t-value" not in err.message


def test_error_messages_never_echo_the_value(tmp_path):
    err = expect_error(tmp_path, BASE + '\n[static.servers.ghidra]\nurl = "nota-url-s3cr3t"\n',
                       "static.servers.ghidra.url")
    assert "s3cr3t" not in err.message


# ── drift guards / positional construction ──────────────────────────
def test_schema_covers_the_static_dataclasses():
    assert "static" in cfgmod.schema_field_names("gateway")
    assert {f.name for f in dataclasses.fields(StaticConfig)} <= cfgmod.schema_field_names("static")
    assert {f.name for f in dataclasses.fields(StaticServerConfig)} <= cfgmod.schema_field_names(
        "static_server")


def test_static_is_appended_after_the_existing_gateway_fields():
    names = [f.name for f in dataclasses.fields(GatewayConfig)]
    before = ["jobs_root", "default_profile", "max_call_s", "profiles", "http", "config_path", "env_file",
              "upload_roots"]
    assert names[: len(before)] == before
    assert names[len(before):] == ["static"]


def test_config_and_registry_agree_on_the_tool_ids():
    from x64dbg_vm_gateway import static_tools

    assert cfgmod.STATIC_TOOL_IDS == static_tools.TOOL_IDS


# ── env / args / names / command paths ──────────────────────────────
def test_env_and_args_are_parsed(tmp_path):
    text = BASE + (
        '\n[static]\ntools = ["ghidra"]\n'
        '[static.servers.ghidra]\nargs = ["--transport", "stdio", "--project-path", "/p"]\n'
        'env = { GHIDRA_INSTALL_DIR = "/g", JAVA_HOME = "/jdk" }\n'
    )
    s = load_text(tmp_path, text).static.servers["ghidra"]
    assert s.args == ("--transport", "stdio", "--project-path", "/p") and s.command is None
    assert s.env == {"GHIDRA_INSTALL_DIR": "/g", "JAVA_HOME": "/jdk"}
    assert s.transport == "stdio"


def test_env_defaults_to_empty_and_goes_with_a_command(tmp_path):
    text = BASE + ('\n[static.servers.ghidra]\ncommand = ["/opt/venv/bin/ghidra-mcp", "--headless"]\n'
                   '[static.servers.ghidra.env]\nJAVA_HOME = "/jdk"\n')
    s = load_text(tmp_path, text).static.servers["ghidra"]
    assert s.env == {"JAVA_HOME": "/jdk"} and s.args is None
    assert StaticServerConfig().env == {} and StaticServerConfig().args is None


@pytest.mark.parametrize("name", ["GW_TOKEN", "api_key", "MY_SECRET", "PASSWORD", "R2_PASSPHRASE"])
def test_secret_looking_env_names_are_refused(tmp_path, name):
    err = expect_error(tmp_path, BASE + f'\n[static.servers.ghidra]\nenv = {{ {name} = "v4lue-s3cr3t" }}\n',
                       f"static.servers.ghidra.env.{name}")
    assert "secret" in err.message and "v4lue-s3cr3t" not in err.message
    assert err.hint and "mcp-config" in err.hint


@pytest.mark.parametrize(
    ("snippet", "key", "fragment"),
    [
        ('env = { "1BAD" = "x" }\n', "static.servers.ghidra.env.1BAD", "NAME of an environment variable"),
        ('env = { "A-B" = "x" }\n', "static.servers.ghidra.env.A-B", "NAME of an environment variable"),
        ('env = { JAVA_HOME = "" }\n', "static.servers.ghidra.env.JAVA_HOME", "must not be empty"),
        ('env = { JAVA_HOME = 1 }\n', "static.servers.ghidra.env", "table of strings"),
        ('env = "JAVA_HOME=/x"\n', "static.servers.ghidra.env", "table of strings"),
        ('url = "http://127.0.0.1:1/"\nenv = { JAVA_HOME = "/x" }\n', "static.servers.ghidra.env",
         "command"),
        ('args = []\n', "static.servers.ghidra.args", "must not be empty"),
        ('args = ["--x", " "]\n', "static.servers.ghidra.args[1]", "must not be empty"),
        ('args = "--x"\n', "static.servers.ghidra.args", "array of strings"),
        ('command = ["x"]\nargs = ["--y"]\n', "static.servers.ghidra.args", "not both"),
        ('url = "http://127.0.0.1:1/"\nargs = ["--y"]\n', "static.servers.ghidra.args", "not both"),
        ('args = ["--y"]\ntransport = "http"\n', "static.servers.ghidra.transport", "stdio"),
        ('name = "x64dbg-vm"\n', "static.servers.ghidra.name", "gateway"),
        ('name = "X64DBG-VM"\n', "static.servers.ghidra.name", "gateway"),
        ('command = ["bin/pyghidra-mcp"]\n', "static.servers.ghidra.command[0]", "absolute path or a bare"),
        ('command = ["./pyghidra-mcp"]\n', "static.servers.ghidra.command[0]", "absolute path or a bare"),
        ("command = ['venv\\Scripts\\ghidra-mcp.exe']\n", "static.servers.ghidra.command[0]",
         "absolute path or a bare"),
        ('command = ["~/venv/bin/pyghidra-mcp"]\n', "static.servers.ghidra.command[0]", "~"),
    ],
)
def test_invalid_env_args_name_and_command_settings(tmp_path, snippet, key, fragment):
    err = expect_error(tmp_path, BASE + "\n[static.servers.ghidra]\n" + snippet, key)
    assert fragment in err.message


def test_args_need_a_registry_command(tmp_path):
    err = expect_error(tmp_path, BASE + '\n[static.servers.cutter]\nargs = ["--x"]\n',
                       "static.servers.cutter.args")
    assert "no default command" in err.message and "command" in (err.hint or "")


@pytest.mark.parametrize("program", ["/opt/venv/bin/pyghidra-mcp", "C:\\venv\\Scripts\\pyghidra-mcp.exe",
                                     "\\\\server\\share\\ghidra-mcp.exe", "pyghidra-mcp", "python3"])
def test_absolute_or_bare_programs_are_accepted(tmp_path, program):
    s = load_text(tmp_path, BASE + f"\n[static.servers.ghidra]\ncommand = ['{program}']\n").static
    assert s.servers["ghidra"].command == (program,)


def test_the_gateway_name_constant_is_the_registration_name():
    assert cfgmod.GATEWAY_MCP_NAME == "x64dbg-vm"
    from x64dbg_vm_gateway import static_tools

    assert all(t.mcp.name != cfgmod.GATEWAY_MCP_NAME for t in static_tools.TOOLS.values())


# ── secrets: mcp-config prints command, args, url and env values verbatim ──
def _refused_as_secret(tmp_path, body: str, key: str, value: str = "s3cr3t") -> None:
    err = expect_error(tmp_path, BASE + "\n[static.servers.ghidra]\n" + body, key)
    assert "secret" in err.message and value not in err.message
    assert err.hint and "own configuration" in err.hint and "never in the gateway config" in err.hint


@pytest.mark.parametrize("url", [
    "https://user:s3cr3t@10.0.0.5:8443/mcp",
    "https://s3cr3t@10.0.0.5:8443/mcp",  # a token as the user name
    "http://127.0.0.1:8089/sse?token=s3cr3t",
    "http://127.0.0.1:8089/sse?x=1&API_KEY=s3cr3t",
])
def test_a_url_carrying_credentials_is_refused(tmp_path, url):
    _refused_as_secret(tmp_path, f'url = "{url}"\n', "static.servers.ghidra.url")


@pytest.mark.parametrize(("args", "index"), [
    (["--api-key", "s3cr3t"], 0),
    (["--transport", "stdio", "--token=s3cr3t"], 2),
    (["--apiKey", "s3cr3t"], 0),
    (["--password", "s3cr3t"], 0),
    (["--private-key", "s3cr3t"], 0),
    (["--credentials", "s3cr3t"], 0),
    (["--auth-header", "s3cr3t"], 0),
    (["--cookie=s3cr3t"], 0),
    (["API_KEY=s3cr3t"], 0),
    (["-H", "Authorization: Bearer s3cr3t"], 1),
    (["--header", "Cookie: session=s3cr3t"], 1),
    (["Bearer s3cr3t"], 0),
    (["--url", "https://user:s3cr3t@h/mcp"], 1),
    (["-Djavax.net.ssl.keyStorePassword=s3cr3t"], 0),
])
def test_args_carrying_a_secret_are_refused(tmp_path, args, index):
    body = "args = [" + ", ".join(json.dumps(a) for a in args) + "]\n"
    _refused_as_secret(tmp_path, body, f"static.servers.ghidra.args[{index}]")


def test_a_command_carrying_a_secret_is_refused(tmp_path):
    body = 'command = ["/opt/ghidra-mcp/run", "--headless", "--secret", "s3cr3t"]\n'
    _refused_as_secret(tmp_path, body, "static.servers.ghidra.command[2]")


@pytest.mark.parametrize("name", ["API_KEY", "GH_TOKEN", "DB_PASS", "AUTH_HEADER", "PRIVATE_KEY", "COOKIE",
                                  "AWS_CREDENTIALS", "BEARER"])
def test_env_names_with_a_secret_segment_are_refused(tmp_path, name):
    _refused_as_secret(tmp_path, f'env = {{ {name} = "s3cr3t" }}\n', f"static.servers.ghidra.env.{name}")


@pytest.mark.parametrize(("name", "value"), [
    ("HTTPS_PROXY", "http://user:s3cr3t@proxy:3128"),
    ("JAVA_TOOL_OPTIONS", "-Xmx2g -Djavax.net.ssl.trustStorePassword=s3cr3t"),
])
def test_env_values_carrying_a_secret_are_refused(tmp_path, name, value):
    _refused_as_secret(tmp_path, f'env = {{ {name} = "{value}" }}\n', f"static.servers.ghidra.env.{name}")


def test_names_that_only_contain_a_secret_word_are_accepted(tmp_path):
    """Segment matching: KEYBOARD, COMPASS and BYPASS are not KEY, PASS or a secret."""
    text = BASE + (
        '\n[static.servers.ghidra]\n'
        'command = ["/opt/token-mcp/run", "--keyboard", "--compass", "--bypass", "--token-file", "/run/t",'
        ' "MONKEY=1", "--project-path", "/srv/pass word", "http://127.0.0.1:1/sse?verbose=1"]\n'
        'env = { KEYBOARD = "us", COMPASS = "n", BYPASS = "1", HTTPS_PROXY = "http://proxy:3128" }\n'
    )
    s = load_text(tmp_path, text).static.servers["ghidra"]
    assert s.command is not None and s.command[1:4] == ("--keyboard", "--compass", "--bypass")
    assert set(s.env) == {"KEYBOARD", "COMPASS", "BYPASS", "HTTPS_PROXY"}


# ── control characters: the printed command must be the configured one ──
#: what the output sanitiser would strip or what would break the printed line: C0 (TAB, LF, CR, NUL,
#: ESC), DEL, C1 (NEL, CSI), bidi controls, line / paragraph separators
UNPRINTABLE = ["\n", "\r", "\t", "\x00", "\x1b", "\x7f", "\x85", "\x9b", "؜", "‎", "‏",
               "‪", "‮", "⁦", "⁩", " ", " "]


def _unprintable_cases():
    for ch in UNPRINTABLE:
        bad = json.dumps(f"x{ch}s3cr3t")
        yield f"command = [\"/opt/g/run\", {bad}]\n", "static.servers.ghidra.command[1]"
        yield f"command = [{json.dumps(f'/opt/g/run{ch}')}]\n", "static.servers.ghidra.command[0]"
        yield f"args = [\"--x\", {bad}]\n", "static.servers.ghidra.args[1]"
        yield f"url = {json.dumps(f'http://127.0.0.1:1/s3cr3t{ch}')}\n", "static.servers.ghidra.url"
        yield f"env = {{ JAVA_HOME = {bad} }}\n", "static.servers.ghidra.env.JAVA_HOME"
        yield f"name = {json.dumps(f'g{ch}')}\n", "static.servers.ghidra.name"
    # a variable NAME with a control character: the key names the table, not the broken name
    yield 'env = { "JAVA_HOME\\n" = "/jdk" }\n', "static.servers.ghidra.env"
    yield 'env = { "JAVA\\u202eHOME" = "/jdk" }\n', "static.servers.ghidra.env"


@pytest.mark.parametrize(("body", "key"), list(_unprintable_cases()))
def test_control_and_bidi_characters_are_refused(tmp_path, body, key):
    err = expect_error(tmp_path, BASE + "\n[static.servers.ghidra]\n" + body, key)
    assert "s3cr3t" not in err.message
    assert any(word in err.message for word in ("control", "letters", "NAME of an environment variable"))


def test_control_characters_are_named_in_the_message(tmp_path):
    err = expect_error(tmp_path, BASE + '\n[static.servers.ghidra]\nargs = ["a\\u001b[31mb"]\n',
                       "static.servers.ghidra.args[0]")
    assert "control characters" in err.message and "bidi" in err.message


def test_a_lone_surrogate_is_refused_from_a_dict():
    with pytest.raises(ConfigError) as ei:
        cfgmod.config_from_dict({"static": {"servers": {"ghidra": {"args": ["a\ud800b"]}}}})
    assert ei.value.details["key"] == "static.servers.ghidra.args[0]"


@pytest.mark.parametrize("program", ["C:pyghidra-mcp.exe", "c:tools\\ghidra-mcp.exe", "C:"])
def test_a_drive_relative_windows_program_is_refused(tmp_path, program):
    err = expect_error(tmp_path, BASE + f"\n[static.servers.ghidra]\ncommand = ['{program}']\n",
                       "static.servers.ghidra.command[0]")
    assert "drive" in err.message


PROFILE_WITH = '''
[profiles.{name}]
vmx = "/vm/x.vmx"
guest_user = "mcp"
guest_password_env = {password_env}

[profiles.{name}.backends.{backend}]
arch = "x64"
port = 9094
'''


@pytest.mark.parametrize(("name", "password_env", "backend", "key"), [
    ('"p\\n"', '"GW_GUEST_PW"', "x64", "profiles.p\n"),
    ("p", '"GW_GUEST_PW\\n"', "x64", "profiles.p.guest_password_env"),
    ("p", '"GW_GUEST_PW"', '"x64\\n"', "profiles.p.backends.x64\n"),
])
def test_names_with_a_trailing_newline_are_refused(tmp_path, name, password_env, backend, key):
    """A regex ending in $ also matches before a final newline: names are matched in full."""
    expect_error(tmp_path, PROFILE_WITH.format(name=name, password_env=password_env, backend=backend), key)
