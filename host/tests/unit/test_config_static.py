"""``[static]``: the static-analysis tools used next to the gateway (IDA, Ghidra, radare2, Cutter)."""

from __future__ import annotations

import dataclasses

import pytest

from x64dbg_vm_gateway import config as cfgmod
from x64dbg_vm_gateway.config import GatewayConfig, StaticConfig, StaticServerConfig

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
