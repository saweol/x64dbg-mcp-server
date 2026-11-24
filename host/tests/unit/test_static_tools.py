"""Static-analysis tool registry (static_tools): data, lookups and MCP recipe overrides.

The gateway does not proxy the static tools: each tool's own MCP server is registered in
the MCP client next to the gateway. The registry records how to register it.
"""

from __future__ import annotations

import dataclasses
import re

import pytest

from x64dbg_vm_gateway import static_tools
from x64dbg_vm_gateway.config import StaticConfig, StaticServerConfig
from x64dbg_vm_gateway.errors import ConfigError
from x64dbg_vm_gateway.static_tools import McpRecipe, StaticTool, effective_recipe, get_tool, server_name


def test_tool_ids_and_registry_agree():
    assert static_tools.TOOL_IDS == ("ida", "ghidra", "radare2", "cutter")
    assert tuple(static_tools.TOOLS) == static_tools.TOOL_IDS
    for tid, tool in static_tools.TOOLS.items():
        assert isinstance(tool, StaticTool) and tool.id == tid
        assert get_tool(tid) is tool


def test_dataclass_shapes_are_the_documented_contract():
    assert [f.name for f in dataclasses.fields(McpRecipe)] == [
        "name", "project", "homepage", "transport", "command", "url", "install", "notes", "verified", "env",
        "warning"]
    assert [f.name for f in dataclasses.fields(StaticTool)] == [
        "id", "display", "executables", "sync_script", "mcp"]
    tool = get_tool("ida")
    with pytest.raises(dataclasses.FrozenInstanceError):
        tool.id = "x"  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        tool.mcp.name = "x"  # type: ignore[misc]


def test_ida_entry():
    t = get_tool("ida")
    assert t.executables == ("ida", "ida64", "idat", "idat64")
    assert t.sync_script == "static/ida/x64dbg_sync.py"
    m = t.mcp
    assert m.name == "ida-multi-mcp" and m.transport == "stdio"
    assert m.command == ("python3", "-m", "ida_multi_mcp") and m.url is None and m.env == ()
    assert m.verified is True and m.warning == ""
    assert any("idb_save" in n for n in m.notes)


GHIDRA_COMMAND = ("pyghidra-mcp", "--transport", "stdio", "--project-path", "<project-dir>", "--project-name",
                  "<project-name>", "--wait-for-analysis", "<binary>")


def test_ghidra_entry_is_headless_pyghidra_mcp():
    t = get_tool("ghidra")
    assert t.executables == ("ghidraRun", "analyzeHeadless", "pyghidraRun")
    assert t.sync_script == "static/ghidra/x64dbg_sync_ghidra.py"
    m = t.mcp
    assert m.name == "ghidra" and m.project == "pyghidra-mcp (headless Ghidra)"
    assert m.homepage == "https://github.com/clearbluejar/pyghidra-mcp"
    assert m.install == "pip install pyghidra-mcp"
    assert m.command == GHIDRA_COMMAND and m.transport == "stdio" and m.url is None
    assert m.env == (("GHIDRA_INSTALL_DIR", "<ghidra-install-dir>"), ("JAVA_HOME", "<jdk25-home>"))
    assert m.verified is True and m.warning == ""
    notes = " ".join(m.notes)
    for fact in ("JDK 25", "MCP_TIMEOUT", "list_project_binaries", "rename_function", "functions only",
                 "save", "pyghidraRun -H"):
        assert fact in notes, fact
    # the documented alternative
    assert "GhidraMCP" in notes and "--extension-jar" in notes and "GUI mode was not verified" in notes


def test_radare2_entry_is_verified_and_says_r2mcp_cannot_save():
    t = get_tool("radare2")
    assert t.executables == ("r2", "radare2")
    assert t.sync_script == "static/radare2/x64dbg_sync_r2.py"
    m = t.mcp
    assert m.name == "radare2" and m.project == "radare2-mcp (r2mcp)"
    assert m.homepage == "https://github.com/radareorg/radare2-mcp"
    assert m.command == ("r2pm", "-r", "r2mcp") and m.install == "r2pm -ci r2mcp" and m.env == ()
    assert m.transport == "stdio" and m.verified is True and m.warning == ""
    notes = " ".join(m.notes)
    assert "no project-save tool" in notes and "--project" in notes


def test_cutter_entry_has_no_default_command_and_warns():
    t = get_tool("cutter")
    assert t.executables == ("cutter", "Cutter")  # the tool itself, not rizin
    assert t.sync_script == "static/radare2/x64dbg_sync_r2.py"  # Cutter is rizin: the r2 script
    m = t.mcp
    assert m.name == "cutter" and m.project == "CutterMCP"
    assert m.homepage == "https://github.com/ap425q/CutterMCP"
    assert m.command == () and m.url is None and m.env == () and m.verified is False
    for fact in ("unsafe", "all interfaces", "without authentication", "cutter.cmd", "127.0.0.1",
                 "sync script", "r2mcp"):
        assert fact in m.warning, fact
    notes = " ".join(m.notes)
    assert "set_decompiler_comment" in notes and "#3659" in notes


def test_executables_name_the_tool_not_its_mcp_server():
    for tool in static_tools.TOOLS.values():
        assert "pyghidra-mcp" not in tool.executables and "rizin" not in tool.executables
        if tool.mcp.command:
            assert tool.mcp.command[0] not in tool.executables, tool.id


def test_placeholders_are_listed_in_order_once():
    assert static_tools.placeholders(get_tool("ghidra").mcp) == (
        "<ghidra-install-dir>", "<jdk25-home>", "<project-dir>", "<project-name>", "<binary>")
    assert static_tools.placeholders(get_tool("ida").mcp) == ()
    twice = dataclasses.replace(get_tool("ida").mcp, command=("x", "<a>", "--b=<a>", "<c>"),
                                env=(("E", "<c>"),))
    assert static_tools.placeholders(twice) == ("<c>", "<a>")


def test_registry_env_names_are_plain_and_not_secrets():
    for tool in static_tools.TOOLS.values():
        for name, value in tool.mcp.env:
            assert re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name)
            assert not static_tools.looks_like_secret_name(name), name
            assert value.startswith("<") and value.endswith(">"), "user-specific values are placeholders"
        for arg in (*tool.mcp.command, tool.mcp.url or ""):
            assert static_tools.secret_in_argument(arg) is None, (tool.id, arg)


def test_registry_holds_no_host_specific_paths():
    """The repository is public: recipes are generic, user paths come from the config."""
    for tool in static_tools.TOOLS.values():
        m = tool.mcp
        texts = [tool.display, tool.sync_script, *tool.executables, m.name, m.project, m.homepage,
                 m.transport, *m.command, m.url or "", m.install, *m.notes, m.warning,
                 *(v for pair in m.env for v in pair)]
        for text in texts:
            assert "/home/" not in text and "\\Users\\" not in text and "/Users/" not in text, text
            assert "/opt/" not in text and "/media/" not in text, text
        assert m.transport in static_tools.TRANSPORTS
        assert m.homepage == "" or m.homepage.startswith("https://")
        assert not tool.sync_script.startswith("/") and tool.sync_script.startswith("static/")
        assert isinstance(m.notes, tuple) and all("\n" not in n for n in m.notes)


@pytest.mark.parametrize("name", [
    "GW_TOKEN", "GH_TOKEN", "api_key", "API_KEY", "APIKEY", "api-key", "apiKey", "X-Api-Key", "MY_SECRET",
    "PASSWORD", "passwd", "DB_PWD", "DB_PASS", "passphrase", "R2_PASSPHRASE", "AUTH_HEADER", "authorization",
    "BEARER", "CREDENTIAL", "aws-credentials", "COOKIE", "private-key", "PRIVATE_KEY", "privateKey",
    "SSH_KEY", "OPENAI_KEY", "keyStorePassword", "MyPass"])
def test_secret_looking_names(name):
    assert static_tools.looks_like_secret_name(name)


@pytest.mark.parametrize("name", [
    "GHIDRA_INSTALL_DIR", "JAVA_HOME", "PATH", "R2_HOME", "KEYBOARD", "COMPASS", "BYPASS", "KEYFILE",
    "MONKEY", "PASSAGE", "SECRETARY", "AUTHOR", "TOKENIZER", "project-path", "wait-for-analysis",
    # where a secret is kept is not the secret: a file, path or variable name
    "TOKEN_FILE", "password-file", "API_KEY_PATH", "token-env"])
def test_plain_names(name):
    assert not static_tools.looks_like_secret_name(name)


@pytest.mark.parametrize("arg", [
    "--token", "--api-key", "--apiKey", "--password=hunter2", "-Dx.trustStorePassword=x", "--auth-header",
    "--private-key", "--credentials", "--cookie=a", "API_KEY=sk-x", "GH_TOKEN=x", "db.password=x",
    "Authorization: Bearer x", "Cookie: a=b", "X-Api-Key: x", "Bearer x", "token:abc",
    "https://user:pw@host/mcp", "https://user@host/mcp", "http://h/mcp?token=x", "http://h/mcp?a=1&api_key=x",
    "--url=https://u:p@h/", "-e GH_TOKEN=x", "JAVA_OPTS=-Xmx1g --password=x"])
def test_arguments_that_carry_a_secret(arg):
    reason = static_tools.secret_in_argument(arg)
    assert reason  # what kind of secret, never the value
    for value in ("hunter2", "sk-x", "pw@", "abc"):
        assert value not in reason


@pytest.mark.parametrize("arg", [
    "--keyboard", "--compass", "--bypass", "--transport", "stdio", "--project-path", "/srv/pass word",
    "--token-file", "--password-file=/run/pw", "MONKEY=1", "pass", "show", "mcp/token", "/opt/token-mcp/run",
    "C:\\tools\\token.exe", "http://127.0.0.1:8089/sse", "https://h/mcp?verbose=1", "<project-dir>",
    "host:9100", "--wait-for-analysis", "the bearer"])
def test_arguments_without_a_secret(arg):
    assert static_tools.secret_in_argument(arg) is None


@pytest.mark.parametrize("bad", ["binja", "", "IDA", None, 3])
def test_unknown_tool_ids_are_config_errors_naming_the_choices(bad):
    with pytest.raises(ConfigError) as ei:
        get_tool(bad)  # type: ignore[arg-type]
    err = ei.value
    assert "unknown static tool" in err.message
    assert "ida, ghidra, radare2, cutter" in (err.hint or "")


# ── effective_recipe ────────────────────────────────────────────────
def test_effective_recipe_without_config_is_the_registry_recipe():
    assert effective_recipe("ida") == get_tool("ida").mcp
    assert effective_recipe("ghidra", StaticConfig()) == get_tool("ghidra").mcp


def test_effective_recipe_for_cutter_without_override_says_what_to_do_instead():
    with pytest.raises(ConfigError) as ei:
        effective_recipe("cutter", StaticConfig(tools=("cutter",)))
    err = ei.value
    assert "CutterMCP" in err.message and "no MCP server is registered by default" in err.message
    assert "unsafe" in err.message
    hint = err.hint or ""
    assert "sync script" in hint and "r2mcp" in hint and "127.0.0.1" in hint
    assert "[static.servers.cutter]" in hint and "command" in hint and "url" in hint
    assert err.details == {"key": "static.servers.cutter", "tool": "cutter"}


def test_command_override_replaces_the_command_and_keeps_the_documentation():
    cfg = StaticConfig(tools=("cutter",), servers={
        "cutter": StaticServerConfig(command=("python3", "/tools/cuttermcp/bridge.py"), transport="stdio")})
    r = effective_recipe("cutter", cfg)
    assert r.command == ("python3", "/tools/cuttermcp/bridge.py") and r.url is None
    assert r.transport == "stdio" and r.name == "cutter"
    assert r.project == "CutterMCP" and r.homepage == get_tool("cutter").mcp.homepage


@pytest.mark.parametrize(("transport", "expected"), [(None, "http"), ("http", "http"), ("sse", "sse")])
def test_url_override_switches_to_a_remote_transport(transport, expected):
    cfg = StaticConfig(servers={"ghidra": StaticServerConfig(url="http://127.0.0.1:8089/sse",
                                                             transport=transport)})
    r = effective_recipe("ghidra", cfg)
    assert r.url == "http://127.0.0.1:8089/sse" and r.command == () and r.transport == expected


def test_name_only_override_keeps_the_registry_command():
    cfg = StaticConfig(servers={"radare2": StaticServerConfig(name="r2")})
    r = effective_recipe("radare2", cfg)
    assert r.name == "r2" and r.command == get_tool("radare2").mcp.command
    assert server_name("radare2", cfg) == "r2"


def test_a_command_override_replaces_the_server_and_its_environment():
    cfg = StaticConfig(servers={"ghidra": StaticServerConfig(
        command=("ghidra-mcp", "--headless"), transport="stdio", env={"JAVA_HOME": "/jdk"})})
    r = effective_recipe("ghidra", cfg)
    assert r.command == ("ghidra-mcp", "--headless") and r.env == (("JAVA_HOME", "/jdk"),)


def test_an_args_override_keeps_the_registry_program_and_merges_env():
    cfg = StaticConfig(servers={"ghidra": StaticServerConfig(
        args=("--transport", "stdio", "--project-path", "/p"), transport="stdio",
        env={"JAVA_HOME": "/jdk", "EXTRA": "1"})})
    r = effective_recipe("ghidra", cfg)
    assert r.command == ("pyghidra-mcp", "--transport", "stdio", "--project-path", "/p")
    assert r.env == (("GHIDRA_INSTALL_DIR", "<ghidra-install-dir>"), ("JAVA_HOME", "/jdk"), ("EXTRA", "1"))
    assert static_tools.placeholders(r) == ("<ghidra-install-dir>",)


def test_an_env_only_override_fills_in_the_registry_env():
    cfg = StaticConfig(servers={"ghidra": StaticServerConfig(
        env={"GHIDRA_INSTALL_DIR": "/g", "JAVA_HOME": "/jdk"})})
    r = effective_recipe("ghidra", cfg)
    assert r.command == GHIDRA_COMMAND
    assert r.env == (("GHIDRA_INSTALL_DIR", "/g"), ("JAVA_HOME", "/jdk"))


@pytest.mark.parametrize(("override", "verified"), [
    (StaticServerConfig(command=("srv",), transport="stdio"), False),
    (StaticServerConfig(args=("--x",), transport="stdio"), False),
    (StaticServerConfig(url="http://127.0.0.1:1/", transport="http"), False),
    (StaticServerConfig(name="g"), True),
    (StaticServerConfig(env={"JAVA_HOME": "/jdk"}), True),
])
def test_a_replaced_server_is_no_longer_the_verified_recipe(override, verified):
    r = effective_recipe("ghidra", StaticConfig(servers={"ghidra": override}))
    assert r.verified is verified


def test_a_url_override_has_no_environment():
    cfg = StaticConfig(servers={"ghidra": StaticServerConfig(url="http://127.0.0.1:8089/mcp",
                                                             transport="http")})
    assert effective_recipe("ghidra", cfg).env == ()


def test_overrides_of_other_tools_do_not_leak():
    cfg = StaticConfig(servers={"ghidra": StaticServerConfig(name="g")})
    assert effective_recipe("ida", cfg) == get_tool("ida").mcp


def test_server_name_never_needs_a_command():
    assert server_name("cutter") == "cutter"
    assert server_name("ida", None) == "ida-multi-mcp"
    with pytest.raises(ConfigError):
        server_name("binja")
