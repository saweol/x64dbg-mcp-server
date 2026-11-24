"""Static-analysis tool registry (static_tools): data, lookups and MCP recipe overrides.

The gateway does not proxy the static tools: each tool's own MCP server is registered in
the MCP client next to the gateway. The registry records how to register it.
"""

from __future__ import annotations

import dataclasses

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
        "name", "project", "homepage", "transport", "command", "url", "install", "notes", "verified"]
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
    assert t.mcp.name == "ida-multi-mcp" and t.mcp.transport == "stdio"
    assert t.mcp.command == ("python3", "-m", "ida_multi_mcp") and t.mcp.url is None
    assert t.mcp.verified is True


def test_ghidra_entry():
    t = get_tool("ghidra")
    assert t.executables == ("ghidraRun", "analyzeHeadless", "pyghidra-mcp")
    assert t.sync_script == "static/ghidra/x64dbg_sync_ghidra.py"
    m = t.mcp
    assert m.name == "ghidra" and m.project == "pyghidra-mcp (headless Ghidra)"
    assert m.homepage == "https://github.com/clearbluejar/pyghidra-mcp"
    assert m.command == ("pyghidra-mcp",) and m.transport == "stdio" and m.verified is False
    assert "GHIDRA_INSTALL_DIR" in m.notes and "LaurieWired/GhidraMCP" in m.notes


def test_radare2_entry():
    t = get_tool("radare2")
    assert t.executables == ("r2", "radare2")
    assert t.sync_script == "static/radare2/x64dbg_sync_r2.py"
    m = t.mcp
    assert m.name == "radare2" and m.project == "radare2-mcp (r2mcp)"
    assert m.homepage == "https://github.com/radareorg/radare2-mcp"
    assert m.command == ("r2pm", "-r", "r2mcp") and m.install == "r2pm -ci r2mcp"
    assert m.transport == "stdio" and m.verified is False


def test_cutter_entry_has_no_default_command():
    t = get_tool("cutter")
    assert t.executables == ("cutter", "Cutter", "rizin")
    assert t.sync_script == "static/radare2/x64dbg_sync_r2.py"  # Cutter is rizin: the r2 script
    m = t.mcp
    assert m.name == "cutter" and m.project == "CutterMCP"
    assert m.homepage == "https://github.com/ap425q/CutterMCP"
    assert m.command == () and m.url is None and m.transport == "stdio" and m.verified is False
    assert "[static.servers.cutter]" in m.notes


def test_registry_holds_no_host_specific_paths():
    """The repository is public: recipes are generic, user paths come from the config."""
    for tool in static_tools.TOOLS.values():
        texts = [tool.display, tool.sync_script, *tool.executables, *dataclasses.astuple(tool.mcp)]
        for text in texts:
            if isinstance(text, str):
                assert "/home/" not in text and "\\Users\\" not in text and "/Users/" not in text, text
        assert tool.mcp.transport in static_tools.TRANSPORTS
        assert tool.mcp.homepage == "" or tool.mcp.homepage.startswith("https://")
        assert not tool.sync_script.startswith("/") and tool.sync_script.startswith("static/")


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


def test_effective_recipe_for_cutter_without_override_says_what_to_configure():
    with pytest.raises(ConfigError) as ei:
        effective_recipe("cutter", StaticConfig(tools=("cutter",)))
    err = ei.value
    assert "CutterMCP" in err.message and "no default command" in err.message
    assert "[static.servers.cutter]" in (err.hint or "")
    assert "command" in (err.hint or "") and "url" in (err.hint or "")
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


def test_overrides_of_other_tools_do_not_leak():
    cfg = StaticConfig(servers={"ghidra": StaticServerConfig(name="g")})
    assert effective_recipe("ida", cfg) == get_tool("ida").mcp


def test_server_name_never_needs_a_command():
    assert server_name("cutter") == "cutter"
    assert server_name("ida", None) == "ida-multi-mcp"
    with pytest.raises(ConfigError):
        server_name("binja")
