"""The configured static-analysis tools in the gateway's instructions (plan 6.4).

IDA, Ghidra, radare2 and Cutter run in their own MCP servers next to the gateway; the
instructions and the static_* tool descriptions name the configured ones so the AI knows
which server to use.
"""

from __future__ import annotations

import dataclasses

import pytest

from tests.fakes.fake_runtime import make_lab
from x64dbg_vm_gateway.app import LOOP_RULES, Gateway
from x64dbg_vm_gateway.config import GatewayConfig, StaticConfig, StaticServerConfig
from x64dbg_vm_gateway.errors import GatewayError


@pytest.fixture
def lab(tmp_path):
    lab = make_lab(tmp_path)
    yield lab
    lab.close()


def with_static(lab, static: StaticConfig, **kwargs):
    lab.set_config(static=static)
    return lab.gateway(**kwargs)


def test_loop_rules_describe_the_static_side_generically():
    rule = next(line for line in LOOP_RULES.splitlines() if "static_rebase" in line)
    assert rule.startswith("9. ")
    for word in ("IDA", "Ghidra", "radare2/rizin", "Cutter", "own MCP server", "image base + RVA",
                 "static_export_annotations", "static_import_annotations"):
        assert word in rule, word
    assert "ida_rebase" not in LOOP_RULES


def test_default_instructions_name_ida_and_its_server(lab):
    text = lab.gateway().instructions()
    assert text.startswith(LOOP_RULES)
    assert "static analysis: ida via MCP server 'ida-multi-mcp' (IDA Pro, default)" in text


def test_instructions_name_every_configured_tool_default_first(lab):
    gw = with_static(lab, StaticConfig(tools=("ghidra", "radare2", "cutter"), servers={
        "radare2": StaticServerConfig(name="r2")}))
    text = gw.instructions()
    lines = [line for line in text.splitlines() if line.startswith("- static analysis:")]
    assert lines == [
        "- static analysis: ghidra via MCP server 'ghidra' (Ghidra, default)",
        "- static analysis: radare2 via MCP server 'r2' (radare2)",
        "- static analysis: cutter via MCP server 'cutter' (Cutter)",
    ]
    assert "ida-multi-mcp" not in text
    assert "gateway_doctor" in text  # where the AI learns that a server is not registered


def test_instructions_keep_the_static_tools_without_a_runtime(lab):
    def broken(name: str):
        raise GatewayError("no runtime")

    cfg = dataclasses.replace(lab.config, static=StaticConfig(tools=("ghidra",)))
    gw = Gateway(cfg, runtime_factory=broken)
    text = gw.instructions()
    assert text.startswith(LOOP_RULES) and "static analysis: ghidra via MCP server 'ghidra'" in text


def test_static_servers_lists_the_configured_tools(lab):
    gw = with_static(lab, StaticConfig(tools=("cutter", "ida"), servers={
        "ida": StaticServerConfig(name="ida")}))
    assert gw.static_servers() == [
        {"id": "cutter", "display": "Cutter", "server": "cutter", "default": True},
        {"id": "ida", "display": "IDA Pro", "server": "ida", "default": False},
    ]
    assert GatewayConfig().static.default_tool == "ida"


def test_the_gateway_offers_the_static_servers_to_the_front_end():
    from x64dbg_vm_gateway.frontends import mcp_server

    assert issubclass(Gateway, mcp_server.StaticToolsApp)


def test_served_static_tool_descriptions_name_the_configured_server(lab):
    from tests.unit.test_mcp_server import drive
    from x64dbg_vm_gateway.frontends import mcp_server

    gw = with_static(lab, StaticConfig(tools=("radare2",)))
    res = drive(mcp_server.build_server(gw), lambda c: c.list_tools())
    by = {t.name: t.description for t in res.tools}
    assert by["static_rebase"].endswith(
        "Static tool configured for this gateway: radare2 via MCP server 'radare2'.")
    assert "MCP server 'radare2'" not in by["session_status"]
