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


# ── doctor: static_tools (WARN, never FAIL) ─────────────────────────
def which_from(found: dict[str, str]):
    calls: list[str] = []

    def which(name: str) -> str | None:
        calls.append(name)
        return found.get(name)

    which.calls = calls  # type: ignore[attr-defined]
    return which


def static_check(gw) -> dict:
    rep = gw.doctor()
    (check,) = [c for c in rep["checks"] if c["name"] == "static_tools"]
    return {**check, "_report_ok": rep["ok"]}


def test_doctor_warns_but_never_fails_when_no_static_tool_is_installed(lab):
    c = static_check(lab.gateway(which=which_from({})))
    assert c["ok"] is True and c["_report_ok"] is True  # the rest of the lab is green
    assert c["level"] == "warn"
    assert "ida: WARN none of ida, ida64, idat, idat64 on PATH" in c["detail"]
    assert "MCP server 'ida-multi-mcp' (stdio: python3 -m ida_multi_mcp)" in c["detail"]
    assert "WARN MCP command python3 not found" in c["detail"]
    assert c["hint"]


def test_doctor_reports_a_found_tool_without_warning(lab):
    which = which_from({"ida64": "/tools/ida/ida64", "python3": "/usr/bin/python3"})
    c = static_check(lab.gateway(which=which))
    assert c["ok"] is True and c["level"] == "ok", c
    assert c["detail"] == ("ida: ida64 found (/tools/ida/ida64); MCP server 'ida-multi-mcp' "
                           "(stdio: python3 -m ida_multi_mcp)")
    assert c["hint"] is None
    (tool,) = c["tools"]
    assert tool["id"] == "ida" and tool["executable"] == "/tools/ida/ida64" and tool["warnings"] == []
    assert tool["mcp"] == {"name": "ida-multi-mcp", "transport": "stdio",
                           "command": ["python3", "-m", "ida_multi_mcp"], "url": None, "verified": True,
                           "command_found": True}
    assert "ida" in which.calls and "ida64" in which.calls  # first executable missing, second found


def test_doctor_reports_every_configured_tool(lab):
    which = which_from({"ghidraRun": "/tools/ghidra/ghidraRun", "pyghidra-mcp": "/tools/bin/pyghidra-mcp",
                        "r2": "/tools/bin/r2"})
    gw = with_static(lab, StaticConfig(tools=("ghidra", "radare2", "cutter")), which=which)
    c = static_check(gw)
    assert c["ok"] is True and c["level"] == "warn"
    parts = c["detail"].split(" | ")
    assert parts[0] == ("ghidra: ghidraRun found (/tools/ghidra/ghidraRun); MCP server 'ghidra' "
                        "(stdio: pyghidra-mcp --transport stdio --project-path <project-dir> --project-name "
                        "<project-name> --wait-for-analysis <binary>)")
    assert parts[1].startswith("radare2: r2 found (/tools/bin/r2); MCP server 'radare2' "
                               "(stdio: r2pm -r r2mcp)")
    assert "WARN MCP command r2pm not found" in parts[1]
    assert parts[2].startswith("cutter: WARN none of cutter, Cutter on PATH")
    assert "WARN no MCP recipe" in parts[2] and "[static.servers.cutter]" in parts[2]
    assert [t["id"] for t in c["tools"]] == ["ghidra", "radare2", "cutter"]
    assert c["tools"][2]["mcp"] is None


def test_doctor_checks_the_override_command(lab, tmp_path):
    bridge = tmp_path / "tools" / "bridge.py"
    bridge.parent.mkdir()
    bridge.write_text("# placeholder\n", encoding="utf-8")
    which = which_from({"cutter": "/tools/bin/cutter"})
    ok = with_static(lab, StaticConfig(tools=("cutter",), servers={
        "cutter": StaticServerConfig(command=(str(bridge), "--stdio"), transport="stdio")}), which=which)
    c = static_check(ok)
    assert c["level"] == "ok", c
    assert f"MCP server 'cutter' (stdio: {bridge} --stdio; recipe not verified)" in c["detail"]
    assert c["tools"][0]["mcp"]["command_found"] is True
    missing = with_static(lab, StaticConfig(tools=("cutter",), servers={
        "cutter": StaticServerConfig(command=(str(tmp_path / "nope.py"),), transport="stdio")}), which=which)
    c = static_check(missing)
    assert c["ok"] is True and c["level"] == "warn"
    assert f"WARN MCP command {tmp_path / 'nope.py'} not found" in c["detail"]


def test_doctor_shows_a_url_recipe_without_credentials(lab):
    which = which_from({"ghidraRun": "/tools/ghidra/ghidraRun"})
    gw = with_static(lab, StaticConfig(tools=("ghidra",), servers={"ghidra": StaticServerConfig(
        url="http://user:s3cr3t@127.0.0.1:8089/sse?token=s3cr3t#x", transport="sse")}), which=which)
    c = static_check(gw)
    assert c["level"] == "ok", c
    assert "MCP server 'ghidra' (sse: http://127.0.0.1:8089/sse; recipe not verified)" in c["detail"]
    assert "s3cr3t" not in str(c)


def test_doctor_masks_secret_looking_command_arguments(lab):
    which = which_from({"ghidraRun": "/g", "srv": "/tools/bin/srv"})
    gw = with_static(lab, StaticConfig(tools=("ghidra",), servers={"ghidra": StaticServerConfig(
        command=("srv", "--token", "s3cr3t", "--api-key=s3cr3t", "--port", "8089"), transport="stdio")}),
        which=which)
    c = static_check(gw)
    assert "stdio: srv --token *** --api-key=*** --port 8089" in c["detail"]
    assert "s3cr3t" not in str(c)


def test_doctor_static_check_survives_a_failing_lookup(lab):
    def broken(name: str) -> str | None:
        raise OSError("PATH unreadable")

    c = static_check(lab.gateway(which=broken))
    assert c["ok"] is True and c["_report_ok"] is True and c["level"] == "warn"
    assert "WARN" in c["detail"]
