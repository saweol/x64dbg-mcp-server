"""MCP prompts (``frontends/prompts.py``): prompts/list and prompts/get on the stdio server and
on every scope of the HTTP server. Prompts only return text, so every scope may read them.

The texts name real tools (every name a prompt mentions is a gateway tool or a plugin tool of
the builtin catalogs) and repeat the safety rules; arguments are declared, checked and quoted."""

from __future__ import annotations

import json
import re
from importlib import resources

import pytest
from mcp import Client
from mcp.shared.exceptions import MCPError
from starlette.testclient import TestClient

from tests.fakes.fake_app import FakeApp
from tests.unit.test_http_server import (
    ADMIN_TOKEN,
    ANALYZE_TOKEN,
    BASE,
    LOCAL,
    READ_TOKEN,
    build,
    open_session,
)
from tests.unit.test_http_server import rpc as http_rpc
from tests.unit.test_mcp_server import drive
from x64dbg_vm_gateway.frontends import mcp_server, prompts
from x64dbg_vm_gateway.frontends.tool_defs import GATEWAY_TOOL_NAMES

NAMES = {"analyze-sample", "trace-api", "find-oep", "static-dynamic", "report"}
SAMPLE = "/home/analyst/samples/invoice.exe"
ARGS = {
    "analyze-sample": {"sample_path": SAMPLE},
    "trace-api": {"sample_path": SAMPLE, "api": "kernel32.CreateFileW"},
    "find-oep": {"sample_path": SAMPLE},
    "static-dynamic": {"sample_path": SAMPLE, "static_address": "0x140001500", "imagebase": "0x140000000"},
    "report": {"job_id": "20261123-101010-abcdef"},
}


def plugin_tool_names() -> set[str]:
    names: set[str] = set()
    for version in ("1.9", "1.10"):
        doc = json.loads(resources.files("x64dbg_vm_gateway").joinpath(f"data/tools-v{version}.json")
                         .read_text(encoding="utf-8"))
        names |= {t["name"] for t in doc["tools"]}
    return names


@pytest.fixture
def app() -> FakeApp:
    return FakeApp()


# ── definitions ─────────────────────────────────────────────────────
def test_the_prompts_and_their_arguments():
    assert {p.name for p in prompts.PROMPTS} == NAMES
    args = {p.name: {(a.name, a.required) for a in p.arguments} for p in prompts.PROMPTS}
    assert ("sample_path", True) in args["analyze-sample"]
    assert {("sample_path", True), ("api", True)} <= args["trace-api"]
    assert ("sample_path", True) in args["find-oep"]
    assert {("sample_path", True), ("static_address", True), ("imagebase", True)} <= args["static-dynamic"]
    assert ("job_id", False) in args["report"]
    for p in prompts.PROMPTS:
        assert p.description and all(a.description for a in p.arguments)


@pytest.mark.parametrize("name", sorted(NAMES))
def test_every_prompt_names_real_tools_and_repeats_the_safety_rules(name):
    text = prompts.render(name, ARGS[name])
    known = set(GATEWAY_TOOL_NAMES) | plugin_tool_names()
    named = set(re.findall(r"\b([a-z]+_[a-z_]+|[A-Z][a-z]+(?:[A-Z][a-z0-9]*)+|run)\(", text))
    assert named, "a prompt names the tools it uses as calls"
    assert named <= known, named - known
    lowered = text.lower()
    assert "only inside the vm" in lowered and "never" in lowered and "host" in lowered
    assert "<untrusted_guest_output>" in text and "untrusted" in lowered
    assert "ask the user" in lowered


def test_tool_names_in_the_texts_exist():
    """Every CamelCase word in a prompt that looks like a plugin tool is one (no invented tools)."""
    known = set(GATEWAY_TOOL_NAMES) | plugin_tool_names()
    for name in NAMES:
        text = prompts.render(name, ARGS[name])
        words = set(re.findall(r"(?<!\")\b(?:Get|Set|Dump|Detect|Step|List|Read|Write|Disassemble|Comment)"
                               r"[A-Za-z]*\b",
                               text))
        assert words <= known, (name, words - known)
        # (not a quoted value such as direction="static_to_runtime", nor artifacts/static_sync.json)
        snake = set(re.findall(r"(?<![\"/])\b(?:analysis|static|session|jobs|vm|file|debugger|gateway)"
                               r"_[a-z_]+\b(?!\.json)", text))
        assert snake <= known, (name, snake - known)


def test_arguments_are_quoted_into_the_text():
    text = prompts.render("analyze-sample", {"sample_path": 'C:\\samples\\a "b".exe'})
    assert json.dumps('C:\\samples\\a "b".exe') in text  # one JSON string literal: unambiguous
    trace = prompts.render("trace-api", ARGS["trace-api"])
    assert '"kernel32.CreateFileW"' in trace
    sd = prompts.render("static-dynamic", ARGS["static-dynamic"])
    assert '"0x140001500"' in sd and '"0x140000000"' in sd and "static_to_runtime" in sd


def test_report_without_a_job_id_uses_the_default_job():
    text = prompts.render("report", {})
    call = text.split("analysis_report(", 1)[1].split(")", 1)[0]
    assert "job_id" not in call and "format" in call


@pytest.mark.parametrize("name,args,fragment", [
    ("analyze-sample", {}, "sample_path"),
    ("analyze-sample", {"sample_path": "  "}, "sample_path"),
    ("analyze-sample", {"sample_path": "a\x1b[31mb"}, "control"),
    ("analyze-sample", {"sample_path": "a\nb"}, "control"),
    ("analyze-sample", {"sample_path": "x" * 5000}, "long"),
    ("analyze-sample", {"sample_path": SAMPLE, "arch": "arm64"}, "arch"),
    ("analyze-sample", {"sample_path": SAMPLE, "bogus": "1"}, "bogus"),
    ("trace-api", {"sample_path": SAMPLE, "api": "CreateFileW; rm -rf /"}, "api"),
    ("static-dynamic", {"sample_path": SAMPLE, "static_address": "main", "imagebase": "0x1"},
     "static_address"),
    ("static-dynamic", {"sample_path": SAMPLE, "static_address": "0x1", "imagebase": "-1"}, "imagebase"),
    ("report", {"job_id": "../../etc"}, "job_id"),
    ("nope", {}, "unknown prompt"),
])
def test_bad_arguments_are_refused(name, args, fragment):
    with pytest.raises(prompts.PromptError) as ei:
        prompts.render(name, args)
    assert fragment in str(ei.value)


def test_optional_arguments():
    assert '"x32"' in prompts.render("analyze-sample", {"sample_path": SAMPLE, "arch": "x32"})
    start = prompts.render("analyze-sample", {"sample_path": SAMPLE}).split("analysis_start(", 1)[1]
    assert "arch" not in start.split(")", 1)[0]
    # an empty optional argument counts as omitted (clients send every declared argument)
    assert prompts.render("analyze-sample", {"sample_path": SAMPLE, "arch": ""}) == \
        prompts.render("analyze-sample", {"sample_path": SAMPLE})


# ── the stdio / in-memory MCP server ────────────────────────────────
@pytest.mark.parametrize("mode", ["legacy", "auto"])
def test_prompts_list_over_mcp(app, mode):
    res = drive(mcp_server.build_server(app), lambda c: c.list_prompts(), mode)
    by = {p.name: p for p in res.prompts}
    assert set(by) == NAMES
    trace = {a.name: a for a in by["trace-api"].arguments}
    assert trace["api"].required is True and "kernel32.CreateFileW" in trace["api"].description
    assert app.calls == []  # prompts never reach the app


@pytest.mark.parametrize("mode", ["legacy", "auto"])
def test_prompts_get_over_mcp(app, mode):
    res = drive(mcp_server.build_server(app),
                lambda c: c.get_prompt("trace-api", ARGS["trace-api"]), mode)
    assert res.description and len(res.messages) == 1
    msg = res.messages[0]
    assert msg.role == "user" and msg.content.type == "text"
    assert msg.content.text == prompts.render("trace-api", ARGS["trace-api"])


def _prompt_error(app: FakeApp, name: str, args: dict[str, str]) -> MCPError:
    async def get(c: Client) -> MCPError | None:
        try:
            await c.get_prompt(name, args)
        except MCPError as e:
            return e
        return None

    err = drive(mcp_server.build_server(app), get)
    assert err is not None, "prompts/get should have failed"
    return err


def test_prompts_get_errors_are_invalid_params(app):
    err = _prompt_error(app, "trace-api", {"sample_path": SAMPLE})
    assert err.code == -32602 and "api" in err.message
    err = _prompt_error(app, "rm-rf", {})
    assert err.code == -32602 and "unknown prompt" in err.message
    err = _prompt_error(app, "analyze-sample", {"sample_path": "a\x1b]0;x\x07b"})
    assert err.code == -32602 and "\x1b" not in err.message  # the value is never echoed


def test_static_dynamic_names_the_configured_static_tool():
    class StaticApp(FakeApp):
        def static_servers(self):
            return [{"id": "ghidra", "display": "Ghidra", "server": "ghidra", "default": True}]

    res = drive(mcp_server.build_server(StaticApp()),
                lambda c: c.get_prompt("static-dynamic", ARGS["static-dynamic"]))
    assert "Ghidra via MCP server 'ghidra'" in res.messages[0].content.text


def test_server_advertises_prompts(app):
    async def caps(c: Client) -> object:
        return c.server_capabilities

    caps_ = drive(mcp_server.build_server(app), caps)
    assert caps_ is not None and caps_.prompts is not None


# ── the HTTP server: every scope may read the prompts ───────────────
@pytest.mark.parametrize("token", [READ_TOKEN, ANALYZE_TOKEN, ADMIN_TOKEN])
def test_prompts_over_http_for_every_scope(app, tmp_path, token):
    with TestClient(build(app, tmp_path), base_url=BASE, client=LOCAL) as c:
        sid = open_session(c, token)
        listed = http_rpc(c, token, sid, "prompts/list", {})
        assert {p["name"] for p in listed["result"]["prompts"]} == NAMES
        got = http_rpc(c, token, sid, "prompts/get", {"name": "report", "arguments": ARGS["report"]}, rid=8)
        text = got["result"]["messages"][0]["content"]["text"]
        assert text == prompts.render("report", ARGS["report"])
        bad = http_rpc(c, token, sid, "prompts/get", {"name": "find-oep", "arguments": {}}, rid=9)
        assert bad["error"]["code"] == -32602
    assert app.calls == []


def test_prompts_over_http_need_a_token(app, tmp_path):
    with TestClient(build(app, tmp_path), base_url=BASE, client=LOCAL) as c:
        r = c.post("/mcp", headers={"Accept": "application/json, text/event-stream",
                                    "Content-Type": "application/json"},
                   json={"jsonrpc": "2.0", "id": 1, "method": "prompts/list", "params": {}})
    assert r.status_code == 401
