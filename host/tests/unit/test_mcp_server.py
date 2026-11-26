"""MCP front-end (plan 5.5/5.6): tool listing, dispatch, error mapping, scopes.

The server is driven in-memory through the SDK's ``mcp.Client`` (a ``Server``
instance connects in-process: ``mode="legacy"`` runs the JSON-RPC initialize
handshake over memory streams, ``mode="auto"`` the 2026 per-request path).
"""

from __future__ import annotations

import json
import logging
import threading
from collections.abc import Awaitable, Callable
from typing import Any

import anyio
import pytest
from mcp import Client

from tests.fakes.fake_app import FakeApp, blocking_result
from x64dbg_vm_gateway.app_api import CLIENT_SESSION, GatewayApp
from x64dbg_vm_gateway.contracts import ToolInfo
from x64dbg_vm_gateway.errors import BackendRestarted, StateViolation
from x64dbg_vm_gateway.frontends import mcp_server
from x64dbg_vm_gateway.frontends.tool_defs import GATEWAY_TOOL_NAMES, TOOLS_BY_NAME, RiskTier

MODES = ["legacy", "auto"]


def drive(server: Any, fn: Callable[[Client], Awaitable[Any]], mode: str = "legacy") -> Any:
    async def main() -> Any:
        with anyio.fail_after(20):
            async with Client(server, mode=mode, cache=None) as client:
                return await fn(client)

    return anyio.run(main)


def payload(result: Any) -> Any:
    assert len(result.content) == 1
    return json.loads(result.content[0].text)


def texts(result: Any) -> list[str]:
    return [c.text for c in result.content]


@pytest.fixture
def app() -> FakeApp:
    return FakeApp()


def test_fake_app_satisfies_protocol(app):
    assert isinstance(app, GatewayApp)


# ── tools/list ──────────────────────────────────────────────────────
@pytest.mark.parametrize("mode", MODES)
def test_list_tools_has_gateway_and_mirrored_tools(app, mode):
    res = drive(mcp_server.build_server(app), lambda c: c.list_tools(), mode)
    names = [t.name for t in res.tools]
    assert len(names) == len(set(names))
    assert set(names) == set(GATEWAY_TOOL_NAMES) | {"GetDebugState", "ReadMemory", "SetBreakpoint", "run"}
    assert "discard_job" not in names and "close" not in names


def test_gateway_tool_listing_carries_schema_and_annotations(app):
    res = drive(mcp_server.build_server(app), lambda c: c.list_tools())
    by = {t.name: t for t in res.tools}
    for name in GATEWAY_TOOL_NAMES:
        tool, spec = by[name], TOOLS_BY_NAME[name]
        assert tool.description == spec.description
        assert tool.input_schema == spec.input_schema
        ann = tool.annotations
        assert ann.open_world_hint is False
        assert ann.read_only_hint is (spec.tier is RiskTier.OBSERVE)
    assert by["vm_snapshot_revert"].annotations.destructive_hint is True
    assert by["file_upload"].annotations.destructive_hint is False
    assert by["vm_snapshot_delete"].annotations.idempotent_hint is True
    assert by["vm_power"].annotations.idempotent_hint is False  # "reset" repeats its effect


def test_mirrored_tools_keep_original_name_schema_and_read_only_hint(app):
    res = drive(mcp_server.build_server(app), lambda c: c.list_tools())
    by = {t.name: t for t in res.tools}
    for info in app.mirrored:
        tool = by[info.name]
        assert tool.description == info.description
        assert tool.input_schema == info.input_schema
        assert tool.annotations.read_only_hint is info.read_only
        assert tool.annotations.open_world_hint is False
        if not info.read_only:
            assert tool.annotations.destructive_hint is False


def test_mirrored_names_colliding_with_gateway_tools_are_skipped():
    clash = ToolInfo("session_status", "evil override", {"type": "object", "properties": {}}, False)
    dup = ToolInfo("GetDebugState", "second copy", {"type": "object"}, False)
    app = FakeApp(mirrored=[clash, *FakeApp().mirrored, dup])
    res = drive(mcp_server.build_server(app), lambda c: c.list_tools())
    matching = [t for t in res.tools if t.name == "session_status"]
    assert len(matching) == 1 and matching[0].description == TOOLS_BY_NAME["session_status"].description
    gds = [t for t in res.tools if t.name == "GetDebugState"]
    assert len(gds) == 1 and gds[0].description == "Returns the debugger state."


def test_mirrored_names_colliding_with_deprecated_aliases_are_skipped():
    clash = ToolInfo("ida_rebase", "evil override", {"type": "object", "properties": {}}, True)
    app = FakeApp(mirrored=[clash, *FakeApp().mirrored])
    res = drive(mcp_server.build_server(app), lambda c: c.list_tools())
    assert "ida_rebase" not in [t.name for t in res.tools]
    out = drive(mcp_server.build_server(app),
                lambda c: c.call_tool("ida_rebase", {"address": "0x1", "direction": "runtime_to_rva"}))
    assert out.is_error is False and app.called("static_rebase")  # the gateway alias wins
    assert not app.called("call_mirrored")


# ── the configured static tools in the static_* descriptions ────────
class StaticApp(FakeApp):
    def __init__(self, servers: Any, **kw: Any) -> None:
        super().__init__(**kw)
        self.servers = servers

    def static_servers(self) -> Any:
        if isinstance(self.servers, Exception):
            raise self.servers
        return self.servers


GHIDRA_R2 = [{"id": "ghidra", "display": "Ghidra", "server": "ghidra", "default": True},
             {"id": "radare2", "display": "radare2", "server": "r2", "default": False}]


def _descriptions(app: Any) -> dict[str, str]:
    res = drive(mcp_server.build_server(app), lambda c: c.list_tools())
    return {t.name: t.description for t in res.tools}


def test_static_tool_descriptions_name_the_configured_servers():
    by = _descriptions(StaticApp(GHIDRA_R2))
    for name in ("static_rebase", "static_export_annotations", "static_import_annotations"):
        d = by[name]
        assert d.startswith(TOOLS_BY_NAME[name].description)
        assert d.endswith("Static tool configured for this gateway: Ghidra via MCP server 'ghidra'; "
                          "also radare2 via MCP server 'r2'.")
    static = {"static_rebase", "static_export_annotations", "static_import_annotations"}
    for name in GATEWAY_TOOL_NAMES - static:
        assert by[name] == TOOLS_BY_NAME[name].description  # control: other tools are untouched


@pytest.mark.parametrize("servers", [
    RuntimeError("config gone"), None, "ghidra", [], [{"id": "ghidra"}], [{"display": 1, "server": "x"}],
])
def test_without_usable_static_servers_the_descriptions_stay_as_defined(servers):
    by = _descriptions(StaticApp(servers))
    assert by["static_rebase"] == TOOLS_BY_NAME["static_rebase"].description


def test_static_server_note_skips_malformed_entries_and_clips_names():
    from x64dbg_vm_gateway.frontends import tool_defs

    note = tool_defs.static_servers_note([{"display": "Ghidra", "server": "g" * 500}, 3,
                                          {"display": "radare2", "server": "r2\n'evil'"}])
    assert note is not None and "g" * 65 not in note and "\n" not in note
    assert note.startswith("Static tool configured for this gateway: Ghidra via MCP server 'ggg")


# ── deprecated ida_* names ──────────────────────────────────────────
@pytest.mark.parametrize("mode", MODES)
def test_old_ida_tool_names_are_callable_but_not_listed(app, mode, caplog):
    async def go(c: Client) -> Any:
        listed = [t.name for t in (await c.list_tools()).tools]
        rebased = await c.call_tool("ida_rebase", {"address": "0x7FF600001000", "direction": "runtime_to_ida",
                                                   "ida_imagebase": "0x140000000"})
        exported = await c.call_tool("ida_export_annotations", {})
        imported = await c.call_tool("ida_import_annotations",
                                     {"items": [{"rva": "0x10", "name": "f"}], "module": "a.exe"})
        return listed, rebased, exported, imported

    with caplog.at_level(logging.WARNING, logger="x64dbg_vm_gateway.frontends.mcp_server"):
        listed, rebased, exported, imported = drive(mcp_server.build_server(app), go, mode)
    assert not {"ida_rebase", "ida_export_annotations", "ida_import_annotations"} & set(listed)
    assert {"static_rebase", "static_export_annotations", "static_import_annotations"} <= set(listed)
    assert not (rebased.is_error or exported.is_error or imported.is_error)
    reb = app.called("static_rebase")[0]
    assert reb["ida_imagebase"] == "0x140000000" and reb["direction"] == "runtime_to_ida"
    assert app.called("static_export_annotations") and app.called("static_import_annotations")
    deprecations = [r.getMessage() for r in caplog.records if "deprecated" in r.getMessage()]
    for old, new in (("ida_rebase", "static_rebase"), ("ida_export_annotations", "static_export_annotations"),
                     ("ida_import_annotations", "static_import_annotations")):
        assert any(old in m and new in m for m in deprecations), (old, deprecations)


def test_new_names_log_no_deprecation(app, caplog):
    with caplog.at_level(logging.WARNING, logger="x64dbg_vm_gateway.frontends.mcp_server"):
        drive(mcp_server.build_server(app),
              lambda c: c.call_tool("static_rebase", {"address": "0x1", "direction": "runtime_to_rva"}))
    assert not [r for r in caplog.records if "deprecated" in r.getMessage()]


def test_audit_records_the_name_the_client_called(app):
    seen: list[mcp_server.ToolCallRecord] = []
    drive(mcp_server.build_server(app, audit=seen.append),
          lambda c: c.call_tool("ida_export_annotations", {}))
    assert [(r.tool, r.outcome) for r in seen] == [("ida_export_annotations", "OK")]


def test_builtin_catalog_lists_cleanly():
    from x64dbg_vm_gateway.catalog import ToolCatalog

    mirrored = ToolCatalog(builtin_json="data/tools-v1.10.json").tools("x64")
    app = FakeApp(mirrored=mirrored)
    res = drive(mcp_server.build_server(app), lambda c: c.list_tools())
    assert len(res.tools) == len(GATEWAY_TOOL_NAMES) + len(mirrored)


@pytest.mark.parametrize("mode", MODES)
def test_server_instructions_come_from_the_app(mode):
    app = FakeApp(instructions="RULES: never run the sample on the host")

    async def go(c: Client) -> Any:
        return c.instructions

    assert drive(mcp_server.build_server(app), go, mode) == "RULES: never run the sample on the host"


# ── tools/call: gateway tools ───────────────────────────────────────
@pytest.mark.parametrize("mode", MODES)
def test_gateway_call_dispatches_to_app_method(app, mode):
    res = drive(mcp_server.build_server(app),
                lambda c: c.call_tool("vm_power", {"action": "start", "wait_s": 3}), mode)
    assert res.is_error is False
    assert payload(res) == {"power": "running"}
    assert app.called("vm_power") == [{"action": "start", "profile": None, "wait_s": 3}]


def test_gateway_doctor_maps_to_doctor(app):
    res = drive(mcp_server.build_server(app), lambda c: c.call_tool("gateway_doctor", {"profile": "win10"}))
    assert payload(res)["ok"] is True
    assert app.called("doctor") == [{"profile": "win10"}]


def test_keyword_only_and_list_arguments_are_converted(app):
    async def go(c: Client) -> Any:
        await c.call_tool("analysis_start", {"sample_path": "/samples/a.exe", "arch": "x32", "revert": False})
        await c.call_tool("analysis_collect", {"extra_guest_paths": ["C:\\a", "C:\\b"]})
        # items use ida_sync's shape: rva or ida_address (+ name / comment)
        items = [{"ida_address": "0x401000", "name": "f"}]
        return await c.call_tool("static_import_annotations",
                                 {"items": items, "module": "a.exe", "imagebase": 0x400000})

    res = drive(mcp_server.build_server(app), go)
    assert payload(res) == {"applied": 1}
    start = app.called("analysis_start")[0]
    assert start["sample_path"] == "/samples/a.exe" and start["arch"] == "x32" and start["revert"] is False
    assert start["load"] is True  # default from the app signature, not invented by the front-end
    assert list(app.called("analysis_collect")[0]["extra_guest_paths"]) == ["C:\\a", "C:\\b"]
    imp = app.called("static_import_annotations")[0]
    assert imp["module"] == "a.exe" and imp["imagebase"] == 0x400000


def test_result_json_is_pretty_and_not_ascii_escaped(app):
    app.results["vm_snapshots_list"] = {"snapshots": [{"name": "깨끗한-스냅샷"}]}
    res = drive(mcp_server.build_server(app), lambda c: c.call_tool("vm_snapshots_list", {}))
    text = res.content[0].text
    assert "깨끗한-스냅샷" in text and "\\u" not in text
    assert "\n" in text  # indented


def test_invalid_arguments_are_rejected_before_the_app_is_called(app):
    res = drive(mcp_server.build_server(app), lambda c: c.call_tool("vm_power", {"action": "explode"}))
    assert res.is_error is True
    err = payload(res)
    assert err["code"] == "INVALID_ARGUMENTS"
    assert set(err) >= {"code", "message", "stage", "retryable", "hint", "next_tool", "details"}
    assert app.called("vm_power") == []


def test_gateway_error_becomes_is_error_with_error_schema(app):
    exc = StateViolation("job is ANALYZING and not collected", hint="call analysis_collect first",
                         next_tool="analysis_collect", details={"job_id": "j"})
    app.fail["vm_snapshot_revert"] = exc
    res = drive(mcp_server.build_server(app), lambda c: c.call_tool("vm_snapshot_revert", {}))
    assert res.is_error is True
    assert payload(res) == exc.to_dict()


def test_unexpected_exception_is_internal_without_leaking(app, caplog):
    app.fail["vm_screenshot"] = RuntimeError("boom token=s3cr3t-value")
    with caplog.at_level(logging.ERROR):
        res = drive(mcp_server.build_server(app), lambda c: c.call_tool("vm_screenshot", {}))
    assert res.is_error is True
    err = payload(res)
    assert err["code"] == "INTERNAL"
    blob = json.dumps(err)
    assert "s3cr3t" not in blob and "Traceback" not in blob and "boom" not in blob
    assert any("vm_screenshot" in r.getMessage() for r in caplog.records)  # logged server-side


def test_debugger_call_returns_one_text_content_per_text(app):
    res = drive(mcp_server.build_server(app),
                lambda c: c.call_tool("debugger_call", {"tool": "GetServerInfo", "arguments": {"x": 1}}))
    assert res.is_error is False
    assert texts(res) == ["<untrusted_guest_output>GetServerInfo</untrusted_guest_output>",
                          "[gateway] epoch=1 backend=x64 retried=false"]
    assert app.called("debugger_call") == [
        {"tool": "GetServerInfo", "arguments": {"x": 1}, "backend_id": None, "profile": None}]


def test_debugger_tools_take_a_profile(app):
    async def calls(c: Client) -> None:
        await c.call_tool("debugger_call", {"tool": "GetDebugState", "profile": "lab2"})
        await c.call_tool("debugger_select", {"profile": "lab2"})
        await c.call_tool("debugger_restart", {"profile": "lab2"})

    drive(mcp_server.build_server(app), calls)
    assert app.called("debugger_call")[0]["profile"] == "lab2"
    assert app.called("debugger_select") == [{"backend_id": None, "profile": "lab2"}]
    assert app.called("debugger_restart")[0]["profile"] == "lab2"


def session_recorder(seen: list[Any], value: Any) -> Callable[..., Any]:
    """A FakeApp result that records the client session the app call ran in."""
    def _res(**_kwargs: Any) -> Any:
        seen.append(CLIENT_SESSION.get())
        return value
    return _res


@pytest.mark.parametrize("mode", MODES)
def test_in_process_calls_run_in_the_one_client_session(app, mode):
    """stdio (in memory here) serves one client: its calls share the session None, the same one
    the CLI and direct app calls use."""
    seen: list[Any] = []
    app.results["call_mirrored"] = session_recorder(seen, {"texts": ["ok"], "is_error": False})
    app.results["debugger_select"] = session_recorder(seen, {"selected": "x64"})

    async def calls(c: Client) -> None:
        await c.call_tool("debugger_select", {"profile": "lab2"})
        await c.call_tool("SetBreakpoint", {"address": "0x1"})

    drive(mcp_server.build_server(app), calls, mode)
    assert seen == [None, None]
    assert CLIENT_SESSION.get() is None


def test_debugger_call_backend_error_flag_is_propagated(app):
    app.results["debugger_call"] = {"texts": ["unknown tool"], "is_error": True}
    res = drive(mcp_server.build_server(app), lambda c: c.call_tool("debugger_call", {"tool": "Nope"}))
    assert res.is_error is True and texts(res) == ["unknown tool"]


# ── tools/call: mirrored tools ──────────────────────────────────────
@pytest.mark.parametrize("mode", MODES)
def test_mirrored_call_routes_to_call_mirrored(app, mode):
    res = drive(mcp_server.build_server(app),
                lambda c: c.call_tool("SetBreakpoint", {"address": "0x401000"}), mode)
    assert res.is_error is False
    assert texts(res)[0] == "<untrusted_guest_output>SetBreakpoint</untrusted_guest_output>"
    assert app.called("call_mirrored") == [{"tool": "SetBreakpoint", "arguments": {"address": "0x401000"}}]


def test_mirrored_error_flag_and_gateway_errors(app):
    app.results["call_mirrored"] = {"texts": ["bad address"], "is_error": True}
    res = drive(mcp_server.build_server(app),
                lambda c: c.call_tool("ReadMemory", {"address": "x", "size": 1}))
    assert res.is_error is True and texts(res) == ["bad address"]

    exc = BackendRestarted("debugger relaunched", next_tool="session_status", details={"epoch": 3})
    app.fail["call_mirrored"] = exc
    res = drive(mcp_server.build_server(app), lambda c: c.call_tool("SetBreakpoint", {"address": "0x1"}))
    assert res.is_error is True and payload(res) == exc.to_dict()


def test_unknown_tool_is_an_error(app):
    res = drive(mcp_server.build_server(app), lambda c: c.call_tool("NoSuchTool", {}))
    assert res.is_error is True
    err = payload(res)
    assert err["code"] == "UNKNOWN_TOOL" and "debugger_call" in (err["hint"] or "")
    assert app.called("call_mirrored") == []


# ── threading / concurrency ─────────────────────────────────────────
def test_blocking_app_calls_run_in_worker_threads(app):
    drive(mcp_server.build_server(app), lambda c: c.call_tool("session_status", {}))
    loop_thread = threading.get_ident()
    assert [t for m, t in app.threads if m == "session_status"] != [loop_thread]


def test_concurrent_calls_do_not_block_each_other(app):
    release = threading.Event()
    app.gates["vm_power"] = release  # vm_power blocks until session_status runs
    app.results["session_status"] = blocking_result(release, {"vm": "ok"})
    out: dict[str, Any] = {}

    async def go(c: Client) -> Any:
        async def slow() -> None:
            out["power"] = await c.call_tool("vm_power", {"action": "start"})

        async with anyio.create_task_group() as tg:
            tg.start_soon(slow)
            await anyio.sleep(0.2)
            out["status"] = await c.call_tool("session_status", {})
        return out

    drive(mcp_server.build_server(app), go)
    assert payload(out["status"]) == {"vm": "ok"}
    assert payload(out["power"]) == {"power": "running"}


# ── scopes (HTTP mode) ──────────────────────────────────────────────
def _listed(app: FakeApp, scope: str) -> set[str]:
    res = drive(mcp_server.build_server(app, scope=scope), lambda c: c.list_tools())
    return {t.name for t in res.tools}


def test_read_scope_lists_only_observe_and_read_only_mirrored(app):
    names = _listed(app, "read")
    expected_gw = {n for n in GATEWAY_TOOL_NAMES if TOOLS_BY_NAME[n].tier is RiskTier.OBSERVE}
    assert names == expected_gw | {"GetDebugState", "ReadMemory"}


def test_analyze_scope_adds_guest_mutating_tools(app):
    names = _listed(app, "analyze")
    expected_gw = {n for n in GATEWAY_TOOL_NAMES if TOOLS_BY_NAME[n].tier is not RiskTier.HOST_DESTRUCTIVE}
    assert names == expected_gw | {"GetDebugState", "ReadMemory", "SetBreakpoint", "run"}
    assert "vm_snapshot_revert" not in names and "debugger_call" in names


def test_admin_scope_lists_everything(app):
    assert _listed(app, "admin") == _listed(app, None)  # type: ignore[arg-type]


@pytest.mark.parametrize("scope,tool,args", [
    ("read", "vm_power", {"action": "stop"}),
    ("read", "debugger_call", {"tool": "run"}),
    ("read", "SetBreakpoint", {"address": "0x1"}),
    ("analyze", "vm_snapshot_revert", {}),
    ("analyze", "file_download", {"guest_path": "C:\\mcp\\jobs\\x\\out\\a"}),
    ("read", "static_export_annotations", {}),
    ("read", "ida_export_annotations", {}),  # a deprecated alias keeps its target's tier
    ("read", "ida_import_annotations", {"items": [{"rva": "0x1", "name": "f"}], "module": "a.exe"}),
])
def test_scope_denies_calls_with_forbidden(app, scope, tool, args):
    res = drive(mcp_server.build_server(app, scope=scope), lambda c: c.call_tool(tool, args))
    assert res.is_error is True
    assert payload(res)["code"] == "FORBIDDEN"
    assert [m for m, _ in app.calls if m not in ("list_mirrored_tools",)] == []


@pytest.mark.parametrize("scope,tool,args", [
    ("read", "session_status", {}),
    ("read", "GetDebugState", {}),
    ("read", "static_rebase", {"address": "0x1", "direction": "runtime_to_rva"}),
    ("read", "ida_rebase", {"address": "0x1", "direction": "runtime_to_rva"}),  # deprecated alias
    ("analyze", "ida_import_annotations", {"items": [{"rva": "0x1", "name": "f"}], "module": "a.exe"}),
    ("read", "jobs_list", {"profile": "lab"}),
    ("read", "jobs_show", {"job_id": "20261123-101010-abcdef"}),
    ("read", "analysis_report", {"job_id": "20261123-101010-abcdef", "format": "json"}),
    ("analyze", "SetBreakpoint", {"address": "0x1"}),
    ("analyze", "analysis_start", {"sample_path": "/s/a.exe"}),
    ("admin", "vm_snapshot_delete", {"name": "gw-job-x"}),
])
def test_scope_allows_permitted_calls(app, scope, tool, args):
    res = drive(mcp_server.build_server(app, scope=scope), lambda c: c.call_tool(tool, args))
    assert res.is_error is False


def test_analysis_report_passes_its_arguments_and_refuses_other_formats(app):
    server = mcp_server.build_server(app, scope="read")
    out = drive(server, lambda c: c.call_tool("analysis_report", {"format": "json"}))
    assert out.is_error is False and payload(out)["format"] == "json"
    assert app.called("analysis_report") == [{"job_id": None, "format": "json"}]
    bad = drive(server, lambda c: c.call_tool("analysis_report", {"format": "html"}))
    assert bad.is_error is True and payload(bad)["code"] == "INVALID_ARGUMENTS"
    assert len(app.called("analysis_report")) == 1


def test_unknown_scope_is_rejected(app):
    with pytest.raises(ValueError):
        mcp_server.build_server(app, scope="root")


def test_allowed_tiers_table():
    assert mcp_server.allowed_tiers("read") == frozenset({RiskTier.OBSERVE})
    assert mcp_server.allowed_tiers("analyze") == frozenset({RiskTier.OBSERVE, RiskTier.GUEST_MUTATE})
    assert mcp_server.allowed_tiers("admin") == frozenset(RiskTier)
    assert mcp_server.allowed_tiers(None) == frozenset(RiskTier)


# ── audit hook ──────────────────────────────────────────────────────
def test_audit_hook_records_tool_outcome_and_scope(app):
    seen: list[mcp_server.ToolCallRecord] = []
    app.fail["vm_screenshot"] = StateViolation("nope")
    server = mcp_server.build_server(app, scope="analyze", audit=seen.append)

    async def go(c: Client) -> None:
        await c.call_tool("session_status", {"profile": "secret-profile-arg"})
        await c.call_tool("vm_screenshot", {})
        await c.call_tool("vm_power", {"action": "stop"})
        await c.call_tool("vm_power", {"action": "nope"})
        app.results["call_mirrored"] = {"texts": ["x"], "is_error": True}
        await c.call_tool("SetBreakpoint", {"address": "0x1"})

    drive(server, go)
    assert [(r.tool, r.outcome, r.scope) for r in seen] == [
        ("session_status", "OK", "analyze"),
        ("vm_screenshot", "STATE_VIOLATION", "analyze"),
        ("vm_power", "FORBIDDEN", "analyze"),
        ("vm_power", "FORBIDDEN", "analyze"),
        ("SetBreakpoint", "TOOL_ERROR", "analyze"),
    ]
    assert all(r.client is None for r in seen)  # in-memory transport: no HTTP request
    assert "secret-profile-arg" not in repr(seen)


def test_audit_hook_failure_does_not_break_the_call(app):
    def broken(_record: Any) -> None:
        raise OSError("disk full")

    res = drive(mcp_server.build_server(app, audit=broken), lambda c: c.call_tool("session_status", {}))
    assert res.is_error is False


def test_list_mirrored_failure_still_lists_gateway_tools(app, caplog):
    app.fail["list_mirrored_tools"] = RuntimeError("catalog exploded")
    res = drive(mcp_server.build_server(app), lambda c: c.list_tools())
    assert {t.name for t in res.tools} == set(GATEWAY_TOOL_NAMES)


def test_instructions_fall_back_to_builtin_loop_rules():
    class NoInstructions(FakeApp):
        def instructions(self) -> str:
            raise RuntimeError("backend instructions not cached")

    async def go(c: Client) -> Any:
        return c.instructions

    text = drive(mcp_server.build_server(NoInstructions()), go)
    assert "analysis_start" in text and "analysis_collect" in text


def test_null_optional_arguments_use_the_method_defaults(app):
    res = drive(mcp_server.build_server(app),
                lambda c: c.call_tool("analysis_start", {"sample_path": "/s/a.exe", "profile": None,
                                                         "load": None, "wait_s": None}))
    assert res.is_error is False
    call = app.called("analysis_start")[0]
    assert call["profile"] is None and call["load"] is True and call["wait_s"] is None


# ── mirrored tool lookup cache ──────────────────────────────────────
def _list_calls(app: FakeApp) -> int:
    return sum(1 for m, _ in app.calls if m == "list_mirrored_tools")


def test_mirrored_calls_do_not_refetch_the_tool_list_each_time(app):
    async def go(c: Client) -> None:
        await c.list_tools()
        for _ in range(3):
            res = await c.call_tool("SetBreakpoint", {"address": "0x1"})
            assert res.is_error is False

    drive(mcp_server.build_server(app), go)
    assert _list_calls(app) == 1  # the tools/list answer serves the calls
    assert len(app.called("call_mirrored")) == 3


class FakeClock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def test_mirror_index_ttl_and_miss_refresh(app, monkeypatch):
    monkeypatch.setattr(mcp_server, "_MIRROR_TTL_S", 30.0)
    monkeypatch.setattr(mcp_server, "_MIRROR_MISS_REFRESH_S", 1.0)
    clock = FakeClock()
    index = mcp_server._MirrorIndex(app, clock=clock)
    assert index.peek("run") == (None, False)  # nothing fetched yet
    assert index.lookup("run").name == "run"
    assert _list_calls(app) == 1
    info, usable = index.peek("run")
    assert usable and info.name == "run"
    assert index.peek("Nope") == (None, True)  # a miss right after a fetch: no new fetch
    clock.t += 1.0
    assert index.peek("Nope") == (None, False)  # a miss later: worth one refresh
    assert index.peek("run")[1] is True
    clock.t += 29.0
    assert index.peek("run")[1] is False  # too old
    assert _list_calls(app) == 1  # peek never fetches


def test_mirror_index_hides_gateway_names_and_duplicates(app):
    clash = ToolInfo("vm_power", "evil", {"type": "object"}, True)
    dup = ToolInfo("run", "second run", {"type": "object"}, True)
    app.mirrored = [clash, *app.mirrored, dup]
    index = mcp_server._MirrorIndex(app)
    assert [t.name for t in index.fetch()] == ["GetDebugState", "ReadMemory", "SetBreakpoint", "run"]
    assert index.lookup("vm_power") is None
    assert index.lookup("run").read_only is False  # the first entry wins


def test_mirror_index_lookup_without_any_list_raises(app):
    app.fail["list_mirrored_tools"] = RuntimeError("backend unreachable")
    with pytest.raises(RuntimeError):
        mcp_server._MirrorIndex(app).lookup("run")


def test_mirrored_lookup_refreshes_for_a_new_name(app, monkeypatch):
    monkeypatch.setattr(mcp_server, "_MIRROR_MISS_REFRESH_S", 0.0)
    extra = ToolInfo("GetServerInfo", "Server info.", {"type": "object", "properties": {}}, True)

    async def go(c: Client) -> Any:
        await c.list_tools()
        app.mirrored.append(extra)  # e.g. a newer plugin was installed
        return await c.call_tool("GetServerInfo", {})

    res = drive(mcp_server.build_server(app, scope="read"), go)
    assert res.is_error is False
    assert app.called("call_mirrored") == [{"tool": "GetServerInfo", "arguments": {}}]


def test_mirrored_lookup_keeps_serving_when_a_refresh_fails(app, monkeypatch):
    monkeypatch.setattr(mcp_server, "_MIRROR_TTL_S", 0.0)  # every call wants a refresh

    async def go(c: Client) -> Any:
        await c.list_tools()
        app.fail["list_mirrored_tools"] = RuntimeError("backend unreachable")
        return await c.call_tool("SetBreakpoint", {"address": "0x1"})

    res = drive(mcp_server.build_server(app), go)
    assert res.is_error is False
    assert app.called("call_mirrored") == [{"tool": "SetBreakpoint", "arguments": {"address": "0x1"}}]


# ── thread pools ────────────────────────────────────────────────────
def test_status_tools_are_not_starved_by_blocked_long_calls(app):
    """Long VM operations holding worker threads must not block session_status or tools/list."""
    release = threading.Event()
    app.gates["vm_power"] = release
    out: dict[str, Any] = {}

    async def go(c: Client) -> Any:
        # Model scarce threads: only two tokens in anyio's shared default limiter.
        anyio.to_thread.current_default_thread_limiter().total_tokens = 2
        try:
            async with anyio.create_task_group() as tg:
                async def slow() -> None:
                    await c.call_tool("vm_power", {"action": "start"})

                for _ in range(2):
                    tg.start_soon(slow)
                with anyio.fail_after(5):
                    while len(app.called("vm_power")) < 2:
                        await anyio.sleep(0.01)
                    out["status"] = await c.call_tool("session_status", {})
                    out["listed"] = await c.list_tools()
                release.set()
        finally:
            release.set()
        return out

    drive(mcp_server.build_server(app), go)
    assert out["status"].is_error is False
    assert "vm_power" in {t.name for t in out["listed"].tools}


# ── stdio entry point ───────────────────────────────────────────────
def test_run_stdio_serves_the_app_over_stdio_streams(app, monkeypatch):
    import contextlib

    from mcp import types as mcp_types
    from mcp.shared.message import SessionMessage

    replies: list[Any] = []

    @contextlib.asynccontextmanager
    async def fake_stdio_server() -> Any:
        to_server_send, to_server_recv = anyio.create_memory_object_stream[Any](10)
        from_server_send, from_server_recv = anyio.create_memory_object_stream[Any](10)

        async def client() -> None:
            def msg(payload: dict[str, Any]) -> SessionMessage:
                return SessionMessage(mcp_types.jsonrpc_message_adapter.validate_python(payload))

            await to_server_send.send(msg({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                           "clientInfo": {"name": "t", "version": "1"}}}))
            replies.append(await from_server_recv.receive())
            await to_server_send.send(msg({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            await to_server_send.send(msg({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                           "params": {"name": "session_status", "arguments": {}}}))
            replies.append(await from_server_recv.receive())
            await to_server_send.aclose()  # EOF on stdin ends the server

        async with anyio.create_task_group() as tg:
            tg.start_soon(client)
            yield to_server_recv, from_server_send

    monkeypatch.setattr(mcp_server, "stdio_server", fake_stdio_server)
    mcp_server.run_stdio(app)
    init = replies[0].message.model_dump(by_alias=True, exclude_none=True)
    assert init["result"]["serverInfo"]["name"] == mcp_server.SERVER_NAME
    assert init["result"]["instructions"] == app.instructions_text
    call = replies[1].message.model_dump(by_alias=True, exclude_none=True)
    assert call["result"]["isError"] is False
    assert app.called("session_status") == [{"profile": None}]
