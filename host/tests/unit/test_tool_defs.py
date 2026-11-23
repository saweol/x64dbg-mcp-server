"""Gateway tool definitions (plan 5.6): names, schemas, tiers, MCP annotations."""

from __future__ import annotations

import inspect

import jsonschema
import pytest

from x64dbg_vm_gateway import policy
from x64dbg_vm_gateway.app_api import GatewayApp
from x64dbg_vm_gateway.errors import GatewayError
from x64dbg_vm_gateway.frontends import tool_defs
from x64dbg_vm_gateway.frontends.tool_defs import GATEWAY_TOOLS, TOOLS_BY_NAME, RiskTier

EXPECTED = {
    "session_status", "gateway_doctor", "vm_snapshots_list", "vm_snapshot_take", "vm_snapshot_revert",
    "vm_snapshot_delete", "vm_power", "vm_screenshot", "file_upload", "file_download", "debugger_select",
    "debugger_restart", "debugger_call", "analysis_start", "analysis_collect", "analysis_finish",
    "ida_rebase", "ida_export_annotations", "ida_import_annotations",
}


def test_exactly_the_gateway_tools_are_defined():
    names = [t.name for t in GATEWAY_TOOLS]
    assert len(names) == len(set(names))
    assert set(names) == EXPECTED
    assert set(TOOLS_BY_NAME) == EXPECTED
    assert tool_defs.GATEWAY_TOOL_NAMES == frozenset(EXPECTED)


@pytest.mark.parametrize("hidden", ["discard_job", "close", "call_mirrored", "list_mirrored_tools",
                                    "instructions"])
def test_human_only_and_internal_methods_are_not_tools(hidden):
    assert hidden not in TOOLS_BY_NAME
    assert all(t.method != hidden for t in GATEWAY_TOOLS)


@pytest.mark.parametrize("tool", GATEWAY_TOOLS, ids=lambda t: t.name)
def test_schema_is_valid_json_schema_object(tool):
    schema = tool.input_schema
    jsonschema.Draft202012Validator.check_schema(schema)
    assert schema["type"] == "object"
    assert schema.get("additionalProperties") is False
    for prop in schema.get("properties", {}).values():
        assert prop.get("description"), "every parameter needs a description for the LLM"


@pytest.mark.parametrize("tool", GATEWAY_TOOLS, ids=lambda t: t.name)
def test_schema_matches_the_gateway_app_method_signature(tool):
    method = getattr(GatewayApp, tool.method)
    params = {n: p for n, p in inspect.signature(method).parameters.items() if n != "self"}
    props = tool.input_schema.get("properties", {})
    assert set(props) == set(params), f"{tool.name}: schema {sorted(props)} vs method {sorted(params)}"
    required = {n for n, p in params.items() if p.default is inspect.Parameter.empty}
    assert set(tool.input_schema.get("required", [])) == required


def test_method_mapping():
    assert TOOLS_BY_NAME["gateway_doctor"].method == "doctor"
    for name in EXPECTED - {"gateway_doctor"}:
        assert TOOLS_BY_NAME[name].method == name


@pytest.mark.parametrize("tool", GATEWAY_TOOLS, ids=lambda t: t.name)
def test_tier_matches_policy_or_local_table(tool):
    if tool.name in policy.GATEWAY_TOOL_TIERS:
        assert tool.tier is policy.tier_of(tool.name)
    else:
        assert tool.tier is tool_defs.LOCAL_TIERS[tool.name]
    assert tool_defs.tool_tier(tool.name) is tool.tier


def test_ida_tiers():
    assert TOOLS_BY_NAME["ida_rebase"].tier is RiskTier.OBSERVE
    assert TOOLS_BY_NAME["ida_export_annotations"].tier is RiskTier.GUEST_MUTATE
    assert TOOLS_BY_NAME["ida_import_annotations"].tier is RiskTier.GUEST_MUTATE


def test_tool_tier_unknown_name_raises():
    with pytest.raises(KeyError):
        tool_defs.tool_tier("SetBreakpoint")


@pytest.mark.parametrize("tool", GATEWAY_TOOLS, ids=lambda t: t.name)
def test_annotations_follow_the_tier(tool):
    ann = tool.annotations
    assert ann["openWorldHint"] is False
    assert ann["readOnlyHint"] is (tool.tier is RiskTier.OBSERVE)
    if tool.tier is RiskTier.OBSERVE:
        assert "destructiveHint" not in ann or ann["destructiveHint"] is False
    else:
        # MCP defaults destructiveHint to true, so non-destructive tools must say false explicitly.
        assert ann["destructiveHint"] is (tool.tier is RiskTier.HOST_DESTRUCTIVE)
    assert isinstance(ann.get("title"), str) and ann["title"]


def test_idempotent_hints():
    for name in ("vm_snapshot_delete", "debugger_select", "ida_import_annotations"):
        assert TOOLS_BY_NAME[name].annotations["idempotentHint"] is True
    # vm_power includes "reset" and a second revert bumps the epoch and discards changes again:
    # repeating either has additional effects, so neither may claim idempotence.
    for name in ("vm_power", "vm_snapshot_revert", "vm_snapshot_take", "debugger_restart", "debugger_call",
                 "analysis_start", "file_upload"):
        assert TOOLS_BY_NAME[name].annotations.get("idempotentHint", False) is False


def test_session_status_says_its_acknowledgement_is_gateway_wide():
    d = TOOLS_BY_NAME["session_status"].description
    assert "gateway-wide" in d and "read-scope" in d


@pytest.mark.parametrize("tool", GATEWAY_TOOLS, ids=lambda t: t.name)
def test_descriptions_are_written_for_an_llm(tool):
    d = tool.description
    assert len(d) >= 120
    if tool.tier is RiskTier.OBSERVE:
        assert "Read-only" in d
    else:
        assert "Side effects:" in d


@pytest.mark.parametrize("name", ["vm_snapshot_revert", "vm_snapshot_delete", "vm_power", "analysis_finish"])
def test_irreversible_tools_say_so(name):
    assert "IRREVERSIBLE" in TOOLS_BY_NAME[name].description


def test_untrusted_output_is_flagged():
    for name in ("debugger_call", "file_download"):
        assert "untrusted" in TOOLS_BY_NAME[name].description.lower()


def test_texts_results_only_for_debugger_call():
    assert {t.name for t in GATEWAY_TOOLS if t.returns_texts} == {"debugger_call"}


# ── argument checking ───────────────────────────────────────────────
def test_check_arguments_returns_kwargs():
    kw = tool_defs.check_arguments(TOOLS_BY_NAME["vm_power"], {"action": "start", "wait_s": 5})
    assert kw == {"action": "start", "wait_s": 5}


def test_check_arguments_accepts_none_as_empty():
    assert tool_defs.check_arguments(TOOLS_BY_NAME["session_status"], None) == {}


@pytest.mark.parametrize("name,args,fragment", [
    ("vm_power", {}, "action"),
    ("vm_power", {"action": "explode"}, "explode"),
    ("vm_power", {"action": "start", "wait_s": -1}, "wait_s"),
    ("vm_power", {"action": "start", "bogus": 1}, "bogus"),
    ("vm_snapshot_take", {"name": 7}, "name"),
    ("analysis_start", {"sample_path": "/x", "load": "yes"}, "load"),
    ("analysis_collect", {"extra_guest_paths": "C:\\x"}, "extra_guest_paths"),
    ("ida_rebase", {"address": 1.5, "direction": "runtime_to_ida"}, "address"),
    ("ida_rebase", {"address": "0x1000", "direction": "sideways"}, "direction"),
    ("debugger_call", {"tool": "run", "arguments": [1]}, "arguments"),
    ("ida_import_annotations", {"items": [1], "module": "a.exe"}, "items"),
])
def test_check_arguments_rejects_bad_input(name, args, fragment):
    with pytest.raises(tool_defs.InvalidArguments) as ei:
        tool_defs.check_arguments(TOOLS_BY_NAME[name], args)
    err = ei.value
    assert isinstance(err, GatewayError)
    assert err.code == "INVALID_ARGUMENTS"
    assert fragment in err.message or any(fragment in str(e) for e in err.details["errors"])
    assert err.next_tool is None or isinstance(err.next_tool, str)


def test_check_arguments_rejects_booleans_for_numbers():
    with pytest.raises(tool_defs.InvalidArguments):
        tool_defs.check_arguments(TOOLS_BY_NAME["vm_power"], {"action": "start", "wait_s": True})


def test_ida_rebase_accepts_int_and_string_addresses():
    for addr in (0x401000, "0x401000"):
        kw = tool_defs.check_arguments(TOOLS_BY_NAME["ida_rebase"],
                                       {"address": addr, "direction": "ida_to_runtime"})
        assert kw["address"] == addr


def test_frontend_error_codes():
    assert tool_defs.InvalidArguments("x").code == "INVALID_ARGUMENTS"
    assert tool_defs.UnknownTool("x").code == "UNKNOWN_TOOL"
    assert tool_defs.Forbidden("x").code == "FORBIDDEN"
    assert tool_defs.InternalError("x").code == "INTERNAL"


# ── numbers: finite and bounded ─────────────────────────────────────
@pytest.mark.parametrize("wait_s", [float("inf"), float("-inf"), float("nan"), 1e18,
                                    tool_defs.MAX_WAIT_S + 1])
@pytest.mark.parametrize("name,base", [
    ("vm_power", {"action": "start"}),
    ("vm_snapshot_revert", {}),
    ("analysis_start", {"sample_path": "/s/a.exe"}),
    ("analysis_finish", {}),
])
def test_wait_s_must_be_finite_and_bounded(name, base, wait_s):
    with pytest.raises(tool_defs.InvalidArguments) as ei:
        tool_defs.check_arguments(TOOLS_BY_NAME[name], {**base, "wait_s": wait_s})
    assert any(e["path"] == "wait_s" for e in ei.value.details["errors"])


def test_wait_s_upper_bound_is_accepted():
    kw = tool_defs.check_arguments(TOOLS_BY_NAME["vm_power"],
                                   {"action": "start", "wait_s": tool_defs.MAX_WAIT_S})
    assert kw["wait_s"] == tool_defs.MAX_WAIT_S
    assert TOOLS_BY_NAME["vm_power"].input_schema["properties"]["wait_s"]["maximum"] == tool_defs.MAX_WAIT_S


@pytest.mark.parametrize("name,args,path", [
    ("debugger_call", {"tool": "run", "arguments": {"timeoutMs": float("nan")}}, "arguments/timeoutMs"),
    ("ida_import_annotations", {"items": [{"address": float("inf")}], "module": "a.exe"}, "items/0/address"),
])
def test_non_finite_numbers_are_rejected_anywhere(name, args, path):
    with pytest.raises(tool_defs.InvalidArguments) as ei:
        tool_defs.check_arguments(TOOLS_BY_NAME[name], args)
    assert any(e["path"] == path for e in ei.value.details["errors"])


# ── null for optional parameters ────────────────────────────────────
@pytest.mark.parametrize("name,args,expected", [
    ("session_status", {"profile": None}, {}),
    ("vm_snapshot_revert", {"name": None, "wait_s": 30}, {"wait_s": 30}),
    ("analysis_collect", {"job_id": None, "extra_guest_paths": None, "extract": None}, {}),
    ("debugger_call", {"tool": "GetServerInfo", "arguments": None, "backend_id": None},
     {"tool": "GetServerInfo"}),
    ("analysis_start", {"sample_path": "/s/a.exe", "args": None, "load": None}, {"sample_path": "/s/a.exe"}),
])
def test_null_optional_arguments_mean_omitted(name, args, expected):
    """JSON null for an optional parameter is treated as "omitted": the method default applies."""
    assert tool_defs.check_arguments(TOOLS_BY_NAME[name], args) == expected


@pytest.mark.parametrize("name,args", [
    ("vm_power", {"action": None}),
    ("vm_snapshot_take", {"name": None}),
    ("analysis_start", {"sample_path": None}),
])
def test_null_for_required_arguments_is_still_rejected(name, args):
    with pytest.raises(tool_defs.InvalidArguments):
        tool_defs.check_arguments(TOOLS_BY_NAME[name], args)


def test_analysis_start_accepts_an_empty_command_line():
    kw = tool_defs.check_arguments(TOOLS_BY_NAME["analysis_start"], {"sample_path": "/s/a.exe", "args": ""})
    assert kw["args"] == ""
