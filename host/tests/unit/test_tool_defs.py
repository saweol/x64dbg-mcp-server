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
    "static_rebase", "static_export_annotations", "static_import_annotations", "jobs_list", "jobs_show",
}
#: tools whose GatewayApp method has another name
METHODS = {"gateway_doctor": "doctor", "jobs_list": "list_jobs", "jobs_show": "get_job"}


def test_exactly_the_gateway_tools_are_defined():
    names = [t.name for t in GATEWAY_TOOLS]
    assert len(names) == len(set(names))
    assert set(names) == EXPECTED
    assert set(TOOLS_BY_NAME) == EXPECTED
    assert tool_defs.GATEWAY_TOOL_NAMES == frozenset(EXPECTED)


@pytest.mark.parametrize("hidden", ["discard_job", "close", "call_mirrored", "list_mirrored_tools",
                                    "instructions", "static_servers"])
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
    for name in EXPECTED:
        assert TOOLS_BY_NAME[name].method == METHODS.get(name, name)


def test_job_views_are_read_only_tools():
    # a second process cannot open the job store a serving gateway holds: its clients read
    # the jobs through these tools (J-integ review)
    for name in ("jobs_list", "jobs_show"):
        tool = TOOLS_BY_NAME[name]
        assert tool.tier is RiskTier.OBSERVE and tool.annotations["readOnlyHint"] is True
    assert TOOLS_BY_NAME["jobs_show"].input_schema["required"] == ["job_id"]


@pytest.mark.parametrize("tool", GATEWAY_TOOLS, ids=lambda t: t.name)
def test_tier_matches_policy_or_local_table(tool):
    if tool.name in policy.GATEWAY_TOOL_TIERS:
        assert tool.tier is policy.tier_of(tool.name)
    else:
        assert tool.tier is tool_defs.LOCAL_TIERS[tool.name]
    assert tool_defs.tool_tier(tool.name) is tool.tier


def test_static_tiers():
    assert TOOLS_BY_NAME["static_rebase"].tier is RiskTier.OBSERVE
    assert TOOLS_BY_NAME["static_export_annotations"].tier is RiskTier.GUEST_MUTATE
    assert TOOLS_BY_NAME["static_import_annotations"].tier is RiskTier.GUEST_MUTATE


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
    for name in ("vm_snapshot_delete", "debugger_select", "static_import_annotations"):
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
    ("static_rebase", {"address": 1.5, "direction": "runtime_to_static"}, "address"),
    ("static_rebase", {"address": "0x1000", "direction": "sideways"}, "direction"),
    ("static_rebase", {"address": "0x1000", "direction": "runtime_to_rva", "imagebase": 1.5}, "imagebase"),
    ("debugger_call", {"tool": "run", "arguments": [1]}, "arguments"),
    ("static_import_annotations", {"items": [1], "module": "a.exe"}, "items"),
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


def test_static_rebase_accepts_int_and_string_addresses():
    for addr in (0x401000, "0x401000"):
        kw = tool_defs.check_arguments(TOOLS_BY_NAME["static_rebase"],
                                       {"address": addr, "direction": "static_to_runtime"})
        assert kw["address"] == addr


# ── static tools follow ida_sync's item shape (J-integ) ─────────────
IMPORT = "static_import_annotations"


def _import_args(*items: object) -> dict:
    return {"items": list(items), "module": "sample.exe", "imagebase": "0x140000000"}


@pytest.mark.parametrize("item", [
    {"rva": "0x1000", "name": "decrypt"},
    {"rva": 4096, "comment": "x"},
    {"ida_address": "0x140001000", "name": "decrypt", "comment": "c"},
    # items of an x64dbg-ida-sync/1 export document are accepted as they are
    {"rva": "0x1010", "comment": "c", "bookmark": True, "breakpoint": {"type": "normal", "enabled": True}},
])
def test_import_items_accept_ida_sync_items(item):
    kw = tool_defs.check_arguments(TOOLS_BY_NAME[IMPORT], _import_args(item))
    assert kw["items"] == [item]


@pytest.mark.parametrize(("item", "fragment"), [
    ({"address": "0x401000", "name": "f"}, "items/0"),  # the old, never-implemented shape
    ({"name": "f"}, "items/0"),
    ({"rva": 1.5, "name": "f"}, "items/0/rva"),
    ({"rva": "0x10", "name": 5}, "items/0/name"),
])
def test_import_items_reject_other_shapes(item, fragment):
    with pytest.raises(tool_defs.InvalidArguments) as ei:
        tool_defs.check_arguments(TOOLS_BY_NAME[IMPORT], _import_args(item))
    assert any(e["path"].startswith(fragment) for e in ei.value.details["errors"])


def test_static_tool_descriptions_name_the_real_mechanics():
    imp = TOOLS_BY_NAME[IMPORT]
    item = imp.input_schema["properties"]["items"]["items"]
    assert {"rva", "ida_address", "name", "comment"} <= set(item["properties"])
    assert "CommentOrLabelAtAddress" in imp.description and "ida_address" in imp.description
    exp = TOOLS_BY_NAME["static_export_annotations"].description
    assert "static_sync.json" in exp and "SaveDatabase" in exp and "x64dbg-ida-sync/1" in exp
    reb = TOOLS_BY_NAME["static_rebase"].description
    assert "ListModules" in reb and "imagebase" in reb


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
    ("static_import_annotations", {"items": [{"rva": float("inf")}], "module": "a.exe"}, "items/0/rva"),
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


# ── tool-neutral static side (IDA, Ghidra, radare2/rizin, Cutter) ───
STATIC = ("static_rebase", "static_export_annotations", "static_import_annotations")
OLD = {"ida_rebase": "static_rebase", "ida_export_annotations": "static_export_annotations",
       "ida_import_annotations": "static_import_annotations"}


@pytest.mark.parametrize("name", STATIC)
def test_static_tool_descriptions_are_tool_neutral(name):
    d = TOOLS_BY_NAME[name].description
    for tool in ("IDA", "Ghidra", "radare2/rizin", "Cutter"):
        assert tool in d, (name, tool)
    assert "image base + RVA" in d
    assert tool_defs.STATIC_TOOL_NAMES == frozenset(STATIC)


@pytest.mark.parametrize("name", ["static_rebase", "static_import_annotations"])
def test_imagebase_replaces_ida_imagebase_which_stays_a_deprecated_alias(name):
    props = TOOLS_BY_NAME[name].input_schema["properties"]
    assert "imagebase" in props
    assert "deprecated" in props["ida_imagebase"]["description"].lower()
    assert "imagebase" in props["ida_imagebase"]["description"]


def test_rebase_offers_neutral_directions_and_keeps_the_old_ones():
    enum = TOOLS_BY_NAME["static_rebase"].input_schema["properties"]["direction"]["enum"]
    assert enum[:4] == ["runtime_to_static", "static_to_runtime", "runtime_to_rva", "rva_to_runtime"]
    assert set(enum[4:]) == {"runtime_to_ida", "ida_to_runtime"}


def test_old_ida_names_are_hidden_aliases():
    assert dict(tool_defs.DEPRECATED_ALIASES) == OLD
    for old, new in OLD.items():
        assert old not in TOOLS_BY_NAME and old not in tool_defs.GATEWAY_TOOL_NAMES
        alias = tool_defs.CALLABLE_TOOLS[old]
        target = TOOLS_BY_NAME[new]
        assert alias.name == old and alias.alias_of == new
        assert alias.method == target.method and alias.input_schema == target.input_schema
        assert alias.tier is target.tier and tool_defs.tool_tier(old) is target.tier
        assert alias.annotations["readOnlyHint"] == target.annotations["readOnlyHint"]
        assert target.alias_of is None
    assert set(tool_defs.CALLABLE_TOOLS) == set(TOOLS_BY_NAME) | set(OLD)
    assert tool_defs.RESERVED_TOOL_NAMES == frozenset(tool_defs.CALLABLE_TOOLS)


def test_aliases_validate_like_their_targets_and_accept_the_old_arguments():
    old_args = {"address": "0x1", "direction": "runtime_to_ida", "ida_imagebase": 0x400000}
    kw = tool_defs.check_arguments(tool_defs.CALLABLE_TOOLS["ida_rebase"], old_args)
    assert kw == old_args
    with pytest.raises(tool_defs.InvalidArguments):
        tool_defs.check_arguments(tool_defs.CALLABLE_TOOLS["ida_import_annotations"], {"items": [1]})
