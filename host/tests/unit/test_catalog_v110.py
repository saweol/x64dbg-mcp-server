"""The shipped v1.10 tool catalog (data/tools-v1.10.json) matches the plugin source.

The catalog is extracted statically from the tool table in src/mcp/tools.zig. These tests
parse that table independently and check that the JSON file is current: same tool count,
the tools new in v1.10, their read_only flags and well-formed input schemas.
"""

from __future__ import annotations

import json
import re
from importlib import resources
from pathlib import Path

import pytest

from x64dbg_vm_gateway.catalog import ToolCatalog

CATALOG_REL = "data/tools-v1.10.json"
TOOLS_ZIG = Path(__file__).resolve().parents[3] / "src" / "mcp" / "tools.zig"

# One table entry: .{ .name = "...", .description = "...", .debug_only = b, .read_only = b, ...
_ENTRY = re.compile(
    r'\.\{\s*\.name\s*=\s*"((?:[^"\\]|\\.)*)",\s*'
    r'\.description\s*=\s*"(?:[^"\\]|\\.)*",\s*'
    r"\.debug_only\s*=\s*(true|false),\s*"
    r"\.read_only\s*=\s*(true|false),"
)


def _catalog() -> dict:
    text = resources.files("x64dbg_vm_gateway").joinpath(CATALOG_REL).read_text(encoding="utf-8")
    return json.loads(text)


def _zig_table() -> dict[str, tuple[bool, bool]]:
    """name -> (debug_only, read_only) for every entry of `pub const tools = [_]ToolDef{...}`."""
    src = TOOLS_ZIG.read_text(encoding="utf-8")
    start = src.index("pub const tools = [_]ToolDef{")
    table = src[start:src.index("\n};", start)]
    entries = _ENTRY.findall(table)
    # Every `.name =` in the table must have been matched by the entry pattern.
    assert len(entries) == table.count(".name ="), "tool table layout changed; update _ENTRY"
    out: dict[str, tuple[bool, bool]] = {}
    for name, debug_only, read_only in entries:
        assert name not in out, f"duplicate tool {name} in tools.zig"
        out[name] = (debug_only == "true", read_only == "true")
    return out


@pytest.fixture(scope="module")
def catalog() -> dict:
    return _catalog()


@pytest.fixture(scope="module")
def zig_table() -> dict[str, tuple[bool, bool]]:
    if not TOOLS_ZIG.is_file():  # pragma: no cover - only outside a full checkout
        pytest.skip(f"plugin source not found at {TOOLS_ZIG}")
    return _zig_table()


def test_catalog_is_valid_json_for_plugin_1_10(catalog):
    assert catalog["plugin_version"] == "1.10"
    assert isinstance(catalog["tools"], list) and catalog["tools"]
    for t in catalog["tools"]:
        assert isinstance(t["name"], str) and t["name"]
        assert isinstance(t["description"], str) and t["description"]
        assert isinstance(t["read_only"], bool)
        assert isinstance(t["debug_only"], bool)


def test_tool_count_matches_the_plugin_table(catalog, zig_table):
    assert len(catalog["tools"]) == len(zig_table)
    names = [t["name"] for t in catalog["tools"]]
    assert len(set(names)) == len(names)
    assert set(names) == set(zig_table)


@pytest.mark.parametrize("name", ["GetServerInfo", "SetArtifactDir"])
def test_v110_tools_present_with_table_flags(catalog, zig_table, name):
    by_name = {t["name"]: t for t in catalog["tools"]}
    assert name in by_name
    debug_only, read_only = zig_table[name]
    assert by_name[name]["read_only"] is read_only
    assert by_name[name]["debug_only"] is debug_only


def test_v110_tool_flags_are_what_the_gateway_relies_on(catalog):
    by_name = {t["name"]: t for t in catalog["tools"]}
    # GetServerInfo is the backend identity probe: read-only, usable without a session.
    assert by_name["GetServerInfo"]["read_only"] is True
    assert by_name["GetServerInfo"]["debug_only"] is False
    # SetArtifactDir changes server state.
    assert by_name["SetArtifactDir"]["read_only"] is False


def test_every_flag_matches_the_plugin_table(catalog, zig_table):
    mismatches = [
        t["name"] for t in catalog["tools"]
        if (t["debug_only"], t["read_only"]) != zig_table[t["name"]]
    ]
    assert mismatches == []


def test_every_input_schema_is_an_object_schema(catalog):
    for t in catalog["tools"]:
        schema = t["inputSchema"]
        assert isinstance(schema, dict), t["name"]
        assert schema.get("type") == "object", t["name"]
        props = schema.get("properties", {})
        assert isinstance(props, dict), t["name"]
        for req in schema.get("required", []):
            assert req in props, f"{t['name']}: required {req!r} is not a property"


def test_catalog_loads_through_tool_catalog_without_warnings(tmp_path, catalog):
    cat = ToolCatalog(builtin_json=CATALOG_REL, cache_dir=tmp_path / "cache")
    assert cat.warnings == []
    tools = cat.tools("x64")
    assert len(tools) == len(catalog["tools"])
    assert cat.is_read_only("GetServerInfo") is True
    assert cat.is_read_only("SetArtifactDir") is False


def test_hardware_breakpoint_schema_documents_valid_sizes(catalog):
    # The plugin rejects sizes x64dbg would silently replace with 1.
    by_name = {t["name"]: t for t in catalog["tools"]}
    size = by_name["SetHardwareBreakpoint"]["inputSchema"]["properties"]["size"]
    assert size["type"] == "integer"
    assert size.get("enum") == [1, 2, 4, 8]
