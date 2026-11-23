"""The shipped v1.10 tool catalog (data/tools-v1.10.json) matches the plugin source.

The catalog is extracted statically from the tool table in src/mcp/tools.zig. These tests
parse that table and its schema functions independently and check that the JSON file is
current: every tool's name, description, flags and input schema equal the source, in table
order, so editing tools.zig without regenerating the catalog fails here. They also pin the
tools new in v1.10 and check that every input schema is a well-formed object schema.
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

_ZIG_STR = r'"((?:[^"\\]|\\.)*)"'
# One table entry: .{ .name = "...", .description = "...", .debug_only = b, .read_only = b,
# .handler = fn, .schema_fn = fn, }
_ENTRY = re.compile(
    r"\.\{\s*\.name\s*=\s*" + _ZIG_STR + r",\s*"
    r"\.description\s*=\s*" + _ZIG_STR + r",\s*"
    r"\.debug_only\s*=\s*(true|false),\s*"
    r"\.read_only\s*=\s*(true|false),\s*"
    r"\.handler\s*=\s*\w+,\s*"
    r"\.schema_fn\s*=\s*(\w+),\s*\}"
)
# A schema function is a single raw JSON string: fn schemaX(w: *JsonWriter) void { w.raw("..."); }
_SCHEMA_FN = re.compile(r"fn (schema\w+)\(w: \*JsonWriter\) void \{\s*w\.raw\(" + _ZIG_STR + r"\);\s*\}")
_ZIG_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", "\\": "\\", "'": "'", '"': '"'}


def _zig_string(body: str) -> str:
    """Decode the body of a Zig string literal (the text between the quotes)."""
    out = bytearray()
    i = 0
    while i < len(body):
        c = body[i]
        if c != "\\":
            out += c.encode("utf-8")
            i += 1
            continue
        e = body[i + 1]
        if e in _ZIG_ESCAPES:
            out += _ZIG_ESCAPES[e].encode("utf-8")
            i += 2
        elif e == "x":
            out.append(int(body[i + 2 : i + 4], 16))
            i += 4
        elif e == "u":
            end = body.index("}", i)
            out += chr(int(body[i + 3 : end], 16)).encode("utf-8")
            i = end + 1
        else:  # pragma: no cover - would mean an invalid Zig literal
            raise AssertionError(f"unknown Zig escape \\{e}")
    return out.decode("utf-8")


def _catalog() -> dict:
    text = resources.files("x64dbg_vm_gateway").joinpath(CATALOG_REL).read_text(encoding="utf-8")
    return json.loads(text)


def _zig_tools() -> list[dict]:
    """Every entry of `pub const tools = [_]ToolDef{...}` in the catalog's tool format."""
    src = TOOLS_ZIG.read_text(encoding="utf-8")
    start = src.index("pub const tools = [_]ToolDef{")
    table = src[start:src.index("\n};", start)]
    entries = _ENTRY.findall(table)
    # Every `.name =` in the table must have been matched by the entry pattern.
    assert len(entries) == table.count(".name ="), "tool table layout changed; update _ENTRY"
    schemas = {m.group(1): m.group(2) for m in _SCHEMA_FN.finditer(src)}
    out: list[dict] = []
    for name, description, debug_only, read_only, schema_fn in entries:
        assert schema_fn in schemas, f"{schema_fn} is not a single w.raw(...) schema; update _SCHEMA_FN"
        out.append({
            "name": _zig_string(name),
            "description": _zig_string(description),
            "debug_only": debug_only == "true",
            "read_only": read_only == "true",
            "inputSchema": json.loads(_zig_string(schemas[schema_fn])),
        })
    names = [t["name"] for t in out]
    assert len(set(names)) == len(names), "duplicate tool name in tools.zig"
    return out


def _zig_table() -> dict[str, tuple[bool, bool]]:
    """name -> (debug_only, read_only) for every tool in tools.zig."""
    return {t["name"]: (t["debug_only"], t["read_only"]) for t in _zig_tools()}


@pytest.fixture(scope="module")
def catalog() -> dict:
    return _catalog()


def _require_source() -> None:
    if not TOOLS_ZIG.is_file():  # pragma: no cover - only outside a full checkout
        pytest.skip(f"plugin source not found at {TOOLS_ZIG}")


@pytest.fixture(scope="module")
def zig_tools() -> list[dict]:
    _require_source()
    return _zig_tools()


@pytest.fixture(scope="module")
def zig_table() -> dict[str, tuple[bool, bool]]:
    _require_source()
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


def test_catalog_is_current_with_the_plugin_source(catalog, zig_tools):
    # A description or schema edited in tools.zig without regenerating the catalog
    # (extract the table, then set plugin_version to 1.10) fails here.
    by_name = {t["name"]: t for t in catalog["tools"]}
    stale = [t["name"] for t in zig_tools if by_name.get(t["name"]) != t]
    assert stale == [], f"tools-v1.10.json is stale for: {stale}"
    assert [t["name"] for t in catalog["tools"]] == [t["name"] for t in zig_tools]


def test_zig_string_decoder_handles_the_escapes_zig_allows():
    assert _zig_string(r'a\"b\\c\nd\te\x41\u{e9}') == 'a"b\\c\nd\teA\u00e9'
    assert _zig_string("plain \u2014 text") == "plain \u2014 text"
