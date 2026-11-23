"""ToolCatalog: builtin list, per-backend live cache, schema sanitation, retry classes."""

from __future__ import annotations

import json
import threading

import pytest

from x64dbg_vm_gateway.catalog import ToolCatalog
from x64dbg_vm_gateway.contracts import ToolInfo


@pytest.fixture
def cat(tmp_path) -> ToolCatalog:
    return ToolCatalog(cache_dir=tmp_path / "cache")


def ti(name: str, ro: bool = False, schema: object | None = None, desc: str = "d") -> ToolInfo:
    return ToolInfo(name=name, description=desc,
                    input_schema={"type": "object", "properties": {}} if schema is None else schema,  # type: ignore[arg-type]
                    read_only=ro)


# ── builtin ─────────────────────────────────────────────────────────
def test_builtin_list_used_without_cache(cat):
    tools = cat.tools("x64")
    assert len(tools) == 80
    assert sum(t.read_only for t in tools) == 36
    assert all(isinstance(t, ToolInfo) for t in tools)
    assert all(t.input_schema["type"] == "object" for t in tools)


def test_default_cache_dir_is_under_home(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    c = ToolCatalog()
    assert c.cache_dir == tmp_path / ".cache" / "x64dbg-vm-gateway"
    assert not c.cache_dir.exists()  # nothing is written until a live update


def test_read_only_and_retryable(cat):
    assert cat.is_read_only("GetDebugState") is True
    assert cat.is_read_only("run") is False
    assert cat.is_read_only("NoSuchTool") is False  # unknown = mutating (conservative)
    assert cat.is_retryable("GetDebugState") is True
    assert cat.is_retryable("ReadMemory") is True
    assert cat.is_read_only("WaitForEvent") is True
    assert cat.is_retryable("WaitForEvent") is False  # drains the plugin event queue
    assert cat.is_retryable("run") is False
    assert cat.is_retryable("NoSuchTool") is False


def test_tool_lookup(cat):
    t = cat.tool("run")
    assert t is not None and t.input_schema["properties"]["timeoutMs"]["default"] == 300000
    assert cat.tool("NoSuchTool") is None


# ── live update / cache ─────────────────────────────────────────────
def test_update_from_live_writes_cache_and_reports_change(cat, tmp_path):
    live = [ti("GetDebugState", True), ti("NewTool", False)]
    assert cat.update_from_live("x64", "1.10", live) is True
    f = tmp_path / "cache" / "tools-x64-1.10.json"
    assert f.is_file()
    data = json.loads(f.read_text())
    assert data["backend_id"] == "x64" and data["server_version"] == "1.10"
    assert [t["name"] for t in data["tools"]] == ["GetDebugState", "NewTool"]
    # no temp files left behind (atomic write)
    assert sorted(p.name for p in (tmp_path / "cache").iterdir()) == ["tools-x64-1.10.json"]
    assert [t.name for t in cat.tools("x64")] == ["GetDebugState", "NewTool"]
    # other backends still see the builtin list
    assert len(cat.tools("x32")) == 80
    # same list again: unchanged
    assert cat.update_from_live("x64", "1.10", list(reversed(live))) is False


def test_update_identical_to_builtin_is_unchanged(cat):
    builtin = cat.tools("x64")
    assert cat.update_from_live("x64", "1.9", builtin) is False


def test_cache_survives_new_instance(tmp_path):
    a = ToolCatalog(cache_dir=tmp_path)
    a.update_from_live("x64", "1.10", [ti("Only", True)])
    b = ToolCatalog(cache_dir=tmp_path)
    assert [t.name for t in b.tools("x64")] == ["Only"]
    assert b.is_read_only("Only", backend_id="x64") is True
    assert len(b.tools("x32")) == 80


def test_newest_cache_version_wins(tmp_path):
    import os
    import time

    a = ToolCatalog(cache_dir=tmp_path)
    a.update_from_live("x64", "1.10", [ti("Old")])
    old = tmp_path / "tools-x64-1.10.json"
    past = time.time() - 100
    os.utime(old, (past, past))
    a.update_from_live("x64", "1.11", [ti("New")])
    b = ToolCatalog(cache_dir=tmp_path)
    assert [t.name for t in b.tools("x64")] == ["New"]


def test_cache_of_prefix_backend_not_confused(tmp_path):
    a = ToolCatalog(cache_dir=tmp_path)
    a.update_from_live("x64-lab", "1.9", [ti("Lab")])
    b = ToolCatalog(cache_dir=tmp_path)
    assert len(b.tools("x64")) == 80
    assert [t.name for t in b.tools("x64-lab")] == ["Lab"]


def test_corrupt_cache_falls_back_to_builtin(tmp_path):
    (tmp_path / "tools-x64-1.9.json").write_text("{broken")
    c = ToolCatalog(cache_dir=tmp_path)
    assert len(c.tools("x64")) == 80
    assert c.warnings  # recorded


def test_backend_id_cannot_escape_cache_dir(tmp_path):
    cache = tmp_path / "cache"
    c = ToolCatalog(cache_dir=cache)
    c.update_from_live("../../evil", "1.9/../../x", [ti("A")])
    written = [p for p in tmp_path.rglob("*") if p.is_file()]
    assert written and all(cache in p.parents for p in written)
    assert [t.name for t in ToolCatalog(cache_dir=cache).tools("../../evil")] == ["A"]


def test_live_read_only_overrides_builtin_for_backend(cat):
    cat.update_from_live("x64", "2.0", [ti("run", ro=True)])
    assert cat.is_read_only("run", backend_id="x64") is True
    assert cat.is_read_only("run", backend_id="x32") is False


# ── schema sanitation ───────────────────────────────────────────────
@pytest.mark.parametrize("bad", [
    None, [], "object", {"type": "array"}, {"properties": {}},
    {"type": "object", "properties": []}, {"type": "object", "required": "x"},
    {"type": "object", "required": [1]},
])
def test_invalid_schema_replaced_and_warned(cat, bad):
    cat.update_from_live("x64", "1.9", [ToolInfo("Bad", "d", bad, False)])  # type: ignore[arg-type]
    (t,) = cat.tools("x64")
    assert t.input_schema == {"type": "object"}
    assert any("Bad" in w for w in cat.warnings)


def test_valid_schema_kept(cat):
    schema = {"type": "object", "properties": {"a": {"type": "string"}}, "required": ["a"]}
    cat.update_from_live("x64", "1.9", [ToolInfo("Good", "d", schema, False)])
    assert cat.tools("x64")[0].input_schema == schema
    assert not cat.warnings


def test_schema_is_copied_not_aliased(cat):
    schema = {"type": "object", "properties": {}}
    cat.update_from_live("x64", "1.9", [ToolInfo("A", "d", schema, False)])
    schema["properties"]["injected"] = {"type": "string"}
    assert "injected" not in cat.tools("x64")[0].input_schema["properties"]


def test_duplicate_and_invalid_names_dropped(cat):
    cat.update_from_live("x64", "1.9", [ti("A"), ti("A"), ti("")])
    assert [t.name for t in cat.tools("x64")] == ["A"]
    assert cat.warnings


# ── instructions ────────────────────────────────────────────────────
def test_instructions_default_none_then_cached(tmp_path):
    c = ToolCatalog(cache_dir=tmp_path)
    assert c.instructions("x64") is None
    c.update_instructions("x64", "RULES 1..12")
    assert c.instructions("x64") == "RULES 1..12"
    assert c.instructions("x32") is None
    assert ToolCatalog(cache_dir=tmp_path).instructions("x64") == "RULES 1..12"


# ── concurrency ─────────────────────────────────────────────────────
def test_concurrent_updates_and_reads(cat):
    errs: list[BaseException] = []

    def writer(i: int) -> None:
        try:
            for j in range(20):
                cat.update_from_live("x64", "1.9", [ti(f"T{i}-{j}")])
        except BaseException as e:  # noqa: BLE001
            errs.append(e)

    def reader() -> None:
        try:
            for _ in range(200):
                assert cat.tools("x64")
                cat.is_read_only("GetDebugState")
        except BaseException as e:  # noqa: BLE001
            errs.append(e)

    ts = [threading.Thread(target=writer, args=(i,)) for i in range(4)] + [threading.Thread(target=reader)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert not errs
    assert len(cat.tools("x64")) == 1
