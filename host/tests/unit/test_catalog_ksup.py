"""A cached live list of another plugin build is not served once the plugin reported its
version (E5: the cache of the old v1.3 plugin hid the v1.10 tools)."""

from __future__ import annotations

import json
from importlib import resources

import pytest

from x64dbg_vm_gateway.catalog import ToolCatalog
from x64dbg_vm_gateway.contracts import ToolInfo

V19, V110 = "data/tools-v1.9.json", "data/tools-v1.10.json"
NEW_TOOLS = {"GetServerInfo", "SetArtifactDir", "ProbeFile"}


def builtin_tools(rel: str) -> list[ToolInfo]:
    data = json.loads(resources.files("x64dbg_vm_gateway").joinpath(rel).read_text(encoding="utf-8"))
    return [ToolInfo(t["name"], t["description"], t["inputSchema"], t["read_only"]) for t in data["tools"]]


def names(cat: ToolCatalog, backend: str = "x64") -> set[str]:
    return {t.name for t in cat.tools(backend)}


@pytest.fixture
def cache(tmp_path):
    path = tmp_path / "cache"
    ToolCatalog(V19, cache_dir=path).update_from_live("x64", "1.3", builtin_tools(V19))
    return path


def test_the_cached_list_serves_until_the_plugin_reports_a_version(cache):
    cat = ToolCatalog(V19, cache_dir=cache)
    assert cat.server_version("x64") == "1.3" and not NEW_TOOLS & names(cat)


def test_a_cached_list_of_another_build_is_ignored_after_the_plugin_reported(cache):
    cat = ToolCatalog(V19, cache_dir=cache)
    cat.set_server_version("x64", "1.10")
    assert NEW_TOOLS <= names(cat)
    assert len(cat.tools("x64")) == len(builtin_tools(V110))
    assert cat.server_version("x64") is None  # the builtin list is what serves now
    assert cat.is_read_only("GetServerInfo", "x64") is True
    assert cat.is_read_only("SetArtifactDir", "x64") is False


def test_a_cached_list_of_the_same_build_keeps_serving(tmp_path):
    path = tmp_path / "cache"
    live = builtin_tools(V110)[:-1]  # e.g. a list cached before the plugin's last tool existed
    ToolCatalog(V19, cache_dir=path).update_from_live("x64", "1.10", live)
    cat = ToolCatalog(V19, cache_dir=path)
    cat.set_server_version("x64", "v1.10.0")  # same build, other spelling
    assert len(cat.tools("x64")) == len(live) and cat.server_version("x64") == "1.10"


@pytest.mark.parametrize(("cached", "reported"), [("unknown", "1.10"), ("1.3", "1.10.0-dev")])
def test_an_unknown_version_on_either_side_keeps_the_cached_list(tmp_path, cached, reported):
    path = tmp_path / "cache"
    ToolCatalog(V19, cache_dir=path).update_from_live("x64", cached, builtin_tools(V19))
    cat = ToolCatalog(V19, cache_dir=path)
    cat.set_server_version("x64", reported)
    assert cat.server_version("x64") == cached and len(cat.tools("x64")) == len(builtin_tools(V19))


def test_a_fresh_live_list_serves_again(cache):
    cat = ToolCatalog(V19, cache_dir=cache)
    cat.set_server_version("x64", "1.10")
    cat.update_from_live("x64", "1.10", builtin_tools(V110))
    assert cat.server_version("x64") == "1.10" and NEW_TOOLS <= names(cat)


def test_an_id_less_lookup_ignores_a_stale_cached_list(tmp_path):
    """Review: ``tool(name)`` without a backend id must apply the same build filter as
    ``tools(backend_id)``: the stale v1.3 list must not answer lookups (or read-only
    flags) for the v1.10 plugin, whose own list does."""
    path = tmp_path / "cache"
    legacy = ToolInfo("LegacyOnlyTool", "only in the old plugin", {"type": "object", "properties": {}}, True)
    ToolCatalog(V19, cache_dir=path).update_from_live("x64", "1.3", [*builtin_tools(V19), legacy])
    cat = ToolCatalog(V19, cache_dir=path)
    assert cat.tool("LegacyOnlyTool", "x64") is not None  # control: served while nothing was reported
    assert cat.tool("LegacyOnlyTool") is not None
    cat.set_server_version("x64", "1.10")
    assert cat.tool("LegacyOnlyTool", "x64") is None
    assert cat.tool("LegacyOnlyTool") is None
    assert cat.tool("GetServerInfo") is not None  # the list the backend serves now
    assert cat.is_read_only("GetServerInfo") is True
