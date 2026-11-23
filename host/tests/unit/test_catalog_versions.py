"""Per-backend builtin catalog chosen by the live plugin version (J-integ).

Both builtin lists ship (tools-v1.9.json, tools-v1.10.json). A backend uses the
newest builtin whose version is <= its plugin's version (else the oldest), as soon
as the version is known from ``GET /`` or ``initialize``: a v1.10 plugin's
GetServerInfo / SetArtifactDir flags are then right on first contact.
"""

from __future__ import annotations

import json
from importlib import resources

import pytest

from tests.fakes.fake_runtime import make_lab
from x64dbg_vm_gateway.catalog import BUILTIN_CATALOGS, ToolCatalog, builtin_for_version
from x64dbg_vm_gateway.contracts import ToolInfo
from x64dbg_vm_gateway.wiring import builtin_catalog_for

V19, V110 = "data/tools-v1.9.json", "data/tools-v1.10.json"


def v110_live_tools() -> list[ToolInfo]:
    data = json.loads(resources.files("x64dbg_vm_gateway").joinpath(V110).read_text(encoding="utf-8"))
    return [ToolInfo(t["name"], t["description"], t["inputSchema"], t["read_only"]) for t in data["tools"]]


@pytest.fixture
def cat(tmp_path) -> ToolCatalog:
    return ToolCatalog(V19, cache_dir=tmp_path / "cache")


# ── version -> builtin ──────────────────────────────────────────────
def test_both_builtins_ship():
    assert set(BUILTIN_CATALOGS.values()) == {V19, V110}
    for rel in BUILTIN_CATALOGS.values():
        assert resources.files("x64dbg_vm_gateway").joinpath(rel).is_file()


@pytest.mark.parametrize(("version", "expected"), [
    (None, V19), ("", V19), ("garbage", V19), ("1.3", V19), ("1.9", V19), ("1.9.5", V19),
    ("1.10", V110), ("v1.10", V110), ("1.10.2", V110), ("1.11", V110), ("2.0", V110), ("0.9", V19),
])
def test_newest_builtin_not_newer_than_the_plugin_else_the_oldest(version, expected):
    assert builtin_for_version(version) == expected
    assert builtin_catalog_for(version) == expected  # wiring keeps its name for it


# ── per-backend choice ──────────────────────────────────────────────
def test_a_backend_uses_the_builtin_of_its_version(cat):
    assert cat.tool("GetServerInfo", "x64") is None and cat.builtin_version("x64") == "1.9"
    assert cat.set_server_version("x64", "1.10") is True
    assert cat.set_server_version("x64", "1.10") is False  # unchanged
    assert cat.builtin_version("x64") == "1.10"
    assert cat.is_read_only("GetServerInfo", "x64") is True
    assert cat.tool("SetArtifactDir", "x64") is not None and cat.is_read_only("SetArtifactDir", "x64") is False
    assert len(cat.tools("x64")) == 82
    # another backend keeps the default
    assert cat.tool("GetServerInfo", "x32") is None and len(cat.tools("x32")) == 80
    # a downgrade goes back
    assert cat.set_server_version("x64", "1.3") is True
    assert cat.tool("GetServerInfo", "x64") is None


def test_live_v110_list_on_a_v19_default_catalog_keeps_the_v110_read_only_flags(cat):
    cat.update_from_live("x64", "1.10", v110_live_tools())
    assert cat.is_read_only("GetServerInfo", "x64") is True
    assert not any("GetServerInfo" in w for w in cat.warnings)


def test_a_live_list_is_reclassified_when_the_version_becomes_known(cat):
    cat.update_from_live("x64", "unknown", v110_live_tools())
    assert cat.is_read_only("GetServerInfo", "x64") is False  # not in the oldest builtin: mutating
    cat.set_server_version("x64", "1.10")
    assert cat.is_read_only("GetServerInfo", "x64") is True


def test_cached_list_uses_the_builtin_of_its_cached_version(tmp_path):
    cache = tmp_path / "cache"
    ToolCatalog(V19, cache_dir=cache).update_from_live("x64", "1.10", v110_live_tools())
    fresh = ToolCatalog(V19, cache_dir=cache)
    assert fresh.is_read_only("GetServerInfo", "x64") is True
    assert fresh.builtin_version("x64") == "1.10" and fresh.builtin_version("x32") == "1.9"


def test_an_explicit_version_wins_over_the_cached_one(tmp_path):
    cache = tmp_path / "cache"
    ToolCatalog(V19, cache_dir=cache).update_from_live("x64", "1.10", v110_live_tools())
    fresh = ToolCatalog(V19, cache_dir=cache)
    fresh.set_server_version("x64", "1.3")  # the plugin was downgraded since the cache was written
    assert fresh.builtin_version("x64") == "1.9"
    assert fresh.is_read_only("GetServerInfo", "x64") is False


# ── the runtime learns the version on first contact ─────────────────
def test_first_contact_with_a_v110_plugin_uses_the_v110_flags(tmp_path):
    lab = make_lab(tmp_path, plugin_version="1.10")
    try:
        gw = lab.gateway()
        rt = gw.runtime()
        assert rt.catalog.builtin_version("x64") == "1.9"  # nothing known yet
        rt.supervisor.bump_epoch("x64", "test: unacknowledged restart")
        # read-only calls are never epoch-gated; with the v1.9 list GetServerInfo would be
        # "unknown, hence mutating" and refused with BACKEND_RESTARTED
        out = gw.debugger_call("GetServerInfo")
        assert out["is_error"] is False
        assert rt.catalog.builtin_version("x64") == "1.10"
        assert lab.servers["x64"].tool_calls("GetServerInfo")
    finally:
        lab.close()


def test_a_plugin_upgrade_seen_by_the_health_check_switches_the_builtin(tmp_path):
    lab = make_lab(tmp_path, plugin_version="1.9")
    try:
        gw = lab.gateway()
        rt = gw.runtime()
        gw.session_status()
        assert rt.catalog.builtin_version("x64") == "1.9"
        lab.servers["x64"].version = "1.10"  # GET / now reports the new build
        gw.session_status()
        assert rt.catalog.builtin_version("x64") == "1.10"
    finally:
        lab.close()
