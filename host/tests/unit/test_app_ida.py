"""IDA integration (plan 6.4 interpretation D) wired into the Gateway, on the fake lab.

The fake debugger loads the sample at SAMPLE_BASE (0x400000, size 0x2000) next to
ntdll.dll; samples are built with the PE image base IMAGE_BASE (0x140000000).
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path, PureWindowsPath

import pytest

from tests.fakes.fake_plugin_server import ToolError
from tests.fakes.fake_runtime import EXE, GUEST_ROOT, NTDLL_BASE, SAMPLE_BASE, make_lab
from x64dbg_vm_gateway import ida_sync
from x64dbg_vm_gateway.contracts import JobState
from x64dbg_vm_gateway.errors import (
    BackendRestarted,
    DatabaseFormatError,
    InvalidArgument,
    StateViolation,
)

IMAGE_BASE = 0x140000000
POSIX = os.name == "posix"


@pytest.fixture
def lab(tmp_path):
    lab = make_lab(tmp_path)
    yield lab
    lab.close()


def start(lab, **kw):
    gw = lab.gateway()
    res = gw.analysis_start(str(lab.sample(image_base=IMAGE_BASE)), **kw)
    name = PureWindowsPath(res["sample"]["guest_path"]).name.lower()
    return gw, res, name


def x64dbg_db(module: str) -> bytes:
    """An uncompressed x64dbg database (JSON) with annotations in ``module`` and ntdll.dll."""
    return json.dumps({
        "labels": [{"module": module, "address": "0x1000", "manual": True, "text": "decrypt_config"},
                   {"module": "ntdll.dll", "address": "0x2000", "manual": True, "text": "nt_hook"}],
        "comments": [{"module": module, "address": "0x1010", "manual": True, "text": "xor loop"},
                     {"module": "", "address": "0x1F0000", "manual": True, "text": "heap"}],
        "bookmarks": [{"module": module, "address": "0x1010", "manual": True}],
        "breakpoints": [{"module": module, "address": "0x1500", "enabled": True, "type": 0,
                         "breakCondition": "rcx==1"}],
        "functions": [{"module": module, "start": "0x1000", "end": "0x10FF", "manual": True}],
    }, indent=1).encode()


# ── ida_rebase ──────────────────────────────────────────────────────
def test_rebase_uses_the_live_module_map(lab):
    gw, _, name = start(lab)
    out = gw.ida_rebase(f"{SAMPLE_BASE + 0x1234:#x}", direction="runtime_to_rva")
    assert out["module"].lower() == name and out["rva"] == "0x1234"
    assert out["module_map_source"] == "live"
    assert lab.servers["x64"].tool_calls("ListModules")


def test_runtime_to_ida_defaults_to_the_sample_pe_image_base(lab):
    gw, _, _ = start(lab)
    out = gw.ida_rebase(SAMPLE_BASE + 0x1234, direction="runtime_to_ida")
    assert out["ida"] == "0x140001234" and out["ida_imagebase"] == "0x140000000"
    rebased = gw.ida_rebase(SAMPLE_BASE + 0x1234, direction="runtime_to_ida", ida_imagebase="0x180000000")
    assert rebased["ida"] == "0x180001234"


def test_ida_to_runtime_defaults_to_the_sample_module(lab):
    gw, _, name = start(lab)
    out = gw.ida_rebase("0x140001500", direction="ida_to_runtime", ida_imagebase=IMAGE_BASE)
    assert out["runtime"] == f"0x{SAMPLE_BASE + 0x1500:X}" and out["module"].lower() == name
    with pytest.raises(InvalidArgument) as ei:  # no default image base for this direction
        gw.ida_rebase("0x140001500", direction="ida_to_runtime")
    assert "ida_imagebase" in ei.value.message


def test_rva_to_runtime_in_another_module(lab):
    gw, _, _ = start(lab)
    out = gw.ida_rebase("0x10", direction="rva_to_runtime", module="ntdll")
    assert out["runtime"] == f"0x{NTDLL_BASE + 0x10:X}"


@pytest.mark.parametrize(("kwargs", "fragment"), [
    ({"address": "0x10", "direction": "sideways"}, "direction"),
    ({"address": "0x9", "direction": "runtime_to_rva"}, "not inside any module"),
    ({"address": "zz", "direction": "runtime_to_rva"}, "hex"),
    ({"address": "0x10", "direction": "rva_to_runtime", "module": "nope.dll"}, "not found"),
])
def test_rebase_errors_are_invalid_arguments(lab, kwargs, fragment):
    gw, _, _ = start(lab)
    with pytest.raises(InvalidArgument) as ei:
        gw.ida_rebase(**kwargs)
    assert fragment in ei.value.message


def test_rebase_falls_back_to_the_collected_map_and_never_relaunches(lab):
    gw, res, name = start(lab)
    gw.analysis_collect()
    lab.kill_debugger("x64")
    out = gw.ida_rebase(SAMPLE_BASE + 0x20, direction="runtime_to_rva", job_id=res["job_id"])
    assert out["module_map_source"] == "manifest" and out["module"].lower() == name and out["rva"] == "0x20"
    assert lab.launches == []  # a rebase never revives a dead debugger
    gw.analysis_finish(revert=False)
    done = gw.ida_rebase(SAMPLE_BASE + 0x20, direction="runtime_to_rva", job_id=res["job_id"])
    assert done["module_map_source"] == "manifest"


def test_rebase_warns_when_a_live_job_falls_back_to_the_collected_map(lab):
    # the job still has its debug session, so the live map was expected: a busy or dead
    # debugger must not be hidden behind module_map_source alone (the collected map can be
    # stale after a reload / relaunch: ASLR)
    gw, res, _ = start(lab)
    gw.analysis_collect()
    lab.servers["x64"].on_tool("ListModules", ToolError("busy"))
    out = gw.ida_rebase(SAMPLE_BASE + 0x20, direction="runtime_to_rva")
    assert out["module_map_source"] == "manifest"
    (warning,) = out["warnings"]
    assert "ListModules" in warning and "analysis_collect" in warning and "stale" in warning


def test_export_reports_the_live_map_fallback_too(lab):
    gw, _, name = start(lab)
    lab.db_content = x64dbg_db(name)
    gw.analysis_collect()
    lab.servers["x64"].on_tool("ListModules", ToolError("busy"))
    out = gw.ida_export_annotations()
    assert out["module_map_source"] == "manifest"
    assert any("ListModules" in w and "stale" in w for w in out["warnings"])


def test_rebase_of_a_finished_job_has_no_fallback_warning(lab):
    # control: without a debug session the collected map is the expected source
    gw, res, _ = start(lab)
    gw.analysis_collect()
    gw.analysis_finish(revert=False)
    out = gw.ida_rebase(SAMPLE_BASE + 0x20, direction="runtime_to_rva", job_id=res["job_id"])
    assert out["module_map_source"] == "manifest" and out["warnings"] == []


def test_rebase_from_the_live_map_has_no_warnings(lab):
    gw, _, _ = start(lab)
    out = gw.ida_rebase(SAMPLE_BASE + 0x20, direction="runtime_to_rva")
    assert out["module_map_source"] == "live" and out["warnings"] == []


def test_rebase_without_any_module_map(lab):
    gw, _, _ = start(lab)
    lab.servers["x64"].on_tool("ListModules", ToolError("Tool requires an active debug session."))
    with pytest.raises(StateViolation) as ei:
        gw.ida_rebase("0x401000", direction="runtime_to_rva")
    assert "analysis_collect" in (ei.value.hint or "")


# ── ida_export_annotations ──────────────────────────────────────────
def test_export_saves_copies_parses_and_writes_the_sync_document(lab):
    gw, res, name = start(lab)
    lab.db_content = x64dbg_db(name)
    out = gw.ida_export_annotations()
    target = Path(lab.config.jobs_root) / res["job_id"] / "artifacts" / "ida_sync.json"
    assert out["host_path"] == str(target) and target.is_file()
    if POSIX:
        assert stat.S_IMODE(target.stat().st_mode) == 0o600
    doc = json.loads(target.read_text(encoding="utf-8"))
    assert doc["schema"] == ida_sync.SCHEMA
    mod = doc["modules"][name]
    assert mod["base_runtime"] == f"0x{SAMPLE_BASE:X}"
    by_rva = {it["rva"]: it for it in mod["items"]}
    assert by_rva["0x1000"]["name"] == "decrypt_config"
    assert by_rva["0x1010"]["comment"] == "xor loop" and by_rva["0x1010"]["bookmark"] is True
    assert by_rva["0x1500"]["breakpoint"]["condition"] == "rcx==1"
    assert doc["modules"]["ntdll.dll"]["items"][0]["name"] == "nt_hook"
    assert out["counts"] == {"labels": 2, "comments": 2, "bookmarks": 1, "breakpoints": 1, "functions": 1,
                             "skipped": 0}
    assert out["modules"] == 2 and out["items"] == 4 and out["module_map_source"] == "live"
    # v1.9 plugin: SaveDatabase without a path, the default database file was fetched
    assert lab.servers["x64"].tool_calls("SaveDatabase")[-1].arguments == {}
    db = out["database"]
    assert db["source"] == "saved"
    assert db["guest_path"].lower() == f"{EXE['x64'].rsplit(chr(92), 1)[0]}\\db\\{name}.dd64".lower()
    assert Path(db["host_path"]).read_bytes() == lab.db_content
    assert Path(db["host_path"]).is_relative_to(Path(lab.config.jobs_root) / res["job_id"])


def test_export_with_a_v110_plugin_saves_into_the_job_out_dir(tmp_path):
    lab = make_lab(tmp_path, plugin_version="1.10")
    try:
        gw, res, name = start(lab)
        lab.db_content = x64dbg_db(name)
        out = gw.ida_export_annotations()
        sha12 = res["sample"]["sha256"][:12]
        expected = f"{GUEST_ROOT}\\{res['job_id']}\\out\\{sha12}.dd64"
        assert lab.servers["x64"].tool_calls("SaveDatabase")[-1].arguments == {"filePath": expected}
        assert out["database"]["guest_path"] == expected and out["items"] == 4
    finally:
        lab.close()


def test_compressed_database_is_refused_with_the_compression_hint(lab):
    gw, _, _ = start(lab)
    lab.db_content = b"\x04\x22\x4d\x18" + os.urandom(64)  # LZ4 frame magic
    with pytest.raises(DatabaseFormatError) as ei:
        gw.ida_export_annotations()
    err = ei.value
    assert err.code == "DATABASE_FORMAT"
    assert "DisableDatabaseCompression" in (err.hint or "") and "provision" in (err.hint or "")


def test_export_without_a_debug_session_uses_the_collected_database(lab):
    gw, res, name = start(lab)
    lab.db_content = x64dbg_db(name)
    gw.analysis_collect()
    gw.analysis_finish(revert=False)
    saves = len(lab.servers["x64"].tool_calls("SaveDatabase"))
    out = gw.ida_export_annotations(res["job_id"])
    assert out["database"]["source"] == "collected" and out["module_map_source"] == "manifest"
    assert len(lab.servers["x64"].tool_calls("SaveDatabase")) == saves
    assert out["items"] == 4


def test_export_without_any_database(lab):
    gw, res, _ = start(lab)
    gw.analysis_collect()  # the default b"x64dbg database" is collected, but is not JSON
    gw.analysis_finish(revert=False)
    with pytest.raises(DatabaseFormatError):
        gw.ida_export_annotations(res["job_id"])


# ── ida_import_annotations ──────────────────────────────────────────
ITEMS = [
    {"rva": "0x1000", "name": "decrypt_config", "comment": "found in IDA"},
    {"ida_address": "0x140001500", "name": "beacon"},
    {"rva": "0x1010", "bookmark": True},  # export-document item without name/comment: skipped
]


def test_import_applies_labels_and_comments_through_the_plugin(lab):
    gw, _, name = start(lab)
    out = gw.ida_import_annotations(ITEMS, module=name, ida_imagebase="0x140000000")
    assert out["applied"] == 3 and out["failed"] == 0 and out["not_attempted"] == 0
    assert out["operations"] == 3 and out["items"] == 2 and len(out["skipped"]) == 1
    calls = [c.arguments for c in lab.servers["x64"].tool_calls("CommentOrLabelAtAddress")]
    assert calls == [
        {"address": f"0x{SAMPLE_BASE + 0x1000:X}", "value": "decrypt_config", "mode": "Label"},
        {"address": f"0x{SAMPLE_BASE + 0x1000:X}", "value": "found in IDA", "mode": "Comment"},
        {"address": f"0x{SAMPLE_BASE + 0x1500:X}", "value": "beacon", "mode": "Label"},
    ]


def test_import_reports_failed_operations(lab):
    gw, _, name = start(lab)

    def apply(args):
        if args["mode"] == "Comment":
            raise ToolError("Failed to set comment")
        return "ok"

    lab.servers["x64"].on_tool("CommentOrLabelAtAddress", apply)
    out = gw.ida_import_annotations(ITEMS[:1], module=name)
    assert out["applied"] == 1 and out["failed"] == 1
    (failure,) = out["failures"]
    assert failure["mode"] == "Comment" and "Failed to set comment" in failure["error"]


def test_invalid_import_items_apply_nothing(lab):
    gw, _, name = start(lab)
    with pytest.raises(InvalidArgument) as ei:
        gw.ida_import_annotations([{"rva": "0x1000", "name": "ok"}, {"rva": "0x99999", "name": "out"}],
                                  module=name)
    assert "items[1]" in ei.value.message
    assert not lab.servers["x64"].tool_calls("CommentOrLabelAtAddress")


def test_import_after_an_unacknowledged_restart_is_refused(lab):
    gw, _, name = start(lab)
    gw.runtime().supervisor.bump_epoch("x64", "test: restart nobody acknowledged")
    with pytest.raises(BackendRestarted):
        gw.ida_import_annotations(ITEMS[:1], module=name)
    assert not lab.servers["x64"].tool_calls("CommentOrLabelAtAddress")


def test_import_needs_a_live_debug_session(lab):
    gw, res, name = start(lab)
    gw.analysis_collect()
    gw.analysis_finish(revert=False)
    with pytest.raises(StateViolation):
        gw.ida_import_annotations(ITEMS[:1], module=name, job_id=res["job_id"])


def test_import_checks_the_job_state_before_anything(lab):
    gw, res, name = start(lab)
    assert gw._jobs().get(res["job_id"]).state == JobState.ANALYZING
    with pytest.raises(InvalidArgument):
        gw.ida_import_annotations("not a list", module=name)  # type: ignore[arg-type]


def test_import_stopped_midway_reports_what_was_applied(lab):
    # the connection drops on the second operation: one applied, the run stops with the
    # proxy's error (RESULT_UNKNOWN: a mutating call is never retried) and says where
    gw, _, name = start(lab)
    srv = lab.servers["x64"]
    seen: list[dict] = []

    def apply(args):
        seen.append(args)
        if len(seen) == 1:
            srv.close_without_response("CommentOrLabelAtAddress", times=1)  # the next one drops
        return "ok"

    srv.on_tool("CommentOrLabelAtAddress", apply)
    out = gw.ida_import_annotations(ITEMS, module=name, ida_imagebase="0x140000000")
    assert out["operations"] == 3 and out["applied"] == 1 and out["failed"] == 0
    assert out["not_attempted"] == 2  # the dropped operation (outcome unknown) and the last one
    stopped = out["stopped"]
    assert stopped["code"] == "RESULT_UNKNOWN"
    assert stopped["operation"] == 2 and stopped["mode"] == "Comment"
    assert stopped["runtime_address"] == f"0x{SAMPLE_BASE + 0x1000:X}"
    assert len(seen) == 1  # the third operation was not sent


def test_import_lists_at_most_the_failure_cap(lab, monkeypatch):
    from x64dbg_vm_gateway import app as app_mod

    monkeypatch.setattr(app_mod, "MAX_IMPORT_FAILURES_LISTED", 2)
    gw, _, name = start(lab)
    lab.servers["x64"].on_tool("CommentOrLabelAtAddress", ToolError("Failed to set label"))
    items = [{"rva": f"0x{0x1000 + 0x10 * i:X}", "name": f"f{i}"} for i in range(5)]
    out = gw.ida_import_annotations(items, module=name)
    assert out["failed"] == 5 and out["applied"] == 0 and out["not_attempted"] == 0
    assert len(out["failures"]) == 2 and out["stopped"] is None


def test_export_refuses_a_database_over_the_size_limit(lab, monkeypatch):
    gw, res, name = start(lab)
    lab.db_content = x64dbg_db(name)
    gw.analysis_collect()
    gw.analysis_finish(revert=False)  # the collected copy is used: no guest-side size probe
    monkeypatch.setattr(ida_sync, "MAX_DB_BYTES", len(lab.db_content) - 1)
    with pytest.raises(DatabaseFormatError) as ei:
        gw.ida_export_annotations(res["job_id"])
    assert "larger than" in ei.value.message
    assert not (Path(lab.config.jobs_root) / res["job_id"] / "artifacts" / "ida_sync.json").exists()
