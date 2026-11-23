"""Tests for ida/x64dbg_sync.py, run with plain Python (no IDA).

From host/:  uv run pytest ../ida/tests -q

Pure helpers are called directly; the IDA-facing functions run against the
stub modules of the ``fake_ida`` fixture (conftest.py).
"""

from __future__ import annotations

import json
import os
import random
import subprocess
import sys
import unicodedata
from pathlib import Path

import pytest
import x64dbg_sync as xs
from conftest import IDA_DIR, FakeFunc, FakeIdaState

IDA_NAME_CHARSET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_$?@")


def make_doc(items: list[dict], module: str = "sample.exe", **extra: object) -> dict:
    doc = {
        "schema": "x64dbg-ida-sync/1",
        "generated_by": "test",
        "modules": {module: {"base_runtime": "0x7FF6A1230000", "items": items}},
    }
    doc.update(extra)
    return doc


def dumps(doc: object) -> bytes:
    return json.dumps(doc).encode("utf-8")


# ── import hygiene ──────────────────────────────────────────────────
def test_module_imports_without_ida() -> None:
    code = (
        "import sys; sys.path.insert(0, sys.argv[1]); import x64dbg_sync; "
        "print(sorted(m for m in sys.modules if m.startswith('ida')))"
    )
    env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}
    out = subprocess.run(  # noqa: S603 - fixed interpreter and code
        [sys.executable, "-I", "-c", code, str(IDA_DIR)],
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
        check=True,
    )
    assert out.stdout.strip() == "[]"


def test_action_labels() -> None:
    assert xs.LABEL_IMPORT == "Import x64dbg annotations (x64dbg-ida-sync JSON)"
    assert xs.LABEL_EXPORT == "Export IDA names/comments for x64dbg (x64dbg-ida-sync JSON)"
    assert xs.SCHEMA == "x64dbg-ida-sync/1"


# ── parse_hex ───────────────────────────────────────────────────────
@pytest.mark.parametrize(("raw", "value"), [("0x10", 16), ("0X1f", 31), (5, 5), ("ff", 255)])
def test_parse_hex_ok(raw: object, value: int) -> None:
    assert xs.parse_hex(raw) == value


@pytest.mark.parametrize("raw", [True, -1, 2**64, "", "0x", "zz", None, 1.5, "1" * 80])
def test_parse_hex_bad(raw: object) -> None:
    with pytest.raises(ValueError):
        xs.parse_hex(raw)


# ── load_sync_document ──────────────────────────────────────────────
class TestLoadDocument:
    def test_normalises_items(self) -> None:
        doc = xs.load_sync_document(
            dumps(
                make_doc(
                    [
                        {
                            "rva": "0x1000",
                            "name": "decrypt_config",
                            "breakpoint": {"type": "normal", "enabled": True},
                        },
                        {"rva": "0x1010", "comment": "decrypts\nconfig", "bookmark": True},
                        {
                            "rva": "0x1500",
                            "name": "c2 loop",
                            "breakpoint": {"type": "hardware", "enabled": False, "condition": "rcx==1"},
                        },
                    ]
                )
            )
        )
        mod = doc["modules"]["sample.exe"]
        assert mod["base_runtime"] == 0x7FF6A1230000
        a, b, c = mod["items"]
        assert a == {
            "rva": 0x1000,
            "name": "decrypt_config",
            "comment": None,
            "bookmark": False,
            "breakpoint": {"type": "normal", "enabled": True, "condition": None},
        }
        assert (b["comment"], b["bookmark"], b["name"]) == ("decrypts config", True, None)
        assert c["name"] == "c2_loop"
        assert c["breakpoint"]["condition"] == "rcx==1"
        assert doc["skipped"] == 0

    def test_accepts_str_and_bom(self) -> None:
        text = "﻿" + json.dumps(make_doc([{"rva": "0x1", "name": "a"}]))
        assert xs.load_sync_document(text)["modules"]["sample.exe"]["items"][0]["rva"] == 1
        assert xs.load_sync_document(text.encode("utf-8"))["modules"]["sample.exe"]["items"][0]["rva"] == 1

    def test_module_keys_are_lowercased(self) -> None:
        doc = xs.load_sync_document(dumps(make_doc([{"rva": "0x1", "name": "a"}], module="Sample.EXE")))
        assert list(doc["modules"]) == ["sample.exe"]

    def test_invalid_items_are_skipped(self) -> None:
        doc = xs.load_sync_document(
            dumps(
                make_doc(
                    [
                        {"rva": "zz", "name": "bad"},
                        {"name": "no rva"},
                        "string",
                        {"rva": "0x10"},  # nothing to apply
                        {"rva": "0x20", "name": 5, "comment": "kept"},  # bad name dropped, comment kept
                        {
                            "rva": "0x30",
                            "breakpoint": {"type": "dll", "enabled": True},
                        },  # not address-bound -> nothing left
                        {"rva": "0x40", "bookmark": "yes", "name": "ok"},
                    ]
                )
            )
        )
        items = doc["modules"]["sample.exe"]["items"]
        assert [(i["rva"], i["name"], i["comment"], i["bookmark"]) for i in items] == [
            (0x20, None, "kept", False),
            (0x40, "ok", None, False),
        ]
        assert doc["skipped"] == 5

    @pytest.mark.parametrize(
        ("payload", "match"),
        [
            (b"", "empty"),
            (b"\x00\x10\x00\x00binary", "JSON"),
            (b"[1]", "object"),
            (dumps({"schema": "x64dbg-ida-sync/2", "modules": {}}), "version"),
            (dumps({"schema": "something-else", "modules": {}}), "schema"),
            (dumps({"modules": {}}), "schema"),
            (dumps({"schema": "x64dbg-ida-sync/1", "modules": []}), "modules"),
            (b'{"a": ' + b"[" * 100_000 + b"]" * 100_000 + b"}", "JSON"),
        ],
    )
    def test_rejects(self, payload: bytes, match: str) -> None:
        with pytest.raises(ValueError, match=match):
            xs.load_sync_document(payload)

    def test_size_cap(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(xs, "MAX_DOC_BYTES", 50)
        with pytest.raises(ValueError, match="too large"):
            xs.load_sync_document(dumps(make_doc([{"rva": "0x1", "name": "a"}])))

    def test_item_cap(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(xs, "MAX_ITEMS", 3)
        doc = xs.load_sync_document(dumps(make_doc([{"rva": hex(i), "name": f"n{i}"} for i in range(10)])))
        assert len(doc["modules"]["sample.exe"]["items"]) == 3
        assert any("truncated" in w for w in doc["warnings"])

    def test_bad_module_entry_is_skipped_with_warning(self) -> None:
        raw = make_doc([{"rva": "0x1", "name": "a"}])
        raw["modules"]["other.dll"] = "nope"
        raw["modules"]["third.dll"] = {"base_runtime": None, "items": "not a list"}
        doc = xs.load_sync_document(dumps(raw))
        assert list(doc["modules"]) == ["sample.exe"]
        assert len(doc["warnings"]) == 2


# ── match_module ────────────────────────────────────────────────────
@pytest.mark.parametrize(
    ("names", "root", "expected"),
    [
        (["sample.exe", "helper.dll"], "sample.exe", "sample.exe"),
        (["sample.exe"], "SAMPLE.EXE", "sample.exe"),
        (["sample.exe"], "sample", "sample.exe"),  # IDB of an input without extension
        (["sample.exe"], "sample.bin", "sample.exe"),  # renamed sample, same stem
        (["sample.exe", "sample.dll"], "sample.bin", None),  # ambiguous stem
        (["helper.dll"], "sample.exe", None),
        ([], "sample.exe", None),
        (["sample.exe"], "", None),
    ],
)
def test_match_module(names: list[str], root: str, expected: str | None) -> None:
    assert xs.match_module(names, root) == expected


# ── sanitisers ──────────────────────────────────────────────────────
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("decrypt_config", "decrypt_config"),
        ("c2 beacon loop", "c2_beacon_loop"),
        ("std::vector<int>::push_back", "std_vector_int_push_back"),
        ("?Func@@YAXXZ", "?Func@@YAXXZ"),
        ("$dispatch", "$dispatch"),
        ("1stage", "_1stage"),
        ("sub_401000", "_sub_401000"),  # dummy-looking names are refused by IDA
        ("loc_140001000", "_loc_140001000"),
        ("sub_main", "sub_main"),  # not followed by hex -> not a dummy name
        ("ｍａｌｗａｒｅ", "malware"),
        ("evil‮gnp", "evil_gnp"),
    ],
)
def test_sanitize_ida_name(raw: str, expected: str) -> None:
    assert xs.sanitize_ida_name(raw) == expected


@pytest.mark.parametrize("raw", ["", "  ", "日本語", "\x00", "__"])
def test_sanitize_ida_name_never_empty(raw: str) -> None:
    assert xs.sanitize_ida_name(raw) == "x64dbg_name"
    assert xs.sanitize_ida_name(raw, fallback="x64dbg_1000") == "x64dbg_1000"


def test_sanitize_ida_name_property() -> None:
    rng = random.Random(3)  # noqa: S311 - deterministic test data
    for _ in range(400):
        s = "".join(chr(rng.randrange(0, 0x30000)) for _ in range(rng.randint(0, 900)))
        out = xs.sanitize_ida_name(s)
        assert out and set(out) <= IDA_NAME_CHARSET
        assert len(out) <= xs.IDA_NAME_MAX
        assert not out[0].isdigit()


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("plain", "plain"),
        ("a\x00b\x1b[31mc", "ab[31mc"),
        ("multi\nline\r\ntext", "multi line text"),
        ("bidi‮⁦x", "bidix"),
        ("악성 코드", "악성 코드"),
        ("   ", ""),
    ],
)
def test_sanitize_ida_comment(raw: str, expected: str) -> None:
    assert xs.sanitize_ida_comment(raw) == expected


def test_sanitize_ida_comment_property() -> None:
    rng = random.Random(5)  # noqa: S311 - deterministic test data
    for _ in range(400):
        s = "".join(chr(rng.randrange(0, 0x110000)) for _ in range(rng.randint(0, 3000)))
        out = xs.sanitize_ida_comment(s)
        assert len(out) <= xs.IDA_COMMENT_MAX
        assert all(unicodedata.category(ch) not in {"Cc", "Cf", "Cs", "Zl", "Zp"} for ch in out)


# ── import planning ─────────────────────────────────────────────────
def test_build_import_plan_rebases_and_tags() -> None:
    doc = xs.load_sync_document(
        dumps(
            make_doc(
                [
                    {
                        "rva": "0x1000",
                        "name": "decrypt_config",
                        "breakpoint": {"type": "normal", "enabled": True},
                    },
                    {"rva": "0x1010", "comment": "decrypts config", "bookmark": True},
                    {
                        "rva": "0x1500",
                        "breakpoint": {"type": "hardware", "enabled": False, "condition": "rcx==1"},
                    },
                ]
            )
        )
    )
    plan = xs.build_import_plan(doc, "sample.exe", 0x140000000)
    assert [p["ea"] for p in plan] == [0x140001000, 0x140001010, 0x140001500]
    assert plan[0]["name"] == "decrypt_config"
    assert plan[0]["comment"] == "[x64dbg: normal bp, enabled]"
    assert plan[1]["comment"] == "decrypts config [x64dbg: bookmark]"
    assert plan[2] == {
        "ea": 0x140001500,
        "rva": 0x1500,
        "name": None,
        "comment": "[x64dbg: hardware bp, disabled, condition rcx==1]",
    }


def test_build_import_plan_uses_any_imagebase() -> None:
    doc = xs.load_sync_document(dumps(make_doc([{"rva": "0x10", "name": "a"}])))
    assert xs.build_import_plan(doc, "sample.exe", 0x400000)[0]["ea"] == 0x400010
    with pytest.raises(ValueError, match="module"):
        xs.build_import_plan(doc, "other.dll", 0x400000)


def test_build_import_plan_skips_overflow() -> None:
    doc = xs.load_sync_document(
        dumps(make_doc([{"rva": "0x20000", "name": "a"}, {"rva": "0x10", "name": "b"}]))
    )
    plan = xs.build_import_plan(doc, "sample.exe", 2**64 - 0x10000)
    assert [p["name"] for p in plan] == ["b"]


@pytest.mark.parametrize(
    ("existing", "new", "expected"),
    [
        (None, "x", "x"),
        ("", "x", "x"),
        ("x", "x", None),
        ("old note x", "x", None),
        ("old", "new", "old\nnew"),
        ("old", "", None),
    ],
)
def test_merge_comment(existing: str | None, new: str, expected: str | None) -> None:
    assert xs.merge_comment(existing, new) == expected


def test_name_flags_uses_available_constants() -> None:
    class Mod:
        SN_NOWARN = 0x100
        SN_FORCE = 0x800

    assert xs.name_flags(Mod) == 0x900


# ── export document ─────────────────────────────────────────────────
def test_build_export_document() -> None:
    doc = xs.build_export_document(
        "Sample.exe",
        0x140000000,
        [
            (0x140001500, "c2_loop", None),
            (0x140001000, "decrypt_config", "decrypts\x00 config"),
            (0x140001000, None, "second"),
            (0x13FFFF000, "below", None),
            (0x140002000, None, None),
        ],
    )
    assert doc["schema"] == xs.SCHEMA
    mod = doc["modules"]["sample.exe"]
    assert mod["ida_imagebase"] == "0x140000000"
    assert mod["base_runtime"] is None
    assert mod["items"] == [
        {"rva": "0x1000", "name": "decrypt_config", "comment": "decrypts config | second"},
        {"rva": "0x1500", "name": "c2_loop"},
    ]
    assert doc["skipped"]["below_imagebase"] == 1
    again = xs.load_sync_document(json.dumps(doc))
    assert [i["rva"] for i in again["modules"]["sample.exe"]["items"]] == [0x1000, 0x1500]


def test_build_export_document_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(xs, "MAX_ITEMS", 2)
    doc = xs.build_export_document("a.exe", 0x400000, [(0x400000 + i, f"n{i}", None) for i in range(5)])
    assert len(doc["modules"]["a.exe"]["items"]) == 2
    assert doc["warnings"]


def test_format_import_report() -> None:
    text = xs.format_import_report(
        {
            "module": "sample.exe",
            "imagebase": "0x140000000",
            "items": 3,
            "renamed": 2,
            "rename_failed": 0,
            "commented": 1,
            "comment_unchanged": 0,
            "comment_failed": 0,
            "unmapped": 1,
            "skipped_invalid": 0,
        }
    )
    assert "sample.exe" in text and "renamed 2" in text and "unmapped 1" in text


# ── IDA-facing code against stub modules ────────────────────────────
class TestWithFakeIda:
    def write_doc(self, tmp_path: Path, doc: dict) -> str:
        p = tmp_path / "sync.json"
        p.write_bytes(dumps(doc))
        return str(p)

    def test_import_applies_names_and_comments(self, fake_ida: FakeIdaState, tmp_path: Path) -> None:
        fake_ida.comments[(0x140001010, False)] = "existing note"
        fake_ida.fail_set_name.add(0x140001020)
        path = self.write_doc(
            tmp_path,
            make_doc(
                [
                    {"rva": "0x1000", "name": "decrypt_config"},
                    {"rva": "0x1010", "comment": "decrypts config", "bookmark": True},
                    {"rva": "0x1020", "name": "will_fail"},
                    {"rva": "0x9000", "name": "unmapped"},
                ]
            ),
        )
        counts = xs.import_from_file(path)
        assert fake_ida.names[0x140001000] == "decrypt_config"
        assert fake_ida.comments[(0x140001010, False)] == "existing note\ndecrypts config [x64dbg: bookmark]"
        flags = fake_ida.set_name_calls[0][2]
        assert flags & 0x100 and flags & 0x800  # SN_NOWARN | SN_FORCE
        assert counts["renamed"] == 1
        assert counts["rename_failed"] == 1
        assert counts["commented"] == 1
        assert counts["unmapped"] == 1
        assert counts["module"] == "sample.exe"
        # importing twice does not duplicate the comment
        counts2 = xs.import_from_file(path)
        assert counts2["comment_unchanged"] == 1
        assert fake_ida.comments[(0x140001010, False)].count("decrypts config") == 1

    def test_import_matches_module_by_root_filename(self, fake_ida: FakeIdaState, tmp_path: Path) -> None:
        raw = make_doc([{"rva": "0x1000", "name": "in_sample"}])
        raw["modules"]["helper.dll"] = {
            "base_runtime": None,
            "items": [{"rva": "0x1000", "name": "in_helper"}],
        }
        fake_ida.root_filename = "HELPER.DLL"
        xs.import_from_file(self.write_doc(tmp_path, raw))
        assert fake_ida.names[0x140001000] == "in_helper"

    def test_import_without_match(self, fake_ida: FakeIdaState, tmp_path: Path) -> None:
        fake_ida.root_filename = "unrelated.exe"
        path = self.write_doc(tmp_path, make_doc([{"rva": "0x1000", "name": "x"}]))
        with pytest.raises(ValueError, match="unrelated.exe"):
            xs.import_from_file(path, interactive=False)
        fake_ida.ask_str_result = "Sample.exe"
        assert xs.import_from_file(path, interactive=True)["renamed"] == 1
        fake_ida.ask_str_result = None
        with pytest.raises(ValueError):
            xs.import_from_file(path, interactive=True)

    def test_import_explicit_module(self, fake_ida: FakeIdaState, tmp_path: Path) -> None:
        fake_ida.root_filename = "unrelated.exe"
        path = self.write_doc(tmp_path, make_doc([{"rva": "0x1000", "name": "x"}]))
        assert xs.import_from_file(path, module="SAMPLE.EXE", interactive=False)["renamed"] == 1

    def test_import_file_size_cap(
        self, fake_ida: FakeIdaState, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = self.write_doc(tmp_path, make_doc([{"rva": "0x1000", "name": "x"}]))
        monkeypatch.setattr(xs, "MAX_DOC_BYTES", 20)
        with pytest.raises(ValueError, match="too large"):
            xs.import_from_file(path)

    def test_collect_and_export(self, fake_ida: FakeIdaState, tmp_path: Path) -> None:
        fake_ida.names.update(
            {0x140001000: "decrypt_config", 0x140008010: "__imp_CreateFileW"}
        )  # 2nd is XTRN
        fake_ida.heads = [0x140001000, 0x140001010, 0x140008010]
        fake_ida.comments[(0x140001010, False)] = "regular"
        fake_ida.comments[(0x140001010, True)] = "repeatable"
        fake_ida.comments[(0x140008010, False)] = "extern comment"
        fake_ida.funcs = [FakeFunc(0x140001000, 0x140001100, cmt="function comment")]
        entries = xs.collect_ida_annotations()
        assert entries == [
            (0x140001000, "decrypt_config", "function comment"),
            (0x140001010, None, "regular | repeatable"),
        ]
        out = tmp_path / "export.json"
        fake_ida.ask_file_result = str(out)
        result = xs.run_export_action()
        assert result is not None and result["items"] == 2
        doc = json.loads(out.read_text(encoding="utf-8"))
        assert doc["schema"] == xs.SCHEMA
        assert doc["modules"]["sample.exe"]["items"][0] == {
            "rva": "0x1000",
            "name": "decrypt_config",
            "comment": "function comment",
        }
        assert fake_ida.infos

    def test_run_import_action(self, fake_ida: FakeIdaState, tmp_path: Path) -> None:
        assert xs.run_import_action() is None  # dialog cancelled
        fake_ida.ask_file_result = self.write_doc(tmp_path, make_doc([{"rva": "0x1000", "name": "x"}]))
        counts = xs.run_import_action()
        assert counts is not None and counts["renamed"] == 1
        assert "renamed 1" in fake_ida.infos[-1]
        bad = tmp_path / "bad.json"
        bad.write_bytes(b"not json")
        fake_ida.ask_file_result = str(bad)
        assert xs.run_import_action() is None
        assert fake_ida.warnings and "import failed" in fake_ida.warnings[-1]

    def test_register_and_unregister_actions(self, fake_ida: FakeIdaState) -> None:
        assert xs.register_actions() is True
        assert set(fake_ida.registered) == {xs.ACTION_IMPORT, xs.ACTION_EXPORT}
        assert fake_ida.registered[xs.ACTION_IMPORT].label == xs.LABEL_IMPORT
        assert {name for _, name, _ in fake_ida.attached} == {xs.ACTION_IMPORT, xs.ACTION_EXPORT}
        # running the script twice re-registers instead of failing
        assert xs.register_actions() is True
        handler = fake_ida.registered[xs.ACTION_IMPORT].handler
        assert handler.update(None) == 0
        assert handler.activate(None) == 1  # ask_file returns None -> cancelled, still handled
        xs.unregister_actions()
        assert fake_ida.registered == {}

    def test_plugin_entry(self, fake_ida: FakeIdaState) -> None:
        plugin = xs.PLUGIN_ENTRY()
        assert plugin.wanted_name == "x64dbg sync"
        assert plugin.init() == 2  # PLUGIN_KEEP
        assert xs.ACTION_EXPORT in fake_ida.registered
        fake_ida.ask_buttons_result = -1
        plugin.run(0)
        plugin.term()
        assert fake_ida.registered == {}


# ── cross-check with the gateway library ────────────────────────────
def test_gateway_export_is_accepted_by_the_script() -> None:
    ida_sync = pytest.importorskip("x64dbg_vm_gateway.ida_sync")
    db = {
        "labels": [{"module": "sample.exe", "address": "0x1000", "manual": True, "text": "decrypt config"}],
        "comments": [{"module": "sample.exe", "address": "0x1010", "manual": True, "text": "xor loop"}],
        "bookmarks": [{"module": "sample.exe", "address": "0x1010", "manual": True}],
        "breakpoints": [{"module": "sample.exe", "address": "0x1000", "enabled": True, "type": 0}],
    }
    exported = ida_sync.export_for_ida(ida_sync.parse_x64dbg_db(dumps(db)))
    doc = xs.load_sync_document(json.dumps(exported))
    plan = xs.build_import_plan(doc, "sample.exe", 0x140000000)
    assert [(p["ea"], p["name"]) for p in plan] == [(0x140001000, "decrypt_config"), (0x140001010, None)]


def test_script_export_is_accepted_by_the_gateway() -> None:
    ida_sync = pytest.importorskip("x64dbg_vm_gateway.ida_sync")
    exported = xs.build_export_document(
        "sample.exe", 0x140000000, [(0x140001000, "decrypt_config", "from IDA")]
    )
    items = exported["modules"]["sample.exe"]["items"]
    mm = {"sample.exe": ida_sync.ModuleInfo("sample.exe", 0x7FF6A1230000, 0x2A000)}
    plan = ida_sync.plan_import(items, module="sample.exe", module_map=mm)
    assert plan == [
        {
            "runtime_address": "0x7FF6A1231000",
            "rva": "0x1000",
            "label": "decrypt_config",
            "comment": "from IDA",
        }
    ]
