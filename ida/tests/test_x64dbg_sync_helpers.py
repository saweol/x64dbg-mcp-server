"""Tests for ida/x64dbg_sync.py, run with plain Python (no IDA).

From host/:  uv run pytest ../ida/tests -q

Pure helpers are called directly; the IDA-facing functions run against the
stub ``idaapi`` / ``ida_*`` / ``idautils`` modules that the ``fake_ida``
fixture below installs into ``sys.modules`` (undone after each test). The
stubs record what the script does to the "database".

The script is loaded by path, so neither ``sys.path`` nor a conftest.py is
needed.
"""

from __future__ import annotations

import importlib.util
import json
import os
import random
import subprocess
import sys
import types
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

IDA_DIR = Path(__file__).resolve().parent.parent
IDA_SCRIPT = IDA_DIR / "x64dbg_sync.py"


def _load_script() -> types.ModuleType:
    """Load ida/x64dbg_sync.py by path (it imports no ida_* module at import time)."""
    spec = importlib.util.spec_from_file_location("x64dbg_sync", IDA_SCRIPT)
    assert spec is not None and spec.loader is not None, f"cannot load {IDA_SCRIPT}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


xs = _load_script()

IDA_NAME_CHARSET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_$?@")


# ── stub IDA modules ────────────────────────────────────────────────
SEG_NORM = 0
SEG_XTRN = 1


@dataclass
class FakeSegment:
    start_ea: int
    end_ea: int
    type: int = SEG_NORM


@dataclass
class FakeFunc:
    start_ea: int
    end_ea: int
    cmt: str | None = None
    rcmt: str | None = None


@dataclass
class FakeIdaState:
    imagebase: int = 0x140000000
    root_filename: str = "sample.exe"
    segments: list[FakeSegment] = field(default_factory=list)
    names: dict[int, str] = field(default_factory=dict)
    comments: dict[tuple[int, bool], str] = field(default_factory=dict)
    heads: list[int] = field(default_factory=list)
    funcs: list[FakeFunc] = field(default_factory=list)
    fail_set_name: set[int] = field(default_factory=set)
    fail_set_cmt: set[int] = field(default_factory=set)
    set_name_calls: list[tuple[int, str, int]] = field(default_factory=list)
    ask_file_result: str | None = None
    ask_str_result: str | None = None
    ask_buttons_result: int = -1
    infos: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    registered: dict[str, Any] = field(default_factory=dict)
    unregistered: list[str] = field(default_factory=list)
    attached: list[tuple[str, str, int]] = field(default_factory=list)
    wait_boxes_shown: int = 0
    wait_boxes_hidden: int = 0
    cancel_after: int | None = None  # user_cancelled() turns True on this call number (1-based)
    cancel_checks: int = 0

    def seg_at(self, ea: int) -> FakeSegment | None:
        for s in self.segments:
            if s.start_ea <= ea < s.end_ea:
                return s
        return None


def _build_modules(st: FakeIdaState) -> dict[str, types.ModuleType]:
    idaapi = types.ModuleType("idaapi")
    # init() return codes
    idaapi.PLUGIN_SKIP = 0
    idaapi.PLUGIN_OK = 1
    idaapi.PLUGIN_KEEP = 2
    # plugin_t.flags bits (a different namespace: 2 is PLUGIN_DRAW, not PLUGIN_KEEP)
    idaapi.PLUGIN_MOD = 0x1
    idaapi.PLUGIN_DRAW = 0x2
    idaapi.PLUGIN_FIX = 0x80

    class plugin_t:  # noqa: N801 - mirrors the IDA class name
        pass

    idaapi.plugin_t = plugin_t
    idaapi.get_imagebase = lambda: st.imagebase

    ida_name = types.ModuleType("ida_name")
    ida_name.SN_NOCHECK = 0x01
    ida_name.SN_NOWARN = 0x100
    ida_name.SN_FORCE = 0x800
    ida_name.SN_NODUMMY = 0x1000

    def set_name(ea: int, name: str, flags: int = 0) -> bool:
        st.set_name_calls.append((ea, name, flags))
        if ea in st.fail_set_name:
            return False
        st.names[ea] = name
        return True

    ida_name.set_name = set_name
    ida_name.get_name = lambda ea: st.names.get(ea, "")

    ida_bytes = types.ModuleType("ida_bytes")

    def set_cmt(ea: int, cmt: str, rpt: bool) -> bool:
        if ea in st.fail_set_cmt:
            return False
        st.comments[(ea, bool(rpt))] = cmt
        return True

    ida_bytes.set_cmt = set_cmt
    ida_bytes.get_cmt = lambda ea, rpt: st.comments.get((ea, bool(rpt)))
    ida_bytes.is_mapped = lambda ea: st.seg_at(ea) is not None

    ida_nalt = types.ModuleType("ida_nalt")
    ida_nalt.get_root_filename = lambda: st.root_filename

    ida_segment = types.ModuleType("ida_segment")
    ida_segment.SEG_NORM = SEG_NORM
    ida_segment.SEG_XTRN = SEG_XTRN
    ida_segment.getseg = st.seg_at

    ida_funcs = types.ModuleType("ida_funcs")

    def get_func(ea: int) -> FakeFunc | None:
        for f in st.funcs:
            if f.start_ea <= ea < f.end_ea:
                return f
        return None

    ida_funcs.get_func = get_func
    ida_funcs.get_func_cmt = lambda f, rpt: f.rcmt if rpt else f.cmt

    idautils = types.ModuleType("idautils")
    idautils.Names = lambda: iter(sorted(st.names.items()))
    idautils.Segments = lambda: iter([s.start_ea for s in st.segments])
    idautils.Heads = lambda start=None, end=None: iter(
        [h for h in sorted(st.heads) if (start is None or h >= start) and (end is None or h < end)]
    )
    idautils.Functions = lambda start=None, end=None: iter([f.start_ea for f in st.funcs])

    ida_kernwin = types.ModuleType("ida_kernwin")
    ida_kernwin.SETMENU_APP = 1
    ida_kernwin.AST_ENABLE_ALWAYS = 0

    class action_handler_t:  # noqa: N801
        def __init__(self) -> None:
            pass

    class action_desc_t:  # noqa: N801
        def __init__(
            self,
            name: str,
            label: str,
            handler: Any,
            shortcut: Any = None,
            tooltip: str | None = None,
            icon: int = -1,
        ) -> None:
            self.name = name
            self.label = label
            self.handler = handler
            self.tooltip = tooltip

    def register_action(desc: action_desc_t) -> bool:
        if desc.name in st.registered:
            return False
        st.registered[desc.name] = desc
        return True

    def unregister_action(name: str) -> bool:
        st.unregistered.append(name)
        return st.registered.pop(name, None) is not None

    ida_kernwin.action_handler_t = action_handler_t
    ida_kernwin.action_desc_t = action_desc_t
    ida_kernwin.register_action = register_action
    ida_kernwin.unregister_action = unregister_action
    ida_kernwin.attach_action_to_menu = lambda path, name, flags: (
        st.attached.append((path, name, flags)) or True
    )
    ida_kernwin.ask_file = lambda for_saving, defval, prompt: st.ask_file_result
    ida_kernwin.ask_str = lambda defval, hist, prompt: st.ask_str_result
    ida_kernwin.ask_buttons = lambda yes, no, cancel, deflt, prompt: st.ask_buttons_result
    ida_kernwin.info = st.infos.append
    ida_kernwin.warning = st.warnings.append
    ida_kernwin.msg = lambda text: None

    def show_wait_box(text: str) -> None:
        st.wait_boxes_shown += 1

    def hide_wait_box() -> None:
        st.wait_boxes_hidden += 1

    def user_cancelled() -> bool:
        st.cancel_checks += 1
        return st.cancel_after is not None and st.cancel_checks >= st.cancel_after

    ida_kernwin.show_wait_box = show_wait_box
    ida_kernwin.hide_wait_box = hide_wait_box
    ida_kernwin.replace_wait_box = lambda text: None
    ida_kernwin.user_cancelled = user_cancelled

    return {
        "idaapi": idaapi,
        "ida_name": ida_name,
        "ida_bytes": ida_bytes,
        "ida_nalt": ida_nalt,
        "ida_segment": ida_segment,
        "ida_funcs": ida_funcs,
        "idautils": idautils,
        "ida_kernwin": ida_kernwin,
    }


@pytest.fixture
def fake_ida(monkeypatch: pytest.MonkeyPatch) -> FakeIdaState:
    st = FakeIdaState(
        segments=[FakeSegment(0x140001000, 0x140008000), FakeSegment(0x140008000, 0x140009000, SEG_XTRN)]
    )
    for name, mod in _build_modules(st).items():
        monkeypatch.setitem(sys.modules, name, mod)
    return st


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
            "label_text": None,
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

    def test_module_keys_differing_only_in_case_are_merged(self) -> None:
        raw = {
            "schema": "x64dbg-ida-sync/1",
            "modules": {
                "A.dll": {"base_runtime": None, "items": [{"rva": "0x10", "name": "first"}]},
                "a.dll": {"base_runtime": "0x10000000", "items": [{"rva": "0x20", "name": "second"}]},
            },
        }
        doc = xs.load_sync_document(dumps(raw))
        assert list(doc["modules"]) == ["a.dll"]
        mod = doc["modules"]["a.dll"]
        assert [i["name"] for i in mod["items"]] == ["first", "second"]
        assert mod["base_runtime"] == 0x10000000
        assert any("differ only in case" in w for w in doc["warnings"])

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
        ("byte3_10", "_byte3_10"),
        ("unk_1000", "_unk_1000"),
        ("str_1", "str_1"),  # not an IDA dummy prefix
        ("funcs_1", "funcs_1"),
        ("def_1A", "def_1A"),
        ("dummy_1", "dummy_1"),
        ("j_1", "j_1"),
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


@pytest.mark.parametrize("raw", ["복호화_루틴", "日本語", "::", "~", "<>"])
def test_unusable_names_become_a_label_tag(raw: str) -> None:
    doc = xs.load_sync_document(dumps(make_doc([{"rva": "0x10", "name": raw}])))
    (item,) = doc["modules"]["sample.exe"]["items"]
    assert item["name"] is None
    assert item["label_text"] == raw
    (entry,) = xs.build_import_plan(doc, "sample.exe", 0x140000000)
    assert entry["name"] is None
    assert entry["comment"] == f"[x64dbg: label {raw}]"


def test_unusable_name_tag_combines_with_other_tags() -> None:
    doc = xs.load_sync_document(
        dumps(make_doc([{"rva": "0x10", "name": "복호화", "comment": "note", "bookmark": True}]))
    )
    (entry,) = xs.build_import_plan(doc, "sample.exe", 0x140000000)
    assert entry["comment"] == "note [x64dbg: label 복호화; bookmark]"


def test_name_of_only_control_characters_is_dropped() -> None:
    doc = xs.load_sync_document(
        dumps(make_doc([{"rva": "0x10", "name": "\u202e\x00"}, {"rva": "0x20", "name": "ok"}]))
    )
    assert [i["rva"] for i in doc["modules"]["sample.exe"]["items"]] == [0x20]
    assert doc["skipped"] == 1


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
        ("old\nx", "x", None),  # already present as a whole line (earlier import)
        ("old\r\nx", "x", None),
        ("old note x", "x", "old note x\nx"),  # a substring of another line is not a duplicate
        ("decrypt_config_v2 note", "decrypt_config", "decrypt_config_v2 note\ndecrypt_config"),
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
    assert "cancelled" not in text


def test_format_import_report_mentions_unusable_names_and_cancel() -> None:
    counts = {
        "module": "sample.exe",
        "imagebase": "0x140000000",
        "items": 3,
        "renamed": 0,
        "rename_failed": 0,
        "commented": 1,
        "comment_unchanged": 0,
        "comment_failed": 0,
        "unmapped": 0,
        "skipped_invalid": 0,
        "name_unusable": 2,
        "cancelled": True,
        "processed": 1,
    }
    text = xs.format_import_report(counts)
    assert "names kept as comments 2" in text
    assert "cancelled" in text and "1 of 3" in text


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

    def test_unusable_name_keeps_the_existing_ida_name(self, fake_ida: FakeIdaState, tmp_path: Path) -> None:
        fake_ida.names[0x140001000] = "my_analysis_name"
        path = self.write_doc(tmp_path, make_doc([{"rva": "0x1000", "name": "복호화_루틴"}]))
        counts = xs.import_from_file(path)
        assert fake_ida.set_name_calls == []
        assert fake_ida.names[0x140001000] == "my_analysis_name"
        assert fake_ida.comments[(0x140001000, False)] == "[x64dbg: label 복호화_루틴]"
        assert counts["name_unusable"] == 1
        assert counts["renamed"] == 0 and counts["commented"] == 1

    def test_import_counts_failed_comments(self, fake_ida: FakeIdaState, tmp_path: Path) -> None:
        fake_ida.fail_set_cmt.add(0x140001010)
        path = self.write_doc(
            tmp_path,
            make_doc([{"rva": "0x1010", "comment": "will fail"}, {"rva": "0x1020", "comment": "fine"}]),
        )
        counts = xs.import_from_file(path)
        assert counts["comment_failed"] == 1
        assert counts["commented"] == 1
        assert (0x140001010, False) not in fake_ida.comments

    def test_import_shows_and_hides_a_wait_box(self, fake_ida: FakeIdaState, tmp_path: Path) -> None:
        path = self.write_doc(tmp_path, make_doc([{"rva": "0x1000", "name": "x"}]))
        xs.import_from_file(path)
        assert fake_ida.wait_boxes_shown == 1
        assert fake_ida.wait_boxes_hidden == 1
        assert fake_ida.cancel_checks >= 1

    def test_import_can_be_cancelled(
        self, fake_ida: FakeIdaState, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(xs, "CANCEL_CHECK_EVERY", 1)
        fake_ida.cancel_after = 3  # the third check (before the third item) cancels
        path = self.write_doc(
            tmp_path, make_doc([{"rva": hex(0x1000 + i * 0x10), "name": f"n{i}"} for i in range(5)])
        )
        counts = xs.import_from_file(path)
        assert counts["cancelled"] is True
        assert counts["processed"] == 2
        assert counts["renamed"] == 2
        assert sorted(fake_ida.names) == [0x140001000, 0x140001010]
        assert fake_ida.wait_boxes_hidden == fake_ida.wait_boxes_shown == 1
        fake_ida.ask_file_result = path
        fake_ida.cancel_checks = 0
        assert xs.run_import_action() is not None
        assert "cancelled" in fake_ida.infos[-1]

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

    def test_failed_export_keeps_the_previous_file(
        self, fake_ida: FakeIdaState, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_ida.names[0x140001000] = "decrypt_config"
        out = tmp_path / "export.json"
        out.write_text("previous export", encoding="utf-8")

        def failing_dump(obj: object, fh: object, **kwargs: object) -> None:
            fh.write('{"schema": "x64dbg-ida-sync/1", "mod')  # type: ignore[attr-defined]
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(xs.json, "dump", failing_dump)
        fake_ida.ask_file_result = str(out)
        assert xs.run_export_action() is None
        assert "export failed" in fake_ida.warnings[-1]
        assert out.read_text(encoding="utf-8") == "previous export"
        assert sorted(p.name for p in tmp_path.iterdir()) == ["export.json"]  # no temp file left
        assert fake_ida.wait_boxes_hidden == fake_ida.wait_boxes_shown

    def test_export_replaces_the_previous_file(self, fake_ida: FakeIdaState, tmp_path: Path) -> None:
        fake_ida.names[0x140001000] = "decrypt_config"
        out = tmp_path / "export.json"
        out.write_text("previous export", encoding="utf-8")
        result = xs.export_to_file(str(out))
        assert result["items"] == 1
        assert json.loads(out.read_text(encoding="utf-8"))["schema"] == xs.SCHEMA
        assert sorted(p.name for p in tmp_path.iterdir()) == ["export.json"]
        assert fake_ida.wait_boxes_shown == fake_ida.wait_boxes_hidden == 1

    def test_export_to_an_unwritable_path_warns(self, fake_ida: FakeIdaState, tmp_path: Path) -> None:
        fake_ida.names[0x140001000] = "decrypt_config"
        fake_ida.ask_file_result = str(tmp_path / "missing_dir" / "export.json")
        assert xs.run_export_action() is None
        assert fake_ida.warnings and "export failed" in fake_ida.warnings[-1]
        assert not (tmp_path / "missing_dir").exists()

    def test_export_can_be_cancelled(
        self, fake_ida: FakeIdaState, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(xs, "CANCEL_CHECK_EVERY", 1)
        fake_ida.names.update({0x140001000: "a", 0x140001010: "b"})
        fake_ida.heads = [0x140001000, 0x140001010]
        fake_ida.cancel_after = 1
        out = tmp_path / "export.json"
        fake_ida.ask_file_result = str(out)
        assert xs.run_export_action() is None
        assert not out.exists()
        assert any("cancelled" in m for m in fake_ida.warnings + fake_ida.infos)
        assert fake_ida.wait_boxes_hidden == fake_ida.wait_boxes_shown == 1

    def test_choose_and_run_dispatches(self, fake_ida: FakeIdaState, tmp_path: Path) -> None:
        fake_ida.ask_buttons_result = 1  # "Import"
        fake_ida.ask_file_result = self.write_doc(tmp_path, make_doc([{"rva": "0x1000", "name": "imported"}]))
        xs.choose_and_run()
        assert fake_ida.names[0x140001000] == "imported"
        assert "renamed 1" in fake_ida.infos[-1]

        fake_ida.ask_buttons_result = 0  # "Export"
        out = tmp_path / "export.json"
        fake_ida.ask_file_result = str(out)
        xs.choose_and_run()
        doc = json.loads(out.read_text(encoding="utf-8"))
        assert doc["modules"]["sample.exe"]["items"] == [{"rva": "0x1000", "name": "imported"}]

        fake_ida.ask_buttons_result = -1  # "Cancel": nothing happens
        infos = len(fake_ida.infos)
        xs.choose_and_run()
        assert len(fake_ida.infos) == infos

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
        # flags are plugin_t bits; PLUGIN_KEEP (2) is an init() return code and would mean PLUGIN_DRAW
        assert plugin.flags == 0
        assert plugin.init() == 2  # PLUGIN_KEEP
        assert xs.ACTION_EXPORT in fake_ida.registered
        fake_ida.ask_buttons_result = -1
        plugin.run(0)
        plugin.term()
        assert fake_ida.registered == {}


# The cross-checks with the gateway library (gateway export -> script import and script
# export -> gateway plan_import) live in host/tests/unit/test_ida_sync.py, which the default
# `uv run pytest` collects; that file also runs this suite in a subprocess.
