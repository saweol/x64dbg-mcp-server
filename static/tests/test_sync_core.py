"""Tests for static/common/x64dbg_sync_core.py (plain Python, no reverse-engineering tool).

From host/:  uv run pytest ../static/tests -q

The core is loaded by path (like static/ida/tests does with the IDA script), so neither
``sys.path`` nor a conftest.py is needed. The parity tests at the end load
static/ida/x64dbg_sync.py the same way and check that the rules meant to be shared give
identical results.
"""

from __future__ import annotations

import importlib.util
import json
import random
import types
import unicodedata
from pathlib import Path

import pytest

STATIC_DIR = Path(__file__).resolve().parent.parent
CORE_PATH = STATIC_DIR / "common" / "x64dbg_sync_core.py"
IDA_SCRIPT = STATIC_DIR / "ida" / "x64dbg_sync.py"


def _load(path: Path, name: str) -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None, f"cannot load {path}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


core = _load(CORE_PATH, "x64dbg_sync_core_under_test")

IDA_CHARSET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_$?@")
R2_CHARSET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.")


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


# ── hygiene ─────────────────────────────────────────────────────────
def test_core_imports_no_tool_module() -> None:
    src = CORE_PATH.read_text(encoding="utf-8")
    banned_imports = ("import ida", "import ghidra", "import r2pipe", "import rzpipe", "import cutter")
    for banned in banned_imports:
        assert banned not in src


def test_targets_and_aliases() -> None:
    assert core.rules_for("ida") is core.IDA
    assert core.rules_for("Ghidra") is core.GHIDRA
    assert core.rules_for("radare2") is core.RADARE2
    assert core.rules_for("rizin") is core.RADARE2
    assert core.rules_for("cutter") is core.RADARE2
    with pytest.raises(ValueError, match="unknown target"):
        core.rules_for("binja")


# ── numbers ─────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    ("raw", "value"),
    [("0x10", 16), ("0X1f", 31), ("ff", 255), (" 0x10 ", 16), (0, 0), (2**64 - 1, 2**64 - 1)],
)
def test_parse_hex_ok(raw: object, value: int) -> None:
    assert core.parse_hex(raw) == value


@pytest.mark.parametrize("raw", [True, -1, 2**64, "", "0x", "zz", None, 1.5, "1" * 80])
def test_parse_hex_bad(raw: object) -> None:
    with pytest.raises(ValueError):
        core.parse_hex(raw)


def test_format_hex() -> None:
    assert core.format_hex(0x14000102C) == "0x14000102C"
    assert core.format_hex(0) == "0x0"


# ── name rules per tool ─────────────────────────────────────────────
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("decrypt_config", "decrypt_config"),
        ("c2 beacon loop", "c2_beacon_loop"),
        ("std::vector<int>::push_back", "std_vector_int_push_back"),
        ("?Func@@YAXXZ", "?Func@@YAXXZ"),
        ("1stage", "_1stage"),
        ("sub_401000", "_sub_401000"),
        ("sub_main", "sub_main"),
        ("ｍａｌｗａｒｅ", "malware"),
        ("evil\u202egnp", "evil_gnp"),
    ],
)
def test_ida_names(raw: str, expected: str) -> None:
    assert core.IDA.sanitize_name(raw) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("decrypt_config", "decrypt_config"),
        ("c2 beacon\tloop", "c2_beacon_loop"),  # Ghidra refuses whitespace
        ("std::vector<int>::push_back", "std::vector<int>::push_back"),  # accepted by Ghidra 12.2
        ("?Func@@YAXXZ", "?Func@@YAXXZ"),
        ("~dtor", "~dtor"),
        ("1stage", "1stage"),
        ("복호화_루틴", "복호화_루틴"),  # Ghidra accepts Unicode letters
        ("a\x00b", "a_b"),
        ("evil\u202egnp", "evil_gnp"),
        ("\u3164x\u2800y", "_x_y"),  # SymbolUtilities.EXTRA_INVALID_CODEPOINTS
        ("ｍａｌｗａｒｅ", "malware"),
    ],
)
def test_ghidra_names(raw: str, expected: str) -> None:
    assert core.GHIDRA.sanitize_name(raw) == expected


def test_ghidra_name_length_cap() -> None:
    assert len(core.GHIDRA.sanitize_name("a" * 5000)) == 2000  # SymbolUtilities.MAX_SYMBOL_NAME_LENGTH


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("decrypt_config", "decrypt_config"),
        ("c2 beacon loop", "c2_beacon_loop"),
        ("std::vector<int>::push_back", "std_vector_int_push_back"),
        ("kernel32.CreateFileA", "kernel32.CreateFileA"),
        ("?Func@@YAXXZ", "Func_YAXXZ"),  # rizin strips a leading '_' and radare2 refuses '?', '@'
        ("_start", "start"),
        ("__imp_x", "imp_x"),
        (".hidden", "hidden"),
        ("1stage", "lbl_1stage"),  # radare2 refuses a leading digit
        ("$x", "x"),
        ("a;b|c`d", "a_b_c_d"),
        ("evil\u202egnp", "evil_gnp"),
    ],
)
def test_r2_names(raw: str, expected: str) -> None:
    assert core.RADARE2.sanitize_name(raw) == expected


@pytest.mark.parametrize("rules", [core.IDA, core.GHIDRA, core.RADARE2])
@pytest.mark.parametrize("raw", ["", "  ", "\x00", "__"])
def test_names_never_empty(rules: object, raw: str) -> None:
    assert rules.sanitize_name(raw) == "x64dbg_name"
    assert rules.sanitize_name(raw, fallback="x64dbg_1000") == "x64dbg_1000"


def test_r2_unusable_names() -> None:
    for raw in ("복호화", "日本語", "::", "~", "<>", "__", "..", "_._"):
        assert core.RADARE2.name_core(raw) == ""


def test_name_properties() -> None:
    rng = random.Random(3)  # noqa: S311 - deterministic test data
    for _ in range(300):
        s = "".join(chr(rng.randrange(0, 0x30000)) for _ in range(rng.randint(0, 900)))
        ida = core.IDA.sanitize_name(s)
        assert ida and set(ida) <= IDA_CHARSET and len(ida) <= 511 and not ida[0].isdigit()
        r2 = core.RADARE2.sanitize_name(s)
        assert r2 and set(r2) <= R2_CHARSET and len(r2) <= core.RADARE2.name_max
        assert r2[0].isalpha() and r2[0].isascii()
        gh = core.GHIDRA.sanitize_name(s)
        assert gh and len(gh) <= 2000
        assert not any(ch.isspace() for ch in gh)
        assert all(unicodedata.category(ch) not in {"Cc", "Cf", "Cs", "Co", "Cn"} for ch in gh)


def test_comment_property() -> None:
    rng = random.Random(5)  # noqa: S311 - deterministic test data
    for rules in (core.IDA, core.GHIDRA, core.RADARE2):
        for _ in range(100):
            s = "".join(chr(rng.randrange(0, 0x110000)) for _ in range(rng.randint(0, 3000)))
            out = rules.sanitize_comment(s)
            assert len(out) <= rules.comment_max
            assert all(unicodedata.category(ch) not in {"Cc", "Cf", "Cs", "Zl", "Zp"} for ch in out)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("plain", "plain"), ("a\x00b\x1b[31mc", "ab[31mc"), ("multi\nline\r\ntext", "multi line text"), ("   ", "")],
)
def test_sanitize_comment(raw: str, expected: str) -> None:
    assert core.GHIDRA.sanitize_comment(raw) == expected


# ── load_sync_document ──────────────────────────────────────────────
class TestLoadDocument:
    def test_normalises_items(self) -> None:
        doc = core.load_sync_document(
            dumps(
                make_doc(
                    [
                        {"rva": "0x1000", "name": "decrypt_config", "breakpoint": {"type": "normal", "enabled": True}},
                        {"rva": "0x1010", "comment": "decrypts\nconfig", "bookmark": True},
                        {"rva": "0x1500", "name": "c2 loop",
                         "breakpoint": {"type": "hardware", "enabled": False, "condition": "rcx==1"}},
                    ]
                )
            ),
            core.RADARE2,
        )
        mod = doc["modules"]["sample.exe"]
        assert mod["base_runtime"] == 0x7FF6A1230000
        a, b, c = mod["items"]
        assert a == {
            "rva": 0x1000, "name": "decrypt_config", "label_text": None, "comment": None, "bookmark": False,
            "breakpoint": {"type": "normal", "enabled": True, "condition": None},
        }
        assert (b["comment"], b["bookmark"], b["name"]) == ("decrypts config", True, None)
        assert c["name"] == "c2_loop"
        assert doc["skipped"] == 0

    def test_rules_decide_what_is_a_usable_name(self) -> None:
        raw = dumps(make_doc([{"rva": "0x10", "name": "복호화_루틴"}]))
        (gh,) = core.load_sync_document(raw, core.GHIDRA)["modules"]["sample.exe"]["items"]
        assert (gh["name"], gh["label_text"]) == ("복호화_루틴", None)
        # radare2 rules keep only "___", and leading underscores are stripped: unusable as a flag name,
        # so the text goes into the comment tag instead of replacing the existing name
        (r2,) = core.load_sync_document(raw, core.RADARE2)["modules"]["sample.exe"]["items"]
        assert (r2["name"], r2["label_text"]) == (None, "복호화_루틴")

    def test_default_rules_are_ida(self) -> None:
        raw = dumps(make_doc([{"rva": "0x10", "name": "1stage"}]))
        (item,) = core.load_sync_document(raw)["modules"]["sample.exe"]["items"]
        assert item["name"] == "_1stage"

    def test_accepts_str_and_bom(self) -> None:
        text = "\ufeff" + json.dumps(make_doc([{"rva": "0x1", "name": "a"}]))
        assert core.load_sync_document(text)["modules"]["sample.exe"]["items"][0]["name"] == "a"
        data = b"\xef\xbb\xbf" + dumps(make_doc([{"rva": "0x1", "name": "a"}]))
        assert core.load_sync_document(data)["modules"]["sample.exe"]["items"][0]["rva"] == 1

    def test_module_keys_merge_case_insensitively(self) -> None:
        doc = core.load_sync_document(
            dumps({"schema": core.SCHEMA, "modules": {
                "A.dll": {"items": [{"rva": "0x1", "name": "x"}]},
                "a.dll": {"base_runtime": "0x1000", "items": [{"rva": "0x2", "name": "y"}]},
            }})
        )
        assert list(doc["modules"]) == ["a.dll"]
        assert [i["rva"] for i in doc["modules"]["a.dll"]["items"]] == [1, 2]
        assert doc["modules"]["a.dll"]["base_runtime"] == 0x1000
        assert any("differ only in case" in w for w in doc["warnings"])

    def test_invalid_items_are_skipped(self) -> None:
        doc = core.load_sync_document(
            dumps(make_doc([
                "nope", {"rva": "zz", "name": "a"}, {"rva": "0x1"}, {"rva": "0x2", "name": "\u202e\x00"},
                {"rva": "0x3", "bookmark": "yes"}, {"rva": "0x4", "breakpoint": {"type": "dll"}},
                {"rva": "0x5", "name": "ok"},
            ]))
        )
        assert [i["rva"] for i in doc["modules"]["sample.exe"]["items"]] == [5]
        assert doc["skipped"] == 6

    @pytest.mark.parametrize(
        ("payload", "match"),
        [
            (b"", "empty"),
            (b"[]", "object"),
            (b"{", "valid JSON"),
            (b"\xff\xfe", "UTF-8"),
            (dumps({"modules": {}}), "no schema"),
            (dumps({"schema": "x64dbg-ida-sync/2", "modules": {}}), "version"),
            (dumps({"schema": "other", "modules": {}}), "unsupported schema"),
            (dumps({"schema": "x64dbg-ida-sync/1", "modules": []}), "'modules'"),
            (b"[" * 100000, "JSON"),
        ],
    )
    def test_rejects(self, payload: bytes, match: str) -> None:
        with pytest.raises(ValueError, match=match):
            core.load_sync_document(payload)

    def test_rejects_other_types(self) -> None:
        with pytest.raises(ValueError, match="bytes or str"):
            core.load_sync_document(123)

    def test_size_cap(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(core, "MAX_DOC_BYTES", 10)
        with pytest.raises(ValueError, match="too large"):
            core.load_sync_document(dumps(make_doc([])))

    def test_item_cap(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(core, "MAX_ITEMS", 2)
        doc = core.load_sync_document(dumps(make_doc([{"rva": i, "name": f"n{i}"} for i in range(5)])))
        assert len(doc["modules"]["sample.exe"]["items"]) == 2
        assert any("truncated" in w for w in doc["warnings"])

    def test_bad_module_entries_are_skipped_with_warning(self) -> None:
        doc = core.load_sync_document(
            dumps({"schema": core.SCHEMA, "modules": {"": {"items": []}, "x.dll": {"items": "no"},
                                                      "y.dll": {"base_runtime": "zz", "items": []}}})
        )
        assert list(doc["modules"]) == ["y.dll"]
        assert doc["modules"]["y.dll"]["base_runtime"] is None
        assert len(doc["warnings"]) == 2


def test_read_capped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "doc.json"
    path.write_bytes(b"x" * 20)
    assert core.read_capped(str(path)) == b"x" * 20
    monkeypatch.setattr(core, "MAX_DOC_BYTES", 10)
    with pytest.raises(ValueError, match="too large"):
        core.read_capped(str(path))


# ── module matching ─────────────────────────────────────────────────
@pytest.mark.parametrize(
    ("names", "root", "expected"),
    [
        (["sample.exe", "helper.dll"], "sample.exe", "sample.exe"),
        (["sample.exe"], "SAMPLE.EXE", "sample.exe"),
        (["sample.exe"], "/work/samples/sample.exe", "sample.exe"),
        (["sample.exe"], "C:\\work\\sample.exe", "sample.exe"),
        (["sample.exe"], "sample.bin", "sample.exe"),
        (["sample.exe", "sample.dll"], "sample.bin", None),
        (["helper.dll"], "sample.exe", None),
        ([], "sample.exe", None),
        (["sample.exe"], "", None),
    ],
)
def test_match_module(names: list[str], root: str, expected: str | None) -> None:
    assert core.match_module(names, root) == expected


class TestResolveModule:
    doc = {"modules": {"sample.exe": {"items": []}, "helper.dll": {"items": []}}}

    def test_explicit_module_wins(self) -> None:
        assert core.resolve_module(self.doc, ["whatever.bin"], "Helper.DLL") == "helper.dll"

    def test_explicit_module_by_stem_or_path(self) -> None:
        assert core.resolve_module(self.doc, [], "helper") == "helper.dll"
        assert core.resolve_module(self.doc, [], "C:\\x\\helper.dll") == "helper.dll"

    def test_first_matching_candidate(self) -> None:
        assert core.resolve_module(self.doc, ["", "nothing.bin", "/work/sample.exe"], None) == "sample.exe"

    def test_errors_list_the_modules(self) -> None:
        with pytest.raises(ValueError, match=r"helper.dll, sample.exe"):
            core.resolve_module(self.doc, ["other.exe"], None)
        with pytest.raises(ValueError, match="not in the document"):
            core.resolve_module(self.doc, [], "nope.dll")

    def test_error_names_each_candidate_once(self) -> None:
        with pytest.raises(ValueError) as info:
            core.resolve_module(self.doc, ["ask_copy.exe", "/work/ask_copy.exe"], None)
        assert str(info.value).count("ask_copy.exe") == 1


# ── import planning ─────────────────────────────────────────────────
def test_build_import_plan_rebases_and_tags() -> None:
    doc = core.load_sync_document(
        dumps(make_doc([
            {"rva": "0x1000", "name": "decrypt_config", "breakpoint": {"type": "normal", "enabled": True}},
            {"rva": "0x1010", "comment": "decrypts config", "bookmark": True},
            {"rva": "0x1500", "breakpoint": {"type": "hardware", "enabled": False, "condition": "rcx==1"}},
        ])),
        core.GHIDRA,
    )
    plan = core.build_import_plan(doc, "sample.exe", 0x140000000, core.GHIDRA)
    assert plan == [
        {"address": 0x140001000, "rva": 0x1000, "name": "decrypt_config", "comment": "[x64dbg: normal bp, enabled]"},
        {"address": 0x140001010, "rva": 0x1010, "name": None, "comment": "decrypts config [x64dbg: bookmark]"},
        {"address": 0x140001500, "rva": 0x1500, "name": None,
         "comment": "[x64dbg: hardware bp, disabled, condition rcx==1]"},
    ]


def test_build_import_plan_unusable_name_becomes_a_tag() -> None:
    doc = core.load_sync_document(dumps(make_doc([{"rva": "0x10", "name": "복호화", "comment": "note",
                                                   "bookmark": True}])), core.RADARE2)
    (entry,) = core.build_import_plan(doc, "sample.exe", 0x140000000, core.RADARE2)
    assert entry["name"] is None
    assert entry["comment"] == "note [x64dbg: label 복호화; bookmark]"


def test_build_import_plan_unknown_module_and_overflow() -> None:
    doc = core.load_sync_document(dumps(make_doc([{"rva": "0x20000", "name": "a"}, {"rva": "0x10", "name": "b"}])))
    with pytest.raises(ValueError, match="module"):
        core.build_import_plan(doc, "other.dll", 0x400000)
    plan = core.build_import_plan(doc, "SAMPLE.EXE", 2**64 - 0x10000)
    assert [p["name"] for p in plan] == ["b"]


def test_probe_document_from_the_e2e_run() -> None:
    """The exact document used for the real-tool verification (rva 0x102c, name + comment + bookmark)."""
    raw = (
        '{"schema": "x64dbg-ida-sync/1", "generated_by": "probe", "modules": {"e2e_sample_x86_64.exe": '
        '{"base_runtime": "0x7FF6A0000000", "items": [{"rva": "0x102c", "name": "gw_probe_entry", '
        '"comment": "set by x64dbg_sync import probe"}, {"rva": "0x102c", "bookmark": true}]}}, '
        '"skipped": {}, "warnings": []}'
    )
    for rules in (core.GHIDRA, core.RADARE2):
        doc = core.load_sync_document(raw, rules)
        key = core.resolve_module(doc, ["/work/e2e_sample_x86_64.exe"], None)
        assert core.build_import_plan(doc, key, 0x140000000, rules) == [
            {"address": 0x14000102C, "rva": 0x102C, "name": "gw_probe_entry",
             "comment": "set by x64dbg_sync import probe"},
            {"address": 0x14000102C, "rva": 0x102C, "name": None, "comment": "[x64dbg: bookmark]"},
        ]


@pytest.mark.parametrize(
    ("existing", "new", "expected"),
    [
        (None, "x", "x"),
        ("", "x", "x"),
        ("x", "x", None),
        ("old\nx", "x", None),
        ("old\r\nx", "x", None),
        ("old note x", "x", "old note x\nx"),
        ("old", "new", "old\nnew"),
        ("old", "", None),
    ],
)
def test_merge_comment(existing: str | None, new: str, expected: str | None) -> None:
    assert core.merge_comment(existing, new) == expected


def test_name_candidates() -> None:
    assert list(core.name_candidates("foo", limit=3)) == ["foo", "foo_1", "foo_2", "foo_3"]
    assert next(iter(core.name_candidates("x" * 300, limit=3, max_len=255))) == "x" * 255
    long = list(core.name_candidates("x" * 300, limit=2, max_len=255))
    assert all(len(n) <= 255 for n in long) and long[-1].endswith("_2")


# ── applying a plan through a tool adapter ──────────────────────────
class FakeOps:
    """Records what apply_import_plan asks a tool to do."""

    def __init__(self, mapped: set[int]) -> None:
        self.mapped = mapped
        self.names: dict[int, str] = {}
        self.comments: dict[int, str] = {}
        self.fail_names: set[int] = set()
        self.fail_comments: set[int] = set()
        self.calls: list[tuple] = []

    def is_mapped(self, address: int) -> bool:
        return address in self.mapped

    def set_name(self, address: int, name: str) -> str:
        self.calls.append(("set_name", address, name))
        if address in self.fail_names:
            return core.NAME_FAILED
        if self.names.get(address) == name:
            return core.NAME_UNCHANGED
        self.names[address] = name
        return core.NAME_RENAMED

    def get_comment(self, address: int) -> str | None:
        return self.comments.get(address)

    def set_comment(self, address: int, text: str) -> bool:
        self.calls.append(("set_comment", address, text))
        if address in self.fail_comments:
            return False
        self.comments[address] = text
        return True


def _plan(rules: object = core.GHIDRA) -> tuple[dict, list[dict]]:
    doc = core.load_sync_document(dumps(make_doc([
        {"rva": "0x102c", "name": "gw_probe_entry", "comment": "set by probe"},
        {"rva": "0x102c", "bookmark": True},
        {"rva": "0x9000", "name": "far_away"},
        {"rva": "0x20", "name": "복호화"},
    ])), rules)
    return doc, core.build_import_plan(doc, "sample.exe", 0x140000000, rules)


def test_apply_import_plan_and_idempotency() -> None:
    doc, plan = _plan(core.RADARE2)
    ops = FakeOps({0x14000102C, 0x140000020})
    counts = core.new_import_counts("radare2", "sample.exe", 0x140000000, plan, doc)
    core.apply_import_plan(plan, ops, counts)
    assert ops.names == {0x14000102C: "gw_probe_entry"}
    assert ops.comments == {
        0x14000102C: "set by probe\n[x64dbg: bookmark]",
        0x140000020: "[x64dbg: label 복호화]",
    }
    assert (counts["renamed"], counts["commented"], counts["unmapped"], counts["name_unusable"]) == (1, 3, 1, 1)
    again = core.new_import_counts("radare2", "sample.exe", 0x140000000, plan, doc)
    core.apply_import_plan(plan, ops, again)
    assert (again["renamed"], again["name_unchanged"], again["commented"], again["comment_unchanged"]) == (0, 1, 0, 3)
    assert ops.comments[0x14000102C] == "set by probe\n[x64dbg: bookmark]"


def test_apply_import_plan_counts_failures() -> None:
    doc, plan = _plan()
    ops = FakeOps({0x14000102C})
    ops.fail_names.add(0x14000102C)
    ops.fail_comments.add(0x14000102C)
    counts = core.new_import_counts("ghidra", "sample.exe", 0x140000000, plan, doc)
    core.apply_import_plan(plan, ops, counts)
    assert (counts["rename_failed"], counts["comment_failed"]) == (1, 2)


def test_apply_import_plan_can_be_cancelled() -> None:
    doc, plan = _plan()
    ops = FakeOps({0x14000102C, 0x140000020})
    counts = core.new_import_counts("ghidra", "sample.exe", 0x140000000, plan, doc)
    seen = []

    def cancel_check(done: int) -> bool:
        seen.append(done)
        return done >= 1

    core.apply_import_plan(plan, ops, counts, cancel_check=cancel_check)
    assert counts["cancelled"] is True and counts["processed"] == 1
    assert "cancelled" in core.format_import_report(counts)


def test_apply_import_plan_counts_tool_exceptions_as_failures() -> None:
    doc, plan = _plan()

    class Exploding(FakeOps):
        def set_name(self, address: int, name: str) -> str:
            raise RuntimeError("tool said no")

        def set_comment(self, address: int, text: str) -> bool:
            raise RuntimeError("tool said no")

    ops = Exploding({0x14000102C})
    counts = core.new_import_counts("ghidra", "sample.exe", 0x140000000, plan, doc)
    core.apply_import_plan(plan, ops, counts)
    assert (counts["rename_failed"], counts["comment_failed"]) == (1, 2)
    assert counts["errors"] and "tool said no" in counts["errors"][0]


def test_format_import_report() -> None:
    doc, plan = _plan()
    counts = core.new_import_counts("ghidra", "sample.exe", 0x140000000, plan, doc)
    text = core.format_import_report(counts)
    assert text.startswith("x64dbg sync (ghidra): imported module sample.exe at image base 0x140000000")
    for word in ("renamed", "unchanged", "unmapped", "names kept as comments"):
        assert word in text


# ── export document ─────────────────────────────────────────────────
def test_build_export_document() -> None:
    doc = core.build_export_document(
        "/work/Sample.exe",
        0x140000000,
        [
            (0x140001500, "c2_loop", None),
            (0x140001000, "decrypt_config", "decrypts\x00 config"),
            (0x140001000, None, "second"),
            (0x13FFFF000, "below", None),
            (0x140002000, None, None),
        ],
        generated_by="x64dbg_sync_ghidra.py 1.0 (Ghidra)",
        rules=core.GHIDRA,
    )
    assert doc["schema"] == core.SCHEMA
    assert doc["generated_by"] == "x64dbg_sync_ghidra.py 1.0 (Ghidra)"
    mod = doc["modules"]["sample.exe"]
    assert mod["ida_imagebase"] == "0x140000000"
    assert mod["base_runtime"] is None
    assert mod["items"] == [
        {"rva": "0x1000", "name": "decrypt_config", "comment": "decrypts config | second"},
        {"rva": "0x1500", "name": "c2_loop"},
    ]
    assert doc["skipped"]["below_imagebase"] == 1
    again = core.load_sync_document(json.dumps(doc))
    assert [i["rva"] for i in again["modules"]["sample.exe"]["items"]] == [0x1000, 0x1500]


def test_build_export_document_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(core, "MAX_ITEMS", 2)
    doc = core.build_export_document("a.exe", 0x400000, [(0x400000 + i, f"n{i}", None) for i in range(5)])
    assert len(doc["modules"]["a.exe"]["items"]) == 2
    assert doc["warnings"]


def test_export_document_is_accepted_by_the_gateway_shape() -> None:
    """Items carry only {rva, name?, comment?}: the import item shape of the gateway's plan_import."""
    doc = core.build_export_document("a.exe", 0x400000, [(0x401000, "n", "c"), (0x401010, None, "only")])
    for item in doc["modules"]["a.exe"]["items"]:
        assert set(item) <= {"rva", "name", "comment"}
        assert isinstance(item["rva"], str) and item["rva"].startswith("0x")


def test_write_json_atomic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "out.json"
    core.write_json_atomic(str(path), {"a": "한글"})
    assert json.loads(path.read_text(encoding="utf-8")) == {"a": "한글"}

    def boom(*_a: object, **_k: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(core.json, "dump", boom)
    with pytest.raises(OSError):
        core.write_json_atomic(str(path), {"b": 1})
    assert json.loads(path.read_text(encoding="utf-8")) == {"a": "한글"}
    assert [p.name for p in tmp_path.iterdir()] == ["out.json"]


# ── parity with static/ida/x64dbg_sync.py ───────────────────────────
@pytest.fixture(scope="module")
def ida_script() -> types.ModuleType:
    assert IDA_SCRIPT.is_file(), f"{IDA_SCRIPT} is missing"
    return _load(IDA_SCRIPT, "x64dbg_sync_ida_for_parity")


def _random_text(rng: random.Random, n: int) -> str:
    alphabet = "aZ09_$?@.:<>~ \t\n;|`\"'\\" + "\u202e\u200b\x00\x1b" + "복호화日本ｍ"
    return "".join(rng.choice(alphabet) if rng.random() < 0.8 else chr(rng.randrange(0, 0x30000)) for _ in range(n))


def test_parity_constants(ida_script: types.ModuleType) -> None:
    assert core.SCHEMA == ida_script.SCHEMA
    assert core.MAX_DOC_BYTES == ida_script.MAX_DOC_BYTES
    assert core.MAX_ITEMS == ida_script.MAX_ITEMS
    assert core.IDA.name_max == ida_script.IDA_NAME_MAX
    assert core.IDA.comment_max == ida_script.IDA_COMMENT_MAX


FIXED_NAMES = [
    "sub_401000", "loc_140001000", "byte3_10", "unk_1000", "SUB_ABC", "sub_main", "str_1", "1stage", "9",
    "ｍａｌｗａｒｅ", "evil‮gnp", "복호화_루틴", "::", "__", "", " ", "?Func@@YAXXZ", "$dispatch",
    "a" * 600, "x​y", "c2 beacon loop", "std::vector<int>::push_back",
]


def test_parity_sanitisers(ida_script: types.ModuleType) -> None:
    for s in FIXED_NAMES:
        assert core.IDA.sanitize_name(s) == ida_script.sanitize_ida_name(s), s
        assert core.IDA.name_core(s) == ida_script._name_core(s), s
    rng = random.Random(11)  # noqa: S311 - deterministic test data
    for _ in range(500):
        s = _random_text(rng, rng.randint(0, 700))
        assert core.IDA.sanitize_name(s) == ida_script.sanitize_ida_name(s)
        assert core.IDA.sanitize_comment(s) == ida_script.sanitize_ida_comment(s)
        assert core.IDA.name_core(s) == ida_script._name_core(s)


def test_parity_parse_hex_and_merge(ida_script: types.ModuleType) -> None:
    for raw in ("0x10", "ff", " 0X1f ", 0, 2**64 - 1):
        assert core.parse_hex(raw) == ida_script.parse_hex(raw)
    for bad in (True, -1, 2**64, "", "0x", "zz", None, 1.5, "1" * 80):
        with pytest.raises(ValueError):
            ida_script.parse_hex(bad)
        with pytest.raises(ValueError):
            core.parse_hex(bad)
    for existing, new in ((None, "x"), ("x", "x"), ("a\nb", "b"), ("ab", "b"), ("old", "")):
        assert core.merge_comment(existing, new) == ida_script.merge_comment(existing, new)


def test_parity_match_module(ida_script: types.ModuleType) -> None:
    cases = [
        (["sample.exe", "helper.dll"], "sample.exe"), (["sample.exe"], "SAMPLE.EXE"),
        (["sample.exe"], "C:\\w\\sample.exe"), (["sample.exe"], "sample.bin"),
        (["sample.exe", "sample.dll"], "sample.bin"), ([], "x"), (["a.exe"], ""),
    ]
    for names, root in cases:
        assert core.match_module(names, root) == ida_script.match_module(names, root)


def test_parity_load_and_plan(ida_script: types.ModuleType) -> None:
    rng = random.Random(7)  # noqa: S311 - deterministic test data
    fixed = [{"rva": f"0x{i * 16:x}", "name": n, "bookmark": i % 2 == 0} for i, n in enumerate(FIXED_NAMES)]
    for _ in range(60):
        items = list(fixed) if _ == 0 else []
        for _ in range(rng.randint(0, 12)):
            item: dict = {"rva": rng.choice([f"0x{rng.randrange(0, 0x40000):x}", rng.randrange(0, 999), "zz", None])}
            if rng.random() < 0.7:
                item["name"] = _random_text(rng, rng.randint(0, 40))
            if rng.random() < 0.5:
                item["comment"] = _random_text(rng, rng.randint(0, 80))
            if rng.random() < 0.3:
                item["bookmark"] = rng.choice([True, False, "yes"])
            if rng.random() < 0.3:
                item["breakpoint"] = {"type": rng.choice(["normal", "hardware", "memory", "dll"]),
                                      "enabled": rng.random() < 0.5,
                                      "condition": _random_text(rng, rng.randint(0, 20))}
            items.append(item)
        module = rng.choice(["sample.exe", "Sample.EXE", "helper.dll"])
        raw = dumps(make_doc(items, module=module))
        ours = core.load_sync_document(raw, core.IDA)
        theirs = ida_script.load_sync_document(raw)
        assert ours == theirs
        key = module.lower()
        base = rng.choice([0x140000000, 0x400000, 2**64 - 0x10000])
        plan = core.build_import_plan(ours, key, base, core.IDA)
        ida_plan = ida_script.build_import_plan(theirs, key, base)
        assert [(p["address"], p["rva"], p["name"], p["comment"]) for p in plan] == [
            (p["ea"], p["rva"], p["name"], p["comment"]) for p in ida_plan
        ]


def test_parity_export_document(ida_script: types.ModuleType) -> None:
    rng = random.Random(13)  # noqa: S311 - deterministic test data
    for _ in range(40):
        base = 0x140000000
        entries = [
            (base + rng.randrange(-0x100, 0x3000), rng.choice([None, _random_text(rng, 30)]),
             rng.choice([None, _random_text(rng, 60)]))
            for _ in range(rng.randint(0, 15))
        ]
        ours = core.build_export_document("Sample.exe", base, entries, generated_by="g", rules=core.IDA)
        theirs = ida_script.build_export_document("Sample.exe", base, entries, generated_by="g")
        assert ours == theirs
