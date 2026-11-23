"""Tests for the IDA <-> x64dbg sync library (plan 6.4 interpretation D).

Fixtures under tests/fixtures/ida/ are synthetic:

- ``list_modules*.txt`` follow the plugin formatter in src/mcp/tools.zig
  ``listModules``: ``"0x{X} | 0x{X} | {s}\\n"`` (base, summed region size,
  ``MEMPAGE.info``), optionally wrapped the way the gateway proxy returns it
  (``<untrusted_guest_output>`` blocks, ``[event:*]``/``[state]`` items and a
  ``[gateway]`` trailer).
- ``db_*.json`` imitate x64dbg user databases written by ``dbsave <path>``
  (uncompressed JSON, ``JSON_INDENT(1)``); no real sample or database is used.
"""

from __future__ import annotations

import importlib.util
import json
import os
import random
import re
import struct
import subprocess
import sys
import unicodedata
from pathlib import Path
from types import ModuleType

import pytest

from x64dbg_vm_gateway import ida_sync
from x64dbg_vm_gateway.ida_sync import (
    COMMENT_MAX_BYTES,
    LABEL_MAX_BYTES,
    SCHEMA,
    Annotations,
    ModuleInfo,
    coerce_module_map,
    export_for_ida,
    parse_address,
    parse_module_list,
    parse_x64dbg_db,
    plan_import,
    plan_import_report,
    rebase,
    sanitize_comment,
    sanitize_label,
)

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "ida"
HOST_DIR = Path(__file__).resolve().parents[2]
IDA_DIR = HOST_DIR.parent / "ida"
IDA_SCRIPT = IDA_DIR / "x64dbg_sync.py"
LABEL_CHARSET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_@?$.:<>~")
# Tokens x64dbg's expression evaluator resolves before labels (see ida_sync._is_reserved_label).
X64DBG_NUMBER_RE = re.compile(r"x?[0-9a-f]+|\.[0-9]+", re.IGNORECASE)

SAMPLE_BASE = 0x7FF6A1230000
SAMPLE_SIZE = 0x2A000
HELPER_BASE = 0x6FFF0000


def zig_line(base: int, size: int, name: str) -> str:
    """Mirror of the plugin formatter ``"0x{X} | 0x{X} | {s}\\n"``."""
    return f"0x{base:X} | 0x{size:X} | {name}\n"


def fixture_text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def fixture_bytes(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


@pytest.fixture
def modmap() -> dict[str, ModuleInfo]:
    return parse_module_list(fixture_text("list_modules.txt"))


@pytest.fixture(scope="module")
def ida_script() -> ModuleType:
    """ida/x64dbg_sync.py loaded by path (it imports no ida_* module at import time)."""
    assert IDA_SCRIPT.is_file(), f"{IDA_SCRIPT} is missing"
    spec = importlib.util.spec_from_file_location("x64dbg_sync_under_test", IDA_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ── import hygiene ──────────────────────────────────────────────────
def test_library_does_not_import_the_proxy_stack() -> None:
    code = (
        "import sys, x64dbg_vm_gateway.ida_sync; "
        "print(sorted(m for m in sys.modules if m.startswith('x64dbg_vm_gateway')))"
    )
    env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=60, env=env, check=True
    )
    assert out.stdout.strip() == "['x64dbg_vm_gateway', 'x64dbg_vm_gateway.ida_sync']"


def test_wrapper_tags_match_the_proxy() -> None:
    from x64dbg_vm_gateway import proxy

    assert ida_sync.UNTRUSTED_OPEN == proxy.UNTRUSTED_OPEN
    assert ida_sync.UNTRUSTED_CLOSE == proxy.UNTRUSTED_CLOSE


# ── cross-check with ida/x64dbg_sync.py (schema drift guard) ────────
def test_gateway_export_is_accepted_by_the_script(ida_script: ModuleType) -> None:
    db = {
        "labels": [
            {"module": "sample.exe", "address": "0x1000", "manual": True, "text": "decrypt config"},
            {"module": "sample.exe", "address": "0x1020", "manual": True, "text": "복호화_루틴"},
        ],
        "comments": [{"module": "sample.exe", "address": "0x1010", "manual": True, "text": "xor loop"}],
        "bookmarks": [{"module": "sample.exe", "address": "0x1010", "manual": True}],
        "breakpoints": [{"module": "sample.exe", "address": "0x1000", "enabled": True, "type": 0}],
    }
    exported = export_for_ida(parse_x64dbg_db(json.dumps(db).encode()))
    doc = ida_script.load_sync_document(json.dumps(exported))
    assert doc["skipped"] == 0
    plan = ida_script.build_import_plan(doc, "sample.exe", 0x140000000)
    assert [(p["ea"], p["name"], p["comment"]) for p in plan] == [
        (0x140001000, "decrypt_config", "[x64dbg: normal bp, enabled]"),
        (0x140001010, None, "xor loop [x64dbg: bookmark]"),
        (0x140001020, None, "x64dbg label: 복호화_루틴"),
    ]


def test_script_export_is_accepted_by_the_gateway(ida_script: ModuleType) -> None:
    exported = ida_script.build_export_document(
        "sample.exe", 0x140000000, [(0x140001000, "decrypt_config", "from IDA")]
    )
    items = exported["modules"]["sample.exe"]["items"]
    mm = {"sample.exe": ModuleInfo("sample.exe", SAMPLE_BASE, SAMPLE_SIZE)}
    assert plan_import(items, module="sample.exe", module_map=mm) == [
        {
            "runtime_address": "0x7FF6A1231000",
            "rva": "0x1000",
            "label": "decrypt_config",
            "comment": "from IDA",
        }
    ]


def test_script_export_with_an_item_past_the_image_end(ida_script: ModuleType) -> None:
    exported = ida_script.build_export_document(
        "sample.exe",
        0x140000000,
        [(0x140001000, "init", None), (0x140000000 + SAMPLE_SIZE + 0x1000, "extern_thing", None)],
    )
    items = exported["modules"]["sample.exe"]["items"]
    mm = {"sample.exe": ModuleInfo("sample.exe", SAMPLE_BASE, SAMPLE_SIZE)}
    with pytest.raises(ValueError, match=r"items\[1\].*outside"):
        plan_import(items, module="sample.exe", module_map=mm)
    report = plan_import_report(items, module="sample.exe", module_map=mm, on_error="skip")
    assert [p["label"] for p in report["plan"]] == ["init"]
    (skip,) = report["skipped"]
    assert skip["index"] == 1 and "outside" in skip["reason"]


def test_ida_script_suite_passes() -> None:
    """ida/tests sits outside this project's testpaths; run it here so the default run covers it."""
    env = {k: v for k, v in os.environ.items() if k != "PYTEST_ADDOPTS"}
    out = subprocess.run(
        [sys.executable, "-m", "pytest", str(IDA_DIR / "tests"), "-q", "-p", "no:cacheprovider"],
        cwd=HOST_DIR,
        capture_output=True,
        text=True,
        timeout=50,
        env=env,
        check=False,
    )
    assert out.returncode == 0, out.stdout[-4000:] + out.stderr[-2000:]
    assert " passed" in out.stdout and "failed" not in out.stdout


# ── parse_module_list ───────────────────────────────────────────────
class TestParseModuleList:
    def test_plain_output(self, modmap: dict[str, ModuleInfo]) -> None:
        assert set(modmap) == {"sample.exe", "ntdll.dll", "kernel32.dll", "kernelbase.dll", "helper.dll"}
        m = modmap["sample.exe"]
        assert m == ModuleInfo(name="sample.exe", base=SAMPLE_BASE, size=SAMPLE_SIZE, path=None)
        # the original spelling is kept in .name, the key is lower-cased
        assert modmap["kernelbase.dll"].name == "KERNELBASE.dll"
        assert modmap["helper.dll"].base == HELPER_BASE

    def test_wrapped_gateway_output_gives_same_map(self, modmap: dict[str, ModuleInfo]) -> None:
        assert parse_module_list(fixture_text("list_modules_wrapped.txt")) == modmap

    def test_state_and_event_lines_are_not_modules(self) -> None:
        text = (
            "[state] PAUSED at 0x7FF6A1231000 (sample.exe) | push rbp\n"
            "[event:warning] Breakpoint hit. Target is now PAUSED. Call GetDebugState to inspect.\n"
            "[gateway] epoch=1 backend=x64 retried=false\n"
        )
        assert parse_module_list(text) == {}

    def test_no_modules_message(self) -> None:
        assert parse_module_list("No modules loaded.") == {}
        assert parse_module_list("") == {}

    def test_tags_glued_to_a_module_line(self) -> None:
        text = "<untrusted_guest_output>0x400000 | 0x1000 | a.exe</untrusted_guest_output>\n"
        assert parse_module_list(text) == {"a.exe": ModuleInfo("a.exe", 0x400000, 0x1000)}

    def test_crlf_lowercase_hex_and_spacing(self) -> None:
        text = "  0x400000|0x1000|a.exe\r\n0x10000000  |  0xa000  |  b.DLL  \r\n"
        mm = parse_module_list(text)
        assert mm["a.exe"].base == 0x400000
        assert mm["b.dll"] == ModuleInfo("b.DLL", 0x10000000, 0xA000)

    def test_memory_map_lines_are_ignored(self) -> None:
        # GetMemoryMap uses the same leading columns: "base | size | prot [| info]".
        text = "0x10000 | 0x1000 | -RW--\n0x7FF6A1230000 | 0x1000 | -R--- | sample.exe\n" + zig_line(
            0x400000, 0x3000, "real.exe"
        )
        assert set(parse_module_list(text)) == {"real.exe"}

    def test_mapped_file_path_names(self) -> None:
        text = zig_line(0x2A0000, 0x5000, "\\Device\\HarddiskVolume2\\Windows\\System32\\mapped.dll")
        m = parse_module_list(text)["mapped.dll"]
        assert m.name == "mapped.dll"
        assert m.path == "\\Device\\HarddiskVolume2\\Windows\\System32\\mapped.dll"

    def test_module_extensions_follow_plugin_filter(self) -> None:
        text = "".join(
            zig_line(0x10000 * (i + 1), 0x1000, n)
            for i, n in enumerate(["a.dll", "b.EXE", "c.drv", "d.sys", "e.ocx", "f.txt", "g", "h.dat"])
        )
        assert set(parse_module_list(text)) == {"a.dll", "b.exe", "c.drv", "d.sys", "e.ocx"}

    def test_malformed_lines_are_skipped(self) -> None:
        text = (
            "0xZZZ | 0x1000 | bad.dll\n"
            "0x10000000000000000 | 0x1000 | toobig.dll\n"  # 17 hex digits
            "0x400000 | 0x0 | zerosize.exe\n"
            "0xFFFFFFFFFFFFF000 | 0x2000 | wraps.dll\n"  # base + size overflows 64 bits
            "0x400000 | 0x1000 | in|valid.dll\n"
            "0x400000 | 0x1000 |\n" + zig_line(0x500000, 0x1000, "good.dll")
        )
        assert set(parse_module_list(text)) == {"good.dll"}

    def test_duplicate_names_get_base_qualified_keys(self) -> None:
        text = zig_line(0x10000000, 0x5000, "dup.dll") + zig_line(0x20000000, 0x5000, "Dup.dll")
        mm = parse_module_list(text)
        assert "dup.dll" not in mm
        assert mm["dup.dll@0x10000000"].base == 0x10000000
        assert mm["dup.dll@0x20000000"].base == 0x20000000

    def test_exact_repeated_line_is_deduplicated(self) -> None:
        text = zig_line(0x400000, 0x1000, "a.exe") * 3
        assert parse_module_list(text) == {"a.exe": ModuleInfo("a.exe", 0x400000, 0x1000)}

    def test_control_and_bidi_characters_removed_from_names(self) -> None:
        text = zig_line(0x400000, 0x1000, "evil\u202egnp.exe")
        assert set(parse_module_list(text)) == {"evilgnp.exe"}

    def test_rejects_non_str_and_huge_input(self, monkeypatch: pytest.MonkeyPatch) -> None:
        with pytest.raises(ValueError):
            parse_module_list(b"0x400000 | 0x1000 | a.exe")  # type: ignore[arg-type]
        monkeypatch.setattr(ida_sync, "MAX_MODULE_TEXT_CHARS", 100)
        with pytest.raises(ValueError, match="too long"):
            parse_module_list("x" * 101)

    def test_too_many_modules(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(ida_sync, "MAX_MODULES", 3)
        text = "".join(zig_line(0x10000 * (i + 1), 0x1000, f"m{i}.dll") for i in range(4))
        with pytest.raises(ValueError, match="too many modules"):
            parse_module_list(text)


# ── parse_address ───────────────────────────────────────────────────
class TestParseAddress:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            (0x401000, 0x401000),
            ("0x401000", 0x401000),
            ("0X401000", 0x401000),
            ("401000", 0x401000),  # strings are always hexadecimal (debugger convention)
            ("7ff6a1231000", 0x7FF6A1231000),
            ("00007ff6`a1231000", 0x7FF6A1231000),  # WinDbg style
            ("401000h", 0x401000),  # IDA/MASM style
            ("  0x10  ", 0x10),
            (0, 0),
            (2**64 - 1, 2**64 - 1),
        ],
    )
    def test_accepted(self, raw: object, expected: int) -> None:
        assert parse_address(raw) == expected

    @pytest.mark.parametrize(
        "raw",
        [True, False, -1, 2**64, "", "0x", "xyz", "0x-1", "1.5", "0x" + "1" * 17, "1" * 100, None, 1.0, [1]],
    )
    def test_rejected(self, raw: object) -> None:
        with pytest.raises(ValueError):
            parse_address(raw)


# ── rebase ──────────────────────────────────────────────────────────
class TestRebase:
    def test_runtime_to_rva(self, modmap: dict[str, ModuleInfo]) -> None:
        r = rebase(SAMPLE_BASE + 0x1234, direction="runtime_to_rva", module_map=modmap)
        assert r["module"] == "sample.exe"
        assert r["rva"] == "0x1234"
        assert r["runtime"] == "0x7FF6A1231234"
        assert r["module_base"] == "0x7FF6A1230000"
        assert r["ida"] is None
        assert r["approximate"] is False
        assert r["direction"] == "runtime_to_rva"
        json.dumps(r)

    def test_runtime_to_rva_accepts_strings(self, modmap: dict[str, ModuleInfo]) -> None:
        for raw in ("0x7FF6A1231234", "7ff6a1231234", "00007ff6`a1231234"):
            assert rebase(raw, direction="runtime_to_rva", module_map=modmap)["rva"] == "0x1234"

    def test_module_boundaries(self, modmap: dict[str, ModuleInfo]) -> None:
        assert rebase(SAMPLE_BASE, direction="runtime_to_rva", module_map=modmap)["rva"] == "0x0"
        last = rebase(SAMPLE_BASE + SAMPLE_SIZE - 1, direction="runtime_to_rva", module_map=modmap)
        assert last["rva"] == "0x29FFF"
        with pytest.raises(ValueError, match="not inside any module"):
            rebase(SAMPLE_BASE + SAMPLE_SIZE, direction="runtime_to_rva", module_map=modmap)

    def test_address_below_all_modules(self, modmap: dict[str, ModuleInfo]) -> None:
        with pytest.raises(ValueError, match="not inside any module"):
            rebase(0x1000, direction="runtime_to_rva", module_map=modmap)

    def test_empty_module_map(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            rebase(0x401000, direction="runtime_to_rva", module_map={})

    def test_unknown_size_uses_nearest_lower_base_and_flags_it(self) -> None:
        mm = {"a.exe": ModuleInfo("a.exe", 0x400000, None), "b.dll": ModuleInfo("b.dll", 0x10000000, None)}
        r = rebase(0x412345, direction="runtime_to_rva", module_map=mm)
        assert (r["module"], r["rva"], r["approximate"]) == ("a.exe", "0x12345", True)
        assert r["warnings"]

    def test_sized_module_between_unsized_and_address_blocks_guess(self) -> None:
        mm = {
            "a.exe": ModuleInfo("a.exe", 0x400000, None),
            "b.dll": ModuleInfo("b.dll", 0x500000, 0x1000),
        }
        with pytest.raises(ValueError, match="not inside any module"):
            rebase(0x502000, direction="runtime_to_rva", module_map=mm)

    def test_overlapping_modules_are_ambiguous(self) -> None:
        mm = {
            "a.dll": ModuleInfo("a.dll", 0x10000000, 0x10000),
            "b.dll": ModuleInfo("b.dll", 0x10008000, 0x10000),
        }
        with pytest.raises(ValueError, match="ambiguous"):
            rebase(0x10009000, direction="runtime_to_rva", module_map=mm)
        # outside the overlap the answer is unique
        assert rebase(0x10001000, direction="runtime_to_rva", module_map=mm)["module"] == "a.dll"

    def test_unsized_module_inside_sized_range_is_ambiguous(self) -> None:
        mm = {
            "a.dll": ModuleInfo("a.dll", 0x10000000, 0x10000),
            "b.dll": ModuleInfo("b.dll", 0x10004000, None),
        }
        with pytest.raises(ValueError, match="ambiguous"):
            rebase(0x10005000, direction="runtime_to_rva", module_map=mm)

    def test_same_module_under_two_keys_is_not_ambiguous(self) -> None:
        m = ModuleInfo("a.exe", 0x400000, 0x1000)
        r = rebase(0x400010, direction="runtime_to_rva", module_map={"a.exe": m, "alias": m})
        assert r["module"] == "a.exe"

    def test_explicit_module_must_contain_address(self, modmap: dict[str, ModuleInfo]) -> None:
        r = rebase(SAMPLE_BASE + 0x10, direction="runtime_to_rva", module_map=modmap, module="sample.exe")
        assert r["rva"] == "0x10"
        with pytest.raises(ValueError, match="outside"):
            rebase(HELPER_BASE + 0x10, direction="runtime_to_rva", module_map=modmap, module="sample.exe")

    def test_runtime_to_ida(self, modmap: dict[str, ModuleInfo]) -> None:
        r = rebase(
            SAMPLE_BASE + 0x1234, direction="runtime_to_ida", module_map=modmap, ida_imagebase=0x140000000
        )
        assert r["ida"] == "0x140001234"
        assert r["ida_imagebase"] == "0x140000000"
        assert r["rva"] == "0x1234"

    def test_runtime_to_ida_needs_an_imagebase(self, modmap: dict[str, ModuleInfo]) -> None:
        with pytest.raises(ValueError, match="ida_imagebase"):
            rebase(SAMPLE_BASE + 0x1234, direction="runtime_to_ida", module_map=modmap)

    def test_runtime_to_ida_defaults_to_preferred_base(self) -> None:
        mm = {"a.exe": ModuleInfo("a.exe", 0x7FF600000000, 0x5000, preferred_base=0x140000000)}
        r = rebase(0x7FF600001000, direction="runtime_to_ida", module_map=mm)
        assert r["ida"] == "0x140001000"
        # an explicit imagebase (rebased IDB) wins over the PE preferred base
        r2 = rebase(0x7FF600001000, direction="runtime_to_ida", module_map=mm, ida_imagebase="0x10000000")
        assert r2["ida"] == "0x10001000"

    def test_rva_to_runtime(self, modmap: dict[str, ModuleInfo]) -> None:
        r = rebase("0x1234", direction="rva_to_runtime", module_map=modmap, module="sample.exe")
        assert r["runtime"] == "0x7FF6A1231234"
        r = rebase(0x10, direction="rva_to_runtime", module_map=modmap, module="KERNEL32.DLL")
        assert r["module"] == "kernel32.dll"

    def test_rva_to_runtime_also_reports_ida_when_known(self, modmap: dict[str, ModuleInfo]) -> None:
        r = rebase(
            0x10, direction="rva_to_runtime", module_map=modmap, module="sample.exe", ida_imagebase=0x400000
        )
        assert r["ida"] == "0x400010"

    def test_rva_to_runtime_requires_module(self, modmap: dict[str, ModuleInfo]) -> None:
        with pytest.raises(ValueError, match="module is required"):
            rebase(0x10, direction="rva_to_runtime", module_map=modmap)

    def test_rva_beyond_module_size(self, modmap: dict[str, ModuleInfo]) -> None:
        with pytest.raises(ValueError, match="outside"):
            rebase(SAMPLE_SIZE, direction="rva_to_runtime", module_map=modmap, module="sample.exe")

    def test_module_lookup_by_stem_path_and_case(self, modmap: dict[str, ModuleInfo]) -> None:
        for name in ("sample", "SAMPLE.EXE", "C:\\mcp\\jobs\\j1\\in\\sample.exe", "  sample.exe "):
            r = rebase(0x10, direction="rva_to_runtime", module_map=modmap, module=name)
            assert r["module"] == "sample.exe"

    def test_unknown_module_lists_known_ones(self, modmap: dict[str, ModuleInfo]) -> None:
        with pytest.raises(ValueError, match="not found") as exc:
            rebase(0x10, direction="rva_to_runtime", module_map=modmap, module="nope.dll")
        assert "sample.exe" in str(exc.value)

    def test_duplicate_module_names_are_ambiguous_by_name(self) -> None:
        mm = parse_module_list(
            zig_line(0x10000000, 0x5000, "dup.dll") + zig_line(0x20000000, 0x5000, "dup.dll")
        )
        with pytest.raises(ValueError, match="ambiguous"):
            rebase(0x10, direction="rva_to_runtime", module_map=mm, module="dup.dll")
        r = rebase(0x10, direction="rva_to_runtime", module_map=mm, module="dup.dll@0x20000000")
        assert r["runtime"] == "0x20000010"
        # containment still works for the duplicates
        assert rebase(0x10000010, direction="runtime_to_rva", module_map=mm)["module_base"] == "0x10000000"

    def test_stem_lookup_ambiguous(self) -> None:
        mm = parse_module_list(zig_line(0x400000, 0x1000, "x.exe") + zig_line(0x10000000, 0x1000, "x.dll"))
        with pytest.raises(ValueError, match="ambiguous"):
            rebase(0x10, direction="rva_to_runtime", module_map=mm, module="x")

    def test_ida_to_runtime(self, modmap: dict[str, ModuleInfo]) -> None:
        r = rebase(
            "0x140001234",
            direction="ida_to_runtime",
            module_map=modmap,
            module="sample.exe",
            ida_imagebase=0x140000000,
        )
        assert (r["rva"], r["runtime"], r["ida"]) == ("0x1234", "0x7FF6A1231234", "0x140001234")

    def test_ida_to_runtime_requires_module_and_imagebase(self) -> None:
        mm = {"a.exe": ModuleInfo("a.exe", 0x7FF600000000, 0x5000, preferred_base=0x140000000)}
        with pytest.raises(ValueError, match="module is required"):
            rebase(0x140001000, direction="ida_to_runtime", module_map=mm, ida_imagebase=0x140000000)
        with pytest.raises(ValueError, match="ida_imagebase"):
            rebase(0x140001000, direction="ida_to_runtime", module_map=mm, module="a.exe")

    def test_ida_address_below_imagebase(self, modmap: dict[str, ModuleInfo]) -> None:
        with pytest.raises(ValueError, match="below"):
            rebase(
                0x1000,
                direction="ida_to_runtime",
                module_map=modmap,
                module="sample.exe",
                ida_imagebase=0x400000,
            )

    def test_invalid_direction(self, modmap: dict[str, ModuleInfo]) -> None:
        with pytest.raises(ValueError, match="direction"):
            rebase(0x10, direction="ida_to_rva", module_map=modmap, module="sample.exe")

    def test_result_overflow(self) -> None:
        mm = {"top.dll": ModuleInfo("top.dll", 0xFFFFFFFFFFFF0000, None)}
        with pytest.raises(ValueError, match="64-bit"):
            rebase(0x20000, direction="rva_to_runtime", module_map=mm, module="top.dll")

    def test_module_map_from_manifest_dicts(self) -> None:
        manifest_like = {
            "sample.exe": {"base": "0x7FF6A1230000", "size": "0x2A000", "preferred_base": "0x140000000"},
            "helper.dll": {
                "name": "helper.dll",
                "base": HELPER_BASE,
                "size": None,
                "image_base": "0x10000000",
            },
        }
        r = rebase(SAMPLE_BASE + 0x20, direction="runtime_to_ida", module_map=manifest_like)
        assert r["ida"] == "0x140000020"
        r = rebase(HELPER_BASE + 0x20, direction="runtime_to_ida", module_map=manifest_like)
        assert (r["ida"], r["approximate"]) == ("0x10000020", True)

    def test_rejects_garbage_module_map(self) -> None:
        for bad in ({"a.exe": {"size": 1}}, {"a.exe": 5}, "a.exe", {"a.exe": {"base": "nope"}}):
            with pytest.raises(ValueError):
                rebase(0x10, direction="rva_to_runtime", module_map=bad, module="a.exe")  # type: ignore[arg-type]

    def test_round_trips_property(self) -> None:
        rng = random.Random(1234)
        for _ in range(300):
            mods: dict[str, ModuleInfo] = {}
            cursor = rng.randrange(0x10000, 0x7FF000000000) & ~0xFFFF
            for i in range(rng.randint(1, 6)):
                size = rng.randrange(0x1000, 0x400000) & ~0xFFF or 0x1000
                mods[f"m{i}.dll"] = ModuleInfo(f"m{i}.dll", cursor, size)
                cursor += size + (rng.randrange(0, 0x100000) & ~0xFFFF)
            name = rng.choice(list(mods))
            m = mods[name]
            imagebase = rng.choice([0x400000, 0x10000000, 0x140000000, 0x180000000])
            rva = rng.randrange(0, m.size or 1)
            runtime = m.base + rva

            fwd = rebase(runtime, direction="runtime_to_ida", module_map=mods, ida_imagebase=imagebase)
            assert fwd["module"] == name
            back = rebase(
                fwd["ida"], direction="ida_to_runtime", module_map=mods, module=name, ida_imagebase=imagebase
            )
            assert int(back["runtime"], 16) == runtime

            r2 = rebase(hex(rva), direction="rva_to_runtime", module_map=mods, module=name)
            assert int(r2["runtime"], 16) == runtime
            r3 = rebase(r2["runtime"], direction="runtime_to_rva", module_map=mods)
            assert int(r3["rva"], 16) == rva


# ── coerce_module_map ───────────────────────────────────────────────
def test_coerce_module_map_accepts_iterables_and_keeps_keys() -> None:
    mm = coerce_module_map([ModuleInfo("A.exe", 0x400000, 0x1000), {"name": "b.dll", "base": "0x10000000"}])
    assert set(mm) == {"a.exe", "b.dll"}
    assert mm["b.dll"].size is None
    assert coerce_module_map({"Alias": ModuleInfo("a.exe", 1, 2)})["alias"].name == "a.exe"


def test_module_info_to_dict_is_json_friendly() -> None:
    d = ModuleInfo("a.exe", 0x400000, 0x1000, "C:\\a.exe", 0x400000).to_dict()
    assert d == {
        "name": "a.exe",
        "base": "0x400000",
        "size": "0x1000",
        "path": "C:\\a.exe",
        "preferred_base": "0x400000",
    }
    assert ModuleInfo.from_dict(d) == ModuleInfo("a.exe", 0x400000, 0x1000, "C:\\a.exe", 0x400000)


# ── parse_x64dbg_db ─────────────────────────────────────────────────
class TestParseDb:
    def test_sample_database(self) -> None:
        ann = parse_x64dbg_db(fixture_bytes("db_sample.dd64.json"))
        assert isinstance(ann, Annotations)
        labels = {(lb.module, lb.rva): lb for lb in ann.labels}
        assert labels[("sample.exe", 0x1000)].text == "decrypt_config"
        assert labels[("sample.exe", 0x1000)].manual is True
        assert labels[("helper.dll", 0x3000)].text == "helper_init"
        assert len(ann.labels) == 3

        comments = {(c.module, c.rva): c for c in ann.comments}
        assert comments[("sample.exe", 0x1010)].text == "decrypts the embedded config"
        assert comments[("sample.exe", 0x2040)].manual is False
        assert comments[("", 0x1F0000)].text.startswith("heap buffer")

        assert [(b.module, b.rva) for b in ann.bookmarks] == [("sample.exe", 0x1010)]

        (fn,) = ann.functions
        assert (fn.module, fn.rva, fn.end_rva, fn.icount, fn.manual) == (
            "sample.exe",
            0x1000,
            0x10FF,
            0x2A,
            True,
        )

        bps = {bp.type: bp for bp in ann.breakpoints}
        assert set(bps) == {"normal", "hardware", "memory", "dll", "exception"}
        assert (bps["normal"].module, bps["normal"].rva, bps["normal"].enabled) == (
            "sample.exe",
            0x1000,
            True,
        )
        hw = bps["hardware"]
        assert (hw.enabled, hw.name, hw.condition, hw.log_text) == (
            False,
            "hw_beacon",
            "rcx==1",
            "beacon {rcx}",
        )
        assert bps["normal"].condition is None and bps["normal"].name is None
        assert bps["exception"].module == ""
        assert bps["exception"].type_code == 4
        assert ann.skipped == 0

    def test_legacy_auto_arrays(self) -> None:
        ann = parse_x64dbg_db(fixture_bytes("db_legacy.dd32.json"))
        labels = {lb.text: lb for lb in ann.labels}
        assert labels["legacy_start"].manual is True  # missing "manual" -> x64dbg default (true)
        assert labels["auto_label"].manual is False  # legacy "autolabels" array
        assert [(c.text, c.manual) for c in ann.comments] == [("auto comment", False)]
        assert [(b.rva, b.manual) for b in ann.bookmarks] == [(0x1300, False)]
        (fn,) = ann.functions  # legacy "address" instead of "start"
        assert (fn.rva, fn.end_rva, fn.manual) == (0x1000, 0x1050, False)

    def test_bom_and_leading_whitespace(self) -> None:
        data = (
            b"\xef\xbb\xbf \n"
            + json.dumps({"labels": [{"module": "a.exe", "address": "0x10", "text": "x"}]}).encode()
        )
        assert parse_x64dbg_db(data).labels[0].text == "x"

    def test_accepts_bytearray_and_memoryview(self) -> None:
        raw = fixture_bytes("db_legacy.dd32.json")
        assert len(parse_x64dbg_db(bytearray(raw)).labels) == 2
        assert len(parse_x64dbg_db(memoryview(raw)).labels) == 2

    def test_tolerates_malformed_entries(self) -> None:
        doc = {
            "labels": [
                {"module": "a.exe", "address": "0x10", "text": "ok"},
                {"address": "0x20", "text": "no module"},
                {"module": "a.exe", "address": "zz", "text": "bad address"},
                {"module": "a.exe", "address": "0x30", "text": 5},
                {"module": "a.exe", "text": "no address"},
                "not an object",
                {"module": "a.exe", "address": 64, "text": "int address", "manual": "yes"},
            ],
            "comments": {"not": "a list"},
            "bookmarks": [None, {"module": "a.exe", "address": "0x40"}],
            "breakpoints": [{"module": "a.exe", "type": 0, "enabled": True}, {"type": "x", "address": "0x1"}],
            "functions": [{"module": "a.exe", "end": "0x20"}],
            "somethingNew": [1, 2, 3],
        }
        ann = parse_x64dbg_db(json.dumps(doc).encode())
        assert [(lb.rva, lb.text, lb.manual) for lb in ann.labels] == [
            (0x10, "ok", True),
            (0x40, "int address", True),
        ]
        assert ann.comments == []
        assert [b.rva for b in ann.bookmarks] == [0x40]
        assert ann.breakpoints == []
        assert ann.functions == []
        assert ann.skipped == 10
        assert any("comments" in w for w in ann.warnings)

    def test_text_is_cleaned_and_capped(self) -> None:
        doc = {
            "labels": [{"module": "a.exe", "address": "0x10", "text": "ab\u202ecd\x00e" + "x" * 10_000}],
            "comments": [{"module": "a.exe", "address": "0x10", "text": "line1\nline2\u200b"}],
        }
        ann = parse_x64dbg_db(json.dumps(doc).encode())
        assert ann.labels[0].text.startswith("abcde")
        assert len(ann.labels[0].text) <= ida_sync.MAX_DB_TEXT_CHARS
        assert ann.comments[0].text == "line1 line2"

    def test_entry_cap(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(ida_sync, "MAX_ITEMS", 5)
        doc = {"labels": [{"module": "a.exe", "address": hex(i), "text": f"l{i}"} for i in range(20)]}
        ann = parse_x64dbg_db(json.dumps(doc).encode())
        assert len(ann.labels) == 5
        assert any("truncated" in w for w in ann.warnings)

    def test_size_cap(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(ida_sync, "MAX_DB_BYTES", 100)
        with pytest.raises(ValueError, match="too large"):
            parse_x64dbg_db(b"{" + b" " * 200 + b"}")

    @pytest.mark.parametrize(
        ("data", "hint"),
        [
            (b"", "empty"),
            (b"   \n", "empty"),
            (struct.pack("<I", 4096) + b'\xf0\x1b{\n "comments": [\n', "LZ4"),
            (b"\x1f\x8b\x08\x00" + b"\x00" * 20, "gzip"),
            (b"PK\x03\x04" + b"\x00" * 20, "zip"),
            (b"[1, 2, 3]", "JSON object"),
            (b'{"labels": [', "invalid JSON"),
            (b'{"a": "\xff\xfe"}', "UTF-8"),
            (b'{"a": ' + b"[" * 200_000 + b"]" * 200_000 + b"}", "invalid JSON"),
        ],
    )
    def test_unsupported_formats(self, data: bytes, hint: str) -> None:
        with pytest.raises(ValueError, match="unsupported database format") as exc:
            parse_x64dbg_db(data)
        assert hint.lower() in str(exc.value).lower()

    def test_rejects_non_bytes(self) -> None:
        with pytest.raises(ValueError):
            parse_x64dbg_db("{}")  # type: ignore[arg-type]

    def test_empty_object_is_valid(self) -> None:
        ann = parse_x64dbg_db(b"{}")
        assert (ann.labels, ann.comments, ann.bookmarks, ann.breakpoints, ann.functions) == (
            [],
            [],
            [],
            [],
            [],
        )

    def test_annotations_to_dict_is_json_serialisable(self) -> None:
        ann = parse_x64dbg_db(fixture_bytes("db_sample.dd64.json"))
        d = ann.to_dict()
        json.dumps(d)
        assert d["labels"][0]["rva"].startswith("0x")
        assert set(d) >= {
            "labels",
            "comments",
            "bookmarks",
            "breakpoints",
            "functions",
            "skipped",
            "warnings",
        }


# ── export_for_ida ──────────────────────────────────────────────────
class TestExport:
    def test_schema_and_items(self, modmap: dict[str, ModuleInfo]) -> None:
        ann = parse_x64dbg_db(fixture_bytes("db_sample.dd64.json"))
        doc = export_for_ida(ann, modmap)
        json.dumps(doc)
        assert doc["schema"] == SCHEMA == "x64dbg-ida-sync/1"
        assert doc["generated_by"].startswith("x64dbg-vm-gateway")
        assert set(doc["modules"]) == {"sample.exe", "helper.dll"}
        sample = doc["modules"]["sample.exe"]
        assert sample["base_runtime"] == "0x7FF6A1230000"
        items = {it["rva"]: it for it in sample["items"]}
        assert [it["rva"] for it in sample["items"]] == sorted(items, key=lambda h: int(h, 16))
        assert items["0x1000"]["name"] == "decrypt_config"
        assert items["0x1000"]["breakpoint"] == {"type": "normal", "enabled": True}
        assert items["0x1010"] == {
            "rva": "0x1010",
            "comment": "decrypts the embedded config",
            "bookmark": True,
        }
        assert items["0x1500"]["name"] == "c2_beacon_loop"
        assert items["0x1500"]["breakpoint"] == {"type": "hardware", "enabled": False, "condition": "rcx==1"}
        assert items["0x2000"]["breakpoint"]["type"] == "memory"
        assert items["0x2040"]["comment"] == "auto: string reference"
        helper = doc["modules"]["helper.dll"]
        assert helper["base_runtime"] == "0x6FFF0000"
        assert helper["items"] == [{"rva": "0x3000", "name": "helper_init"}]
        # no-module comment, DLL and exception breakpoints are not address-bound
        assert doc["skipped"]["no_module"] == 1
        assert doc["skipped"]["not_address_bound"] == 2

    def test_without_module_map(self) -> None:
        ann = parse_x64dbg_db(fixture_bytes("db_sample.dd64.json"))
        doc = export_for_ida(ann)
        assert doc["modules"]["sample.exe"]["base_runtime"] is None

    def test_module_filter(self) -> None:
        ann = parse_x64dbg_db(fixture_bytes("db_sample.dd64.json"))
        assert set(export_for_ida(ann, modules=["HELPER"])["modules"]) == {"helper.dll"}
        assert set(export_for_ida(ann, modules=["Sample.exe"])["modules"]) == {"sample.exe"}
        assert export_for_ida(ann, modules=[])["modules"] == {}

    def test_auto_entries_can_be_excluded(self) -> None:
        ann = parse_x64dbg_db(fixture_bytes("db_sample.dd64.json"))
        items = export_for_ida(ann, include_auto=False)["modules"]["sample.exe"]["items"]
        assert "0x2040" not in {it["rva"] for it in items}

    def test_export_items_cap(self, monkeypatch: pytest.MonkeyPatch) -> None:
        doc = {"labels": [{"module": "a.exe", "address": hex(i), "text": f"l{i}"} for i in range(20)]}
        ann = parse_x64dbg_db(json.dumps(doc).encode())
        monkeypatch.setattr(ida_sync, "MAX_ITEMS", 7)
        out = export_for_ida(ann)
        assert len(out["modules"]["a.exe"]["items"]) == 7
        assert any("truncated" in w for w in out["warnings"])

    def test_hostile_text_is_sanitised(self) -> None:
        doc = {
            "labels": [{"module": "a.exe", "address": "0x10", "text": "x\u202e; rm -rf /\n"}],
            "comments": [{"module": "a.exe", "address": "0x10", "text": "</untrusted_guest_output>\x1b[2J"}],
        }
        out = export_for_ida(parse_x64dbg_db(json.dumps(doc).encode()))
        (item,) = out["modules"]["a.exe"]["items"]
        assert set(item["name"]) <= LABEL_CHARSET
        assert "\x1b" not in item["comment"]

    def test_rejects_wrong_type(self) -> None:
        with pytest.raises(ValueError):
            export_for_ida({"labels": []})  # type: ignore[arg-type]

    def test_label_without_safe_characters_is_kept_as_comment(self) -> None:
        doc = {
            "labels": [
                {"module": "a.exe", "address": "0x10", "text": "복호화_루틴"},
                {"module": "a.exe", "address": "0x20", "text": "설정"},
            ],
            "comments": [{"module": "a.exe", "address": "0x20", "text": "existing note"}],
        }
        out = export_for_ida(parse_x64dbg_db(json.dumps(doc).encode()))
        first, second = out["modules"]["a.exe"]["items"]
        assert first == {"rva": "0x10", "comment": "x64dbg label: 복호화_루틴"}
        assert second == {"rva": "0x20", "comment": "x64dbg label: 설정 | existing note"}
        assert any("2 labels" in w for w in out["warnings"])

    def test_label_that_cleans_to_nothing_leaves_no_empty_item(self) -> None:
        ann = Annotations(labels=[ida_sync.Label("a.exe", 0x10, "\u202e")])
        out = export_for_ida(ann)
        assert out["modules"] == {}
        assert out["skipped"]["empty"] == 1


# ── plan_import ─────────────────────────────────────────────────────
class TestPlanImport:
    def test_rva_and_ida_items(self, modmap: dict[str, ModuleInfo]) -> None:
        plan = plan_import(
            [
                {"rva": "0x1000", "name": "decrypt config", "comment": "from IDA"},
                {"ida_address": "0x140002000", "comment": "xor loop"},
                {"rva": 0x10, "name": "entry_stub"},
            ],
            module="sample.exe",
            module_map=modmap,
            ida_imagebase="0x140000000",
        )
        assert plan == [
            {
                "runtime_address": "0x7FF6A1231000",
                "rva": "0x1000",
                "label": "decrypt_config",
                "comment": "from IDA",
            },
            {"runtime_address": "0x7FF6A1232000", "rva": "0x2000", "label": None, "comment": "xor loop"},
            {"runtime_address": "0x7FF6A1230010", "rva": "0x10", "label": "entry_stub", "comment": None},
        ]
        json.dumps(plan)

    def test_ida_address_requires_imagebase(self, modmap: dict[str, ModuleInfo]) -> None:
        with pytest.raises(ValueError, match="ida_imagebase"):
            plan_import([{"ida_address": "0x140002000", "name": "x"}], module="sample.exe", module_map=modmap)

    @pytest.mark.parametrize(
        ("item", "match"),
        [
            ({"rva": "0x10", "ida_address": "0x140000010", "name": "x"}, "either"),
            ({"name": "x"}, "either"),
            ({"rva": "0x10"}, "name"),
            ({"rva": "0x10", "name": None, "comment": None}, "name"),
            ({"rva": "0x10", "name": "", "comment": "\x00\x01"}, "nothing"),
            ({"rva": "0x10", "name": 5}, "name"),
            ({"rva": "0x10", "comment": ["x"]}, "comment"),
            ({"rva": "zz", "name": "x"}, "rva"),
            ({"rva": hex(SAMPLE_SIZE), "name": "x"}, "outside"),
            ("not a mapping", "mapping"),
        ],
    )
    def test_invalid_items(self, modmap: dict[str, ModuleInfo], item: object, match: str) -> None:
        with pytest.raises(ValueError, match=match) as exc:
            plan_import(
                [{"rva": "0x1", "name": "fine"}, item],
                module="sample.exe",
                module_map=modmap,
                ida_imagebase=0x140000000,
            )
        assert "items[1]" in str(exc.value)

    def test_items_must_be_a_sequence(self, modmap: dict[str, ModuleInfo]) -> None:
        for bad in ("rva", b"x", {"rva": "0x1"}, None):
            with pytest.raises(ValueError):
                plan_import(bad, module="sample.exe", module_map=modmap)  # type: ignore[arg-type]

    def test_item_count_cap(self, modmap: dict[str, ModuleInfo], monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(ida_sync, "MAX_ITEMS", 3)
        items = [{"rva": hex(i), "name": f"n{i}"} for i in range(4)]
        with pytest.raises(ValueError, match="too many items"):
            plan_import(items, module="sample.exe", module_map=modmap)

    def test_unknown_module(self, modmap: dict[str, ModuleInfo]) -> None:
        with pytest.raises(ValueError, match="not found"):
            plan_import([{"rva": "0x1", "name": "x"}], module="other.dll", module_map=modmap)

    def test_accepts_export_document_items(self, modmap: dict[str, ModuleInfo]) -> None:
        ann = parse_x64dbg_db(fixture_bytes("db_sample.dd64.json"))
        items = export_for_ida(ann)["modules"]["sample.exe"]["items"]
        named = [it for it in items if "name" in it or "comment" in it]
        plan = plan_import(named, module="sample.exe", module_map=modmap)
        assert len(plan) == len(named)
        assert plan[0]["runtime_address"] == "0x7FF6A1231000"

    def test_accepts_unfiltered_export_items(self) -> None:
        db = {
            "labels": [{"module": "sample.exe", "address": "0x1000", "text": "decrypt_config"}],
            "bookmarks": [{"module": "sample.exe", "address": "0x1100"}],
            "breakpoints": [{"module": "sample.exe", "address": "0x1200", "type": 0, "enabled": True}],
        }
        items = export_for_ida(parse_x64dbg_db(json.dumps(db).encode()))["modules"]["sample.exe"]["items"]
        assert len(items) == 3
        mm = {"sample.exe": ModuleInfo("sample.exe", SAMPLE_BASE, SAMPLE_SIZE)}
        plan = plan_import(items, module="sample.exe", module_map=mm)
        assert [(p["rva"], p["label"]) for p in plan] == [("0x1000", "decrypt_config")]
        report = plan_import_report(items, module="sample.exe", module_map=mm)
        assert [s["index"] for s in report["skipped"]] == [1, 2]
        assert all("bookmark/breakpoint" in s["reason"] for s in report["skipped"])

    def test_report_skip_mode_collects_invalid_items(self, modmap: dict[str, ModuleInfo]) -> None:
        items = [
            {"rva": "0x10", "name": "ok"},
            {"rva": "zz", "name": "bad rva"},
            "not a mapping",
            {"rva": hex(SAMPLE_SIZE), "name": "past the end"},
            {"rva": "0x10"},
            {"rva": "0x20", "comment": "also ok"},
        ]
        report = plan_import_report(items, module="sample.exe", module_map=modmap, on_error="skip")
        assert [p["rva"] for p in report["plan"]] == ["0x10", "0x20"]
        assert [s["index"] for s in report["skipped"]] == [1, 2, 3, 4]
        assert report["module"] == "sample.exe"
        json.dumps(report)
        # the default mode keeps the all-or-nothing contract
        with pytest.raises(ValueError, match=r"items\[1\]"):
            plan_import_report(items, module="sample.exe", module_map=modmap)

    def test_report_rejects_unknown_mode_and_batch_errors(self, modmap: dict[str, ModuleInfo]) -> None:
        with pytest.raises(ValueError, match="on_error"):
            plan_import_report([], module="sample.exe", module_map=modmap, on_error="ignore")
        with pytest.raises(ValueError, match="not found"):
            plan_import_report(
                [{"rva": "0x1", "name": "x"}], module="x.dll", module_map=modmap, on_error="skip"
            )

    def test_name_without_safe_characters_goes_to_the_comment(self, modmap: dict[str, ModuleInfo]) -> None:
        report = plan_import_report(
            [
                {"rva": "0x10", "name": "복호화_루틴"},
                {"rva": "0x20", "name": "설정", "comment": "from IDA"},
            ],
            module="sample.exe",
            module_map=modmap,
        )
        first, second = report["plan"]
        assert first == {
            "runtime_address": "0x7FF6A1230010",
            "rva": "0x10",
            "label": None,
            "comment": "IDA name: 복호화_루틴",
        }
        assert (second["label"], second["comment"]) == (None, "IDA name: 설정 | from IDA")
        assert len(report["warnings"]) == 2 and "items[0]" in report["warnings"][0]
        assert plan_import(
            [{"rva": "0x10", "name": "복호화_루틴"}], module="sample.exe", module_map=modmap
        ) == [first]

    def test_overlong_strings_are_capped(self, modmap: dict[str, ModuleInfo]) -> None:
        (p,) = plan_import(
            [{"rva": "0x1", "name": "n" * 100_000, "comment": "가" * 100_000}],
            module="sample.exe",
            module_map=modmap,
        )
        assert len(p["label"]) <= LABEL_MAX_BYTES
        assert len(p["comment"].encode("utf-8")) <= COMMENT_MAX_BYTES


# ── sanitisers ──────────────────────────────────────────────────────
class TestSanitizeLabel:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("decrypt_config", "decrypt_config"),
            ("hello world", "hello_world"),
            ("  padded  ", "padded"),
            ("std::vector<int>::~vector", "std::vector<int>::~vector"),
            ("a@b?c$d.e", "a@b?c$d.e"),
            ("a  -  b", "a_b"),  # a run of invalid characters becomes one '_'
            ("__imp_CreateFileW", "__imp_CreateFileW"),  # existing underscores are kept
            ("ｍａｌｗａｒｅ", "malware"),  # NFKC folds full-width letters
            ("1stage", "_1stage"),  # would be read as a number in x64dbg expressions
            ("deadbeef", "_deadbeef"),  # x64dbg reads hex digits as a number before labels
            ("abc", "_abc"),
            ("CAFE", "_CAFE"),
            ("xdeadbeef", "_xdeadbeef"),  # 'x' hex prefix
            (".10", "_.10"),  # '.' decimal prefix
            ("rax", "_rax"),  # registers are resolved before labels
            ("RIP", "_RIP"),
            ("r15d", "_r15d"),
            ("cip", "_cip"),
            ("xmm7", "_xmm7"),
            ("dr7", "_dr7"),
            ("eflags", "_eflags"),
            ("_zf", "__zf"),  # x64dbg flag syntax
            ("cf", "__cf"),  # hex, and '_cf' would be a flag
            ("cafe_babe", "cafe_babe"),  # not a number
            ("raxx", "raxx"),
            ("x", "x"),
            ("0x401000", "_0x401000"),
            ("evil\u202egnp", "evil_gnp"),
            ("tab\there", "tab_here"),
        ],
    )
    def test_cases(self, raw: str, expected: str) -> None:
        assert sanitize_label(raw) == expected

    @pytest.mark.parametrize("raw", ["", "   ", "日本語", "\x00\x01", "___", "\u202e"])
    def test_never_empty(self, raw: str) -> None:
        assert sanitize_label(raw) == "lbl"
        assert sanitize_label(raw, fallback="lbl_1000") == "lbl_1000"

    def test_fallback_is_itself_sanitised(self) -> None:
        assert sanitize_label("", fallback="bad fallback!") == "bad_fallback_"
        assert sanitize_label("", fallback="") == "lbl"

    def test_overlong(self) -> None:
        assert len(sanitize_label("a" * 1000)) == LABEL_MAX_BYTES

    def test_rejects_non_str(self) -> None:
        with pytest.raises(ValueError):
            sanitize_label(None)  # type: ignore[arg-type]

    def test_property_random_unicode(self) -> None:
        rng = random.Random(7)
        for _ in range(500):
            s = "".join(
                chr(
                    rng.choice(
                        [
                            rng.randrange(0, 0x80),
                            rng.randrange(0x80, 0x3000),
                            rng.randrange(0xD800, 0xE000),
                            rng.randrange(0x10000, 0x10FFFF),
                        ]
                    )
                )
                for _ in range(rng.randint(0, 400))
            )
            out = sanitize_label(s)
            assert out
            assert set(out) <= LABEL_CHARSET
            assert len(out) <= LABEL_MAX_BYTES
            assert not out[0].isdigit()
            assert not X64DBG_NUMBER_RE.fullmatch(out)

    def test_overlong_hex_stays_reserved_safe(self) -> None:
        out = sanitize_label("a" * 300 + "_tail")
        assert len(out) == LABEL_MAX_BYTES
        assert not X64DBG_NUMBER_RE.fullmatch(out)


class TestSanitizeComment:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("plain", "plain"),
            ("a\x00b\x1bc", "abc"),
            ("line1\nline2\r\nline3", "line1 line2 line3"),
            ("tab\tsep", "tab sep"),
            ("bidi\u202e\u2066x\u2069", "bidix"),
            ("zero\u200bwidth\ufeff", "zerowidth"),
            ("악성 코드 설정 복호화", "악성 코드 설정 복호화"),
            ("emoji 🔑 ok", "emoji 🔑 ok"),
            ("lone \ud800 surrogate", "lone surrogate"),
            ("   ", ""),
            ("c1\x85next\x9b", "c1 next"),
            ("para\u2028sep", "para sep"),
        ],
    )
    def test_cases(self, raw: str, expected: str) -> None:
        assert sanitize_comment(raw) == expected

    def test_byte_cap_respects_utf8_boundaries(self) -> None:
        out = sanitize_comment("가" * 1000)
        assert len(out.encode("utf-8")) <= COMMENT_MAX_BYTES
        assert set(out) == {"가"}

    def test_rejects_non_str(self) -> None:
        with pytest.raises(ValueError):
            sanitize_comment(b"x")  # type: ignore[arg-type]

    def test_property_random_unicode(self) -> None:
        rng = random.Random(11)
        for _ in range(500):
            s = "".join(chr(rng.randrange(0, 0x110000)) for _ in range(rng.randint(0, 700)))
            out = sanitize_comment(s)
            assert len(out.encode("utf-8")) <= COMMENT_MAX_BYTES
            for ch in out:
                assert unicodedata.category(ch) not in {"Cc", "Cf", "Cs", "Zl", "Zp"}
            assert out == out.strip()
