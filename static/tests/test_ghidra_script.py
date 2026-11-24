"""Tests for static/ghidra/x64dbg_sync_ghidra.py against fake Ghidra objects (no Ghidra, no JVM).

From host/:  uv run pytest ../static/tests -q

The script imports no ``ghidra`` / ``java`` module at import time. Its Ghidra-facing
code takes the Ghidra classes it needs as one namespace (``load_ghidra_api()`` in
Ghidra), so these tests hand it fakes that model what Ghidra 12.2 was measured to
do (see static/README.md): duplicate label and function names are allowed,
whitespace is invalid, names longer than 2000 characters are refused, and
``SymbolUtilities.isReservedDynamicLabelName`` flags names such as ``FUN_140001000``.
"""

from __future__ import annotations

import importlib.util
import json
import types
from pathlib import Path

import pytest

STATIC_DIR = Path(__file__).resolve().parent.parent
SCRIPT = STATIC_DIR / "ghidra" / "x64dbg_sync_ghidra.py"


def _load() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("x64dbg_sync_ghidra_under_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


xg = _load()
core = xg.core

BASE = 0x140000000
ENTRY = BASE + 0x102C


# ── fake Ghidra ─────────────────────────────────────────────────────
class InvalidInputException(Exception):
    pass


class DuplicateNameException(Exception):
    pass


class SourceType:
    DEFAULT = "DEFAULT"
    ANALYSIS = "ANALYSIS"
    IMPORTED = "IMPORTED"
    USER_DEFINED = "USER_DEFINED"


class SymbolType:
    LABEL = "Label"
    FUNCTION = "Function"
    NAMESPACE = "Namespace"


class CommentType:
    EOL = "EOL"
    PRE = "PRE"
    POST = "POST"
    PLATE = "PLATE"
    REPEATABLE = "REPEATABLE"

    @staticmethod
    def values() -> list[str]:
        return ["EOL", "PRE", "POST", "PLATE", "REPEATABLE"]


class SymbolUtilities:
    MAX_SYMBOL_NAME_LENGTH = 2000

    @staticmethod
    def isReservedDynamicLabelName(name: str, factory: object) -> bool:  # noqa: N802 - Ghidra API name
        prefix, _, rest = name.partition("_")
        return prefix in {"FUN", "LAB", "DAT", "PTR", "BYTE"} and len(rest) >= 4 and all(
            c in "0123456789abcdefABCDEF" for c in rest
        )


class Addr:
    def __init__(self, offset: int) -> None:
        self.offset = offset & (2**64 - 1)

    def getOffset(self) -> int:  # noqa: N802
        return self.offset - 2**64 if self.offset >= 2**63 else self.offset

    def getUnsignedOffset(self) -> int:  # noqa: N802
        return self.offset

    def isMemoryAddress(self) -> bool:  # noqa: N802
        return True

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Addr) and other.offset == self.offset

    def __hash__(self) -> int:
        return hash(self.offset)

    def __repr__(self) -> str:
        return f"Addr(0x{self.offset:x})"


class Space:
    def getAddress(self, offset: int) -> Addr:  # noqa: N802
        if not -(2**63) <= offset < 2**63:
            raise OverflowError("Java long")
        return Addr(offset)


class Factory:
    def getDefaultAddressSpace(self) -> Space:  # noqa: N802
        return Space()


class Namespace:
    def isGlobal(self) -> bool:  # noqa: N802
        return True


class Block:
    def __init__(self, name: str) -> None:
        self.name = name

    def getName(self) -> str:  # noqa: N802
        return self.name


class Memory:
    def __init__(self, ranges: list[tuple[int, int, str]]) -> None:
        self.ranges = ranges

    def contains(self, addr: Addr) -> bool:
        return self.getBlock(addr) is not None

    def getBlock(self, addr: Addr) -> Block | None:  # noqa: N802
        for start, end, name in self.ranges:
            if start <= addr.offset < end:
                return Block(name)
        return None


class Symbol:
    def __init__(self, table: SymbolTable, addr: Addr, name: str, source: str, stype: str) -> None:
        self.table, self.addr, self.name, self.source, self.stype = table, addr, name, source, stype
        self.external = False

    def getName(self, include_namespace: bool = False) -> str:  # noqa: N802
        return self.name

    def getAddress(self) -> Addr:  # noqa: N802
        return self.addr

    def getSource(self) -> str:  # noqa: N802
        return self.source

    def getSymbolType(self) -> str:  # noqa: N802
        return self.stype

    def isExternal(self) -> bool:  # noqa: N802
        return self.external

    def getParentNamespace(self) -> Namespace:  # noqa: N802
        return Namespace()

    def isPrimary(self) -> bool:  # noqa: N802
        return self.table.primary.get(self.addr) is self

    def setPrimary(self) -> bool:  # noqa: N802
        self.table.primary[self.addr] = self
        return True


class Function:
    def __init__(self, table: SymbolTable, entry: Addr, name: str) -> None:
        self.symbol = Symbol(table, entry, name, SourceType.ANALYSIS, SymbolType.FUNCTION)
        table.symbols.append(self.symbol)
        table.primary[entry] = self.symbol
        self.entry = entry
        self.fail_with: Exception | None = None

    def getName(self) -> str:  # noqa: N802
        return self.symbol.name

    def setName(self, name: str, source: str) -> None:  # noqa: N802
        if self.fail_with is not None:
            raise self.fail_with
        if not name or any(c.isspace() for c in name):
            raise InvalidInputException("Symbol name contains invalid characters")
        self.symbol.name, self.symbol.source = name, source

    def getEntryPoint(self) -> Addr:  # noqa: N802
        return self.entry


class SymbolTable:
    def __init__(self) -> None:
        self.symbols: list[Symbol] = []
        self.primary: dict[Addr, Symbol] = {}

    def getSymbols(self, addr: Addr) -> list[Symbol]:  # noqa: N802
        return [s for s in self.symbols if s.addr == addr]

    def createLabel(self, addr: Addr, name: str, source: str) -> Symbol:  # noqa: N802
        if not name or any(c.isspace() for c in name):
            raise InvalidInputException("Symbol name contains invalid characters")
        if len(name) > 2000:
            raise InvalidInputException("Symbol name exceeds maximum length of 2000")
        sym = Symbol(self, addr, name, source, SymbolType.LABEL)
        self.symbols.append(sym)
        self.primary.setdefault(addr, sym)
        return sym

    def getAllSymbols(self, include_dynamic: bool) -> list[Symbol]:  # noqa: N802
        return list(self.symbols)


class FunctionManager:
    def __init__(self) -> None:
        self.functions: dict[Addr, Function] = {}

    def getFunctionAt(self, addr: Addr) -> Function | None:  # noqa: N802
        return self.functions.get(addr)


class Listing:
    def __init__(self) -> None:
        self.comments: dict[tuple[str, Addr], str] = {}

    def getComment(self, ctype: str, addr: Addr) -> str | None:  # noqa: N802
        return self.comments.get((ctype, addr))

    def setComment(self, addr: Addr, ctype: str, text: str | None) -> None:  # noqa: N802
        if text is None:
            self.comments.pop((ctype, addr), None)
        else:
            self.comments[(ctype, addr)] = text

    def getCommentAddressIterator(self, ctype: str, addr_set: object, forward: bool) -> list[Addr]:  # noqa: N802
        return sorted({a for (t, a) in self.comments if t == ctype}, key=lambda a: a.offset)


class Program:
    def __init__(self, name: str = "e2e_sample_x86_64.exe", in_transaction: bool = True) -> None:
        self.name = name
        self.symtab = SymbolTable()
        self.fm = FunctionManager()
        self.listing = Listing()
        self.memory = Memory([(BASE, BASE + 0x1000, "Headers"), (BASE + 0x1000, BASE + 0x1A000, ".text"),
                              (BASE + 0x1A000, BASE + 0x20000, ".rdata")])
        self.in_transaction = in_transaction
        self.transactions: list[tuple[str, bool]] = []

    def add_function(self, offset: int, name: str) -> Function:
        func = Function(self.symtab, Addr(offset), name)
        self.fm.functions[Addr(offset)] = func
        return func

    def getName(self) -> str:  # noqa: N802
        return self.name

    def getExecutablePath(self) -> str:  # noqa: N802
        return "/work/" + self.name

    def getImageBase(self) -> Addr:  # noqa: N802
        return Addr(BASE)

    def getAddressFactory(self) -> Factory:  # noqa: N802
        return Factory()

    def getMemory(self) -> Memory:  # noqa: N802
        return self.memory

    def getListing(self) -> Listing:  # noqa: N802
        return self.listing

    def getSymbolTable(self) -> SymbolTable:  # noqa: N802
        return self.symtab

    def getFunctionManager(self) -> FunctionManager:  # noqa: N802
        return self.fm

    def getCurrentTransactionInfo(self) -> object | None:  # noqa: N802
        return object() if self.in_transaction else None

    def startTransaction(self, description: str) -> int:  # noqa: N802
        self.transactions.append((description, False))
        return len(self.transactions)

    def endTransaction(self, tx: int, commit: bool) -> None:  # noqa: N802
        self.transactions[tx - 1] = (self.transactions[tx - 1][0], commit)


class Monitor:
    def __init__(self, cancel_after: int | None = None) -> None:
        self.cancel_after = cancel_after
        self.checks = 0

    def isCancelled(self) -> bool:  # noqa: N802
        self.checks += 1
        return self.cancel_after is not None and self.checks > self.cancel_after


API = types.SimpleNamespace(
    SourceType=SourceType, SymbolType=SymbolType, SymbolUtilities=SymbolUtilities, CommentType=CommentType,
    CodeUnit=None, DuplicateNameException=DuplicateNameException, InvalidInputException=InvalidInputException,
)

PROBE_ITEMS = [
    {"rva": "0x102c", "name": "gw_probe_entry", "comment": "set by x64dbg_sync import probe"},
    {"rva": "0x102c", "bookmark": True},
]


def write_doc(tmp_path: Path, items: list[dict], module: str = "e2e_sample_x86_64.exe") -> str:
    path = tmp_path / "doc.json"
    path.write_text(json.dumps({"schema": "x64dbg-ida-sync/1", "generated_by": "t",
                                "modules": {module: {"base_runtime": None, "items": items}}}), encoding="utf-8")
    return str(path)


def names_at(program: Program, offset: int) -> list[tuple[str, str, bool]]:
    return [(s.name, s.source, s.isPrimary()) for s in program.symtab.getSymbols(Addr(offset))]


# ── loading and arguments ───────────────────────────────────────────
def test_script_header_and_hygiene() -> None:
    src = SCRIPT.read_text(encoding="utf-8")
    assert "# @runtime PyGhidra" in src
    assert "# @category x64dbg" in src
    assert "\nimport ghidra" not in src and "\nfrom ghidra" not in src and "\nimport java" not in src


def test_core_lookup(tmp_path: Path) -> None:
    (tmp_path / "x64dbg_sync_core.py").write_text("", encoding="utf-8")
    assert xg.find_core(str(tmp_path / "x64dbg_sync_ghidra.py")) == str(tmp_path / "x64dbg_sync_core.py")
    assert xg.find_core(str(SCRIPT)).endswith("common/x64dbg_sync_core.py")
    with pytest.raises(ImportError):
        xg.find_core(str(tmp_path / "nowhere" / "x.py"))


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        (["import", "/d.json"], {"action": "import", "path": "/d.json", "module": None, "comment": "eol"}),
        (["import", "/d.json", "sample.exe"], {"action": "import", "path": "/d.json", "module": "sample.exe",
                                               "comment": "eol"}),
        (["IMPORT", "/d.json", "--comment=pre"], {"action": "import", "path": "/d.json", "module": None,
                                                  "comment": "pre"}),
        (["export", "/o.json"], {"action": "export", "path": "/o.json", "module": None, "comment": "eol"}),
        (["export", "/o.json", "--all-comments"], {"action": "export", "path": "/o.json", "module": None,
                                                   "comment": "eol", "all_comments": True}),
    ],
)
def test_parse_script_args(args: list[str], expected: dict) -> None:
    out = xg.parse_script_args(args)
    expected.setdefault("all_comments", False)
    assert out == expected


@pytest.mark.parametrize("args", [["frob", "x"], ["import"], ["export"], ["import", "a", "b", "c"],
                                  ["import", "a", "--comment=post"], ["export", "a", "--what"]])
def test_parse_script_args_rejects(args: list[str]) -> None:
    with pytest.raises(ValueError):
        xg.parse_script_args(args)


# ── import ──────────────────────────────────────────────────────────
def test_import_renames_the_function_and_merges_comments(tmp_path: Path) -> None:
    program = Program()
    program.add_function(ENTRY, "entry")
    counts = xg.import_into(program, write_doc(tmp_path, PROBE_ITEMS), api=API)
    assert program.fm.getFunctionAt(Addr(ENTRY)).getName() == "gw_probe_entry"
    assert program.fm.getFunctionAt(Addr(ENTRY)).symbol.source == SourceType.USER_DEFINED
    assert program.listing.getComment("EOL", Addr(ENTRY)) == "set by x64dbg_sync import probe\n[x64dbg: bookmark]"
    assert (counts["renamed"], counts["commented"], counts["module"], counts["imagebase"]) == (
        1, 2, "e2e_sample_x86_64.exe", "0x140000000")


def test_import_is_idempotent(tmp_path: Path) -> None:
    program = Program()
    program.add_function(ENTRY, "entry")
    path = write_doc(tmp_path, PROBE_ITEMS)
    xg.import_into(program, path, api=API)
    snapshot = (names_at(program, ENTRY), dict(program.listing.comments))
    again = xg.import_into(program, path, api=API)
    assert (names_at(program, ENTRY), dict(program.listing.comments)) == snapshot
    assert (again["renamed"], again["name_unchanged"], again["commented"], again["comment_unchanged"]) == (0, 1, 0, 2)


def test_import_creates_a_primary_user_label_without_a_function(tmp_path: Path) -> None:
    program = Program()
    old = program.symtab.createLabel(Addr(ENTRY), "imported_name", SourceType.IMPORTED)
    old.setPrimary()
    xg.import_into(program, write_doc(tmp_path, [{"rva": "0x102c", "name": "gw_label"}]), api=API)
    assert names_at(program, ENTRY) == [("imported_name", "IMPORTED", False), ("gw_label", "USER_DEFINED", True)]
    again = xg.import_into(program, write_doc(tmp_path, [{"rva": "0x102c", "name": "gw_label"}]), api=API)
    assert again["name_unchanged"] == 1 and len(names_at(program, ENTRY)) == 2


def test_import_pre_comments(tmp_path: Path) -> None:
    program = Program()
    program.listing.setComment(Addr(ENTRY), "PRE", "existing pre")
    xg.import_into(program, write_doc(tmp_path, PROBE_ITEMS), comment_type="pre", api=API)
    assert program.listing.getComment("PRE", Addr(ENTRY)) == (
        "existing pre\nset by x64dbg_sync import probe\n[x64dbg: bookmark]")
    assert program.listing.getComment("EOL", Addr(ENTRY)) is None


def test_reserved_dynamic_names_get_a_prefix(tmp_path: Path) -> None:
    program = Program()
    xg.import_into(program, write_doc(tmp_path, [{"rva": "0x102c", "name": "FUN_140001000"}]), api=API)
    assert ("_FUN_140001000", "USER_DEFINED", True) in names_at(program, ENTRY)


def test_ghidra_rules_keep_names_ida_would_rewrite(tmp_path: Path) -> None:
    program = Program()
    xg.import_into(program, write_doc(tmp_path, [{"rva": "0x102c", "name": "std::vector<int>::at"},
                                                 {"rva": "0x1030", "name": "복호화 루틴"}]), api=API)
    assert names_at(program, ENTRY)[0][0] == "std::vector<int>::at"
    assert names_at(program, BASE + 0x1030)[0][0] == "복호화_루틴"


def test_invalid_names_and_tool_errors_are_counted(tmp_path: Path) -> None:
    program = Program()
    program.add_function(ENTRY, "entry").fail_with = InvalidInputException("nope")
    counts = xg.import_into(program, write_doc(tmp_path, PROBE_ITEMS), api=API)
    assert counts["rename_failed"] == 1 and counts["commented"] == 2


def test_duplicate_function_names_fall_back_to_a_suffix(tmp_path: Path) -> None:
    program = Program()
    func = program.add_function(ENTRY, "entry")
    calls = []
    original = func.setName

    def picky(name: str, source: str) -> None:
        calls.append(name)
        if name == "gw_probe_entry":
            raise DuplicateNameException("in use")
        original(name, source)

    func.setName = picky
    counts = xg.import_into(program, write_doc(tmp_path, PROBE_ITEMS), api=API)
    assert calls == ["gw_probe_entry", "gw_probe_entry_1"]
    assert func.getName() == "gw_probe_entry_1" and counts["renamed"] == 1


def test_unmapped_and_unknown_module(tmp_path: Path) -> None:
    program = Program()
    counts = xg.import_into(program, write_doc(tmp_path, [{"rva": "0x90000", "name": "far"}]), api=API)
    assert counts["unmapped"] == 1
    with pytest.raises(ValueError, match="e2e_sample_x86_64.exe"):
        xg.import_into(Program("other.bin"), write_doc(tmp_path, PROBE_ITEMS), api=API)
    counts = xg.import_into(Program("other.bin"), write_doc(tmp_path, PROBE_ITEMS), module="e2e_sample_x86_64",
                            api=API)
    assert counts["module"] == "e2e_sample_x86_64.exe"


def test_import_opens_a_transaction_only_when_none_is_open(tmp_path: Path) -> None:
    inside = Program(in_transaction=True)
    xg.import_into(inside, write_doc(tmp_path, PROBE_ITEMS), api=API)
    assert inside.transactions == []
    outside = Program(in_transaction=False)
    xg.import_into(outside, write_doc(tmp_path, PROBE_ITEMS), api=API)
    assert outside.transactions == [("x64dbg sync import", True)]


def test_import_can_be_cancelled(tmp_path: Path) -> None:
    program = Program()
    counts = xg.import_into(program, write_doc(tmp_path, PROBE_ITEMS), monitor=Monitor(cancel_after=0), api=API)
    assert counts["cancelled"] is True and counts["processed"] == 0


def test_high_addresses_are_passed_as_signed_longs() -> None:
    ops = xg.GhidraOps(Program(), api=API)
    assert ops.to_address(2**64 - 0x10).getUnsignedOffset() == 2**64 - 0x10
    assert xg.to_signed64(2**63) == -(2**63)
    assert xg.to_signed64(5) == 5


# ── export ──────────────────────────────────────────────────────────
def test_export_writes_user_names_and_comments(tmp_path: Path) -> None:
    program = Program()
    program.add_function(ENTRY, "entry")
    program.add_function(BASE + 0x2000, "FUN_140002000")  # analysis name: not exported
    xg.import_into(program, write_doc(tmp_path, PROBE_ITEMS), api=API)
    program.symtab.createLabel(Addr(BASE + 0x3000), "my_label", SourceType.USER_DEFINED)
    program.symtab.createLabel(Addr(BASE + 0x3100), "imported_sym", SourceType.IMPORTED)
    ext = program.symtab.createLabel(Addr(BASE + 0x3200), "external_thing", SourceType.USER_DEFINED)
    ext.external = True
    program.listing.setComment(Addr(BASE + 0x4000), "PLATE", "plate note")
    program.listing.setComment(Addr(BASE + 0x4000), "POST", "post note")
    program.listing.setComment(Addr(BASE + 0x180), "EOL", ".text")  # PE header markup (Headers block)
    # loader markup Ghidra 12.2 wrote into .rdata of the E2E sample
    for offset, kind, text in ((0x1DA58, "EOL", "IMAGE_THUNK_DATA64"), (0x1DAC8, "PRE", "0  NtClose  <<not bound>>"),
                               (0x1DC0E, "EOL", "IMAGE_IMPORT_DESCRIPTOR - DLL NAME"),
                               (0x1DFFF, "EOL", ".NET PDB Info")):
        program.listing.setComment(Addr(BASE + offset), kind, text)  # raw strings as Ghidra stores them
    out = tmp_path / "out.json"
    result = xg.export_from(program, str(out), api=API)
    doc = json.loads(out.read_text(encoding="utf-8"))
    mod = doc["modules"]["e2e_sample_x86_64.exe"]
    assert doc["generated_by"].startswith("x64dbg_sync_ghidra.py")
    assert mod["ida_imagebase"] == "0x140000000"
    assert mod["items"] == [
        {"rva": "0x102C", "name": "gw_probe_entry", "comment": "set by x64dbg_sync import probe [x64dbg: bookmark]"},
        {"rva": "0x3000", "name": "my_label"},
        {"rva": "0x4000", "comment": "plate note | post note"},
    ]
    assert result == {"module": "e2e_sample_x86_64.exe", "items": 3, "path": str(out)}
    xg.export_from(program, str(out), all_comments=True, api=API)
    rvas = [i["rva"] for i in json.loads(out.read_text(encoding="utf-8"))["modules"]["e2e_sample_x86_64.exe"]["items"]]
    assert {"0x180", "0x1DA58", "0x1DAC8", "0x1DC0E", "0x1DFFF"} <= set(rvas)


def test_export_is_accepted_by_the_r2_rules_and_back(tmp_path: Path) -> None:
    program = Program()
    program.add_function(ENTRY, "entry")
    xg.import_into(program, write_doc(tmp_path, PROBE_ITEMS), api=API)
    out = tmp_path / "rt.json"
    xg.export_from(program, str(out), api=API)
    doc = core.load_sync_document(out.read_bytes(), core.RADARE2)
    plan = core.build_import_plan(doc, "e2e_sample_x86_64.exe", BASE, core.RADARE2)
    assert plan[0]["name"] == "gw_probe_entry" and plan[0]["address"] == ENTRY


# ── script entry point ──────────────────────────────────────────────
class Globals(dict):
    def __init__(self, program: Program, args: list[str], **asks: object) -> None:
        super().__init__()
        self.out: list[str] = []
        self.err: list[str] = []
        self["currentProgram"] = program
        self["monitor"] = Monitor()
        self["getScriptArgs"] = lambda: list(args)
        self["println"] = self.out.append
        self["printerr"] = self.err.append
        self["isRunningHeadless"] = lambda: not asks
        for key, value in asks.items():
            self[key] = value


def test_run_headless_import_and_export(tmp_path: Path) -> None:
    program = Program()
    program.add_function(ENTRY, "entry")
    g = Globals(program, ["import", write_doc(tmp_path, PROBE_ITEMS)])
    xg.run(g, api=API)
    assert any("renamed 1" in line for line in g.out), g.out
    out = tmp_path / "x.json"
    g2 = Globals(program, ["export", str(out)])
    xg.run(g2, api=API)
    assert out.is_file() and any("exported 1 items" in line for line in g2.out)


def test_run_reports_bad_input_without_a_traceback(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{}", encoding="utf-8")
    g = Globals(Program(), ["import", str(bad)])
    xg.run(g, api=API)
    assert any("import failed" in line and "no schema" in line for line in g.err)
    g = Globals(Program(), ["nonsense"])
    xg.run(g, api=API)
    assert any("usage" in line.lower() for line in g.err)


def test_run_interactive_asks_for_action_and_file(tmp_path: Path) -> None:
    program = Program()
    program.add_function(ENTRY, "entry")
    path = write_doc(tmp_path, PROBE_ITEMS)
    asked = []

    def ask_choice(title: str, message: str, choices: list, default: object) -> object:
        asked.append(("choice", message, list(choices)))
        return choices[0] if "Action" in message else choices[0]

    def ask_file(title: str, button: str) -> object:
        asked.append(("file", title))
        return types.SimpleNamespace(getAbsolutePath=lambda: path)

    g = Globals(program, [], askChoice=ask_choice, askFile=ask_file, askString=lambda *a: "")
    xg.run(g, api=API)
    assert asked[0][0] == "choice" and asked[0][2][:2] == ["import", "export"]
    assert program.fm.getFunctionAt(Addr(ENTRY)).getName() == "gw_probe_entry"


def test_run_interactive_asks_for_the_module_when_nothing_matches(tmp_path: Path) -> None:
    program = Program("renamed.bin")
    path = write_doc(tmp_path, PROBE_ITEMS)
    choices = iter(["import"])
    g = Globals(
        program, [],
        askChoice=lambda title, message, options, default: next(choices) if "Action" in message else options[0],
        askFile=lambda title, button: types.SimpleNamespace(getAbsolutePath=lambda: path),
        askString=lambda title, message, default: "e2e_sample_x86_64.exe",
    )
    xg.run(g, api=API)
    assert ("gw_probe_entry", "USER_DEFINED", True) in names_at(program, ENTRY)
