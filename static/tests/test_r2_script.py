"""Tests for static/radare2/x64dbg_sync_r2.py with a fake r2/rizin pipe (no real tool).

From host/:  uv run pytest ../static/tests -q

``FakeCore`` models the behaviour measured on radare2 6.2.6 and rizin 0.9.1 (see
static/README.md): flag names are unique (setting an existing name moves the
flag), ``fj``/``flj`` list only the selected flagspace, ``CCu base64:`` replaces
the comment at an address, JSON keys are ``addr`` (radare2) / ``offset`` (rizin).
It records every command line so the tests can check that no document text ever
reaches a command unencoded.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import re
import types
from pathlib import Path

import pytest

STATIC_DIR = Path(__file__).resolve().parent.parent
SCRIPT = STATIC_DIR / "radare2" / "x64dbg_sync_r2.py"


def _load() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("x64dbg_sync_r2_under_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


xr = _load()
core = xr.core

BASE = 0x140000000
ENTRY = BASE + 0x102C
SAFE_CMD_RE = re.compile(r"[A-Za-z0-9_.*:+/= @-]*")  # what may appear in a command line we send


class FakeCore:
    """A tiny r2/rizin: flags, flagspaces, functions, comments, sections."""

    def __init__(self, flavor: str = "radare2", file: str = "/work/e2e_sample_x86_64.exe") -> None:
        self.flavor = flavor
        self.file = file
        self.flags: dict[str, tuple[int, str | None]] = {"entry0": (ENTRY, "symbols"), "rip": (ENTRY, "registers")}
        self.spaces = {"symbols", "registers", "sections"}
        self.selected: str | None = None  # None = "*"
        self.functions: dict[int, str] = {}
        self.comments: dict[int, str] = {BASE + 0x1000: "[00] -r-x section size 102400 named .text"}
        self.sections = [(BASE + 0x1000, 0x19000)]
        self.calls: list[str] = []
        self.saved: list[str] = []
        self.analysed = False
        self.ignore_afn = False

    # helpers
    def _key(self) -> str:
        return "addr" if self.flavor == "radare2" else "offset"

    def _split_at(self, cmd: str) -> tuple[str, int | None]:
        if " @ " in cmd:
            head, at = cmd.rsplit(" @ ", 1)
            return head, int(at, 0)
        return cmd, None

    def _func_containing(self, addr: int) -> int | None:
        for start in self.functions:
            if start <= addr < start + 0x100:
                return start
        return None

    def cmd(self, cmd: str) -> str:  # noqa: C901 - a dispatcher
        self.calls.append(cmd)
        head, at = self._split_at(cmd)
        k = self._key()
        if head == "ij":
            return json.dumps({"core": {"file": self.file}, "bin": {"baddr": BASE}})
        if head == "iSj":
            return json.dumps([{"name": ".text", "vaddr": a, "vsize": s, "size": s} for a, s in self.sections])
        if head in ("fsj", "fslj"):
            return json.dumps([{"name": n, "count": 0, "selected": n == self.selected} for n in sorted(self.spaces)])
        if head == "fs *":
            self.selected = None
            return ""
        if head.startswith("fs "):
            self.selected = head[3:]
            self.spaces.add(self.selected)
            return ""
        if head in ("fj", "flj"):
            return json.dumps([
                {"name": n, "size": 1, k: a} for n, (a, s) in self.flags.items()
                if self.selected is None or s == self.selected
            ])
        m = re.fullmatch(r"f ([A-Za-z0-9_.]+)", head)
        if m and at is not None:
            self.flags[m.group(1)] = (at, self.selected)  # moves an existing flag of that name
            return ""
        m = re.fullmatch(r"f- ([A-Za-z0-9_.]+)" if self.flavor == "rizin" else r"f-([A-Za-z0-9_.]+)", head)
        if m:
            self.flags.pop(m.group(1), None)
            return ""
        if head == "afij" and at is not None:
            start = self._func_containing(at)
            return json.dumps([] if start is None else [{k: start, "name": self.functions[start], "size": 0x100}])
        m = re.fullmatch(r"afn ([A-Za-z0-9_.]+)", head)
        if m and at is not None:
            start = self._func_containing(at)
            if start is not None and not self.ignore_afn:
                old = self.functions[start]
                self.flags.pop(old, None)
                self.functions[start] = m.group(1)
                self.flags[m.group(1)] = (start, "functions")
            return ""
        if head == "aflj":
            return json.dumps([{k: a, "name": n} for a, n in sorted(self.functions.items())])
        if head == "aa":
            self.analysed = True
            self.functions.setdefault(ENTRY, "entry0")
            return ""
        if head == "CC." and at is not None:
            text = self.comments.get(at)
            return text + "\n" if text else ""
        m = re.fullmatch(r"CCu base64:([A-Za-z0-9+/=]*)", head)
        if m and at is not None:
            self.comments[at] = base64.b64decode(m.group(1)).decode("utf-8")
            return ""
        if head == "CC*" and self.flavor == "radare2":
            return "".join(
                f"CCu base64:{base64.b64encode(t.encode()).decode()} @ 0x{a:x}\n"
                for a, t in sorted(self.comments.items())
            )
        if head == "CClj" and self.flavor == "rizin":
            # rizin escapes non-ASCII bytes as \\xNN in this listing; the script must not rely on its text
            return json.dumps([{"offset": a, "type": "CCu", "name": "garbled"} for a in sorted(self.comments)])
        if head.startswith("Ps "):
            self.saved.append(head[3:])
            return ""
        if head == "e dir.projects":
            return "/work/.local/share/radare2/projects\n"
        if head == "Pl":
            return ""
        return ""


def make_doc(items: list[dict], module: str = "e2e_sample_x86_64.exe") -> dict:
    return {"schema": "x64dbg-ida-sync/1", "generated_by": "test",
            "modules": {module: {"base_runtime": "0x7FF6A0000000", "items": items}}}


PROBE_ITEMS = [
    {"rva": "0x102c", "name": "gw_probe_entry", "comment": "set by x64dbg_sync import probe"},
    {"rva": "0x102c", "bookmark": True},
]


def write_doc(tmp_path: Path, items: list[dict], module: str = "e2e_sample_x86_64.exe") -> str:
    path = tmp_path / "doc.json"
    path.write_text(json.dumps(make_doc(items, module)), encoding="utf-8")
    return str(path)


def ops_for(fake: FakeCore) -> object:
    return xr.R2Ops(xr.Commands(fake.cmd, fake.flavor))


def flags_at(fake: FakeCore, addr: int) -> dict[str, str | None]:
    return {n: s for n, (a, s) in fake.flags.items() if a == addr}


# ── loading ─────────────────────────────────────────────────────────
def test_script_imports_without_r2pipe() -> None:
    assert xr.SCRIPT_VERSION
    assert xr.core.SCHEMA == "x64dbg-ida-sync/1"
    src = SCRIPT.read_text(encoding="utf-8")
    assert "\nimport r2pipe" not in src and "\nimport rzpipe" not in src and "\nimport cutter" not in src


def test_core_is_found_next_to_the_script_first(tmp_path: Path) -> None:
    (tmp_path / "x64dbg_sync_core.py").write_text("MARK = 'local copy'\n", encoding="utf-8")
    assert xr.find_core(str(tmp_path / "x64dbg_sync_r2.py")) == str(tmp_path / "x64dbg_sync_core.py")
    assert xr.find_core(str(SCRIPT)).endswith("common/x64dbg_sync_core.py")
    with pytest.raises(ImportError, match="x64dbg_sync_core.py"):
        xr.find_core(str(tmp_path / "sub" / "x.py"))


# ── command adapter ─────────────────────────────────────────────────
@pytest.mark.parametrize("flavor", ["radare2", "rizin"])
def test_commands_adapter_flavours(flavor: str) -> None:
    c = xr.Commands(lambda _c: None, flavor)
    assert c.cmd("anything") == ""
    assert c.cmdj("anything") is None
    assert c.flag_list == ("fj" if flavor == "radare2" else "flj")
    assert c.space_list == ("fsj" if flavor == "radare2" else "fslj")
    assert c.remove_flag("x") == ("f-x" if flavor == "radare2" else "f- x")
    with pytest.raises(ValueError):
        xr.Commands(lambda _c: "", "ghidra")


def test_commands_cmdj_tolerates_garbage() -> None:
    c = xr.Commands(lambda _c: "not json", "radare2")
    assert c.cmdj("x") is None
    assert xr.Commands(lambda _c: '{"a": 1}\n', "rizin").cmdj("x") == {"a": 1}


def test_adapter_constructors() -> None:
    class Pipe:
        def cmd(self, c: str) -> str:
            return "ok:" + c

    assert xr.Commands.from_r2pipe(Pipe()).flavor == "radare2"
    assert xr.Commands.from_rzpipe(Pipe()).cmd("x") == "ok:x"
    cutter = types.SimpleNamespace(cmd=lambda c: "cutter:" + c)
    c = xr.Commands.from_cutter(cutter)
    assert (c.flavor, c.cmd("ij")) == ("rizin", "cutter:ij")


# ── import ──────────────────────────────────────────────────────────
@pytest.mark.parametrize("flavor", ["radare2", "rizin"])
def test_import_without_function_sets_a_flag_and_comment(tmp_path: Path, flavor: str) -> None:
    fake = FakeCore(flavor)
    counts = xr.import_document(ops_for(fake), write_doc(tmp_path, PROBE_ITEMS))
    assert counts["module"] == "e2e_sample_x86_64.exe"
    assert counts["imagebase"] == "0x140000000"
    assert flags_at(fake, ENTRY)["gw_probe_entry"] == "x64dbg"
    assert fake.comments[ENTRY] == "set by x64dbg_sync import probe\n[x64dbg: bookmark]"
    assert (counts["renamed"], counts["commented"]) == (1, 2)
    assert fake.selected is None  # the user's flagspace selection is restored


@pytest.mark.parametrize("flavor", ["radare2", "rizin"])
def test_import_is_idempotent(tmp_path: Path, flavor: str) -> None:
    fake = FakeCore(flavor)
    path = write_doc(tmp_path, PROBE_ITEMS)
    xr.import_document(ops_for(fake), path)
    before = (dict(fake.flags), dict(fake.comments))
    again = xr.import_document(ops_for(fake), path)
    assert (dict(fake.flags), dict(fake.comments)) == before
    assert (again["renamed"], again["name_unchanged"], again["commented"], again["comment_unchanged"]) == (0, 1, 0, 2)


@pytest.mark.parametrize("flavor", ["radare2", "rizin"])
def test_import_renames_a_function_with_afn(tmp_path: Path, flavor: str) -> None:
    fake = FakeCore(flavor)
    fake.cmd("aa")
    counts = xr.import_document(ops_for(fake), write_doc(tmp_path, PROBE_ITEMS))
    assert fake.functions[ENTRY] == "gw_probe_entry"
    assert f"afn gw_probe_entry @ 0x{ENTRY:x}" in fake.calls
    assert not any(s == "x64dbg" for s in flags_at(fake, ENTRY).values())  # no extra flag for a function
    assert counts["renamed"] == 1
    again = xr.import_document(ops_for(fake), write_doc(tmp_path, PROBE_ITEMS))
    assert (again["renamed"], again["name_unchanged"]) == (0, 1)


def test_failed_afn_is_reported(tmp_path: Path) -> None:
    fake = FakeCore("radare2")
    fake.cmd("aa")
    fake.ignore_afn = True
    counts = xr.import_document(ops_for(fake), write_doc(tmp_path, PROBE_ITEMS))
    assert counts["rename_failed"] == 1


def test_import_replaces_its_own_earlier_flag(tmp_path: Path) -> None:
    fake = FakeCore("rizin")
    xr.import_document(ops_for(fake), write_doc(tmp_path, [{"rva": "0x102c", "name": "first_name"}]))
    xr.import_document(ops_for(fake), write_doc(tmp_path, [{"rva": "0x102c", "name": "second_name"}]))
    ours = [n for n, s in flags_at(fake, ENTRY).items() if s == "x64dbg"]
    assert ours == ["second_name"]
    assert "entry0" in fake.flags  # flags of other spaces are never touched


def test_import_never_moves_a_flag_of_the_same_name(tmp_path: Path) -> None:
    fake = FakeCore("radare2")
    fake.flags["decrypt"] = (BASE + 0x5000, "symbols")
    counts = xr.import_document(ops_for(fake), write_doc(tmp_path, [{"rva": "0x102c", "name": "decrypt"}]))
    assert fake.flags["decrypt"] == (BASE + 0x5000, "symbols")
    assert fake.flags["decrypt_1"] == (ENTRY, "x64dbg")
    assert counts["renamed"] == 1


def test_import_name_already_present_at_the_address_is_unchanged(tmp_path: Path) -> None:
    fake = FakeCore("radare2")
    counts = xr.import_document(ops_for(fake), write_doc(tmp_path, [{"rva": "0x102c", "name": "entry0"}]))
    assert counts["name_unchanged"] == 1
    assert flags_at(fake, ENTRY)["entry0"] == "symbols"


def test_comments_are_merged_with_existing_ones(tmp_path: Path) -> None:
    fake = FakeCore("radare2")
    xr.import_document(ops_for(fake), write_doc(tmp_path, [{"rva": "0x1000", "comment": "start of text"}]))
    assert fake.comments[BASE + 0x1000] == "[00] -r-x section size 102400 named .text\nstart of text"


def test_hostile_text_never_reaches_a_command_line(tmp_path: Path) -> None:
    hostile = 'x; f- *; CC-* | ! rm -rf / `!id` @ 0 "q" \\ $(id) #c ~grep 한글'
    fake = FakeCore("radare2")
    fake.cmd("aa")
    items = [{"rva": "0x102c", "name": hostile, "comment": hostile},
             {"rva": "0x1100", "name": hostile, "comment": hostile, "bookmark": True}]
    counts = xr.import_document(ops_for(fake), write_doc(tmp_path, items))
    assert counts["comment_failed"] == 0
    for line in fake.calls:
        assert SAFE_CMD_RE.fullmatch(line), line
    assert fake.comments[ENTRY].startswith("x; f- *; CC-* | ! rm -rf / `!id` @ 0")
    assert "한글" in fake.comments[ENTRY]


def test_unmapped_items_are_counted(tmp_path: Path) -> None:
    fake = FakeCore("rizin")
    counts = xr.import_document(ops_for(fake), write_doc(tmp_path, [{"rva": "0x90000", "name": "far"}]))
    assert counts["unmapped"] == 1
    assert "far" not in fake.flags


def test_import_module_selection(tmp_path: Path) -> None:
    fake = FakeCore("radare2", file="/w/renamed.bin")
    path = write_doc(tmp_path, PROBE_ITEMS)
    with pytest.raises(ValueError, match="e2e_sample_x86_64.exe"):
        xr.import_document(ops_for(fake), path)
    counts = xr.import_document(ops_for(fake), path, module="e2e_sample_x86_64")
    assert counts["module"] == "e2e_sample_x86_64.exe"


# ── export ──────────────────────────────────────────────────────────
@pytest.mark.parametrize("flavor", ["radare2", "rizin"])
def test_export_collects_user_names_and_comments(tmp_path: Path, flavor: str) -> None:
    fake = FakeCore(flavor)
    fake.cmd("aa")
    fake.functions[BASE + 0x2000] = "fcn.140002000"  # auto name: not exported
    fake.functions[BASE + 0x3000] = "decrypt_config"  # user rename (afn)
    fake.flags["user_flag"] = (BASE + 0x4000, None)  # flag created without a flagspace
    # switch analysis (aa) adds these without a flagspace in radare2 6.2.6 and rizin 0.9.1
    fake.flags["switch.0x14000154c"] = (BASE + 0x154C, None)
    fake.flags["case.0x14000154c.0"] = (BASE + 0x154E, None)
    fake.flags["str.hello"] = (BASE + 0x4100, "strings")
    fake.spaces.add("strings")
    xr.import_document(ops_for(fake), write_doc(tmp_path, PROBE_ITEMS))
    fake.comments[BASE + 0x154C] = "switch table (5 cases) at 0x14001a040"
    fake.comments[BASE + 0x5000] = "한글 note; with | specials"
    out = tmp_path / "out.json"
    result = xr.export_document(ops_for(fake), str(out))
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["schema"] == "x64dbg-ida-sync/1"
    assert doc["generated_by"].startswith("x64dbg_sync_r2.py")
    mod = doc["modules"]["e2e_sample_x86_64.exe"]
    assert mod["ida_imagebase"] == "0x140000000"
    by_rva = {i["rva"]: i for i in mod["items"]}
    assert by_rva["0x102C"] == {"rva": "0x102C", "name": "gw_probe_entry",
                                "comment": "set by x64dbg_sync import probe [x64dbg: bookmark]"}
    assert by_rva["0x3000"] == {"rva": "0x3000", "name": "decrypt_config"}
    assert by_rva["0x4000"] == {"rva": "0x4000", "name": "user_flag"}
    assert by_rva["0x5000"] == {"rva": "0x5000", "comment": "한글 note; with | specials"}
    for skipped in ("0x2000", "0x4100", "0x154C", "0x154E", "0x1000"):  # auto names / auto comments
        assert skipped not in by_rva
    assert result["items"] == len(mod["items"])
    assert fake.selected is None


def test_export_then_import_round_trip(tmp_path: Path) -> None:
    src = FakeCore("radare2")
    xr.import_document(ops_for(src), write_doc(tmp_path, PROBE_ITEMS))
    out = tmp_path / "rt.json"
    xr.export_document(ops_for(src), str(out))
    dst = FakeCore("rizin")
    counts = xr.import_document(ops_for(dst), str(out))
    assert flags_at(dst, ENTRY)["gw_probe_entry"] == "x64dbg"
    assert counts["rename_failed"] == 0


@pytest.mark.parametrize(
    ("name", "auto"),
    [("fcn.140001000", True), ("entry0", True), ("main", True), ("sym.imp.KERNEL32.dll_Sleep", True),
     ("sub.KERNEL32.dll_Sleep", True), ("loc.x", True), ("entry.init0", True), ("decrypt_config", False),
     ("gw_probe_entry", False), ("mainloop", False), ("fcnx", False)],
)
def test_auto_function_names(name: str, auto: bool) -> None:
    assert xr.is_auto_function_name(name) is auto


@pytest.mark.parametrize(
    ("text", "kept"),
    [("[00] -r-x section size 102400 named .text\nmine", "mine"),
     ("switch table (5 cases) at 0x14001a040", ""), ("plain", "plain"), ("a\nb", "a\nb")],
)
def test_auto_comment_lines_are_dropped(text: str, kept: str) -> None:
    assert xr.strip_auto_comment(text) == kept


# ── CLI ─────────────────────────────────────────────────────────────
def test_parse_args() -> None:
    a = xr.parse_args(["--binary", "/w/s.exe", "import", "doc.json", "--module", "s.exe", "--project", "p"])
    assert (a.binary, a.action, a.path, a.module, a.project, a.tool) == ("/w/s.exe", "import", "doc.json", "s.exe",
                                                                          "p", None)
    b = xr.parse_args(["--tool", "rizin", "--binary", "s.exe", "-A", "export", "out.json"])
    assert (b.tool, b.action, b.analyze) == ("rizin", "export", True)
    with pytest.raises(SystemExit):
        xr.parse_args(["frobnicate", "x"])


def test_choose_tool_from_environment() -> None:
    assert xr.choose_tool(None, {"R2PIPE_IN": "3", "R2PIPE_OUT": "4"}) == ("radare2", True)
    assert xr.choose_tool(None, {"RZ_PIPE_IN": "3", "RZ_PIPE_OUT": "4"}) == ("rizin", True)
    assert xr.choose_tool(None, {}) == ("radare2", False)
    assert xr.choose_tool("rizin", {}) == ("rizin", False)
    assert xr.choose_tool("rizin", {"RZ_PIPE_IN": "3", "RZ_PIPE_OUT": "4"}) == ("rizin", True)


def test_main_with_a_fake_pipe(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    fake = FakeCore("rizin")
    opened: list[tuple] = []

    class FakePipe:
        def cmd(self, c: str) -> str:
            return fake.cmd(c)

        def quit(self) -> None:
            opened.append(("quit",))

    def opener(tool: str, binary: str | None, flags: list[str]) -> FakePipe:
        opened.append((tool, binary, tuple(flags)))
        return FakePipe()

    prj = tmp_path / "p.rzdb"
    rc = xr.main(["--tool", "rizin", "--binary", "/w/e2e_sample_x86_64.exe", "--project", str(prj), "-A",
                  "import", write_doc(tmp_path, PROBE_ITEMS)], opener=opener, environ={})
    assert rc == 0
    assert opened[0] == ("rizin", "/w/e2e_sample_x86_64.exe", ())  # no project file yet
    assert fake.analysed and fake.saved == [str(prj)]
    assert fake.functions[ENTRY] == "gw_probe_entry"
    assert "renamed 1" in capsys.readouterr().out


def test_main_loads_an_existing_r2_project_from_a_directory(tmp_path: Path) -> None:
    (tmp_path / "prj" / "sample_prj").mkdir(parents=True)
    (tmp_path / "prj" / "sample_prj" / "rc.r2").write_text("# r2 project\n", encoding="utf-8")
    fake = FakeCore("radare2")
    opened: list[tuple] = []

    def opener(tool: str, binary: str | None, flags: list[str]) -> object:
        opened.append((tool, binary, tuple(flags)))
        return types.SimpleNamespace(cmd=fake.cmd, quit=lambda: None)

    rc = xr.main(["--binary", "/w/e2e_sample_x86_64.exe", "import", write_doc(tmp_path, PROBE_ITEMS),
                  "--project", str(tmp_path / "prj" / "sample_prj")], opener=opener, environ={})
    assert rc == 0
    flags = ("-e", f"dir.projects={tmp_path / 'prj'}")
    assert opened == [("radare2", "/w/e2e_sample_x86_64.exe", flags),
                      ("radare2", "/w/e2e_sample_x86_64.exe", flags + ("-p", "sample_prj"))]
    assert fake.saved == ["sample_prj"]


@pytest.mark.parametrize(
    ("tool", "spec"),
    [("radare2", "bad;name"), ("radare2", "a b"), ("radare2", "/x/.."), ("rizin", "p.r2"),
     ("rizin", "/work/with space.rzdb"), ("rizin", "x;Ps y.rzdb")],
)
def test_project_specs_are_checked(tool: str, spec: str) -> None:
    with pytest.raises(ValueError):
        xr.Project(tool, spec)


def test_main_in_pipe_mode_uses_the_parent_session(tmp_path: Path) -> None:
    fake = FakeCore("rizin")
    opened: list[tuple] = []

    def opener(tool: str, binary: str | None, flags: list[str]) -> object:
        opened.append((tool, binary, tuple(flags)))
        return types.SimpleNamespace(cmd=fake.cmd, quit=lambda: opened.append(("quit",)))

    rc = xr.main(["import", write_doc(tmp_path, PROBE_ITEMS)], opener=opener,
                 environ={"RZ_PIPE_IN": "3", "RZ_PIPE_OUT": "4"})
    assert rc == 0
    assert opened == [("rizin", None, ())]  # the parent's pipe, never quit (it is the user's session)
    assert flags_at(fake, ENTRY)["gw_probe_entry"] == "x64dbg"


def test_main_reports_errors(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    def opener(tool: str, binary: str | None, flags: list[str]) -> object:
        return types.SimpleNamespace(cmd=FakeCore("radare2").cmd, quit=lambda: None)

    bad = tmp_path / "bad.json"
    bad.write_text("{}", encoding="utf-8")
    rc = xr.main(["--binary", "/w/x.exe", "import", str(bad)], opener=opener, environ={})
    assert rc == 1
    assert "no schema" in capsys.readouterr().err


def test_main_needs_a_binary_outside_a_pipe(capsys: pytest.CaptureFixture[str]) -> None:
    rc = xr.main(["import", "doc.json"], opener=lambda *a: None, environ={})
    assert rc == 2
    assert "--binary" in capsys.readouterr().err


def test_cutter_entry_points(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeCore("rizin")
    refreshed = []
    cutter = types.SimpleNamespace(cmd=fake.cmd, refresh=lambda: refreshed.append(True))
    monkeypatch.setitem(__import__("sys").modules, "cutter", cutter)
    counts = xr.cutter_import(write_doc(tmp_path, PROBE_ITEMS))
    assert counts["renamed"] == 1 and refreshed
    out = tmp_path / "cut.json"
    assert xr.cutter_export(str(out))["items"] == 1
