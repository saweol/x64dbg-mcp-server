#!/usr/bin/env python3
"""x64dbg <-> radare2 / rizin / Cutter annotation sync (x64dbg-ida-sync JSON).

One script for three front ends, through a small command adapter
(:class:`Commands`) around "run one command, get its text":

* radare2 via r2pipe, rizin via rzpipe (command line, or ``#!pipe`` from inside
  a running session), and
* Cutter, whose embedded Python offers ``cutter.cmd`` (Cutter runs rizin).

``import`` applies a document produced by the x64dbg-vm-gateway at
``baddr + rva``: a name renames the function that starts there (``afn``) or
becomes a flag in the ``x64dbg`` flagspace; comments are merged into the
existing comment (``CCu base64:...``, so arbitrary text never meets the
command parser); bookmarks/breakpoints become ``[x64dbg: ...]`` tags in the
comment. Re-importing the same document changes nothing.

``export`` writes user names (renamed functions, flags of the ``x64dbg``
flagspace and flags without a flagspace) and comments (minus the section
banners and switch-table notes radare2/rizin add themselves) as RVAs
relative to ``baddr``, ready for the gateway's ``plan_import``.

Usage::

    python3 x64dbg_sync_r2.py --binary sample.exe [--tool radare2|rizin] [--project P] [-A] \\
        import doc.json [--module NAME]
    python3 x64dbg_sync_r2.py --binary sample.exe [--tool ...] [--project P] [-A] export out.json

    [0x140001000]> #!pipe python3 /path/to/x64dbg_sync_r2.py import doc.json     (radare2 / rizin)

    # Cutter: Windows > Python console (or a Cutter Python plugin)
    import sys; sys.path.insert(0, "/path/to/static/radare2")
    import x64dbg_sync_r2 as xs; xs.cutter_import("/path/doc.json"); xs.cutter_export("/path/out.json")

``--project``: radare2 project name (in ``dir.projects``, or ``DIR/NAME``) or
rizin ``.rzdb`` file; it is loaded when it exists and saved after an import. Without it a command
line import only lives as long as the r2/rizin process (use ``#!pipe`` inside
your session, or ``--project``). ``-A`` runs ``aa`` first so that functions exist
and can be renamed.

The tool-independent rules live in ``x64dbg_sync_core.py``, looked up next to
this file first, then in ``../common/``. Python 3.9+.
"""

from __future__ import annotations

import argparse
import base64
import importlib.util
import json
import os
import re
import sys
from collections.abc import Callable, Iterable
from typing import Any

SCRIPT_VERSION = "1.0"
FLAGSPACE = "x64dbg"
CORE_FILE = "x64dbg_sync_core.py"
_FLAVORS = ("radare2", "rizin")


def find_core(script_path: str) -> str:
    """Path of x64dbg_sync_core.py: next to the script, else ``../common/``."""
    here = os.path.dirname(os.path.abspath(script_path))
    candidates = [os.path.join(here, CORE_FILE), os.path.join(os.path.dirname(here), "common", CORE_FILE)]
    for path in candidates:
        if os.path.isfile(path):
            return path
    raise ImportError(f"{CORE_FILE} not found (looked in: {', '.join(candidates)})")


def _load_core() -> Any:
    path = find_core(__file__)
    spec = importlib.util.spec_from_file_location("x64dbg_sync_core", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


core = _load_core()
RULES = core.RADARE2
GENERATED_BY = f"x64dbg_sync_r2.py {SCRIPT_VERSION}"

# Names radare2/rizin give on their own (analysis, symbols, imports): not exported.
_AUTO_FUNC_RE = re.compile(
    r"(?:entry\d*|main|_?start"
    r"|(?:fcn|sub|loc|sym|imp|dbg|method|class|section|segment|reloc|str|obj|entry|case|switch|int|unk|aav"
    r"|ord|vtable|func|fun)\..*)"
)
# Comment lines radare2 6.2 / rizin 0.9 add themselves (seen on the E2E sample).
_AUTO_COMMENT_RES = (
    re.compile(r"\[\d+\] [-rwxsp]{3,5} section size \d+ named \S*"),
    re.compile(r"switch table \(\d+ cases\) at 0x[0-9a-fA-F]+"),
)
_CC_STAR_RE = re.compile(r"CCu base64:([A-Za-z0-9+/=]*) @ (0x[0-9a-fA-F]+)")
# Names read back from the tool (flagspaces, our own old flags) are re-sent in a command line
# only when they are plain tokens the r2/rizin parser cannot interpret.
_TOKEN_RE = re.compile(r"[A-Za-z0-9_.:]+")


def is_auto_function_name(name: str) -> bool:
    return bool(_AUTO_FUNC_RE.fullmatch(name))


def strip_auto_comment(text: str) -> str:
    """The comment without the lines radare2/rizin generate themselves."""
    lines = [line for line in text.splitlines() if not any(r.fullmatch(line.strip()) for r in _AUTO_COMMENT_RES)]
    return "\n".join(lines).strip()


def _hex(address: int) -> str:
    return f"0x{address:x}"


def _addr_of(entry: Any) -> int | None:
    """``addr`` (radare2 6.x JSON) or ``offset`` (rizin, older radare2)."""
    if not isinstance(entry, dict):
        return None
    value = entry.get("addr", entry.get("offset"))
    return value if isinstance(value, int) and not isinstance(value, bool) else None


class Commands:
    """Runs r2/rizin commands through ``run(command) -> str`` and knows the
    few command spellings that differ between radare2 6.x and rizin 0.9."""

    def __init__(self, run: Callable[[str], Any], flavor: str) -> None:
        if flavor not in _FLAVORS:
            raise ValueError(f"flavor must be one of {', '.join(_FLAVORS)}, got {flavor!r}")
        self._run = run
        self.flavor = flavor
        rizin = flavor == "rizin"
        self.flag_list = "flj" if rizin else "fj"
        self.space_list = "fslj" if rizin else "fsj"

    @classmethod
    def from_r2pipe(cls, pipe: Any) -> Commands:
        return cls(pipe.cmd, "radare2")

    @classmethod
    def from_rzpipe(cls, pipe: Any) -> Commands:
        return cls(pipe.cmd, "rizin")

    @classmethod
    def from_cutter(cls, cutter_module: Any) -> Commands:
        """Cutter 2.x runs rizin; ``cutter.cmd`` returns the command output."""
        return cls(cutter_module.cmd, "rizin")

    def cmd(self, command: str) -> str:
        out = self._run(command)
        return out if isinstance(out, str) else ""

    def cmdj(self, command: str) -> Any:
        text = self.cmd(command).strip()
        if not text:
            return None
        try:
            return json.loads(text)
        except ValueError:
            return None

    def remove_flag(self, name: str) -> str:
        return f"f- {name}" if self.flavor == "rizin" else f"f-{name}"


class R2Ops:
    """The tool adapter :func:`core.apply_import_plan` drives, plus export collection."""

    def __init__(self, commands: Commands) -> None:
        self.c = commands
        self._info: dict[str, Any] | None = None
        self._sections: list[tuple[int, int]] | None = None
        self._index: dict[str, set[int]] | None = None

    # ── binary info ────────────────────────────────────────────────
    def info(self) -> dict[str, Any]:
        if self._info is None:
            data = self.c.cmdj("ij")
            self._info = data if isinstance(data, dict) else {}
        return self._info

    def imagebase(self) -> int:
        baddr = (self.info().get("bin") or {}).get("baddr")
        if not isinstance(baddr, int) or isinstance(baddr, bool):
            raise ValueError("cannot read the binary's baddr ('ij'); is a file open?")
        return baddr

    def file_names(self) -> list[str]:
        name = (self.info().get("core") or {}).get("file")
        return [name] if isinstance(name, str) and name else []

    def is_mapped(self, address: int) -> bool:
        if self._sections is None:
            data = self.c.cmdj("iSj")
            if isinstance(data, dict):  # {"sections": [...]} in some versions, a list in 6.2 / 0.9
                data = data.get("sections", [])
            rows = data if isinstance(data, list) else []
            self._sections = []
            for row in rows:
                if isinstance(row, dict) and isinstance(row.get("vaddr"), int):
                    size = max(int(row.get("vsize") or 0), int(row.get("size") or 0))
                    if size > 0:
                        self._sections.append((row["vaddr"], size))
        if not self._sections:
            return True  # no section table (raw blob): every address is fair game
        return any(start <= address < start + size for start, size in self._sections)

    # ── flagspaces ─────────────────────────────────────────────────
    def _selected_space(self) -> str:
        spaces = self.c.cmdj(self.c.space_list)
        for row in spaces if isinstance(spaces, list) else []:
            if isinstance(row, dict) and row.get("selected") is True and isinstance(row.get("name"), str):
                return row["name"]
        return "*"

    def _space_names(self) -> list[str]:
        spaces = self.c.cmdj(self.c.space_list)
        if not isinstance(spaces, list):
            return []
        return [r["name"] for r in spaces
                if isinstance(r, dict) and isinstance(r.get("name"), str) and _TOKEN_RE.fullmatch(r["name"])]

    def _select(self, space: str) -> None:
        # space names come from the tool itself or are FLAGSPACE, never from the document; a name
        # that is not a plain token is not re-sent (the selection falls back to all flagspaces)
        self.c.cmd(f"fs {space}" if space != "*" and _TOKEN_RE.fullmatch(space) else "fs *")

    def _flags_in(self, space: str) -> list[tuple[str, int]]:
        self._select(space)
        data = self.c.cmdj(self.c.flag_list)
        out = []
        for row in data if isinstance(data, list) else []:
            addr = _addr_of(row)
            if addr is not None and isinstance(row.get("name"), str):
                out.append((row["name"], addr))
        return out

    def _with_selection(self, action: Callable[[], Any]) -> Any:
        """Run ``action`` and restore the user's flagspace selection afterwards."""
        previous = self._selected_space()
        try:
            return action()
        finally:
            self._select(previous)

    def _flag_index(self) -> dict[str, set[int]]:
        if self._index is None:
            index: dict[str, set[int]] = {}
            for name, addr in self._with_selection(lambda: self._flags_in("*")):
                index.setdefault(name, set()).add(addr)
            self._index = index
        return self._index

    # ── names ──────────────────────────────────────────────────────
    def function_at(self, address: int) -> dict[str, Any] | None:
        data = self.c.cmdj(f"afij @ {_hex(address)}")
        for row in data if isinstance(data, list) else []:
            if _addr_of(row) == address and isinstance(row.get("name"), str):
                return row
        return None

    def _free_name(self, name: str, address: int) -> str | None:
        index = self._flag_index()
        for candidate in core.name_candidates(name, 100, RULES.name_max):
            if index.get(candidate, set()) <= {address}:
                return candidate
        return None

    def set_name(self, address: int, name: str) -> str:
        if not RULES.name_core(name) == name:  # only names made by the r2 rules ever reach a command
            return core.NAME_FAILED
        index = self._flag_index()
        func = self.function_at(address)
        if func is not None:
            if func["name"] == name:
                return core.NAME_UNCHANGED
            candidate = self._free_name(name, address)
            if candidate is None:
                return core.NAME_FAILED
            self.c.cmd(f"afn {candidate} @ {_hex(address)}")
            after = self.function_at(address)
            if after is None or after.get("name") != candidate:
                return core.NAME_FAILED
            index.get(func["name"], set()).discard(address)
            index.setdefault(candidate, set()).add(address)
            return core.NAME_RENAMED
        if address in index.get(name, set()):
            return core.NAME_UNCHANGED  # already a flag of that name here (any flagspace)

        def apply() -> str:
            ours = [n for n, a in self._flags_in(FLAGSPACE) if a == address]
            candidate = self._free_name(name, address)
            if candidate is None:
                return core.NAME_FAILED
            for old in ours:  # an earlier import's name here is replaced, like IDA's set_name
                if old != candidate and _TOKEN_RE.fullmatch(old):
                    self.c.cmd(self.c.remove_flag(old))
                    index.get(old, set()).discard(address)
            self.c.cmd(f"f {candidate} @ {_hex(address)}")
            if (candidate, address) not in self._flags_in(FLAGSPACE):
                return core.NAME_FAILED
            index.setdefault(candidate, set()).add(address)
            return core.NAME_RENAMED

        return self._with_selection(apply)

    # ── comments ───────────────────────────────────────────────────
    def get_comment(self, address: int) -> str | None:
        text = self.c.cmd(f"CC. @ {_hex(address)}")
        if text.endswith("\n"):
            text = text[:-1]
        return text or None

    def set_comment(self, address: int, text: str) -> bool:
        encoded = base64.b64encode(text.encode("utf-8")).decode("ascii")
        self.c.cmd(f"CCu base64:{encoded} @ {_hex(address)}")
        return self.get_comment(address) == text

    def _comments(self) -> dict[int, str]:
        out: dict[int, str] = {}
        if self.c.flavor == "radare2":
            for line in self.c.cmd("CC*").splitlines():
                m = _CC_STAR_RE.fullmatch(line.strip())
                if m:
                    try:
                        out[int(m.group(2), 16)] = base64.b64decode(m.group(1)).decode("utf-8", "replace")
                    except ValueError:
                        continue
        else:  # rizin's CClj escapes non-ASCII text; take only the addresses from it
            rows = self.c.cmdj("CClj")
            for row in rows if isinstance(rows, list) else []:
                if len(out) >= core.MAX_ITEMS:
                    break
                addr = _addr_of(row)
                if addr is not None and addr not in out:
                    text = self.get_comment(addr)
                    if text:
                        out[addr] = text
        return out

    # ── export ─────────────────────────────────────────────────────
    def collect_annotations(self) -> list[tuple[int, str | None, str | None]]:
        names: dict[int, str] = {}
        funcs = self.c.cmdj("aflj")
        for row in funcs if isinstance(funcs, list) else []:
            addr = _addr_of(row)
            name = row.get("name") if isinstance(row, dict) else None
            if addr is not None and isinstance(name, str) and not is_auto_function_name(name):
                names.setdefault(addr, name)

        def flags() -> tuple[list[tuple[str, int]], list[tuple[str, int]]]:
            ours = self._flags_in(FLAGSPACE)
            in_spaces = set()
            for space in self._space_names():
                in_spaces.update(self._flags_in(space))
            unspaced = [f for f in self._flags_in("*") if f not in in_spaces]
            return ours, unspaced

        ours, unspaced = self._with_selection(flags)
        for name, addr in ours:
            names.setdefault(addr, name)
        for name, addr in unspaced:  # also holds analysis flags such as switch.0x... / case.0x...
            if not is_auto_function_name(name):
                names.setdefault(addr, name)
        comments = {}
        for addr, text in self._comments().items():
            kept = strip_auto_comment(text)
            if kept:
                comments[addr] = kept
        return [(a, names.get(a), comments.get(a)) for a in sorted(set(names) | set(comments))]


# ── actions ─────────────────────────────────────────────────────────
def import_document(ops: R2Ops, path: str, module: str | None = None) -> dict[str, Any]:
    """Apply the document at ``path``; returns the counters of :func:`core.format_import_report`."""
    doc = core.load_sync_document(core.read_capped(path), RULES)
    key = core.resolve_module(doc, ops.file_names(), module)
    imagebase = ops.imagebase()
    plan = core.build_import_plan(doc, key, imagebase, RULES)
    counts = core.new_import_counts(ops.c.flavor, key, imagebase, plan, doc)
    return core.apply_import_plan(plan, ops, counts)


def export_document(ops: R2Ops, path: str) -> dict[str, Any]:
    files = ops.file_names()
    module = files[0] if files else "unknown"
    doc = core.build_export_document(
        module, ops.imagebase(), ops.collect_annotations(), generated_by=f"{GENERATED_BY} ({ops.c.flavor})",
        rules=RULES,
    )
    core.write_json_atomic(path, doc)
    (key,) = doc["modules"]
    return {"module": key, "items": len(doc["modules"][key]["items"]), "path": path}


# ── Cutter ──────────────────────────────────────────────────────────
def _cutter_ops() -> R2Ops:
    import cutter  # noqa: PLC0415 - only inside Cutter

    return R2Ops(Commands.from_cutter(cutter))


def _cutter_refresh() -> None:
    import cutter  # noqa: PLC0415

    refresh = getattr(cutter, "refresh", None)
    if callable(refresh):
        refresh()


def cutter_import(path: str, module: str | None = None) -> dict[str, Any]:
    """Import from Cutter's Python console; refreshes Cutter's views afterwards."""
    counts = import_document(_cutter_ops(), path, module)
    _cutter_refresh()
    print(core.format_import_report(counts))
    return counts


def cutter_export(path: str) -> dict[str, Any]:
    result = export_document(_cutter_ops(), path)
    print("x64dbg sync (cutter): exported {items} items of {module} to {path}".format(**result))
    return result


# ── command line ────────────────────────────────────────────────────
_OPTION_DEFAULTS = {"tool": None, "binary": None, "project": None, "analyze": False, "module": None}


def parse_args(argv: Iterable[str]) -> argparse.Namespace:
    """Options may come before or after the action (``--binary b import d.json --project p``)."""
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--tool", choices=_FLAVORS, default=argparse.SUPPRESS,
                        help="radare2 (r2pipe) or rizin (rzpipe); default: radare2, or the tool whose #!pipe "
                        "started this script")
    common.add_argument("--binary", default=argparse.SUPPRESS, help="binary to open (not needed inside #!pipe)")
    common.add_argument("--project", default=argparse.SUPPRESS,
                        help="radare2 project name / rizin .rzdb file: loaded if it exists, saved after an import")
    common.add_argument("-A", "--analyze", action="store_true", default=argparse.SUPPRESS,
                        help="run 'aa' first (functions to rename)")
    parser = argparse.ArgumentParser(
        prog="x64dbg_sync_r2.py", parents=[common],
        description="Import/export x64dbg annotations (x64dbg-ida-sync JSON) with radare2 or rizin.",
    )
    sub = parser.add_subparsers(dest="action", required=True)
    p_import = sub.add_parser("import", parents=[common], help="apply a document")
    p_import.add_argument("path")
    p_import.add_argument("--module", default=argparse.SUPPRESS,
                          help="module of the document to apply (default: matched by file name)")
    p_export = sub.add_parser("export", parents=[common], help="write a document")
    p_export.add_argument("path")
    args = parser.parse_args(list(argv))
    for key, value in _OPTION_DEFAULTS.items():
        if not hasattr(args, key):
            setattr(args, key, value)
    return args


def choose_tool(requested: str | None, environ: dict[str, str]) -> tuple[str, bool]:
    """(tool, inside_pipe): a #!pipe from radare2 sets R2PIPE_IN/OUT, from rizin RZ_PIPE_IN/OUT."""
    if requested in (None, "rizin") and "RZ_PIPE_IN" in environ and "RZ_PIPE_OUT" in environ:
        return "rizin", True
    if requested in (None, "radare2") and "R2PIPE_IN" in environ and "R2PIPE_OUT" in environ:
        return "radare2", True
    return requested or "radare2", False


def _default_opener(tool: str, binary: str | None, flags: list[str]) -> Any:
    if tool == "rizin":
        import rzpipe  # noqa: PLC0415

        return rzpipe.open(binary, flags=flags) if binary else rzpipe.open()
    import r2pipe  # noqa: PLC0415

    return r2pipe.open(binary, flags=flags) if binary else r2pipe.open()


class Project:
    """Where the project lives and how to name it in a command line.

    radare2: a project *name* in ``dir.projects`` (``NAME``), or ``DIR/NAME`` to keep
    it in ``DIR`` (passed as ``-e dir.projects=DIR``, a process argument). rizin: a
    ``.rzdb`` file. Whatever ends up in the ``Ps`` command line is restricted to
    characters the r2/rizin parser cannot interpret.
    """

    _NAME_RE = re.compile(r"[A-Za-z0-9_.\-]+")
    _RZDB_RE = re.compile(r"[A-Za-z0-9_.\-/:\\]+\.rzdb")

    def __init__(self, tool: str, spec: str) -> None:
        self.tool = tool
        self.open_flags: list[str] = []
        if tool == "rizin":
            if not self._RZDB_RE.fullmatch(spec):
                raise ValueError("the rizin project must be a .rzdb path made of [A-Za-z0-9_.-/:\\] "
                                 "(no spaces or shell characters)")
            self.name = spec
            self.directory = None
        else:
            directory, name = os.path.split(spec)
            if not self._NAME_RE.fullmatch(name) or name in (".", ".."):
                raise ValueError("radare2 project names may only use [A-Za-z0-9_.-] (give DIR/NAME for a directory)")
            self.name = name
            self.directory = os.path.abspath(directory) if directory else None
            if self.directory:
                self.open_flags = ["-e", f"dir.projects={self.directory}"]

    def exists(self, pipe: Any) -> bool:
        if self.tool == "rizin":
            return os.path.isfile(self.name)
        directory = self.directory or (pipe.cmd("e dir.projects") or "").strip()
        return bool(directory) and os.path.isfile(os.path.join(os.path.expanduser(directory), self.name, "rc.r2"))

    def load_flags(self) -> list[str]:
        return self.open_flags + ["-p", self.name]

    def save_command(self) -> str:
        return f"Ps {self.name}"


def main(
    argv: Iterable[str] | None = None,
    opener: Callable[[str, str | None, list[str]], Any] | None = None,
    environ: dict[str, str] | None = None,
) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    env = dict(os.environ) if environ is None else environ
    open_tool = opener or _default_opener
    tool, in_pipe = choose_tool(args.tool, env)
    if not in_pipe and not args.binary:
        print("x64dbg sync: --binary is required outside a #!pipe session", file=sys.stderr)
        return 2
    pipe = None
    try:
        project = Project(tool, args.project) if args.project and not in_pipe else None
        pipe = open_tool(tool, None if in_pipe else args.binary, project.open_flags if project else [])
        if project and project.exists(pipe):
            if hasattr(pipe, "quit"):
                pipe.quit()
            pipe = open_tool(tool, args.binary, project.load_flags())
        commands = Commands(pipe.cmd, tool)
        if args.analyze:
            commands.cmd("aa")
        ops = R2Ops(commands)
        if args.action == "import":
            counts = import_document(ops, args.path, args.module)
            print(core.format_import_report(counts))
            if project:
                commands.cmd(project.save_command())
                print(f"x64dbg sync ({tool}): project saved: {args.project}")
            elif not in_pipe:
                print(f"x64dbg sync ({tool}): no --project given, the changes end with this {tool} process")
        else:
            result = export_document(ops, args.path)
            print(f"x64dbg sync ({tool}): exported {result['items']} items of {result['module']} to {result['path']}")
        return 0
    except (OSError, ValueError, ImportError) as exc:
        print(f"x64dbg sync ({tool}): {args.action} failed: {exc}", file=sys.stderr)
        return 1
    finally:
        if pipe is not None and not in_pipe and hasattr(pipe, "quit"):
            try:
                pipe.quit()
            except Exception:  # noqa: BLE001, S110 - closing a pipe whose tool already exited
                pass


if __name__ == "__main__":
    sys.exit(main())
