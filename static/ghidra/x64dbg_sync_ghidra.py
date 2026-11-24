# Import x64dbg annotations into the program, or export its user names/comments for x64dbg
# (x64dbg-ida-sync JSON). Headless: -postScript x64dbg_sync_ghidra.py import <doc.json> [module]
# [--comment=eol|pre]  or  export <out.json> [--all-comments]. See static/README.md.
# @author x64dbg-vm-gateway
# @category x64dbg
# @runtime PyGhidra
"""x64dbg <-> Ghidra annotation sync (x64dbg-ida-sync JSON), for PyGhidra (Ghidra >= 11.3, Python 3).

``import``: applies a document produced by the x64dbg-vm-gateway at
``image base + rva``: a name renames the function that starts there, or becomes
a primary USER_DEFINED label (other labels at the address stay as secondary
labels); comments are merged into the EOL comment (``--comment=pre``: the pre
comment), never overwritten, and re-importing the same document changes
nothing; bookmarks/breakpoints become ``[x64dbg: ...]`` tags in the comment,
like ida/x64dbg_sync.py does in IDA.

``export``: writes the USER_DEFINED label and function names and the comments
of the program's memory as RVAs relative to the program's image base, ready for
the gateway's ``plan_import``. Comments the PE loader adds (header markup and
``IMAGE_*`` structure names) are left out unless ``--all-comments`` is given.

Run it from the Script Manager (it asks for the action, the file and, when no
module of the document matches the program, the module), or headless with
``support/pyghidraRun -H <project_dir> <project> -import <bin> -postScript
x64dbg_sync_ghidra.py import <doc.json>`` (``-process <name> -noanalysis`` for an
existing program). The tool-independent rules live in ``x64dbg_sync_core.py``,
looked up next to this script first, then in ``../common/``.

No ``ghidra``/``java`` module is imported at import time: the Ghidra classes come
in through :func:`load_ghidra_api`, so the pure parts run under plain Python
(static/tests).
"""

from __future__ import annotations

import importlib.util
import os
import re
import types
from typing import Any

SCRIPT_VERSION = "1.0"
CORE_FILE = "x64dbg_sync_core.py"
COMMENT_TYPES = ("eol", "pre")
CANCEL_CHECK_EVERY = 256
USAGE = (
    "usage: x64dbg_sync_ghidra.py import <doc.json> [module] [--comment=eol|pre]\n"
    "       x64dbg_sync_ghidra.py export <out.json> [--all-comments]"
)


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
RULES = core.GHIDRA

# Comments the PE loader writes (all 48 that Ghidra 12.2 put on the E2E sample: section
# names on the section headers, IMAGE_* structure names, "0 NtClose <<not bound>>" on IAT
# slots, ".NET PDB Info" on the debug directory). Not user knowledge.
_LOADER_BLOCKS = frozenset({"Headers"})
_LOADER_COMMENT_RE = re.compile(
    r"IMAGE_[A-Z0-9_]+(?: - .*)?"
    r"|\S+ \S+ <<(?:not )?bound>>"
    r"|(?:\.NET )?PDB Info"
)
# Display order of Ghidra's comment kinds when several are joined.
_COMMENT_ORDER = ("PLATE", "PRE", "EOL", "POST", "REPEATABLE")
_LEGACY_COMMENT_CODES = {"EOL": "EOL_COMMENT", "PRE": "PRE_COMMENT", "POST": "POST_COMMENT",
                         "PLATE": "PLATE_COMMENT", "REPEATABLE": "REPEATABLE_COMMENT"}


class Cancelled(Exception):
    """The user cancelled the task monitor."""


def to_signed64(value: int) -> int:
    """Java ``long`` for an unsigned 64-bit address (JPype refuses ints >= 2**63)."""
    return value - 2**64 if value >= 2**63 else value


def load_ghidra_api() -> types.SimpleNamespace:
    """The Ghidra classes the script uses (only inside Ghidra / PyGhidra)."""
    from ghidra.program.model.listing import CodeUnit  # noqa: PLC0415
    from ghidra.program.model.symbol import SourceType, SymbolType, SymbolUtilities  # noqa: PLC0415
    from ghidra.util.exception import DuplicateNameException, InvalidInputException  # noqa: PLC0415

    try:
        from ghidra.program.model.listing import CommentType  # noqa: PLC0415 - Ghidra 11.4+
    except ImportError:
        CommentType = None  # noqa: N806 - older Ghidra uses CodeUnit.*_COMMENT ints
    return types.SimpleNamespace(
        SourceType=SourceType, SymbolType=SymbolType, SymbolUtilities=SymbolUtilities, CommentType=CommentType,
        CodeUnit=CodeUnit, DuplicateNameException=DuplicateNameException,
        InvalidInputException=InvalidInputException,
    )


def comment_kind(api: Any, name: str) -> Any:
    """``CommentType.<name>`` (Ghidra 11.4+) or ``CodeUnit.<name>_COMMENT`` (older)."""
    if api.CommentType is not None:
        return getattr(api.CommentType, name)
    return getattr(api.CodeUnit, _LEGACY_COMMENT_CODES[name])


def parse_script_args(args: list[str]) -> dict[str, Any]:
    """``import <doc.json> [module] [--comment=eol|pre]`` / ``export <out.json> [--all-comments]``."""
    words = [str(a) for a in args]
    options = [w for w in words if w.startswith("--")]
    positional = [w for w in words if not w.startswith("--")]
    out: dict[str, Any] = {"action": None, "path": None, "module": None, "comment": "eol", "all_comments": False}
    if not positional or positional[0].lower() not in ("import", "export"):
        raise ValueError("the first argument must be 'import' or 'export'")
    out["action"] = positional[0].lower()
    rest = positional[1:]
    limit = 2 if out["action"] == "import" else 1
    if not rest or len(rest) > limit:
        wanted = "a document path and an optional module" if limit == 2 else "an output path"
        raise ValueError(f"'{out['action']}' takes {wanted}")
    out["path"] = rest[0]
    if len(rest) == 2:
        out["module"] = rest[1]
    for opt in options:
        key, _, value = opt.partition("=")
        if out["action"] == "import" and key == "--comment" and value.lower() in COMMENT_TYPES:
            out["comment"] = value.lower()
        elif out["action"] == "export" and key == "--all-comments" and not value:
            out["all_comments"] = True
        else:
            raise ValueError(f"unknown option {opt!r} for {out['action']}")
    return out


class GhidraOps:
    """The tool adapter :func:`core.apply_import_plan` drives, plus export collection."""

    def __init__(self, program: Any, comment_type: str = "eol", api: Any = None) -> None:
        if comment_type not in COMMENT_TYPES:
            raise ValueError(f"comment type must be one of {', '.join(COMMENT_TYPES)}")
        self.program = program
        self.api = api if api is not None else load_ghidra_api()
        self.kind = comment_kind(self.api, comment_type.upper())
        self._space = program.getAddressFactory().getDefaultAddressSpace()

    def imagebase(self) -> int:
        base = self.program.getImageBase()
        getter = getattr(base, "getUnsignedOffset", None)
        return int(getter()) if getter is not None else int(base.getOffset()) & (2**64 - 1)

    def file_names(self) -> list[str]:
        names = []
        for getter in ("getName", "getExecutablePath"):
            value = getattr(self.program, getter, lambda: None)()
            if value:
                names.append(str(value))
        return names

    def to_address(self, address: int) -> Any:
        try:
            return self._space.getAddress(to_signed64(address))
        except Exception:  # noqa: BLE001 - AddressOutOfBoundsException and friends
            return None

    def is_mapped(self, address: int) -> bool:
        addr = self.to_address(address)
        return addr is not None and bool(self.program.getMemory().contains(addr))

    def fix_name(self, name: str) -> str:
        """Ghidra's own check for default-looking names (``FUN_...``, ``DAT_...``, ...)."""
        if self.api.SymbolUtilities.isReservedDynamicLabelName(name, self.program.getAddressFactory()):
            name = "_" + name
        return name[: RULES.name_max]

    def set_name(self, address: int, name: str) -> str:
        addr = self.to_address(address)
        if addr is None:
            return core.NAME_FAILED
        name = self.fix_name(name)
        user = self.api.SourceType.USER_DEFINED
        func = self.program.getFunctionManager().getFunctionAt(addr)
        if func is not None:
            if str(func.getName()) == name:
                return core.NAME_UNCHANGED
            for candidate in core.name_candidates(name, 20, RULES.name_max):
                try:
                    func.setName(candidate, user)
                    return core.NAME_RENAMED
                except self.api.DuplicateNameException:
                    continue
                except self.api.InvalidInputException:
                    return core.NAME_FAILED
            return core.NAME_FAILED
        table = self.program.getSymbolTable()
        for sym in table.getSymbols(addr):
            if str(sym.getName()) == name:
                if not sym.isPrimary():
                    sym.setPrimary()
                return core.NAME_UNCHANGED
        try:
            sym = table.createLabel(addr, name, user)
        except self.api.InvalidInputException:
            return core.NAME_FAILED
        sym.setPrimary()
        return core.NAME_RENAMED

    def get_comment(self, address: int) -> str | None:
        addr = self.to_address(address)
        text = self.program.getListing().getComment(self.kind, addr) if addr is not None else None
        return str(text) if text else None

    def set_comment(self, address: int, text: str) -> bool:
        addr = self.to_address(address)
        if addr is None:
            return False
        self.program.getListing().setComment(addr, self.kind, text)
        return self.get_comment(address) == text

    # ── export ─────────────────────────────────────────────────────
    def _unsigned(self, addr: Any) -> int:
        getter = getattr(addr, "getUnsignedOffset", None)
        return int(getter()) if getter is not None else int(addr.getOffset()) & (2**64 - 1)

    def _loader_comment(self, addr: Any, text: str) -> bool:
        block = self.program.getMemory().getBlock(addr)
        if block is not None and str(block.getName()) in _LOADER_BLOCKS:
            return True
        return bool(_LOADER_COMMENT_RE.fullmatch(" ".join(text.split())))  # Ghidra pads with double spaces

    def collect_annotations(
        self, monitor: Any = None, all_comments: bool = False
    ) -> list[tuple[int, str | None, str | None]]:
        api = self.api
        memory = self.program.getMemory()
        wanted_types = {str(api.SymbolType.LABEL), str(api.SymbolType.FUNCTION)}
        user = str(api.SourceType.USER_DEFINED)
        seen = 0

        def poll() -> None:
            nonlocal seen
            if monitor is not None and seen % CANCEL_CHECK_EVERY == 0 and monitor.isCancelled():
                raise Cancelled()
            seen += 1

        names: dict[int, tuple[bool, str]] = {}
        for sym in self.program.getSymbolTable().getAllSymbols(False):
            poll()
            if str(sym.getSource()) != user or str(sym.getSymbolType()) not in wanted_types or sym.isExternal():
                continue
            addr = sym.getAddress()
            if not addr.isMemoryAddress() or not memory.contains(addr):
                continue
            offset = self._unsigned(addr)
            primary = bool(sym.isPrimary())
            if offset not in names or (primary and not names[offset][0]):
                names[offset] = (primary, str(sym.getName()))
        comments: dict[int, list[str]] = {}
        listing = self.program.getListing()
        for kind_name in _COMMENT_ORDER:
            kind = comment_kind(api, kind_name)
            for addr in listing.getCommentAddressIterator(kind, memory, True):
                poll()
                text = listing.getComment(kind, addr)
                if not text:
                    continue
                text = str(text)
                if not all_comments and self._loader_comment(addr, text):
                    continue
                comments.setdefault(self._unsigned(addr), []).append(text)
        joined = {a: " | ".join(parts) for a, parts in comments.items()}
        return [(a, names[a][1] if a in names else None, joined.get(a)) for a in sorted(set(names) | set(joined))]


def _cancel_check(monitor: Any) -> Any:
    if monitor is None:
        return None
    return lambda done: done % CANCEL_CHECK_EVERY == 0 and bool(monitor.isCancelled())


def import_into(
    program: Any,
    path: str,
    module: str | None = None,
    comment_type: str = "eol",
    monitor: Any = None,
    api: Any = None,
) -> dict[str, Any]:
    """Apply the document at ``path`` to ``program``; returns the counters of
    :func:`core.format_import_report`. Opens a transaction when none is open."""
    ops = GhidraOps(program, comment_type, api)
    doc = core.load_sync_document(core.read_capped(path), RULES)
    key = core.resolve_module(doc, ops.file_names(), module)
    imagebase = ops.imagebase()
    plan = core.build_import_plan(doc, key, imagebase, RULES)
    counts = core.new_import_counts("ghidra", key, imagebase, plan, doc)
    tx = None
    if program.getCurrentTransactionInfo() is None:
        tx = program.startTransaction("x64dbg sync import")
    try:
        core.apply_import_plan(plan, ops, counts, _cancel_check(monitor))
    finally:
        if tx is not None:
            program.endTransaction(tx, True)
    return counts


def export_from(
    program: Any, path: str, monitor: Any = None, all_comments: bool = False, api: Any = None
) -> dict[str, Any]:
    """Write the export document to ``path`` atomically; raises :class:`Cancelled`."""
    ops = GhidraOps(program, "eol", api)
    names = ops.file_names()
    doc = core.build_export_document(
        names[0] if names else "unknown", ops.imagebase(), ops.collect_annotations(monitor, all_comments),
        generated_by=f"x64dbg_sync_ghidra.py {SCRIPT_VERSION} (Ghidra)", rules=RULES,
    )
    core.write_json_atomic(path, doc)
    (key,) = doc["modules"]
    return {"module": key, "items": len(doc["modules"][key]["items"]), "path": path}


# ── script entry point ──────────────────────────────────────────────
def _g(g: Any, key: str, default: Any = None) -> Any:
    """PyGhidra's script globals resolve GhidraScript members through ``__missing__``,
    which ``in`` and ``.get`` bypass: always index."""
    try:
        return g[key]
    except KeyError:
        return default


def _choices(items: list[str]) -> Any:
    try:
        from java.util import ArrayList  # noqa: PLC0415 - inside Ghidra only

        out = ArrayList()
        for item in items:
            out.add(item)
        return out
    except ImportError:
        return list(items)


def _ask_options(g: Any) -> dict[str, Any]:
    ask_choice, ask_file = _g(g, "askChoice"), _g(g, "askFile")
    action = str(ask_choice("x64dbg sync", "Action", _choices(["import", "export"]), "import"))
    opts: dict[str, Any] = {"action": action, "module": None, "comment": "eol", "all_comments": False}
    if action == "import":
        chosen = ask_file("x64dbg-ida-sync JSON to import", "Import")
        opts["comment"] = str(ask_choice("x64dbg sync", "Comment type for x64dbg comments",
                                         _choices(list(COMMENT_TYPES)), "eol"))
    else:
        chosen = ask_file("Save x64dbg-ida-sync JSON", "Export")
    opts["path"] = str(chosen.getAbsolutePath())
    return opts


def run(g: Any, api: Any = None) -> None:
    """Entry point with the script's globals (``currentProgram``, ``getScriptArgs``, ``ask*``...)."""
    out = _g(g, "println") or print
    err = _g(g, "printerr") or out
    program = _g(g, "currentProgram")
    if program is None:
        err("x64dbg sync: run this script inside Ghidra with a program open (PyGhidra)")
        return
    monitor = _g(g, "monitor")
    get_args = _g(g, "getScriptArgs")
    args = [str(a) for a in get_args()] if get_args is not None else []
    headless = _g(g, "isRunningHeadless")
    try:
        if args or (headless is not None and headless()):
            opts = parse_script_args(args)
        else:
            opts = _ask_options(g)
    except ValueError as exc:
        err(f"x64dbg sync: {exc}\n{USAGE}")
        return
    try:
        if opts["action"] == "import":
            try:
                counts = import_into(program, opts["path"], opts["module"], opts["comment"], monitor, api)
            except ValueError as exc:
                ask_string = _g(g, "askString")
                if opts["module"] or args or ask_string is None or "matches" not in str(exc):
                    raise
                answer = ask_string("x64dbg sync", f"{exc}\nModule to import:", "")
                if not answer:
                    return
                counts = import_into(program, opts["path"], str(answer), opts["comment"], monitor, api)
            out(core.format_import_report(counts))
        else:
            result = export_from(program, opts["path"], monitor, opts["all_comments"], api)
            out("x64dbg sync (ghidra): exported {items} items of {module} to {path}".format(**result))
    except Cancelled:
        err("x64dbg sync: export cancelled; nothing was written")
    except (OSError, ValueError) as exc:
        err(f"x64dbg sync: {opts['action']} failed: {exc}")


if __name__ == "__main__":
    run(globals())
