"""x64dbg <-> IDA annotation sync for IDA Pro 8.4 / 9.x (x64dbg-ida-sync JSON).

Two actions:

- "Import x64dbg annotations (x64dbg-ida-sync JSON)" (File > Load file):
  reads a document produced by the x64dbg-vm-gateway (``export_for_ida``),
  picks the module matching the IDB input file name and applies, at
  ``get_imagebase() + rva``: labels as names, comments as regular comments,
  bookmarks/breakpoints as ``[x64dbg: ...]`` comment tags.
- "Export IDA names/comments for x64dbg (x64dbg-ida-sync JSON)"
  (File > Produce file): writes the IDB's non-dummy names and comments as
  RVAs relative to the IDB image base, ready for the gateway's
  ``plan_import`` (AI: ``ida_import_annotations``).

Install: copy this file into IDA's ``plugins`` directory (menu entries appear
at start-up), or run it once with File > Script file... (Alt+F7), which
registers the actions and asks what to do now.

Design: all logic that does not need IDA (JSON validation, rebasing,
sanitising, module matching, report text) lives in plain functions; IDA
modules are imported lazily inside the functions that talk to IDA, so the
file imports and tests under plain Python (static/ida/tests). Keep it compatible with
Python 3.8 (IDA 8.4 may run on it): no ``match``, no runtime ``X | Y`` types.
Input files are untrusted (they derive from a malware VM): sizes and counts
are capped and every string is cleaned of control/bidi characters.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import unicodedata
from collections.abc import Iterable
from typing import Any

SCHEMA = "x64dbg-ida-sync/1"
SCHEMA_FAMILY = "x64dbg-ida-sync/"
SCRIPT_VERSION = "1.0"
GENERATED_BY = f"x64dbg_sync.py {SCRIPT_VERSION} (IDA)"

MAX_DOC_BYTES = 64 * 1024 * 1024
MAX_ITEMS = 50_000
MAX_ADDRESS = 2**64 - 1
IDA_NAME_MAX = 511  # MAXNAMELEN (512) including the NUL
IDA_COMMENT_MAX = 1024
_MAX_HEX_CHARS = 64
_MAX_MODULE_KEY_CHARS = 255
_MAX_CONDITION_CHARS = 256
CANCEL_CHECK_EVERY = 256  # items between ida_kernwin.user_cancelled() polls (module global for tests)

ACTION_IMPORT = "x64dbg_sync:import"
ACTION_EXPORT = "x64dbg_sync:export"
LABEL_IMPORT = "Import x64dbg annotations (x64dbg-ida-sync JSON)"
LABEL_EXPORT = "Export IDA names/comments for x64dbg (x64dbg-ida-sync JSON)"
MENU_IMPORT = "File/Load file/"
MENU_EXPORT = "File/Produce file/"

_HEX_RE = re.compile(r"[0-9a-fA-F]+")
_PATH_SEP_RE = re.compile(r"[\\/]")
_IDA_NAME_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_$?@")
# IDA refuses user names that look like its own dummy names ("sub_401000"). The prefixes are
# the ones listed in IDA's "Names representation" help; SN_NODUMMY (passed when available)
# makes IDA itself prefix anything else it considers dummy-like.
_DUMMY_NAME_RE = re.compile(
    r"(?:sub|locret|loc|off|seg|asc|byte|word|dword|qword|byte3|xmmword|ymmword|zmmword|packreal"
    r"|flt|dbl|tbyte|stru|custdata|algn|unk)_[0-9A-Fa-f]+",
    re.IGNORECASE,
)
_DROP_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn"})
_BP_TYPES = ("normal", "hardware", "memory")


# ── pure helpers ────────────────────────────────────────────────────
def parse_hex(value: Any, what: str = "value") -> int:
    """An int, or a hex string with optional ``0x`` prefix, within 64 bits."""
    if isinstance(value, bool):
        raise ValueError(f"{what} must be a number, not a bool")
    if isinstance(value, int):
        number = value
    elif isinstance(value, str):
        text = value.strip()
        if len(text) > _MAX_HEX_CHARS:
            raise ValueError(f"{what} is too long")
        digits = text[2:] if text[:2] in ("0x", "0X") else text
        if not _HEX_RE.fullmatch(digits):
            raise ValueError(f"{what} {value!r} is not a hex number")
        number = int(digits, 16)
    else:
        raise ValueError(f"{what} must be a hex string or an integer")
    if not 0 <= number <= MAX_ADDRESS:
        raise ValueError(f"{what} is outside the 64-bit range")
    return number


def _clean_text(text: str, max_chars: int) -> str:
    """One line: whitespace -> single space; controls, format (bidi, zero-width),
    surrogate, private-use and unassigned code points dropped."""
    out = []
    for ch in text[: max_chars * 4]:
        if ch.isspace():
            out.append(" ")
        elif unicodedata.category(ch) not in _DROP_CATEGORIES:
            out.append(ch)
    return " ".join("".join(out).split())[:max_chars]


def _name_core(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text[: IDA_NAME_MAX * 4]).strip()
    out = []
    replaced = False
    for ch in normalized:
        if ch in _IDA_NAME_CHARS:
            out.append(ch)
            replaced = False
        elif not replaced:  # one '_' per run of invalid characters
            out.append("_")
            replaced = True
    name = "".join(out)
    if not name.strip("_"):
        return ""
    if name[0].isdigit() or _DUMMY_NAME_RE.fullmatch(name):
        name = "_" + name
    return name[:IDA_NAME_MAX]


def sanitize_ida_name(text: str, fallback: str = "x64dbg_name") -> str:
    """Name safe for ``ida_name.set_name``: ``[A-Za-z0-9_$?@]`` (each run of other
    characters becomes one ``_``), NFKC-normalised, no leading digit, not an IDA
    dummy name, at most ``IDA_NAME_MAX`` characters, never empty."""
    if not isinstance(text, str):
        raise ValueError("name must be a string")
    name = _name_core(text)
    if name:
        return name
    return (_name_core(fallback) if isinstance(fallback, str) else "") or "x64dbg_name"


def sanitize_ida_comment(text: str) -> str:
    """One-line comment without control/bidi/format characters, at most
    ``IDA_COMMENT_MAX`` characters. May return ``""``."""
    if not isinstance(text, str):
        raise ValueError("comment must be a string")
    return _clean_text(text, IDA_COMMENT_MAX)


class Cancelled(Exception):
    """The user pressed Cancel in IDA's wait box."""


def _normalize_item(raw: Any) -> dict[str, Any] | None:
    """Validated import item, or None when it is unusable.

    A name without any IDA-safe character (e.g. all Korean, or ``"::"``) is not
    turned into a placeholder, which would overwrite the IDB's own name: it is
    kept as ``label_text`` and ends up in the comment tag instead.
    """
    if not isinstance(raw, dict):
        return None
    try:
        rva = parse_hex(raw.get("rva"), "rva")
    except ValueError:
        return None
    raw_name = raw.get("name")
    name = None
    label_text = None
    if isinstance(raw_name, str) and raw_name.strip():
        name = _name_core(raw_name) or None
        if name is None:
            label_text = _clean_text(raw_name, IDA_NAME_MAX) or None
    comment = raw.get("comment")
    comment = (sanitize_ida_comment(comment) or None) if isinstance(comment, str) else None
    bookmark = raw.get("bookmark") is True
    breakpoint_info = None
    bp = raw.get("breakpoint")
    if isinstance(bp, dict) and bp.get("type") in _BP_TYPES:
        condition = bp.get("condition")
        breakpoint_info = {
            "type": bp["type"],
            "enabled": bp.get("enabled") is True,
            "condition": (_clean_text(condition, _MAX_CONDITION_CHARS) or None)
            if isinstance(condition, str) else None,
        }
    if name is None and label_text is None and comment is None and not bookmark and breakpoint_info is None:
        return None
    return {
        "rva": rva,
        "name": name,
        "label_text": label_text,
        "comment": comment,
        "bookmark": bookmark,
        "breakpoint": breakpoint_info,
    }


def load_sync_document(data: Any) -> dict[str, Any]:
    """Parse and validate an ``x64dbg-ida-sync/1`` document (bytes or str).

    Returns ``{"schema", "modules": {lower-cased name: {"base_runtime":
    int|None, "items": [{"rva", "name", "label_text", "comment", "bookmark",
    "breakpoint"}]}}, "skipped": int, "warnings": [str]}`` with names and
    comments already sanitised for IDA. Invalid items and module entries are
    skipped (counted / warned); module keys that differ only in case are
    merged (warned). A wrong schema, non-JSON content or an oversized document
    raises ValueError.
    """
    if isinstance(data, (bytes, bytearray)):
        if len(data) > MAX_DOC_BYTES:
            raise ValueError(f"document too large ({len(data)} bytes, limit {MAX_DOC_BYTES})")
        try:
            text = bytes(data).decode("utf-8-sig")
        except UnicodeDecodeError:
            raise ValueError("document is not UTF-8 JSON") from None
    elif isinstance(data, str):
        if len(data) > MAX_DOC_BYTES:
            raise ValueError(f"document too large ({len(data)} characters, limit {MAX_DOC_BYTES})")
        text = data[1:] if data.startswith("﻿") else data
    else:
        raise ValueError("document must be bytes or str")
    if not text.strip():
        raise ValueError("document is empty")
    try:
        root = json.loads(text)
    except RecursionError:
        raise ValueError("document is not valid JSON (nesting too deep)") from None
    except ValueError as exc:
        raise ValueError(f"document is not valid JSON ({str(exc)[:200]})") from None
    if not isinstance(root, dict):
        raise ValueError("document top level must be a JSON object")
    schema = root.get("schema")
    if not isinstance(schema, str):
        raise ValueError(f"document has no schema (expected {SCHEMA!r})")
    if schema != SCHEMA:
        if schema.startswith(SCHEMA_FAMILY):
            raise ValueError(f"unsupported schema version {schema[:40]!r} (this script reads {SCHEMA!r})")
        raise ValueError(f"unsupported schema {schema[:40]!r} (expected {SCHEMA!r})")
    modules = root.get("modules")
    if not isinstance(modules, dict):
        raise ValueError("'modules' must be an object")

    out: dict[str, Any] = {}
    skipped = 0
    warnings: list[str] = []
    total = 0
    truncated = False
    for key, entry in modules.items():
        label = _clean_text(key, _MAX_MODULE_KEY_CHARS) if isinstance(key, str) else ""
        if not label:
            warnings.append("module with an empty name skipped")
            continue
        if not isinstance(entry, dict) or not isinstance(entry.get("items"), list):
            warnings.append(f"module {label!r} skipped: expected an object with an 'items' list")
            continue
        try:
            raw_base = entry.get("base_runtime")
            base = None if raw_base is None else parse_hex(raw_base, "base_runtime")
        except ValueError:
            base = None
        items = []
        for raw in entry["items"]:
            if total >= MAX_ITEMS:
                truncated = True
                break
            item = _normalize_item(raw)
            if item is None:
                skipped += 1
                continue
            items.append(item)
            total += 1
        key = label.lower()
        if key in out:
            warnings.append(f"module {label!r} merged with an earlier key: module names differ only in case")
            out[key]["items"].extend(items)
            if out[key]["base_runtime"] is None:
                out[key]["base_runtime"] = base
        else:
            out[key] = {"base_runtime": base, "items": items}
    if truncated:
        warnings.append(f"document truncated to {MAX_ITEMS} items")
    return {"schema": schema, "modules": out, "skipped": skipped, "warnings": warnings}


def _stem(name: str) -> str:
    return name.rsplit(".", 1)[0] if "." in name else name


def match_module(module_names: Iterable[str], input_file_name: str) -> str | None:
    """Module of the document that belongs to this IDB, or None.

    Case-insensitive exact file-name match first, then a unique match on the
    name without extension (an IDB of ``sample.bin`` matches ``sample.exe``).
    """
    names = [n for n in module_names if isinstance(n, str)]
    root = _PATH_SEP_RE.split(input_file_name or "")[-1].strip().lower()
    if not root or not names:
        return None
    for n in names:
        if n.lower() == root:
            return n
    stem = _stem(root)
    candidates = [n for n in names if _stem(n.lower()) == stem]
    return candidates[0] if len(candidates) == 1 else None


def describe_tags(item: dict[str, Any]) -> str | None:
    """``[x64dbg: label <text>; bookmark; hardware bp, disabled, condition rcx==1]`` or None.

    ``label <text>`` carries an x64dbg label that has no IDA-safe characters."""
    tags = []
    if item.get("label_text"):
        tags.append("label {}".format(item["label_text"]))
    if item.get("bookmark"):
        tags.append("bookmark")
    bp = item.get("breakpoint")
    if bp:
        text = "{} bp, {}".format(bp["type"], "enabled" if bp.get("enabled") else "disabled")
        if bp.get("condition"):
            text += ", condition {}".format(bp["condition"])
        tags.append(text)
    return "[x64dbg: {}]".format("; ".join(tags)) if tags else None


def build_import_plan(doc: dict[str, Any], module_key: str, imagebase: int) -> list[dict[str, Any]]:
    """``[{"ea", "rva", "name", "comment"}]`` for one module of a loaded document.

    ``ea = imagebase + rva``; items whose address would overflow are dropped.
    The comment combines the item comment and its bookmark/breakpoint tags.
    """
    modules = doc.get("modules", {})
    key = (module_key or "").lower()
    if key not in modules:
        raise ValueError("module {!r} is not in the document (has: {})".format(
            module_key, ", ".join(sorted(modules)[:20]) or "none"))
    base = parse_hex(imagebase, "imagebase")
    plan = []
    for item in modules[key]["items"]:
        ea = base + item["rva"]
        if ea > MAX_ADDRESS:
            continue
        parts = [p for p in (item.get("comment"), describe_tags(item)) if p]
        comment = sanitize_ida_comment(" ".join(parts)) if parts else ""
        plan.append({"ea": ea, "rva": item["rva"], "name": item.get("name"), "comment": comment or None})
    return plan


def merge_comment(existing: str | None, new: str | None) -> str | None:
    """Comment to store, or None when nothing changes (empty, or already present as a
    whole line, which keeps re-imports idempotent since merged comments are joined
    with newlines). A substring of a longer line is not a duplicate."""
    if not new:
        return None
    if not existing:
        return new
    if new in existing.splitlines():
        return None
    return existing + "\n" + new


def name_flags(ida_name_module: Any) -> int:
    """``SN_NOWARN | SN_FORCE`` plus ``SN_NOCHECK`` / ``SN_NODUMMY`` when the IDA
    version provides them (invalid characters replaced, dummy-like names
    prefixed instead of failing)."""
    flags = 0
    for attr in ("SN_NOWARN", "SN_FORCE", "SN_NOCHECK", "SN_NODUMMY"):
        flags |= int(getattr(ida_name_module, attr, 0))
    return flags


def build_export_document(
    module_name: str,
    imagebase: int,
    entries: Iterable[tuple[int, str | None, str | None]],
    generated_by: str = GENERATED_BY,
) -> dict[str, Any]:
    """``x64dbg-ida-sync/1`` document from ``(ea, name, comment)`` entries.

    RVAs are relative to ``imagebase``; addresses below it are skipped.
    Entries at the same address are merged (comments joined with `` | ``).
    Names keep IDA's spelling (cleaned of control characters); the gateway
    makes them x64dbg-safe in ``plan_import``.
    """
    base = parse_hex(imagebase, "imagebase")
    merged: dict[int, dict[str, Any]] = {}
    below = 0
    for ea, name, comment in entries:
        if ea < base:
            below += 1
            continue
        name = _clean_text(name, IDA_NAME_MAX) if isinstance(name, str) else ""
        comment = sanitize_ida_comment(comment) if isinstance(comment, str) else ""
        if not name and not comment:
            continue
        item = merged.setdefault(ea - base, {"rva": f"0x{ea - base:X}"})
        if name and "name" not in item:
            item["name"] = name
        if comment:
            item["comment"] = item["comment"] + " | " + comment if "comment" in item else comment
    warnings = []
    items = [merged[rva] for rva in sorted(merged)]
    if len(items) > MAX_ITEMS:
        warnings.append(f"export truncated to {MAX_ITEMS} items")
        items = items[:MAX_ITEMS]
    key = (_PATH_SEP_RE.split(module_name or "")[-1].strip() or "unknown").lower()
    return {
        "schema": SCHEMA,
        "generated_by": generated_by,
        "modules": {key: {"base_runtime": None, "ida_imagebase": f"0x{base:X}", "items": items}},
        "skipped": {"below_imagebase": below},
        "warnings": warnings,
    }


def format_import_report(counts: dict[str, Any]) -> str:
    values = {"name_unusable": 0, "cancelled": False, "processed": counts.get("items", 0)}
    values.update(counts)
    text = (
        "x64dbg sync: imported module {module} at image base {imagebase}\n"
        "items {items}: renamed {renamed} (failed {rename_failed}), commented {commented} "
        "(unchanged {comment_unchanged}, failed {comment_failed}), unmapped {unmapped}, "
        "names kept as comments {name_unusable}, invalid items skipped {skipped_invalid}"
    ).format(**values)
    if values["cancelled"]:
        text += "\ncancelled by the user after {processed} of {items} items".format(**values)
    return text


def _cancel_poller(ida_kernwin: Any) -> Any:
    """Callable that raises :class:`Cancelled` once the user pressed Cancel; it
    polls ``user_cancelled()`` on the first call and every ``CANCEL_CHECK_EVERY``."""
    calls = [0]

    def poll() -> None:
        if calls[0] % max(1, CANCEL_CHECK_EVERY) == 0 and ida_kernwin.user_cancelled():
            raise Cancelled()
        calls[0] += 1

    return poll


def _write_json_atomic(path: str, doc: Any) -> None:
    """Write to a temporary file next to ``path`` and rename it over ``path``, so a
    failed write (disk full, ...) never leaves a truncated file behind."""
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".x64dbg-sync-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=1, ensure_ascii=False)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _read_capped(path: str) -> bytes:
    with open(path, "rb") as fh:
        data = fh.read(MAX_DOC_BYTES + 1)
    if len(data) > MAX_DOC_BYTES:
        raise ValueError(f"document too large (limit {MAX_DOC_BYTES} bytes)")
    return data


# ── IDA-facing code (imports IDA modules lazily) ────────────────────
def import_from_file(path: str, module: str | None = None, interactive: bool = True) -> dict[str, Any]:
    """Apply a document to the current IDB; returns counters (see
    :func:`format_import_report`). Raises ValueError/OSError on bad input."""
    import ida_bytes
    import ida_kernwin
    import ida_nalt
    import ida_name
    import idaapi

    doc = load_sync_document(_read_capped(path))
    root = ida_nalt.get_root_filename() or ""
    key = module.strip().lower() if module else match_module(doc["modules"], root)
    if key is None and interactive and doc["modules"]:
        choices = ", ".join(sorted(doc["modules"])[:20])
        answer = ida_kernwin.ask_str(
            sorted(doc["modules"])[0], 0,
            f"No module in the file matches '{root}'. Module to import ({choices}):",
        )
        key = answer.strip().lower() if answer else None
    if key is None or key not in doc["modules"]:
        raise ValueError("no module in the document matches the input file {!r} (document has: {})".format(
            root, ", ".join(sorted(doc["modules"])[:20]) or "none"))

    imagebase = int(idaapi.get_imagebase())
    plan = build_import_plan(doc, key, imagebase)
    flags = name_flags(ida_name)
    counts = {
        "module": key, "imagebase": f"0x{imagebase:X}", "items": len(plan),
        "renamed": 0, "rename_failed": 0, "commented": 0, "comment_unchanged": 0, "comment_failed": 0,
        "unmapped": 0, "skipped_invalid": doc["skipped"],
        "name_unusable": sum(1 for item in doc["modules"][key]["items"] if item.get("label_text")),
        "cancelled": False, "processed": 0,
    }
    poll = _cancel_poller(ida_kernwin)
    ida_kernwin.show_wait_box(f"x64dbg sync: importing {len(plan)} items of {key}")
    try:
        for entry in plan:
            poll()
            counts["processed"] += 1
            ea = entry["ea"]
            if not ida_bytes.is_mapped(ea):
                counts["unmapped"] += 1
                continue
            if entry["name"]:
                if ida_name.set_name(ea, entry["name"], flags):
                    counts["renamed"] += 1
                else:
                    counts["rename_failed"] += 1
            if entry["comment"]:
                merged = merge_comment(ida_bytes.get_cmt(ea, False), entry["comment"])
                if merged is None:
                    counts["comment_unchanged"] += 1
                elif ida_bytes.set_cmt(ea, merged, False):
                    counts["commented"] += 1
                else:
                    counts["comment_failed"] += 1
    except Cancelled:
        counts["cancelled"] = True  # changes made so far stay (IDA's undo can revert them)
    finally:
        ida_kernwin.hide_wait_box()
    return counts


def collect_ida_annotations() -> list[tuple[int, str | None, str | None]]:
    """``(ea, name, comment)`` for non-dummy names and comments outside extern
    segments, sorted by address. Comments: regular + repeatable instruction
    comments and, at function starts, the function comments. Raises
    :class:`Cancelled` when the user cancels the wait box shown by the caller."""
    import ida_bytes
    import ida_funcs
    import ida_kernwin
    import ida_segment
    import idautils

    xtrn = getattr(ida_segment, "SEG_XTRN", 1)
    poll = _cancel_poller(ida_kernwin)

    def in_image(ea: int) -> bool:
        seg = ida_segment.getseg(ea)
        return seg is not None and seg.type != xtrn

    names: dict[int, str] = {}
    comments: dict[int, list[str]] = {}
    for ea, name in idautils.Names():
        poll()
        if in_image(ea):
            names[ea] = name
    for fea in idautils.Functions():
        poll()
        func = ida_funcs.get_func(fea)
        if func is None or not in_image(fea):
            continue
        for rpt in (False, True):
            text = ida_funcs.get_func_cmt(func, rpt)
            if text:
                comments.setdefault(fea, []).append(text)
    for seg_start in idautils.Segments():
        seg = ida_segment.getseg(seg_start)
        if seg is None or seg.type == xtrn:
            continue
        for ea in idautils.Heads(seg.start_ea, seg.end_ea):
            poll()
            for rpt in (False, True):
                text = ida_bytes.get_cmt(ea, rpt)
                if text:
                    comments.setdefault(ea, []).append(text)
    return [
        (ea, names.get(ea), " | ".join(comments[ea]) if ea in comments else None)
        for ea in sorted(set(names) | set(comments))
    ]


def export_to_file(path: str) -> dict[str, Any]:
    """Write the export document to ``path`` atomically (the previous file survives
    a failed or cancelled export). Raises OSError/ValueError or :class:`Cancelled`."""
    import ida_kernwin
    import ida_nalt
    import idaapi

    root = ida_nalt.get_root_filename() or "unknown"
    ida_kernwin.show_wait_box(f"x64dbg sync: collecting names and comments of {root}")
    try:
        doc = build_export_document(root, int(idaapi.get_imagebase()), collect_ida_annotations())
        _write_json_atomic(path, doc)
    finally:
        ida_kernwin.hide_wait_box()
    (module,) = doc["modules"]
    return {"module": module, "items": len(doc["modules"][module]["items"]), "path": path}


def run_import_action() -> dict[str, Any] | None:
    import ida_kernwin

    path = ida_kernwin.ask_file(False, "*.json", "Select an x64dbg-ida-sync JSON file to import")
    if not path:
        return None
    try:
        counts = import_from_file(path)
    except (OSError, ValueError) as exc:
        ida_kernwin.warning(f"x64dbg sync: import failed: {exc}")
        return None
    ida_kernwin.info(format_import_report(counts))
    return counts


def run_export_action() -> dict[str, Any] | None:
    import ida_kernwin
    import ida_nalt

    default = "{}.x64dbg-ida-sync.json".format(ida_nalt.get_root_filename() or "idb")
    path = ida_kernwin.ask_file(True, default, "Save IDA names/comments for x64dbg")
    if not path:
        return None
    try:
        result = export_to_file(path)
    except Cancelled:
        ida_kernwin.warning("x64dbg sync: export cancelled; nothing was written")
        return None
    except (OSError, ValueError) as exc:
        ida_kernwin.warning(f"x64dbg sync: export failed: {exc}")
        return None
    ida_kernwin.info("x64dbg sync: exported {items} items of {module} to {path}".format(**result))
    return result


_ACTIONS = (
    (ACTION_IMPORT, LABEL_IMPORT, "Apply x64dbg labels/comments/bookmarks/breakpoints to this IDB",
     run_import_action, MENU_IMPORT),
    (ACTION_EXPORT, LABEL_EXPORT, "Write this IDB's names and comments as RVAs for x64dbg",
     run_export_action, MENU_EXPORT),
)


def _make_handler(ida_kernwin: Any, callback: Any) -> Any:
    class _Handler(ida_kernwin.action_handler_t):
        def __init__(self) -> None:
            ida_kernwin.action_handler_t.__init__(self)

        def activate(self, ctx: Any) -> int:
            callback()
            return 1

        def update(self, ctx: Any) -> int:
            return ida_kernwin.AST_ENABLE_ALWAYS

    return _Handler()


def register_actions() -> bool:
    """Register both actions and attach them to the menus; re-running replaces them."""
    import ida_kernwin

    ok = True
    for action_id, label, tooltip, callback, menu in _ACTIONS:
        ida_kernwin.unregister_action(action_id)
        handler = _make_handler(ida_kernwin, callback)
        desc = ida_kernwin.action_desc_t(action_id, label, handler, None, tooltip, -1)
        if not ida_kernwin.register_action(desc):
            ok = False
            continue
        ida_kernwin.attach_action_to_menu(menu, action_id, ida_kernwin.SETMENU_APP)
    return ok


def unregister_actions() -> None:
    import ida_kernwin

    for action_id, _label, _tooltip, _callback, _menu in _ACTIONS:
        ida_kernwin.unregister_action(action_id)


def choose_and_run() -> None:
    import ida_kernwin

    choice = ida_kernwin.ask_buttons(
        "Import", "Export", "Cancel", 1,
        "x64dbg sync: import x64dbg annotations into this IDB, or export its names/comments?",
    )
    if choice == 1:
        run_import_action()
    elif choice == 0:
        run_export_action()


def PLUGIN_ENTRY() -> Any:  # noqa: N802 - name required by IDA
    import idaapi

    class X64dbgSyncPlugin(idaapi.plugin_t):
        # plugin_t.flags takes PLUGIN_* flag bits; PLUGIN_KEEP is only an init() return
        # code (its value 2 would mean PLUGIN_DRAW here). 0: loaded per database.
        flags = 0
        comment = "Exchange names/comments with x64dbg (x64dbg-ida-sync JSON)"
        help = "File > Load file / Produce file > x64dbg-ida-sync JSON; see static/ida/README.md"
        wanted_name = "x64dbg sync"
        wanted_hotkey = ""

        def init(self) -> int:
            register_actions()
            return idaapi.PLUGIN_KEEP

        def run(self, arg: int) -> bool:
            choose_and_run()
            return True

        def term(self) -> None:
            unregister_actions()

    return X64dbgSyncPlugin()


def main() -> None:
    register_actions()
    choose_and_run()


if __name__ == "__main__":
    main()
