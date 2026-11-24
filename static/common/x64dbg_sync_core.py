"""Tool-independent core of the x64dbg <-> static-tool annotation sync.

The x64dbg-vm-gateway exchanges annotations with static analysis tools through
one JSON document, schema ``x64dbg-ida-sync/1``, keyed by module + RVA::

    {"schema": "x64dbg-ida-sync/1", "generated_by": "...",
     "modules": {"sample.exe": {"base_runtime": "0x7FF6A1230000" | null,
                                "items": [{"rva": "0x1000", "name"?, "comment"?,
                                           "bookmark"?: true,
                                           "breakpoint"?: {type, enabled, condition?}}]}},
     "skipped": {...}, "warnings": [...]}

``static address = image base of the static tool + rva``. This module holds the
logic every per-tool script shares (Ghidra, radare2 / rizin / Cutter): loading and
validating a document, module matching, the import plan for an image base, the
name/comment rules of each target tool, applying a plan through a small tool
adapter, and building an export document.

It mirrors the rules of ``static/ida/x64dbg_sync.py`` (it does not import it; the
parity tests in static/tests run both on the same inputs). Pure Python 3.9+,
standard library only, no tool module is imported. Input documents are
untrusted (they derive from a malware analysis VM): sizes and counts are capped
and every string is cleaned of control/bidi characters.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import unicodedata
from collections.abc import Callable, Iterable, Iterator
from typing import Any

SCHEMA = "x64dbg-ida-sync/1"
SCHEMA_FAMILY = "x64dbg-ida-sync/"
CORE_VERSION = "1.0"

MAX_DOC_BYTES = 64 * 1024 * 1024
MAX_ITEMS = 50_000
MAX_ADDRESS = 2**64 - 1
_MAX_HEX_CHARS = 64
_MAX_MODULE_KEY_CHARS = 255
_MAX_CONDITION_CHARS = 256
_MAX_LISTED = 20
_MAX_ERRORS = 20

NAME_RENAMED = "renamed"
NAME_UNCHANGED = "unchanged"
NAME_FAILED = "failed"

_HEX_RE = re.compile(r"[0-9a-fA-F]+")
_PATH_SEP_RE = re.compile(r"[\\/]")
_DROP_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn"})
_BP_TYPES = ("normal", "hardware", "memory")


# ── numbers and text ────────────────────────────────────────────────
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


def format_hex(value: int) -> str:
    """``0x`` followed by upper-case hex, the document's address format."""
    return f"0x{value:X}"


def clean_text(text: str, max_chars: int) -> str:
    """One line: whitespace -> single space; controls, format (bidi, zero-width),
    surrogate, private-use and unassigned code points dropped."""
    out = []
    for ch in text[: max_chars * 4]:
        if ch.isspace():
            out.append(" ")
        elif unicodedata.category(ch) not in _DROP_CATEGORIES:
            out.append(ch)
    return " ".join("".join(out).split())[:max_chars]


def _replace_runs(text: str, keep: Callable[[str], bool]) -> str:
    """Characters for which ``keep`` is false become ``_``, one per run."""
    out = []
    replaced = False
    for ch in text:
        if keep(ch):
            out.append(ch)
            replaced = False
        elif not replaced:
            out.append("_")
            replaced = True
    return "".join(out)


# ── name rules per target tool ──────────────────────────────────────
_IDA_NAME_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_$?@")
# IDA refuses user names that look like its own dummy names ("sub_401000"); same list as
# static/ida/x64dbg_sync.py (IDA's "Names representation" help).
_IDA_DUMMY_RE = re.compile(
    r"(?:sub|locret|loc|off|seg|asc|byte|word|dword|qword|byte3|xmmword|ymmword|zmmword|packreal"
    r"|flt|dbl|tbyte|stru|custdata|algn|unk)_[0-9A-Fa-f]+",
    re.IGNORECASE,
)


def _ida_core(text: str, max_len: int) -> str:
    """Exactly ``_name_core`` of static/ida/x64dbg_sync.py: ``[A-Za-z0-9_$?@]``, no leading
    digit, no IDA dummy name; ``""`` when no IDA-safe character is left."""
    normalized = unicodedata.normalize("NFKC", text[: max_len * 4]).strip()
    name = _replace_runs(normalized, lambda ch: ch in _IDA_NAME_CHARS)
    if not name.strip("_"):
        return ""
    if name[0].isdigit() or _IDA_DUMMY_RE.fullmatch(name):
        name = "_" + name
    return name[:max_len]


# Ghidra 12.2 SymbolUtilities: whitespace and these code points are invalid in symbol
# names (EXTRA_INVALID_CODEPOINTS, read from the class); everything else is accepted
# (checked with createLabel in Ghidra 12.2: "a::b", "~dtor", "a<b>", Korean, ...).
_GHIDRA_EXTRA_INVALID = frozenset(chr(c) for c in (0x2800, 0x115F, 0x1160, 0x3164, 0xFFA0, 0xFFFC))
# Ghidra's own default/dynamic names; a user label spelled like one is confusing (and is
# taken for a default name by some Ghidra code), so such names get a "_" prefix. The
# Ghidra script additionally asks SymbolUtilities.isReservedDynamicLabelName at runtime.
_GHIDRA_DEFAULT_RE = re.compile(
    r"(?:FUN|LAB|SUB|DAT|UNK|EXT|OFF|PTR|BYTE|WORD|DWORD|QWORD|FLOAT|DOUBLE|CHAR|BOOL|STRUCT|UNION|ARRAY"
    r"|PTR_FUN|PTR_LAB|PTR_DAT|switchD|caseD|thunk_FUN)_[0-9A-Fa-f]{4,}"
    r"|[su]_\S*_[0-9A-Fa-f]{8,}"
)


def _ghidra_keep(ch: str) -> bool:
    return not ch.isspace() and ch not in _GHIDRA_EXTRA_INVALID and unicodedata.category(ch) not in _DROP_CATEGORIES


def _ghidra_core(text: str, max_len: int) -> str:
    """NFKC; whitespace, control/format characters and Ghidra's extra invalid code
    points become ``_`` (one per run); default-looking names get a ``_`` prefix."""
    normalized = unicodedata.normalize("NFKC", text[: max_len * 4]).strip()
    name = _replace_runs(normalized, _ghidra_keep)
    if not name.strip("_"):
        return ""
    if _GHIDRA_DEFAULT_RE.fullmatch(name):
        name = "_" + name
    return name[:max_len]


_R2_NAME_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.")
R2_DIGIT_PREFIX = "lbl_"


def _r2_core(text: str, max_len: int) -> str:
    """Flag/function names that radare2 6.2 and rizin 0.9 both store unchanged.

    Measured with ``f <name> @ addr``: radare2 refuses names with characters outside
    ``[A-Za-z0-9_.:]`` and names starting with a digit or ``.``; rizin replaces other
    characters with ``_`` and strips a leading ``_``. So: ``[A-Za-z0-9_.]`` (each run of
    other characters becomes one ``_``), leading ``_``/``.`` stripped, a leading digit
    gets the ``lbl_`` prefix. Only these characters are ever written into an r2/rizin
    command line, so a name can never inject a command (``;``, ``|``, `` ` ``, ``@``...).
    """
    normalized = unicodedata.normalize("NFKC", text[: max_len * 4]).strip()
    name = _replace_runs(normalized, lambda ch: ch in _R2_NAME_CHARS).lstrip("_.")
    if not name:
        return ""
    if name[0].isdigit():
        name = R2_DIGIT_PREFIX + name
    return name[:max_len]


class TargetRules:
    """Name/comment rules of one target tool."""

    def __init__(self, tool: str, name_max: int, comment_max: int, core: Callable[[str, int], str]) -> None:
        self.tool = tool
        self.name_max = name_max
        self.comment_max = comment_max
        self._core = core

    def __repr__(self) -> str:
        return f"TargetRules({self.tool!r})"

    def name_core(self, text: str) -> str:
        """The tool-safe name, or ``""`` when no usable character is left."""
        return self._core(text, self.name_max)

    def sanitize_name(self, text: str, fallback: str = "x64dbg_name") -> str:
        """Tool-safe name, never empty (``fallback``, then ``x64dbg_name``)."""
        if not isinstance(text, str):
            raise ValueError("name must be a string")
        name = self.name_core(text)
        if name:
            return name
        return (self.name_core(fallback) if isinstance(fallback, str) else "") or "x64dbg_name"

    def sanitize_comment(self, text: str) -> str:
        """One-line comment without control/bidi/format characters, at most
        ``comment_max`` characters. May return ``""``."""
        if not isinstance(text, str):
            raise ValueError("comment must be a string")
        return clean_text(text, self.comment_max)


IDA = TargetRules("ida", 511, 1024, _ida_core)  # MAXNAMELEN (512) including the NUL
GHIDRA = TargetRules("ghidra", 2000, 1024, _ghidra_core)  # SymbolUtilities.MAX_SYMBOL_NAME_LENGTH
RADARE2 = TargetRules("radare2", 255, 1024, _r2_core)  # also rizin and Cutter (rizin core)
_TARGETS = {"ida": IDA, "ghidra": GHIDRA, "radare2": RADARE2, "r2": RADARE2, "rizin": RADARE2, "cutter": RADARE2}


def rules_for(tool: str) -> TargetRules:
    try:
        return _TARGETS[tool.strip().lower()]
    except (KeyError, AttributeError):
        raise ValueError(f"unknown target tool {tool!r} (known: {', '.join(sorted(_TARGETS))})") from None


def name_candidates(name: str, limit: int = 100, max_len: int | None = None) -> Iterator[str]:
    """``name``, then ``name_1`` ... ``name_<limit>`` (each within ``max_len``), for tools
    whose names must be unique (like IDA's ``SN_FORCE`` numeric suffixes)."""
    if max_len is None:
        max_len = len(name) + len(str(limit)) + 1
    yield name[:max_len]
    for i in range(1, limit + 1):
        suffix = f"_{i}"
        yield name[: max(1, max_len - len(suffix))] + suffix


# ── document loading ────────────────────────────────────────────────
def _normalize_item(raw: Any, rules: TargetRules) -> dict[str, Any] | None:
    """Validated import item, or None when it is unusable.

    A name without any character usable by the target tool (e.g. all Korean for
    IDA/radare2, or ``"::"``) is not turned into a placeholder, which would overwrite
    the tool's own name: it is kept as ``label_text`` and ends up in the comment tag.
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
        name = rules.name_core(raw_name) or None
        if name is None:
            label_text = clean_text(raw_name, rules.name_max) or None
    comment = raw.get("comment")
    comment = (rules.sanitize_comment(comment) or None) if isinstance(comment, str) else None
    bookmark = raw.get("bookmark") is True
    breakpoint_info = None
    bp = raw.get("breakpoint")
    if isinstance(bp, dict) and bp.get("type") in _BP_TYPES:
        condition = bp.get("condition")
        breakpoint_info = {
            "type": bp["type"],
            "enabled": bp.get("enabled") is True,
            "condition": (clean_text(condition, _MAX_CONDITION_CHARS) or None)
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


def load_sync_document(data: Any, rules: TargetRules = IDA) -> dict[str, Any]:
    """Parse and validate an ``x64dbg-ida-sync/1`` document (bytes or str).

    Returns ``{"schema", "modules": {lower-cased name: {"base_runtime": int|None,
    "items": [{"rva", "name", "label_text", "comment", "bookmark", "breakpoint"}]}},
    "skipped": int, "warnings": [str]}`` with names and comments already made safe
    for ``rules``' tool. Invalid items and module entries are skipped (counted /
    warned); module keys that differ only in case are merged (warned). A wrong
    schema, non-JSON content or an oversized document raises ValueError.
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
        label = clean_text(key, _MAX_MODULE_KEY_CHARS) if isinstance(key, str) else ""
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
            item = _normalize_item(raw, rules)
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


def read_capped(path: str) -> bytes:
    """The file's bytes; ValueError when it is larger than ``MAX_DOC_BYTES``."""
    with open(path, "rb") as fh:
        data = fh.read(MAX_DOC_BYTES + 1)
    if len(data) > MAX_DOC_BYTES:
        raise ValueError(f"document too large (limit {MAX_DOC_BYTES} bytes)")
    return data


# ── module matching ─────────────────────────────────────────────────
def _stem(name: str) -> str:
    return name.rsplit(".", 1)[0] if "." in name else name


def _base_name(path: str) -> str:
    return _PATH_SEP_RE.split(path or "")[-1].strip()


def match_module(module_names: Iterable[str], input_file_name: str) -> str | None:
    """Module of the document that belongs to the analysed file, or None.

    Case-insensitive exact file-name match first, then a unique match on the
    name without extension (``sample.bin`` matches ``sample.exe``).
    """
    names = [n for n in module_names if isinstance(n, str)]
    root = _base_name(input_file_name).lower()
    if not root or not names:
        return None
    for n in names:
        if n.lower() == root:
            return n
    stem = _stem(root)
    candidates = [n for n in names if _stem(n.lower()) == stem]
    return candidates[0] if len(candidates) == 1 else None


def _known(doc: dict[str, Any]) -> str:
    return ", ".join(sorted(doc.get("modules", {}))[:_MAX_LISTED]) or "none"


def resolve_module(doc: dict[str, Any], file_names: Iterable[str], module: str | None = None) -> str:
    """Key of the module to import: ``module`` when given (file name, path or stem,
    case-insensitive), else the first of ``file_names`` (program name, executable
    path, ...) that :func:`match_module` matches. ValueError lists the modules."""
    modules = doc.get("modules", {})
    if module is not None and module.strip():
        wanted = _base_name(module).lower()
        if wanted in modules:
            return wanted
        found = match_module(modules, wanted)
        if found is None and "." not in wanted:
            stems = [n for n in modules if _stem(n) == wanted]
            found = stems[0] if len(stems) == 1 else None
        if found is None:
            raise ValueError(f"module {module!r} is not in the document (has: {_known(doc)})")
        return found
    tried: list[str] = []
    for name in file_names:
        if not name:
            continue
        if _base_name(name) not in tried:
            tried.append(_base_name(name))
        found = match_module(modules, name)
        if found is not None:
            return found
    raise ValueError("no module in the document matches {} (document has: {}); name one explicitly".format(
        ", ".join(repr(t) for t in tried) or "the program", _known(doc)))


# ── import planning ─────────────────────────────────────────────────
def describe_tags(item: dict[str, Any]) -> str | None:
    """``[x64dbg: label <text>; bookmark; hardware bp, disabled, condition rcx==1]`` or None.

    ``label <text>`` carries an x64dbg label that has no character usable by the tool."""
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


def build_import_plan(
    doc: dict[str, Any], module_key: str, imagebase: int, rules: TargetRules = IDA
) -> list[dict[str, Any]]:
    """``[{"address", "rva", "name", "comment"}]`` for one module of a loaded document.

    ``address = imagebase + rva``; items whose address would overflow are dropped.
    The comment combines the item comment and its bookmark/breakpoint tags. Items
    keep document order (two items at one RVA give two entries, applied in turn).
    """
    modules = doc.get("modules", {})
    key = (module_key or "").lower()
    if key not in modules:
        raise ValueError(f"module {module_key!r} is not in the document (has: {_known(doc)})")
    base = parse_hex(imagebase, "imagebase")
    plan = []
    for item in modules[key]["items"]:
        address = base + item["rva"]
        if address > MAX_ADDRESS:
            continue
        parts = [p for p in (item.get("comment"), describe_tags(item)) if p]
        comment = rules.sanitize_comment(" ".join(parts)) if parts else ""
        plan.append({"address": address, "rva": item["rva"], "name": item.get("name"), "comment": comment or None})
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


def new_import_counts(
    tool: str, module_key: str, imagebase: int, plan: list[dict[str, Any]], doc: dict[str, Any]
) -> dict[str, Any]:
    """Counters for :func:`apply_import_plan` / :func:`format_import_report`."""
    items = doc.get("modules", {}).get(module_key, {}).get("items", [])
    return {
        "tool": tool, "module": module_key, "imagebase": format_hex(imagebase), "items": len(plan),
        "renamed": 0, "name_unchanged": 0, "rename_failed": 0,
        "commented": 0, "comment_unchanged": 0, "comment_failed": 0,
        "unmapped": 0, "skipped_invalid": doc.get("skipped", 0),
        "name_unusable": sum(1 for item in items if item.get("label_text")),
        "cancelled": False, "processed": 0, "errors": [],
    }


def _note_error(counts: dict[str, Any], what: str, address: int, exc: BaseException) -> None:
    if len(counts["errors"]) < _MAX_ERRORS:
        counts["errors"].append(f"{what} at {format_hex(address)}: {type(exc).__name__}: {str(exc)[:200]}")


def apply_import_plan(
    plan: list[dict[str, Any]],
    ops: Any,
    counts: dict[str, Any],
    cancel_check: Callable[[int], bool] | None = None,
) -> dict[str, Any]:
    """Apply a plan through a tool adapter and update ``counts`` in place.

    ``ops`` provides ``is_mapped(address) -> bool``, ``set_name(address, name) ->
    NAME_RENAMED | NAME_UNCHANGED | NAME_FAILED``, ``get_comment(address) -> str|None``
    and ``set_comment(address, text) -> bool``. Comments are merged with
    :func:`merge_comment` (never overwritten; re-imports change nothing). An
    exception raised by the tool counts as a failure of that one operation.
    ``cancel_check(done)`` is called before each entry; True stops the import
    (``counts["cancelled"]``), the changes made so far stay.
    """
    for entry in plan:
        if cancel_check is not None and cancel_check(counts["processed"]):
            counts["cancelled"] = True
            break
        counts["processed"] += 1
        address = entry["address"]
        try:
            mapped = ops.is_mapped(address)
        except Exception as exc:  # noqa: BLE001 - tool errors are reported, not fatal
            _note_error(counts, "is_mapped", address, exc)
            mapped = False
        if not mapped:
            counts["unmapped"] += 1
            continue
        if entry["name"]:
            try:
                result = ops.set_name(address, entry["name"])
            except Exception as exc:  # noqa: BLE001
                _note_error(counts, "set_name", address, exc)
                result = NAME_FAILED
            if result == NAME_RENAMED:
                counts["renamed"] += 1
            elif result == NAME_UNCHANGED:
                counts["name_unchanged"] += 1
            else:
                counts["rename_failed"] += 1
        if entry["comment"]:
            try:
                merged = merge_comment(ops.get_comment(address), entry["comment"])
                if merged is None:
                    counts["comment_unchanged"] += 1
                elif ops.set_comment(address, merged):
                    counts["commented"] += 1
                else:
                    counts["comment_failed"] += 1
            except Exception as exc:  # noqa: BLE001
                _note_error(counts, "comment", address, exc)
                counts["comment_failed"] += 1
    return counts


def format_import_report(counts: dict[str, Any]) -> str:
    values = {"tool": "?", "name_unusable": 0, "cancelled": False, "processed": counts.get("items", 0)}
    values.update(counts)
    text = (
        "x64dbg sync ({tool}): imported module {module} at image base {imagebase}\n"
        "items {items}: renamed {renamed} (unchanged {name_unchanged}, failed {rename_failed}), "
        "commented {commented} (unchanged {comment_unchanged}, failed {comment_failed}), unmapped {unmapped}, "
        "names kept as comments {name_unusable}, invalid items skipped {skipped_invalid}"
    ).format(**values)
    if values["cancelled"]:
        text += "\ncancelled by the user after {processed} of {items} items".format(**values)
    for error in values.get("errors") or []:
        text += "\nerror: " + error
    return text


# ── export ──────────────────────────────────────────────────────────
def build_export_document(
    module_name: str,
    imagebase: int,
    entries: Iterable[tuple[int, str | None, str | None]],
    generated_by: str = f"x64dbg_sync_core {CORE_VERSION}",
    rules: TargetRules = IDA,
) -> dict[str, Any]:
    """``x64dbg-ida-sync/1`` document from ``(address, name, comment)`` entries.

    RVAs are relative to ``imagebase``; addresses below it are skipped. Entries at
    the same address are merged (first name wins, comments joined with `` | ``).
    Names keep the tool's spelling (cleaned of control characters); the gateway
    makes them x64dbg-safe in ``plan_import``. The module entry carries the image
    base as ``ida_imagebase`` (the field name the schema defines for the static
    tool's image base; readers use only ``items``).
    """
    base = parse_hex(imagebase, "imagebase")
    merged: dict[int, dict[str, Any]] = {}
    below = 0
    for address, name, comment in entries:
        if address < base:
            below += 1
            continue
        name = clean_text(name, rules.name_max) if isinstance(name, str) else ""
        comment = rules.sanitize_comment(comment) if isinstance(comment, str) else ""
        if not name and not comment:
            continue
        item = merged.setdefault(address - base, {"rva": f"0x{address - base:X}"})
        if name and "name" not in item:
            item["name"] = name
        if comment:
            item["comment"] = item["comment"] + " | " + comment if "comment" in item else comment
    warnings = []
    items = [merged[rva] for rva in sorted(merged)]
    if len(items) > MAX_ITEMS:
        warnings.append(f"export truncated to {MAX_ITEMS} items")
        items = items[:MAX_ITEMS]
    key = (_base_name(module_name) or "unknown").lower()
    return {
        "schema": SCHEMA,
        "generated_by": generated_by,
        "modules": {key: {"base_runtime": None, "ida_imagebase": f"0x{base:X}", "items": items}},
        "skipped": {"below_imagebase": below},
        "warnings": warnings,
    }


def write_json_atomic(path: str, doc: Any) -> None:
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
