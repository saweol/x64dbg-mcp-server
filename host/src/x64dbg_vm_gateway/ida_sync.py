"""IDA <-> x64dbg annotation exchange (plan 6.4, interpretation D).

x64dbg works with runtime (ASLR) addresses, IDA with the image base of the
IDB. Both sides agree on *module + RVA*, so everything here converts through
that pair. Despite the IDA names (module, ``ida_*`` parameters, the schema
name), nothing here is IDA specific: Ghidra, radare2/rizin and Cutter address a
module the same way (image base of their database + RVA), and the gateway's
tool-neutral ``static_*`` tools use this module for all of them
(``static_tools``):

- :func:`parse_module_list` turns the plugin tool ``ListModules`` output into
  a module map (name -> :class:`ModuleInfo`).
- :func:`rebase` converts one address between runtime, RVA and IDA addresses.
- :func:`parse_x64dbg_db` reads an x64dbg user database (``.dd64``/``.dd32``)
  into :class:`Annotations`; :func:`export_for_ida` turns those into the
  ``x64dbg-ida-sync/1`` JSON document consumed by ``ida/x64dbg_sync.py``.
- :func:`plan_import` turns IDA-side items (RVA or IDA address + name/comment)
  into runtime addresses with x64dbg-safe labels/comments, ready for the
  ``CommentOrLabelAtAddress`` tool; :func:`plan_import_report` is the same with
  a per-item skip mode and the list of skipped items.

Everything is pure: no I/O, no global mutable state, and no gateway imports
beyond the package version (the proxy's wrapper tags are mirrored below and a
test keeps them equal). Every malformed input
raises ``ValueError`` with a message meant for the AI client; wrong argument
types raise ``ValueError`` too, so callers need a single ``except``. Sizes are
never trusted: text, item counts and string lengths are capped (the caps are
module constants read at call time).

ListModules format (src/mcp/tools.zig ``listModules``, unchanged since v1.0,
so it also covers the v1.3 plugin)::

    0x{base:X} | 0x{size:X} | {MEMPAGE.info}\\n

``size`` sums the consecutive memory regions of the allocation base; ``info``
is the module file name (or a mapped-file device path). The plugin keeps only
names ending in .dll/.exe/.drv/.sys/.ocx (``isModulePath``); the parser applies
the same filter, which also rejects ``GetMemoryMap`` lines (same leading
columns, protection string in the third column). Lines that do not match
(``[state]``/``[event:*]``/``[gateway]`` lines, ``<untrusted_guest_output>``
tags, prose) are ignored.

x64dbg database assumptions (checked against x64dbg ``development`` sources:
``serializablemap.h``, ``label.cpp``, ``comment.cpp``, ``bookmark.cpp``,
``function.cpp``, ``breakpoint.cpp``/``.h``, ``database.cpp``,
``jansson_x64dbg.h``, ``cmd-user-database.cpp``):

1. The file is one JSON object (``JSON_INDENT(1)``). ``DbSave`` LZ4-compresses
   it in place unless ``dbsave <path>`` was given a path (``disablecompression
   = argc > 1``) or the setting ``Engine/DisableDatabaseCompression`` is on.
   The compressed layout lives in a prebuilt library and is NOT parsed here:
   anything that does not start with ``{`` is rejected as
   ``unsupported database format``. The plugin tool ``SaveDatabase`` with a
   ``filePath`` therefore produces a parseable file. The error message only
   guesses the kind of binary data: an LZ4 frame magic (``04 22 4D 18``) is
   recognised, and a plausible little-endian 4-byte size prefix is reported as
   "looks compressed"; x64dbg's exact compressed layout is NOT verified here.
2. Addresses are written by ``json_hex`` as ``"0x%llX"`` strings. Labels,
   comments and bookmarks (``AddrInfoSerializer``) use ``module`` (file name
   with extension, ``""`` for addresses outside any module) and ``address``
   relative to that module; ``manual`` defaults to true when missing.
   Labels/comments add ``text``. Keys: ``labels``, ``comments``,
   ``bookmarks``; legacy databases also carry ``autolabels``,
   ``autocomments``, ``autobookmarks``, ``autofunctions`` (x64dbg loads them
   with ``CacheLoad(root, "auto")``). Entries from those legacy arrays are
   treated as automatic (``manual=False``) when they carry no ``manual`` key,
   deviating from x64dbg's loader, which marks them manual.
3. Functions (``RangeInfoSerializer``): ``module``, ``start``, ``end`` (both
   module-relative), ``manual``, plus ``icount`` and ``parent`` (hex). Very old
   databases used ``address`` instead of ``start``; it is accepted as fallback.
4. Breakpoints (``BpCacheSave``): ``address`` (RVA), ``enabled``, ``type``
   (0 normal, 1 hardware, 2 memory, 3 DLL, 4 exception), ``titantype``,
   ``name``, ``module`` (empty or possibly absent for exception breakpoints;
   both are accepted and mean "no module"), ``breakCondition``,
   ``logText``, ``logCondition``, ``commandText``, ``commandCondition``,
   ``logFile``, ``fastResume``, ``silent``, ``oldbytes`` (normal),
   ``memsize`` (memory). Single-shot breakpoints are never saved. For DLL
   breakpoints the address is meaningless and for exception breakpoints it is
   the exception code, so only types 0-2 are address-bound. Missing ``type``
   means 0 and missing ``enabled`` means false, as in ``BpCacheLoad``.
5. Other top-level keys (``notes``, ``xrefs``, ``hash``, ``plugins``, ...) are
   ignored. Unknown or malformed entries are skipped and counted.

x64dbg limits used by the sanitisers: ``LabelSet``/``CommentSet`` reject
``strlen(text) >= MAX_LABEL_SIZE - 1`` / ``MAX_COMMENT_SIZE - 1`` (256/512),
i.e. at most 254/510 UTF-8 bytes.

Label names that x64dbg's expression evaluator would resolve before labels
get a ``_`` prefix (see :func:`_is_reserved_label`): numbers (hex digits with
an optional ``x`` prefix, ``.``-prefixed decimals, anything starting with a
digit), register names and ``_<flag>``. The evaluation order (registers,
flags and numbers before labels) and the ``_cf``-style flag syntax are taken
from x64dbg's ``valfromstring`` and expression documentation as recalled;
they were not re-checked against an x64dbg build here, and the prefix is
harmless if x64dbg is more lenient.

Thread-safety: all functions are pure; dataclasses are immutable except
:class:`Annotations`, which is a plain result container.
"""

from __future__ import annotations

import json
import re
import struct
import unicodedata
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from . import __version__

__all__ = [
    "COMMENT_MAX_BYTES",
    "DIRECTIONS",
    "LABEL_MAX_BYTES",
    "SCHEMA",
    "Annotations",
    "Bookmark",
    "Breakpoint",
    "Comment",
    "Function",
    "Label",
    "ModuleInfo",
    "coerce_module_map",
    "export_for_ida",
    "find_module",
    "format_address",
    "parse_address",
    "parse_module_list",
    "parse_x64dbg_db",
    "plan_import",
    "plan_import_report",
    "rebase",
    "sanitize_comment",
    "sanitize_label",
]

SCHEMA = "x64dbg-ida-sync/1"
DIRECTIONS = ("runtime_to_rva", "rva_to_runtime", "runtime_to_ida", "ida_to_runtime")
ON_ERROR_MODES = ("raise", "skip")
MAX_ADDRESS = 2**64 - 1

# Mirrors proxy.UNTRUSTED_OPEN / UNTRUSTED_CLOSE (kept equal by a unit test) so this
# pure library does not import the proxy/supervisor stack.
UNTRUSTED_OPEN = "<untrusted_guest_output>"
UNTRUSTED_CLOSE = "</untrusted_guest_output>"

# Input caps (module globals so tests can lower them; read at call time).
MAX_ITEMS = 50_000  # entries per database category, items per export/import
MAX_MODULES = 10_000
MAX_MODULE_TEXT_CHARS = 16 * 1024 * 1024
MAX_DB_BYTES = 64 * 1024 * 1024
MAX_DB_TEXT_CHARS = 4096  # label/comment/breakpoint text kept from a database

LABEL_MAX_BYTES = 254  # x64dbg LabelSet: strlen < MAX_LABEL_SIZE(256) - 1
COMMENT_MAX_BYTES = 510  # x64dbg CommentSet: strlen < MAX_COMMENT_SIZE(512) - 1

MODULE_EXTENSIONS = (".dll", ".exe", ".drv", ".sys", ".ocx")  # plugin isModulePath
_MAX_MODULE_NAME_CHARS = 255  # MAX_MODULE_SIZE (256) including the NUL
_MAX_ADDRESS_CHARS = 64
_MAX_QUERY_CHARS = 1024
_MAX_LISTED_NAMES = 20
_MAX_REPORT_WARNINGS = 100

_HEX_RE = re.compile(r"[0-9a-fA-F]+")
_MODULE_LINE_RE = re.compile(r"0x([0-9A-Fa-f]{1,16})\s*\|\s*0x([0-9A-Fa-f]{1,16})\s*\|\s*(.*\S)")
_QUALIFIED_RE = re.compile(r"(.+)@0x([0-9a-f]{1,16})")
_PATH_SEP_RE = re.compile(r"[\\/]")
_INVALID_FILENAME_CHARS = frozenset('<>:"/\\|?*')
_LABEL_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_@?$.:<>~")
_DROP_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn"})
# Tokens x64dbg resolves before labels in expressions (see the module docstring).
_X64DBG_NUMBER_RE = re.compile(r"x?[0-9a-f]+|\.[0-9]+", re.IGNORECASE)
_X64DBG_REGISTER_RE = re.compile(
    r"[re]?(?:ax|bx|cx|dx|si|di|bp|sp|ip)|[abcd][hl]|(?:si|di|bp|sp)l|r(?:[89]|1[0-5])[dwb]?"
    r"|c(?:ax|bx|cx|dx|si|di|bp|sp|ip)|[c-gs]s|dr[0-7]|[cer]?flags|st[0-7]|x87r[0-7]|mm[0-7]"
    r"|[xyz]mm(?:[0-9]|[12][0-9]|3[01])|lasterror|laststatus",
    re.IGNORECASE,
)
_X64DBG_FLAGS = frozenset(
    {"cf", "pf", "af", "zf", "sf", "tf", "if", "df", "of", "rf", "vm", "ac", "vif", "vip", "id"}
)

_BP_TYPES = {0: "normal", 1: "hardware", 2: "memory", 3: "dll", 4: "exception"}
_ADDRESS_BOUND_BP_TYPES = frozenset({"normal", "hardware", "memory"})

_COMPRESSED_MAGIC = (
    (b"\x1f\x8b", "gzip"),
    (b"PK\x03\x04", "zip"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"BZh", "bzip2"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x04\x22\x4d\x18", "LZ4 frame"),
)
_LZ4_MAX_DECLARED = 256 * 1024 * 1024
_SAVE_HINT = (
    "save it uncompressed with SaveDatabase(filePath=...) / 'dbsave <path>' (x64dbg skips LZ4 "
    "compression when a path is given) or enable Engine/DisableDatabaseCompression"
)


# ── addresses ───────────────────────────────────────────────────────
def parse_address(value: object, *, what: str = "address") -> int:
    """Parse an address/RVA: an int, or a hex string.

    Strings are always hexadecimal (debugger convention): ``"0x401000"``,
    ``"401000"``, ``"401000h"`` (IDA/MASM) and WinDbg's ``"00007ff6`a1231000"``
    are accepted. Result must fit in 64 bits.
    """
    if isinstance(value, bool):
        raise ValueError(f"{what} must be an integer or a hex string, not a bool")
    if isinstance(value, int):
        number = value
    elif isinstance(value, str):
        text = value.strip()
        if len(text) > _MAX_ADDRESS_CHARS:
            raise ValueError(f"{what} is too long ({len(text)} characters)")
        text = text.replace("`", "")
        if text[:2] in ("0x", "0X"):
            digits = text[2:]
        elif text[-1:] in ("h", "H"):
            digits = text[:-1]
        else:
            digits = text
        if not _HEX_RE.fullmatch(digits):
            raise ValueError(f"{what} {value!r} is not a hex number")
        number = int(digits, 16)
    else:
        raise ValueError(f"{what} must be an integer or a hex string, got {type(value).__name__}")
    if not 0 <= number <= MAX_ADDRESS:
        raise ValueError(f"{what} {number:#x} is outside the 64-bit address range")
    return number


def format_address(value: int) -> str:
    """``0x`` + upper-case hex, the format x64dbg and the plugin print."""
    return f"0x{value:X}"


def _fmt_opt(value: int | None) -> str | None:
    return None if value is None else format_address(value)


# ── text cleaning ───────────────────────────────────────────────────
def _clean_text(text: str, max_chars: int) -> str:
    """One line of printable text.

    Whitespace (including CR/LF, NEL, U+2028/U+2029) becomes a single space;
    controls, format characters (bidi overrides, zero-width, BOM), surrogates,
    private-use and unassigned code points are dropped; ends are stripped.
    """
    out: list[str] = []
    for ch in text[: max_chars * 4]:  # bound the work before cleaning
        if ch.isspace():
            out.append(" ")
        elif unicodedata.category(ch) not in _DROP_CATEGORIES:
            out.append(ch)
    return " ".join("".join(out).split())[:max_chars]


def _truncate_utf8(text: str, max_bytes: int) -> str:
    raw = text.encode("utf-8")
    if len(raw) <= max_bytes:
        return text
    return raw[:max_bytes].decode("utf-8", "ignore").rstrip()


def sanitize_comment(text: str) -> str:
    """x64dbg-safe comment: one line, no control/bidi/format characters,
    at most :data:`COMMENT_MAX_BYTES` UTF-8 bytes. May return ``""``."""
    if not isinstance(text, str):
        raise ValueError(f"comment must be a string, got {type(text).__name__}")
    return _truncate_utf8(_clean_text(text, COMMENT_MAX_BYTES), COMMENT_MAX_BYTES)


def _is_reserved_label(label: str) -> bool:
    """True when x64dbg would read ``label`` as a number, register or flag in an
    expression instead of looking the label up."""
    return (
        label[:1].isdigit()
        or _X64DBG_NUMBER_RE.fullmatch(label) is not None
        or _X64DBG_REGISTER_RE.fullmatch(label) is not None
        or (label[:1] == "_" and label[1:].lower() in _X64DBG_FLAGS)
    )


def _label_core(text: str) -> str:
    """x64dbg-safe label, or ``""`` when ``text`` has no usable character."""
    normalized = unicodedata.normalize("NFKC", text[: LABEL_MAX_BYTES * 4]).strip()
    out: list[str] = []
    replaced = False
    for ch in normalized:
        if ch in _LABEL_CHARS:
            out.append(ch)
            replaced = False
        elif not replaced:  # a run of invalid characters becomes one '_'
            out.append("_")
            replaced = True
    label = "".join(out)
    if not label.strip("_"):
        return ""
    label = label[:LABEL_MAX_BYTES]
    while _is_reserved_label(label):  # at most twice: "cf" -> "_cf" (a flag) -> "__cf"
        label = ("_" + label)[:LABEL_MAX_BYTES]
    return label


def sanitize_label(text: str, *, fallback: str = "lbl") -> str:
    """x64dbg-safe label, never empty.

    NFKC-normalised (full-width letters become ASCII), restricted to
    ``[A-Za-z0-9_@?$.:<>~]`` (each run of other characters becomes one ``_``),
    at most :data:`LABEL_MAX_BYTES` characters, and prefixed with ``_`` while
    x64dbg would read it as a number, register or flag (``1stage``,
    ``deadbeef``, ``rax``, ``_zf``; see :func:`_is_reserved_label`). When
    nothing but underscores remains, the (sanitised) ``fallback`` is returned,
    or ``"lbl"``.
    """
    if not isinstance(text, str):
        raise ValueError(f"label must be a string, got {type(text).__name__}")
    label = _label_core(text)
    if label:
        return label
    return (_label_core(fallback) if isinstance(fallback, str) else "") or "lbl"


# ── modules ─────────────────────────────────────────────────────────
@dataclass(frozen=True)
class ModuleInfo:
    """A loaded module. ``size`` is None when unknown; ``preferred_base`` is the
    PE ``ImageBase`` (the default IDA image base) when known."""

    name: str
    base: int
    size: int | None = None
    path: str | None = None
    preferred_base: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise ValueError("module name must be a non-empty string")
        for label, value in (("base", self.base), ("preferred_base", self.preferred_base)):
            if value is None and label == "preferred_base":
                continue
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_ADDRESS:
                raise ValueError(f"module {self.name!r}: {label} must be a 64-bit unsigned integer")
        if self.size is not None:
            if isinstance(self.size, bool) or not isinstance(self.size, int) or self.size <= 0:
                raise ValueError(f"module {self.name!r}: size must be a positive integer")
            if self.base + self.size > MAX_ADDRESS + 1:
                raise ValueError(f"module {self.name!r}: base + size exceeds the 64-bit address space")
        if self.path is not None and not isinstance(self.path, str):
            raise ValueError(f"module {self.name!r}: path must be a string")

    @property
    def end(self) -> int | None:
        """Exclusive end address, or None when the size is unknown."""
        return None if self.size is None else self.base + self.size

    def contains(self, address: int) -> bool:
        return self.size is not None and self.base <= address < self.base + self.size

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "base": format_address(self.base),
            "size": _fmt_opt(self.size),
            "path": self.path,
            "preferred_base": _fmt_opt(self.preferred_base),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any], *, default_name: str | None = None) -> ModuleInfo:
        """Build from a JSON-style mapping (e.g. a job manifest entry).

        Keys: ``name`` (defaults to ``default_name``), ``base`` (required),
        ``size``, ``path``, ``preferred_base`` (aliases ``image_base``,
        ``imagebase``); numbers may be ints or hex strings.
        """
        if not isinstance(data, Mapping):
            raise ValueError(f"module entry must be an object, got {type(data).__name__}")
        raw_name = data.get("name", default_name)
        if not isinstance(raw_name, str):
            raise ValueError("module entry needs a 'name' string")
        name = _clean_text(raw_name, _MAX_MODULE_NAME_CHARS)
        if not name:
            raise ValueError("module entry needs a non-empty 'name'")
        if data.get("base") is None:
            raise ValueError(f"module {name!r}: 'base' is required")
        base = parse_address(data["base"], what=f"module {name!r} base")
        size_raw = data.get("size")
        size = None if size_raw is None else parse_address(size_raw, what=f"module {name!r} size")
        if size == 0:
            raise ValueError(f"module {name!r}: size must be positive")
        preferred_raw = next(
            (data[k] for k in ("preferred_base", "image_base", "imagebase") if data.get(k) is not None), None
        )
        preferred = None
        if preferred_raw is not None:
            preferred = parse_address(preferred_raw, what=f"module {name!r} preferred_base")
        path = data.get("path")
        if path is not None:
            if not isinstance(path, str):
                raise ValueError(f"module {name!r}: 'path' must be a string")
            path = _clean_text(path, 4096) or None
        return cls(name=name, base=base, size=size, path=path, preferred_base=preferred)


def _unique(mods: Iterable[ModuleInfo]) -> list[ModuleInfo]:
    """Drop repeats of the same module (the same entry may sit under two keys)."""
    seen: set[tuple[str, int, int | None]] = set()
    out: list[ModuleInfo] = []
    for m in mods:
        ident = (m.name.lower(), m.base, m.size)
        if ident not in seen:
            seen.add(ident)
            out.append(m)
    return out


def _key_modules(mods: Iterable[ModuleInfo]) -> dict[str, ModuleInfo]:
    """Key by lower-cased name; names loaded more than once get ``name@0x<base>`` keys."""
    groups: dict[str, list[ModuleInfo]] = {}
    for m in _unique(mods):
        groups.setdefault(m.name.lower(), []).append(m)
    out: dict[str, ModuleInfo] = {}
    for lname, group in groups.items():
        if len(group) == 1:
            out[lname] = group[0]
        else:
            for m in group:
                out[f"{lname}@0x{m.base:x}"] = m
    return out


def _strip_wrapper_tags(line: str) -> str:
    text = line.strip()
    changed = True
    while changed:
        changed = False
        for tag in (UNTRUSTED_OPEN, UNTRUSTED_CLOSE):
            if text.startswith(tag):
                text = text[len(tag):].strip()
                changed = True
            if text.endswith(tag):
                text = text[: -len(tag)].strip()
                changed = True
    return text


def _module_from_line(base: int, size: int, info: str) -> ModuleInfo | None:
    if size == 0 or base + size > MAX_ADDRESS + 1:
        return None
    cleaned = _clean_text(info, 4096)
    name = _PATH_SEP_RE.split(cleaned)[-1].strip()
    if not name or len(name) > _MAX_MODULE_NAME_CHARS:
        return None
    if any(c in _INVALID_FILENAME_CHARS for c in name) or not name.lower().endswith(MODULE_EXTENSIONS):
        return None
    return ModuleInfo(name=name, base=base, size=size, path=cleaned if cleaned != name else None)


def parse_module_list(text: str) -> dict[str, ModuleInfo]:
    """Parse ``ListModules`` output into ``{lower-cased name: ModuleInfo}``.

    Accepts the raw tool text or the gateway's wrapped result (see module
    docstring). A name loaded at several bases is stored once per base under
    ``"<name>@0x<base>"`` (no plain key), so lookups by the bare name report the
    ambiguity instead of silently picking one. ``"No modules loaded."`` gives
    ``{}``. Raises ValueError for non-str input, text longer than
    ``MAX_MODULE_TEXT_CHARS`` or more than ``MAX_MODULES`` modules.
    """
    if not isinstance(text, str):
        raise ValueError(f"ListModules output must be a str, got {type(text).__name__}")
    if len(text) > MAX_MODULE_TEXT_CHARS:
        raise ValueError(f"ListModules output is too long ({len(text)} > {MAX_MODULE_TEXT_CHARS} characters)")
    mods: list[ModuleInfo] = []
    seen: set[tuple[str, int]] = set()
    for raw in text.splitlines():
        match = _MODULE_LINE_RE.fullmatch(_strip_wrapper_tags(raw))
        if match is None:
            continue
        mod = _module_from_line(int(match[1], 16), int(match[2], 16), match[3])
        if mod is None or (mod.name.lower(), mod.base) in seen:
            continue
        if len(mods) >= MAX_MODULES:
            raise ValueError(f"too many modules in ListModules output (limit {MAX_MODULES})")
        seen.add((mod.name.lower(), mod.base))
        mods.append(mod)
    return _key_modules(mods)


def _key_name(key: str) -> str:
    """File name part of a module-map key (drops a path and an ``@0x<base>`` suffix)."""
    name = _PATH_SEP_RE.split(key.strip())[-1].strip()
    qualified = _QUALIFIED_RE.fullmatch(name.lower())
    return name[: len(qualified[1])] if qualified else name


def coerce_module_map(module_map: object) -> dict[str, ModuleInfo]:
    """Normalise a module map.

    Accepts the result of :func:`parse_module_list`, a mapping of
    ``name -> ModuleInfo | dict`` (e.g. from a job manifest, see
    :meth:`ModuleInfo.from_dict`) or a list of ``ModuleInfo``/dicts. Mapping
    keys are kept (lower-cased); lists are keyed like :func:`parse_module_list`.
    """
    if isinstance(module_map, Mapping):
        if len(module_map) > MAX_MODULES:
            raise ValueError(f"too many modules (limit {MAX_MODULES})")
        out: dict[str, ModuleInfo] = {}
        for key, value in module_map.items():
            if not isinstance(key, str) or not key.strip() or len(key) > _MAX_QUERY_CHARS:
                raise ValueError("module map keys must be non-empty strings")
            if isinstance(value, ModuleInfo):
                mod = value
            elif isinstance(value, Mapping):
                mod = ModuleInfo.from_dict(value, default_name=_key_name(key))
            else:
                raise ValueError(f"module map entry {key!r} must be a ModuleInfo or an object")
            lkey = key.strip().lower()
            if lkey in out and out[lkey] != mod:
                raise ValueError(f"module map has two different entries for {key!r}")
            out[lkey] = mod
        return out
    if isinstance(module_map, (str, bytes, bytearray)) or not isinstance(module_map, Iterable):
        raise ValueError("module_map must be a mapping or a list of modules")
    mods: list[ModuleInfo] = []
    for value in module_map:
        if len(mods) >= MAX_MODULES:
            raise ValueError(f"too many modules (limit {MAX_MODULES})")
        if isinstance(value, ModuleInfo):
            mods.append(value)
        elif isinstance(value, Mapping):
            mods.append(ModuleInfo.from_dict(value))
        else:
            raise ValueError("module list entries must be ModuleInfo objects or objects")
    return _key_modules(mods)


def _stem(name: str) -> str:
    return name.rsplit(".", 1)[0] if "." in name else name


def _describe(mods: Iterable[ModuleInfo]) -> str:
    return ", ".join(f"{m.name}@{format_address(m.base)}" for m in mods)


def _known_names(module_map: Mapping[str, ModuleInfo]) -> str:
    names = sorted({m.name for m in module_map.values()}, key=str.lower)
    shown = ", ".join(names[:_MAX_LISTED_NAMES])
    return shown + (f", ... ({len(names)} total)" if len(names) > _MAX_LISTED_NAMES else "")


def find_module(module_map: Mapping[str, ModuleInfo], name: str) -> ModuleInfo:
    """Look a module up by name: exact key, then file name, then stem.

    Case-insensitive; a Windows/POSIX path is reduced to its file name;
    ``"name@0x<base>"`` selects one of several modules with the same name.
    Raises ValueError when nothing or more than one module matches.
    """
    if not isinstance(name, str) or not name.strip():
        raise ValueError("module must be a non-empty string")
    if len(name) > _MAX_QUERY_CHARS:
        raise ValueError("module name is too long")
    query = _PATH_SEP_RE.split(name.strip())[-1].strip().lower()
    if query in module_map:
        return module_map[query]
    values = _unique(module_map.values())
    qualified = _QUALIFIED_RE.fullmatch(query)
    if qualified:
        qname, qbase = qualified[1], int(qualified[2], 16)
        candidates = [m for m in values if m.name.lower() == qname and m.base == qbase]
    else:
        candidates = [m for m in values if m.name.lower() == query]
        if not candidates:
            candidates = [m for m in values if _stem(m.name.lower()) == query]
    if len(candidates) == 1:
        return candidates[0]
    if candidates:
        raise ValueError(
            f"module {name.strip()!r} is ambiguous: {_describe(candidates)}; "
            "pass one of them as 'name@0x<base>'"
        )
    raise ValueError(
        f"module {name.strip()!r} not found in the module map (known: {_known_names(module_map)})"
    )


def _module_for_address(mods: list[ModuleInfo], address: int) -> tuple[ModuleInfo, bool]:
    """Module containing ``address``; the flag is True when the size was unknown
    and the nearest module below was assumed to extend up to the address."""
    lower = [m for m in mods if m.base <= address]
    if not lower:
        raise ValueError(
            f"address {format_address(address)} is not inside any module "
            f"(lowest module base is {format_address(min(m.base for m in mods))})"
        )
    containing = [m for m in mods if m.contains(address)]
    if len(containing) > 1:
        raise ValueError(
            f"address {format_address(address)} is ambiguous: it lies inside {_describe(containing)}"
        )
    if containing:
        mod = containing[0]
        intruders = [o for o in mods if o is not mod and o.size is None and mod.base <= o.base <= address]
        if intruders:
            raise ValueError(
                f"address {format_address(address)} is ambiguous: inside {_describe([mod])} and after the "
                f"base of {_describe(intruders)} (size unknown)"
            )
        return mod, False
    top = max(m.base for m in lower)
    nearest = [m for m in lower if m.base == top]
    if len(nearest) > 1:
        raise ValueError(f"address {format_address(address)} is ambiguous: {_describe(nearest)} share a base")
    near = nearest[0]
    if near.size is not None:
        raise ValueError(
            f"address {format_address(address)} is not inside any module (nearest module below is "
            f"{near.name} at {format_address(near.base)}, ending at {_fmt_opt(near.end)})"
        )
    return near, True


def rebase(
    address: int | str,
    *,
    direction: str,
    module_map: object,
    module: str | None = None,
    ida_imagebase: int | str | None = None,
) -> dict[str, Any]:
    """Convert an address between x64dbg runtime, RVA and IDA addresses.

    ``direction``:

    - ``runtime_to_rva``: the module is found by containment
      (``base <= addr < base + size``); with an unknown size the nearest lower
      base is used and ``approximate`` is True. ``module`` is optional and, if
      given, must contain the address.
    - ``rva_to_runtime``: ``module`` required.
    - ``runtime_to_ida``: like ``runtime_to_rva``; ``ida = ida_imagebase + rva``
      where ``ida_imagebase`` defaults to the module's ``preferred_base``.
    - ``ida_to_runtime``: ``module`` and ``ida_imagebase`` required (no default,
      because a rebased IDB would silently give a wrong runtime address).

    ``module_map`` is anything :func:`coerce_module_map` accepts. Returns
    ``{direction, module, module_base, module_size, rva, runtime, ida,
    ida_imagebase, approximate, warnings}`` with addresses as ``0x`` hex
    strings (``ida``/``ida_imagebase``/``module_size`` may be None).
    """
    if direction not in DIRECTIONS:
        raise ValueError(f"direction must be one of {', '.join(DIRECTIONS)}; got {direction!r}")
    modules = coerce_module_map(module_map)
    if not modules:
        raise ValueError("module map is empty: run ListModules in an active debug session first")
    addr = parse_address(address)
    explicit_base = None if ida_imagebase is None else parse_address(ida_imagebase, what="ida_imagebase")
    warnings: list[str] = []
    approximate = False

    if direction in ("runtime_to_rva", "runtime_to_ida"):
        if module is None:
            mod, approximate = _module_for_address(_unique(modules.values()), addr)
        else:
            mod = find_module(modules, module)
            if mod.size is None:
                approximate = True
            if addr < mod.base or (mod.size is not None and not mod.contains(addr)):
                raise ValueError(
                    f"address {format_address(addr)} is outside module {mod.name} "
                    f"[{format_address(mod.base)}, {_fmt_opt(mod.end) or '?'})"
                )
        rva = addr - mod.base
        runtime = addr
        if approximate:
            warnings.append(
                f"size of {mod.name} is unknown: assumed it extends up to {format_address(addr)}; "
                "confirm with ListModules"
            )
    else:
        if module is None:
            raise ValueError(f"module is required for {direction}")
        mod = find_module(modules, module)
        if direction == "rva_to_runtime":
            rva = addr
        else:
            if explicit_base is None:
                raise ValueError(
                    "ida_imagebase is required for ida_to_runtime: pass the IDB image base "
                    "(idaapi.get_imagebase())"
                )
            if addr < explicit_base:
                raise ValueError(
                    f"IDA address {format_address(addr)} is below ida_imagebase "
                    f"{format_address(explicit_base)}"
                )
            rva = addr - explicit_base
        if mod.size is not None and rva >= mod.size:
            raise ValueError(
                f"rva {format_address(rva)} is outside module {mod.name} (size {format_address(mod.size)})"
            )
        if mod.size is None:
            warnings.append(
                f"size of {mod.name} is unknown: rva {format_address(rva)} was not bounds-checked"
            )
        runtime = mod.base + rva
        if runtime > MAX_ADDRESS:
            raise ValueError(
                f"runtime address {mod.name}+{format_address(rva)} exceeds the 64-bit address space"
            )

    imagebase = explicit_base if explicit_base is not None else mod.preferred_base
    if direction == "runtime_to_ida" and imagebase is None:
        raise ValueError(
            f"ida_imagebase is required for runtime_to_ida (no preferred image base known for {mod.name}): "
            "pass the IDB image base (idaapi.get_imagebase())"
        )
    ida: int | None = None
    if imagebase is not None:
        if imagebase + rva > MAX_ADDRESS:
            if direction == "runtime_to_ida":
                raise ValueError("IDA address exceeds the 64-bit address space")
            warnings.append("IDA address exceeds the 64-bit address space; omitted")
        else:
            ida = imagebase + rva
    return {
        "direction": direction,
        "module": mod.name,
        "module_base": format_address(mod.base),
        "module_size": _fmt_opt(mod.size),
        "rva": format_address(rva),
        "runtime": format_address(runtime),
        "ida": _fmt_opt(ida),
        "ida_imagebase": _fmt_opt(imagebase),
        "approximate": approximate,
        "warnings": warnings,
    }


# ── x64dbg database ─────────────────────────────────────────────────
@dataclass(frozen=True)
class Label:
    module: str  # "" = address outside any module (rva is then absolute)
    rva: int
    text: str
    manual: bool = True


@dataclass(frozen=True)
class Comment:
    module: str
    rva: int
    text: str
    manual: bool = True


@dataclass(frozen=True)
class Bookmark:
    module: str
    rva: int
    manual: bool = True


@dataclass(frozen=True)
class Function:
    module: str
    rva: int  # start
    end_rva: int | None = None  # inclusive end as stored by x64dbg
    icount: int | None = None
    manual: bool = True


@dataclass(frozen=True)
class Breakpoint:
    module: str
    rva: int  # exception code for "exception", meaningless for "dll"
    type: str  # normal | hardware | memory | dll | exception | unknown_<n>
    type_code: int
    enabled: bool
    name: str | None = None
    condition: str | None = None
    log_text: str | None = None
    command_text: str | None = None

    @property
    def address_bound(self) -> bool:
        return self.type in _ADDRESS_BOUND_BP_TYPES


@dataclass
class Annotations:
    """Parsed x64dbg database. Text fields are already cleaned (one line, no
    control/bidi characters, at most ``MAX_DB_TEXT_CHARS``)."""

    labels: list[Label] = field(default_factory=list)
    comments: list[Comment] = field(default_factory=list)
    bookmarks: list[Bookmark] = field(default_factory=list)
    breakpoints: list[Breakpoint] = field(default_factory=list)
    functions: list[Function] = field(default_factory=list)
    skipped: int = 0  # malformed entries (and non-list categories) that were ignored
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        def base(module: str, rva: int) -> dict[str, Any]:
            return {"module": module, "rva": format_address(rva)}

        return {
            "labels": [{**base(x.module, x.rva), "text": x.text, "manual": x.manual} for x in self.labels],
            "comments": [
                {**base(x.module, x.rva), "text": x.text, "manual": x.manual} for x in self.comments
            ],
            "bookmarks": [{**base(x.module, x.rva), "manual": x.manual} for x in self.bookmarks],
            "breakpoints": [
                {
                    **base(x.module, x.rva),
                    "type": x.type,
                    "type_code": x.type_code,
                    "enabled": x.enabled,
                    "name": x.name,
                    "condition": x.condition,
                    "log_text": x.log_text,
                    "command_text": x.command_text,
                }
                for x in self.breakpoints
            ],
            "functions": [
                {
                    **base(x.module, x.rva),
                    "end_rva": _fmt_opt(x.end_rva),
                    "icount": x.icount,
                    "manual": x.manual,
                }
                for x in self.functions
            ],
            "skipped": self.skipped,
            "warnings": list(self.warnings),
        }


def _describe_binary(raw: bytes) -> str:
    for magic, kind in _COMPRESSED_MAGIC:
        if raw.startswith(magic):
            return f"{kind}-compressed data, not JSON; {_SAVE_HINT}"
    if len(raw) >= 8:
        # Heuristic only (the exact x64dbg layout is not verified here): a
        # plausible little-endian uncompressed-size prefix (not smaller than the
        # payload, within LZ4's ~255:1 maximum ratio and below 256 MiB).
        (declared,) = struct.unpack_from("<I", raw)
        if len(raw) - 4 <= declared <= min(_LZ4_MAX_DECLARED, 255 * len(raw)):
            return (
                "binary data that looks compressed (x64dbg LZ4-compresses databases saved without an "
                f"explicit path); {_SAVE_HINT}"
            )
    return f"expected a JSON object, data starts with {raw[:16].hex()}"


def _hex_field(entry: Mapping[str, Any], key: str) -> int | None:
    value = entry.get(key)
    if value is None:
        return None
    try:
        return parse_address(value, what=key)
    except ValueError:
        return None


def _opt_text(entry: Mapping[str, Any], key: str, max_chars: int) -> str | None:
    value = entry.get(key)
    if not isinstance(value, str):
        return None
    return _clean_text(value, max_chars) or None


def _addr_info(entry: object) -> tuple[str, int] | None:
    if not isinstance(entry, dict):
        return None
    module = entry.get("module")
    if not isinstance(module, str) or len(module) > _MAX_MODULE_NAME_CHARS:
        return None
    rva = _hex_field(entry, "address")
    if rva is None:
        return None
    return _clean_text(module, _MAX_MODULE_NAME_CHARS), rva


def _manual(entry: Mapping[str, Any], auto: bool) -> bool:
    value = entry.get("manual")
    return value if isinstance(value, bool) else not auto


def _parse_text_entry(entry: object, auto: bool) -> tuple[str, int, str, bool] | None:
    info = _addr_info(entry)
    if info is None:
        return None
    assert isinstance(entry, dict)
    text = entry.get("text")
    if not isinstance(text, str):
        return None
    cleaned = _clean_text(text, MAX_DB_TEXT_CHARS)
    if not cleaned:
        return None
    return info[0], info[1], cleaned, _manual(entry, auto)


def _parse_label(entry: object, auto: bool) -> Label | None:
    parsed = _parse_text_entry(entry, auto)
    return None if parsed is None else Label(*parsed)


def _parse_comment(entry: object, auto: bool) -> Comment | None:
    parsed = _parse_text_entry(entry, auto)
    return None if parsed is None else Comment(*parsed)


def _parse_bookmark(entry: object, auto: bool) -> Bookmark | None:
    info = _addr_info(entry)
    if info is None:
        return None
    assert isinstance(entry, dict)
    return Bookmark(info[0], info[1], _manual(entry, auto))


def _parse_function(entry: object, auto: bool) -> Function | None:
    if not isinstance(entry, dict):
        return None
    module = entry.get("module")
    if not isinstance(module, str) or len(module) > _MAX_MODULE_NAME_CHARS:
        return None
    start = _hex_field(entry, "start")
    if start is None:
        start = _hex_field(entry, "address")  # very old databases
    if start is None:
        return None
    return Function(
        module=_clean_text(module, _MAX_MODULE_NAME_CHARS),
        rva=start,
        end_rva=_hex_field(entry, "end"),
        icount=_hex_field(entry, "icount"),
        manual=_manual(entry, auto),
    )


def _parse_breakpoint(entry: object, auto: bool) -> Breakpoint | None:
    del auto  # breakpoints have no manual/auto distinction
    if not isinstance(entry, dict):
        return None
    code = entry.get("type", 0)
    if isinstance(code, bool) or not isinstance(code, int) or not 0 <= code <= 255:
        return None
    bp_type = _BP_TYPES.get(code, f"unknown_{code}")
    module = entry.get("module", "")
    if not isinstance(module, str) or len(module) > _MAX_MODULE_NAME_CHARS:
        return None
    rva = _hex_field(entry, "address")
    if rva is None:
        if bp_type in _ADDRESS_BOUND_BP_TYPES:
            return None
        rva = 0
    return Breakpoint(
        module=_clean_text(module, _MAX_MODULE_NAME_CHARS),
        rva=rva,
        type=bp_type,
        type_code=code,
        enabled=entry.get("enabled") is True,
        name=_opt_text(entry, "name", MAX_DB_TEXT_CHARS),
        condition=_opt_text(entry, "breakCondition", MAX_DB_TEXT_CHARS),
        log_text=_opt_text(entry, "logText", MAX_DB_TEXT_CHARS),
        command_text=_opt_text(entry, "commandText", MAX_DB_TEXT_CHARS),
    )


def _collect(root: Mapping[str, Any], ann: Annotations, key: str, target: list[Any], parse_one: Any,
             *, legacy_auto: bool) -> None:
    arrays = [(key, False)] + ([("auto" + key, True)] if legacy_auto else [])
    for array_key, auto in arrays:
        entries = root.get(array_key)
        if entries is None:
            continue
        if not isinstance(entries, list):
            ann.warnings.append(f"{array_key}: expected a list, got {type(entries).__name__}; ignored")
            ann.skipped += 1
            continue
        for entry in entries:
            if len(target) >= MAX_ITEMS:
                ann.warnings.append(f"{array_key}: truncated after {MAX_ITEMS} {key}")
                break
            item = parse_one(entry, auto)
            if item is None:
                ann.skipped += 1
            else:
                target.append(item)


def parse_x64dbg_db(data: bytes) -> Annotations:
    """Parse an uncompressed x64dbg user database (``.dd64``/``.dd32``).

    See the module docstring for the format assumptions. Raises
    ``ValueError("unsupported database format: ...")`` for empty, compressed,
    non-UTF-8, non-JSON or non-object content, and ValueError for non-bytes
    input or more than ``MAX_DB_BYTES``. Malformed entries are skipped and
    counted in ``Annotations.skipped``; each category is capped at
    ``MAX_ITEMS`` entries (noted in ``warnings``).
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise ValueError(f"database content must be bytes, got {type(data).__name__}")
    raw = bytes(data)
    if len(raw) > MAX_DB_BYTES:
        raise ValueError(f"database too large: {len(raw)} bytes (limit {MAX_DB_BYTES})")
    body = raw[3:] if raw.startswith(b"\xef\xbb\xbf") else raw
    body = body.lstrip(b" \t\r\n")
    if not body:
        raise ValueError("unsupported database format: empty file")
    if not body.startswith(b"{"):
        raise ValueError(f"unsupported database format: {_describe_binary(raw)}")
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"unsupported database format: not valid UTF-8 (byte offset {exc.start})") from None
    try:
        root = json.loads(text)
    except RecursionError:
        raise ValueError("unsupported database format: invalid JSON (nesting too deep)") from None
    except ValueError as exc:
        raise ValueError(f"unsupported database format: invalid JSON ({str(exc)[:200]})") from None
    if not isinstance(root, dict):
        raise ValueError("unsupported database format: top level is not a JSON object")

    ann = Annotations()
    _collect(root, ann, "labels", ann.labels, _parse_label, legacy_auto=True)
    _collect(root, ann, "comments", ann.comments, _parse_comment, legacy_auto=True)
    _collect(root, ann, "bookmarks", ann.bookmarks, _parse_bookmark, legacy_auto=True)
    _collect(root, ann, "functions", ann.functions, _parse_function, legacy_auto=True)
    _collect(root, ann, "breakpoints", ann.breakpoints, _parse_breakpoint, legacy_auto=False)
    return ann


# ── export / import ─────────────────────────────────────────────────
def _exact_module(module_map: Mapping[str, ModuleInfo], lname: str) -> ModuleInfo | None:
    found = [m for m in _unique(module_map.values()) if m.name.lower() == lname]
    return found[0] if len(found) == 1 else None


def export_for_ida(
    annotations: Annotations,
    module_map: object = None,
    *,
    modules: Iterable[str] | None = None,
    include_auto: bool = True,
) -> dict[str, Any]:
    """Build an ``x64dbg-ida-sync/1`` document from parsed database annotations.

    ``{schema, generated_by, modules: {name: {base_runtime, items}}, skipped,
    warnings}``; each item is ``{rva, name?, comment?, bookmark?: true,
    breakpoint?: {type, enabled, condition?}}``, sorted by RVA and merged per
    address. Names go through :func:`sanitize_label`, comments and conditions
    through :func:`sanitize_comment`. A label without any x64dbg-safe
    character (e.g. all Korean) is not replaced by a placeholder name, which
    would overwrite the IDA name on import: it is kept at the front of the
    comment as ``x64dbg label: <text>`` (counted in ``warnings``).
    ``base_runtime`` comes from
    ``module_map`` (exact name match) or is None. ``modules`` filters by name
    or stem (case-insensitive). Entries without a module and DLL/exception
    breakpoints are counted in ``skipped``; the item total is capped at
    ``MAX_ITEMS``.
    """
    if not isinstance(annotations, Annotations):
        raise ValueError("annotations must be an Annotations object (see parse_x64dbg_db)")
    mm = coerce_module_map(module_map) if module_map is not None else {}
    wanted: set[str] | None = None
    if modules is not None:
        names = [modules] if isinstance(modules, str) else list(modules)
        if not all(isinstance(n, str) for n in names):
            raise ValueError("modules must be a list of module names")
        wanted = {_PATH_SEP_RE.split(n.strip())[-1].lower() for n in names}
    skipped = {"no_module": 0, "not_address_bound": 0, "filtered": 0, "empty": 0}
    warnings: list[str] = []
    per_module: dict[str, dict[int, dict[str, Any]]] = {}

    def slot(module: str, rva: int, manual: bool = True) -> dict[str, Any] | None:
        if not module:
            skipped["no_module"] += 1
            return None
        key = module.lower()
        if (not include_auto and not manual) or (
            wanted is not None and key not in wanted and _stem(key) not in wanted
        ):
            skipped["filtered"] += 1
            return None
        return per_module.setdefault(key, {}).setdefault(rva, {"rva": format_address(rva)})

    label_notes: list[tuple[dict[str, Any], str]] = []
    for lb in annotations.labels:
        item = slot(lb.module, lb.rva, lb.manual)
        if item is None:
            continue
        name = _label_core(lb.text)
        if name:
            item["name"] = name
            continue
        note = sanitize_comment(lb.text)
        if note:
            label_notes.append((item, f"x64dbg label: {note}"))
        else:
            skipped["empty"] += 1
    for cm in annotations.comments:
        text = sanitize_comment(cm.text)
        if not text:
            skipped["empty"] += 1
            continue
        item = slot(cm.module, cm.rva, cm.manual)
        if item is not None:
            item["comment"] = text
    for item, note in label_notes:  # in front, so the comment byte cap cannot cut it off
        existing = item.get("comment")
        item["comment"] = sanitize_comment(f"{note} | {existing}" if existing else note)
    if label_notes:
        warnings.append(
            f"{len(label_notes)} labels have no x64dbg/IDA-safe characters; kept as 'x64dbg label:' comments"
        )
    for bm in annotations.bookmarks:
        item = slot(bm.module, bm.rva, bm.manual)
        if item is not None:
            item["bookmark"] = True
    for bp in annotations.breakpoints:
        if not bp.address_bound:
            skipped["not_address_bound"] += 1
            continue
        item = slot(bp.module, bp.rva)
        if item is not None:
            info: dict[str, Any] = {"type": bp.type, "enabled": bp.enabled}
            condition = sanitize_comment(bp.condition) if bp.condition else ""
            if condition:
                info["condition"] = condition
            item["breakpoint"] = info

    out_modules: dict[str, Any] = {}
    total = 0
    truncated = False
    for key in sorted(per_module):
        items = [it for _, it in sorted(per_module[key].items()) if len(it) > 1]  # drop empty slots
        if not items:
            continue
        room = MAX_ITEMS - total
        if len(items) > room:
            items = items[:room]
            truncated = True
        total += len(items)
        base: str | None = None
        if mm:
            mod = _exact_module(mm, key)
            if mod is None:
                warnings.append(f"{key}: not (uniquely) in the module map; base_runtime is null")
            else:
                base = format_address(mod.base)
        out_modules[key] = {"base_runtime": base, "items": items}
    if truncated:
        warnings.append(f"export truncated to {MAX_ITEMS} items")
    return {
        "schema": SCHEMA,
        "generated_by": f"x64dbg-vm-gateway {__version__}",
        "modules": out_modules,
        "skipped": skipped,
        "warnings": warnings,
    }


class _NothingToImport(Exception):
    """An item that is valid but carries nothing a label/comment can hold."""


def _plan_item(
    item: object, where: str, mod: ModuleInfo, base_ida: int | None
) -> tuple[dict[str, Any], str | None]:
    """One plan entry (plus an optional warning). Raises ValueError for an
    invalid item and :class:`_NothingToImport` for a bookmark/breakpoint-only one."""
    if not isinstance(item, Mapping):
        raise ValueError(f"{where}: must be a mapping (JSON object), got {type(item).__name__}")
    has_rva = item.get("rva") is not None
    has_ida = item.get("ida_address") is not None
    if has_rva and has_ida:
        raise ValueError(f"{where}: give either 'rva' or 'ida_address', not both")
    if not (has_rva or has_ida):
        raise ValueError(f"{where}: needs either 'rva' or 'ida_address'")
    name = item.get("name")
    comment = item.get("comment")
    if name is not None and not isinstance(name, str):
        raise ValueError(f"{where}: 'name' must be a string")
    if comment is not None and not isinstance(comment, str):
        raise ValueError(f"{where}: 'comment' must be a string")
    if name is None and comment is None:
        if item.get("bookmark") is not None or item.get("breakpoint") is not None:
            raise _NothingToImport(
                f"{where}: bookmark/breakpoint data only (no 'name' or 'comment' to import)"
            )
        raise ValueError(f"{where}: needs a 'name' and/or a 'comment'")
    try:
        if has_rva:
            rva = parse_address(item["rva"], what="rva")
        else:
            if base_ida is None:
                raise ValueError("ida_imagebase is required for items with 'ida_address'")
            ida = parse_address(item["ida_address"], what="ida_address")
            if ida < base_ida:
                raise ValueError(
                    f"ida_address {format_address(ida)} is below ida_imagebase {format_address(base_ida)}"
                )
            rva = ida - base_ida
    except ValueError as exc:
        raise ValueError(f"{where}: {exc}") from None
    if mod.size is not None and rva >= mod.size:
        raise ValueError(
            f"{where}: rva {format_address(rva)} is outside module {mod.name} "
            f"(size {format_address(mod.size)})"
        )
    runtime = mod.base + rva
    if runtime > MAX_ADDRESS:
        raise ValueError(f"{where}: runtime address exceeds the 64-bit address space")
    label: str | None = None
    note = ""
    warning = None
    if name and name.strip():
        label = _label_core(name) or None
        if label is None:  # no x64dbg-safe character: keep the name as text, never a placeholder
            note = sanitize_comment(name)
            if note:
                warning = f"{where}: name has no x64dbg-safe characters; kept in the comment"
    text = sanitize_comment(comment) if comment else ""
    if note:
        text = sanitize_comment(f"IDA name: {note} | {text}" if text else f"IDA name: {note}")
    if label is None and not text:
        raise ValueError(f"{where}: nothing to import after sanitising 'name'/'comment'")
    entry = {
        "runtime_address": format_address(runtime),
        "rva": format_address(rva),
        "label": label,
        "comment": text or None,
    }
    return entry, warning


def plan_import_report(
    items: Sequence[Mapping[str, Any]],
    *,
    module: str,
    module_map: object,
    ida_imagebase: int | str | None = None,
    on_error: str = "raise",
) -> dict[str, Any]:
    """Turn IDA-side annotations into x64dbg operations, with a report.

    Each item has either ``rva`` or ``ida_address`` (the latter needs
    ``ida_imagebase``) plus ``name`` and/or ``comment``; other keys are
    ignored. Items that carry only ``bookmark``/``breakpoint`` data (as in an
    ``x64dbg-ida-sync/1`` document) produce no operation and are listed in
    ``skipped``. A name without any x64dbg-safe character is not turned into a
    placeholder label: it goes to the front of the comment as ``IDA name:
    <text>`` (listed in ``warnings``).

    ``on_error``: ``"raise"`` (default) rejects the whole batch with a
    ValueError naming the first invalid ``items[i]``; ``"skip"`` lists invalid
    items in ``skipped`` with the reason and plans the rest. Batch-level
    problems (not a list, more than ``MAX_ITEMS`` items, unknown module, bad
    ``ida_imagebase``) always raise.

    Returns ``{module, plan: [{runtime_address, rva, label, comment}],
    skipped: [{index, reason}], warnings: [str]}``; ``plan`` keeps input order
    with :func:`sanitize_label` / :func:`sanitize_comment` applied (``label`` /
    ``comment`` None when absent).
    """
    if on_error not in ON_ERROR_MODES:
        raise ValueError(f"on_error must be one of {', '.join(ON_ERROR_MODES)}; got {on_error!r}")
    if isinstance(items, (str, bytes, bytearray, Mapping)) or not isinstance(items, Sequence):
        raise ValueError("items must be a list of objects")
    if len(items) > MAX_ITEMS:
        raise ValueError(f"too many items: {len(items)} (limit {MAX_ITEMS})")
    modules = coerce_module_map(module_map)
    if not modules:
        raise ValueError("module map is empty: run ListModules in an active debug session first")
    mod = find_module(modules, module)
    base_ida = None if ida_imagebase is None else parse_address(ida_imagebase, what="ida_imagebase")

    plan: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    warnings: list[str] = []
    for i, item in enumerate(items):
        try:
            entry, warning = _plan_item(item, f"items[{i}]", mod, base_ida)
        except _NothingToImport as exc:
            skipped.append({"index": i, "reason": str(exc)})
            continue
        except ValueError as exc:
            if on_error == "raise":
                raise
            skipped.append({"index": i, "reason": str(exc)})
            continue
        plan.append(entry)
        if warning is not None:
            warnings.append(warning)
    if len(warnings) > _MAX_REPORT_WARNINGS:
        warnings = warnings[:_MAX_REPORT_WARNINGS] + [
            f"... {len(warnings) - _MAX_REPORT_WARNINGS} more warnings omitted"
        ]
    return {"module": mod.name, "plan": plan, "skipped": skipped, "warnings": warnings}


def plan_import(
    items: Sequence[Mapping[str, Any]],
    *,
    module: str,
    module_map: object,
    ida_imagebase: int | str | None = None,
) -> list[dict[str, Any]]:
    """Turn IDA-side annotations into x64dbg operations (all or nothing).

    Same rules as :func:`plan_import_report` with ``on_error="raise"``: returns
    only the ``plan`` list ``[{runtime_address, rva, label, comment}]``. Items
    of an ``x64dbg-ida-sync/1`` document are accepted as-is; bookmark- or
    breakpoint-only items produce no entry (use :func:`plan_import_report` to
    see them). The whole batch is rejected with a ValueError naming the
    offending ``items[i]`` on the first invalid item, and when it holds more
    than ``MAX_ITEMS`` items.
    """
    return plan_import_report(
        items, module=module, module_map=module_map, ida_imagebase=ida_imagebase, on_error="raise"
    )["plan"]
