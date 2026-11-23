"""Tool catalog: which x64dbg-MCP tools exist, their schemas and their retry class.

Sources, in order of preference for a backend:

1. the live list most recently fetched from that backend (``update_from_live``),
   persisted as ``<cache_dir>/tools-<backend_id>-<server_version>.json``;
2. the builtin list matching the backend's plugin version (``BUILTIN_CATALOGS``:
   ``data/tools-v1.9.json``, ``data/tools-v1.10.json``).

Builtin choice, per backend: the newest builtin whose version is <= the plugin
version (else the oldest; an unparsable version counts as unknown). The version
comes from ``set_server_version`` (the runtime calls it as soon as ``GET /`` or
``initialize`` reported it), from ``update_from_live``, or from the version of a
cached live list; before any of these the constructor's ``builtin_json`` is used.
When a backend's builtin changes, its live list is classified again.

The gateway exposes the full list at session start because some MCP clients
ignore ``notifications/tools/list_changed`` (plan 5.5). Schemas are sanitised so
the mirrored ``inputSchema`` is always a JSON-Schema object.

Trust: live lists and cache files come from the guest (or from disk) and are not
trusted for policy. ``readOnlyHint`` decides lock bypass, epoch gating and
retries, so a live/cached entry is read-only only if it says so AND the backend's
builtin list marks the same tool read-only; tools unknown to that builtin list are
mutating. A live list may still mark a builtin read-only tool mutating (the safe
direction). Descriptions and every string value inside a schema are stripped of
control/bidi characters (``proxy.sanitize_untrusted_text``); descriptions are
also capped at ``MAX_DESCRIPTION_CHARS``. Cached ``initialize`` instructions get
the same treatment (capped at ``MAX_INSTRUCTIONS_CHARS``).

Thread-safety: all public methods may be called concurrently; internal state
is guarded by one re-entrant lock and cache files are written atomically
(temp file + fsync + ``os.replace``).
"""

from __future__ import annotations

import copy
import json
import logging
import os
import re
import tempfile
import threading
from collections.abc import Mapping
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from types import MappingProxyType
from typing import Any

from .contracts import ToolInfo
from .proxy import sanitize_untrusted_text

log = logging.getLogger(__name__)

#: Shipped builtin tool lists by plugin (major, minor) version.
BUILTIN_CATALOGS: Mapping[tuple[int, int], str] = MappingProxyType({
    (1, 9): "data/tools-v1.9.json",
    (1, 10): "data/tools-v1.10.json",
})
_VERSION_RE = re.compile(r"\s*v?(\d+)\.(\d+)(?:\.\d+)*\s*")

CACHE_FORMAT = 1
MAX_DESCRIPTION_CHARS = 4000  # builtin descriptions are < 300 chars
MAX_INSTRUCTIONS_CHARS = 20_000  # the plugin's initialize instructions are a few KB
_MAX_SCHEMA_DEPTH = 64
# Read-only tools that must still never be retried: WaitForEvent drains the
# plugin's pending-event queue, so a blind retry can lose events.
NON_RETRYABLE_READ_ONLY = frozenset({"WaitForEvent"})
_SAFE = re.compile(r"[^A-Za-z0-9_.-]")


def version_tuple(version: str | None) -> tuple[int, int] | None:
    """``"1.10"`` / ``"v1.10.2"`` -> ``(1, 10)``; None for anything else."""
    m = _VERSION_RE.fullmatch(version or "") if isinstance(version, str) else None
    return (int(m.group(1)), int(m.group(2))) if m else None


def builtin_for_version(version: str | None) -> str:
    """Builtin list for a plugin version: the newest shipped one <= ``version``, else the oldest."""
    shipped = sorted(BUILTIN_CATALOGS)
    vt = version_tuple(version)
    older = [v for v in shipped if vt is not None and v <= vt]
    return BUILTIN_CATALOGS[older[-1] if older else shipped[0]]


def _safe_component(s: str) -> str:
    """File-name-safe form of a backend id / version (no separators, no '..')."""
    out = _SAFE.sub("_", s).strip(".") or "_"
    return out.replace("..", "_")


def default_cache_dir() -> Path:
    return Path.home() / ".cache" / "x64dbg-vm-gateway"


def _schema_problem(schema: Any) -> str | None:
    """Return why ``schema`` is not an acceptable object schema, or None if it is."""
    if not isinstance(schema, dict):
        return f"inputSchema is {type(schema).__name__}, not an object"
    if schema.get("type") != "object":
        return f"inputSchema type is {schema.get('type')!r}, not 'object'"
    props = schema.get("properties")
    if props is not None and not (
            isinstance(props, dict) and all(isinstance(v, dict) for v in props.values())):
        return "inputSchema.properties is not an object of schemas"
    req = schema.get("required")
    if req is not None and not (isinstance(req, list) and all(isinstance(r, str) for r in req)):
        return "inputSchema.required is not a list of strings"
    try:
        json.dumps(schema)
    except (TypeError, ValueError):
        return "inputSchema is not JSON-serialisable"
    except RecursionError:
        return "inputSchema is nested too deeply"
    return None


def _clean_schema_strings(obj: Any, depth: int = 0) -> Any:
    """Copy of a JSON value with control/bidi characters removed from every string value.

    Keys are left as they are (property names must match the arguments the
    client sends). Raises ValueError when nested deeper than ``_MAX_SCHEMA_DEPTH``.
    """
    if depth > _MAX_SCHEMA_DEPTH:
        raise ValueError("schema nested too deeply")
    if isinstance(obj, str):
        return sanitize_untrusted_text(obj, max_len=len(obj))
    if isinstance(obj, dict):
        return {k: _clean_schema_strings(v, depth + 1) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean_schema_strings(v, depth + 1) for v in obj]
    return copy.deepcopy(obj)


def _atomic_write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=1, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _tool_to_json(t: ToolInfo) -> dict[str, Any]:
    return {"name": t.name, "description": t.description, "inputSchema": t.input_schema,
            "read_only": t.read_only}


def _key(t: ToolInfo) -> tuple[str, str, str, bool]:
    return (t.name, t.description, json.dumps(t.input_schema, sort_keys=True), t.read_only)


class _Builtin:
    """One shipped builtin list: its tools, read-only map and plugin version."""

    __slots__ = ("read_only", "rel", "tools", "version")

    def __init__(self, rel: str, version: str, tools: list[ToolInfo]) -> None:
        self.rel = rel
        self.version = version
        self.tools = tools
        self.read_only = {t.name: t.read_only for t in tools}


class ToolCatalog:
    def __init__(self, builtin_json: str = "data/tools-v1.9.json",
                 cache_dir: Path | str | None = None) -> None:
        """``builtin_json``: the builtin list for backends whose plugin version is not known yet."""
        self._lock = threading.RLock()
        self.cache_dir = Path(cache_dir).expanduser() if cache_dir is not None else default_cache_dir()
        self._warnings: list[str] = []
        self._builtins: dict[str, _Builtin] = {}  # rel path -> loaded list
        self._default_rel = builtin_json
        self._builtin = self._get_builtin(builtin_json).tools  # the default list (kept for callers)
        self._backend_rel: dict[str, str] = {}  # backend_id -> builtin chosen by its version
        self._explicit: set[str] = set()  # backends whose version came from the plugin itself
        self._live: dict[str, tuple[str, list[ToolInfo]]] = {}  # backend_id -> (version, tools)
        self._live_raw: dict[str, tuple[list[ToolInfo], str]] = {}  # unclassified copy + source
        self._loaded_from_disk: set[str] = set()
        self._instructions: dict[str, str | None] = {}

    # ── loading ─────────────────────────────────────────────────────
    def _get_builtin(self, rel: str) -> _Builtin:
        with self._lock:
            loaded = self._builtins.get(rel)
            if loaded is None:
                text = resources.files("x64dbg_vm_gateway").joinpath(rel).read_text(encoding="utf-8")
                data = json.loads(text)
                tools = self._clean([  # a builtin list is the reference for read-only flags
                    ToolInfo(name=t.get("name"), description=t.get("description", ""),
                             input_schema=t.get("inputSchema"), read_only=bool(t.get("read_only")))
                    for t in data["tools"]
                ], source=f"builtin {rel}")
                loaded = self._builtins[rel] = _Builtin(rel, str(data.get("plugin_version", "")), tools)
            return loaded

    def _backend_builtin(self, backend_id: str | None) -> _Builtin:
        with self._lock:
            rel = self._backend_rel.get(backend_id, self._default_rel) if backend_id else self._default_rel
            return self._get_builtin(rel)

    def _choose(self, backend_id: str, version: str | None, *, explicit: bool) -> bool:
        """Pick the builtin for ``backend_id`` by ``version``; re-classify its live list on a change.

        A version derived from a cache file (``explicit=False``) never overrides one the
        plugin reported itself. Returns True when the builtin changed.
        """
        with self._lock:
            if not explicit and backend_id in self._explicit:
                return False
            if explicit:
                self._explicit.add(backend_id)
            before = self._backend_builtin(backend_id).rel
            self._backend_rel[backend_id] = builtin_for_version(version)
            after = self._backend_builtin(backend_id).rel
            if before == after:
                return False
            claimed = self._live_raw.get(backend_id)
            live = self._live.get(backend_id)
            if claimed is not None and live is not None:
                tools, source = claimed
                reclassified = self._classify(tools, source=source, backend_id=backend_id)
                self._live[backend_id] = (live[0], reclassified)
        log.info("tool catalog: backend %s uses the builtin list %s", backend_id, after)
        return True

    def _warn(self, msg: str) -> None:
        with self._lock:
            self._warnings.append(msg)
        log.warning("tool catalog: %s", msg)

    @property
    def warnings(self) -> list[str]:
        with self._lock:
            return list(self._warnings)

    def _read_only_policy(self, name: str, claimed: bool, source: str, reference: Mapping[str, bool]) -> bool:
        """Effective read-only flag for a live/cached entry (see module docstring)."""
        builtin = reference.get(name)
        if claimed and builtin is False:
            self._warn(f"{source}: tool {name!r} claims readOnlyHint but the builtin catalog marks it "
                       "mutating; treated as mutating")
            return False
        if claimed and builtin is None:
            log.info("tool catalog: %s: tool %r is not in the builtin catalog; treated as mutating",
                     source, name)
            return False
        return claimed

    def _classify(self, tools: list[ToolInfo], *, source: str, backend_id: str) -> list[ToolInfo]:
        """Cleaned live/cached tools with read-only flags checked against ``backend_id``'s builtin."""
        reference = self._backend_builtin(backend_id).read_only
        return [t if not t.read_only or self._read_only_policy(t.name, True, source, reference)
                else ToolInfo(name=t.name, description=t.description, input_schema=t.input_schema,
                              read_only=False)
                for t in tools]

    def _clean(self, tools: list[ToolInfo], *, source: str) -> list[ToolInfo]:
        """Sanitised copy (names, schemas, descriptions); read-only flags as claimed."""
        out: list[ToolInfo] = []
        seen: set[str] = set()
        for t in tools:
            if not isinstance(t.name, str) or not t.name:
                self._warn(f"{source}: dropped a tool without a valid name")
                continue
            if t.name in seen:
                self._warn(f"{source}: dropped duplicate tool {t.name!r}")
                continue
            seen.add(t.name)
            problem = _schema_problem(t.input_schema)
            schema: dict[str, Any] = {"type": "object"}
            if problem is None:
                try:
                    schema = _clean_schema_strings(t.input_schema)
                except (ValueError, RecursionError):
                    problem = "inputSchema is nested too deeply"
            if problem is not None:
                self._warn(f"{source}: tool {t.name!r}: {problem}; replaced with {{'type': 'object'}}")
                schema = {"type": "object"}
            desc = t.description if isinstance(t.description, str) else ""
            desc = sanitize_untrusted_text(desc, max_len=MAX_DESCRIPTION_CHARS)
            out.append(ToolInfo(name=t.name, description=desc, input_schema=schema,
                                read_only=bool(t.read_only)))
        return out

    def _cache_files(self, backend_id: str) -> list[Path]:
        prefix = f"tools-{_safe_component(backend_id)}-"
        try:
            return [p for p in self.cache_dir.iterdir()
                    if p.is_file() and p.name.startswith(prefix) and p.suffix == ".json"]
        except OSError:
            return []

    def _load_cache(self, backend_id: str) -> None:
        """Populate ``_live[backend_id]`` from the newest valid cache file (lock held)."""
        if backend_id in self._loaded_from_disk:
            return
        self._loaded_from_disk.add(backend_id)
        if backend_id in self._live:
            return
        candidates = []
        for p in self._cache_files(backend_id):
            try:
                candidates.append((p.stat().st_mtime, p))
            except OSError:
                continue
        for _mtime, p in sorted(candidates, reverse=True):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                if data.get("format") != CACHE_FORMAT or data.get("backend_id") != backend_id:
                    continue  # another backend whose id shares the prefix, or an old format
                tools = [ToolInfo(name=t.get("name"), description=t.get("description", ""),
                                  input_schema=t.get("inputSchema"), read_only=bool(t.get("read_only")))
                         for t in data["tools"]]
                version = str(data.get("server_version", ""))
            except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError) as e:
                self._warn(f"ignoring unreadable cache file {p.name}: {type(e).__name__}")
                continue
            if version_tuple(version) is not None:
                self._choose(backend_id, version, explicit=False)  # before classifying the list
            source = f"cache {p.name}"
            claimed = self._clean(tools, source=source)
            self._live_raw[backend_id] = (claimed, source)
            self._live[backend_id] = (version, self._classify(claimed, source=source, backend_id=backend_id))
            return

    # ── versions ────────────────────────────────────────────────────
    def set_server_version(self, backend_id: str, version: str | None) -> bool:
        """The backend's plugin reported ``version`` (``GET /`` / ``initialize``): use the
        matching builtin list for it from now on. Returns True when that list changed."""
        with self._lock:
            self._load_cache(backend_id)  # a cached version must not override this one later
            return self._choose(backend_id, version, explicit=True)

    def builtin_version(self, backend_id: str | None = None) -> str:
        """Plugin version of the builtin list ``backend_id`` uses (e.g. ``"1.9"``)."""
        with self._lock:
            if backend_id is not None:
                self._load_cache(backend_id)
            return self._backend_builtin(backend_id).version

    # ── queries ─────────────────────────────────────────────────────
    def tools(self, backend_id: str) -> list[ToolInfo]:
        """Tool list for ``backend_id``: its live cache if present, else its builtin list.

        Returned ToolInfo objects are shared; treat their ``input_schema`` as read-only.
        """
        with self._lock:
            self._load_cache(backend_id)
            live = self._live.get(backend_id)
            return list(live[1] if live is not None else self._backend_builtin(backend_id).tools)

    def server_version(self, backend_id: str) -> str | None:
        """Plugin version the cached list came from, or None when the builtin list is used."""
        with self._lock:
            self._load_cache(backend_id)
            live = self._live.get(backend_id)
            return live[0] if live is not None else None

    def tool(self, name: str, backend_id: str | None = None) -> ToolInfo | None:
        """Look ``name`` up in ``backend_id``'s list, or in any known list when omitted.

        Without a backend id, live lists win over the builtin list (first match).
        """
        with self._lock:
            if backend_id is not None:
                lists = [self.tools(backend_id)]
            else:
                lists = [tools for _v, tools in self._live.values()] + [self._backend_builtin(None).tools]
            for tools in lists:
                for t in tools:
                    if t.name == name:
                        return t
        return None

    def is_read_only(self, name: str, backend_id: str | None = None) -> bool:
        """``readOnlyHint`` of the tool; unknown tools are treated as mutating."""
        t = self.tool(name, backend_id)
        return bool(t is not None and t.read_only)

    def is_retryable(self, name: str, backend_id: str | None = None) -> bool:
        """Safe to retry once on a connection failure: read-only and not event-draining."""
        return self.is_read_only(name, backend_id) and name not in NON_RETRYABLE_READ_ONLY

    # ── updates ─────────────────────────────────────────────────────
    def update_from_live(self, backend_id: str, server_version: str, tools: list[ToolInfo]) -> bool:
        """Store the list fetched from a live backend; return True if it differs from before.

        A parsable ``server_version`` selects the backend's builtin list first, so the
        read-only flags are checked against the list of the same plugin version. The
        cache file keeps the claimed flags (they are checked again on every load).
        """
        version = str(server_version)
        source = f"live {backend_id} v{version}"
        claimed = self._clean(list(tools), source=source)
        with self._lock:
            before = {_key(t) for t in self.tools(backend_id)}  # loads the cache first
            if version_tuple(version) is not None:
                self._choose(backend_id, version, explicit=True)
            clean = self._classify(claimed, source=source, backend_id=backend_id)
            changed = before != {_key(t) for t in clean}
            path = self.cache_dir / f"tools-{_safe_component(backend_id)}-{_safe_component(version)}.json"
            try:
                _atomic_write_json(path, {
                    "format": CACHE_FORMAT,
                    "backend_id": backend_id,
                    "server_version": version,
                    "updated": datetime.now(UTC).isoformat(timespec="seconds"),
                    "tools": [_tool_to_json(t) for t in claimed],
                })
            except OSError as e:
                self._warn(f"could not write tool cache {path.name}: {type(e).__name__}")
            self._live_raw[backend_id] = (claimed, source)
            self._live[backend_id] = (version, clean)
            self._loaded_from_disk.add(backend_id)
        if changed:
            log.info("tool catalog: backend %s v%s list changed (%d tools)", backend_id, version, len(clean))
        return changed

    def _instructions_path(self, backend_id: str) -> Path:
        return self.cache_dir / f"instructions-{_safe_component(backend_id)}.json"

    def update_instructions(self, backend_id: str, instructions: str) -> None:
        """Cache the backend's ``initialize`` instructions (persisted for later sessions).

        The text comes from the guest: control/bidi characters are removed and it is
        capped at ``MAX_INSTRUCTIONS_CHARS``.
        """
        instructions = sanitize_untrusted_text(str(instructions), max_len=MAX_INSTRUCTIONS_CHARS)
        with self._lock:
            self._instructions[backend_id] = instructions
            path = self._instructions_path(backend_id)
            try:
                _atomic_write_json(path, {"format": CACHE_FORMAT, "backend_id": backend_id,
                                          "instructions": instructions})
            except OSError as e:
                self._warn(f"could not write instructions cache {path.name}: {type(e).__name__}")

    def instructions(self, backend_id: str) -> str | None:
        with self._lock:
            if backend_id not in self._instructions:
                value: str | None = None
                path = self._instructions_path(backend_id)
                if path.is_file():
                    try:
                        data = json.loads(path.read_text(encoding="utf-8"))
                        text = data.get("instructions")
                        if data.get("backend_id") == backend_id and isinstance(text, str):
                            value = sanitize_untrusted_text(text, max_len=MAX_INSTRUCTIONS_CHARS)
                    except (OSError, ValueError, AttributeError, RecursionError) as e:
                        self._warn(f"ignoring unreadable instructions cache {path.name}: {type(e).__name__}")
                self._instructions[backend_id] = value
            return self._instructions[backend_id]
