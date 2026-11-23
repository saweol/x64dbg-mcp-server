"""Tool catalog: which x64dbg-MCP tools exist, their schemas and their retry class.

Sources, in order of preference for a backend:

1. the live list most recently fetched from that backend (``update_from_live``),
   persisted as ``<cache_dir>/tools-<backend_id>-<server_version>.json``;
2. the builtin v1.9 list shipped with the package (``data/tools-v1.9.json``).

The gateway exposes the full list at session start because some MCP clients
ignore ``notifications/tools/list_changed`` (plan 5.5). Schemas are sanitised so
the mirrored ``inputSchema`` is always a JSON-Schema object.

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
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from typing import Any

from .contracts import ToolInfo

log = logging.getLogger(__name__)

CACHE_FORMAT = 1
# Read-only tools that must still never be retried: WaitForEvent drains the
# plugin's pending-event queue, so a blind retry can lose events.
NON_RETRYABLE_READ_ONLY = frozenset({"WaitForEvent"})
_SAFE = re.compile(r"[^A-Za-z0-9_.-]")


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
    return None


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


class ToolCatalog:
    def __init__(self, builtin_json: str = "data/tools-v1.9.json",
                 cache_dir: Path | str | None = None) -> None:
        self._lock = threading.RLock()
        self.cache_dir = Path(cache_dir).expanduser() if cache_dir is not None else default_cache_dir()
        self._warnings: list[str] = []
        self._builtin = self._load_builtin(builtin_json)
        self._live: dict[str, tuple[str, list[ToolInfo]]] = {}  # backend_id -> (version, tools)
        self._loaded_from_disk: set[str] = set()
        self._instructions: dict[str, str | None] = {}

    # ── loading ─────────────────────────────────────────────────────
    def _load_builtin(self, rel: str) -> list[ToolInfo]:
        data = json.loads(resources.files("x64dbg_vm_gateway").joinpath(rel).read_text(encoding="utf-8"))
        return self._sanitize([
            ToolInfo(name=t.get("name"), description=t.get("description", ""),
                     input_schema=t.get("inputSchema"), read_only=bool(t.get("read_only")))
            for t in data["tools"]
        ], source=f"builtin {rel}")

    def _warn(self, msg: str) -> None:
        with self._lock:
            self._warnings.append(msg)
        log.warning("tool catalog: %s", msg)

    @property
    def warnings(self) -> list[str]:
        with self._lock:
            return list(self._warnings)

    def _sanitize(self, tools: list[ToolInfo], *, source: str) -> list[ToolInfo]:
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
            if problem is not None:
                self._warn(f"{source}: tool {t.name!r}: {problem}; replaced with {{'type': 'object'}}")
                schema: dict[str, Any] = {"type": "object"}
            else:
                schema = copy.deepcopy(t.input_schema)
            desc = t.description if isinstance(t.description, str) else ""
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
            except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
                self._warn(f"ignoring unreadable cache file {p.name}: {type(e).__name__}")
                continue
            self._live[backend_id] = (version, self._sanitize(tools, source=f"cache {p.name}"))
            return

    # ── queries ─────────────────────────────────────────────────────
    def tools(self, backend_id: str) -> list[ToolInfo]:
        """Tool list for ``backend_id``: its live cache if present, else the builtin list.

        Returned ToolInfo objects are shared; treat their ``input_schema`` as read-only.
        """
        with self._lock:
            self._load_cache(backend_id)
            live = self._live.get(backend_id)
            return list(live[1] if live is not None else self._builtin)

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
                lists = [tools for _v, tools in self._live.values()] + [self._builtin]
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
        """Store the list fetched from a live backend; return True if it differs from before."""
        version = str(server_version)
        clean = self._sanitize(list(tools), source=f"live {backend_id} v{version}")
        with self._lock:
            before = {_key(t) for t in self.tools(backend_id)}
            changed = before != {_key(t) for t in clean}
            path = self.cache_dir / f"tools-{_safe_component(backend_id)}-{_safe_component(version)}.json"
            try:
                _atomic_write_json(path, {
                    "format": CACHE_FORMAT,
                    "backend_id": backend_id,
                    "server_version": version,
                    "updated": datetime.now(UTC).isoformat(timespec="seconds"),
                    "tools": [_tool_to_json(t) for t in clean],
                })
            except OSError as e:
                self._warn(f"could not write tool cache {path.name}: {type(e).__name__}")
            self._live[backend_id] = (version, clean)
            self._loaded_from_disk.add(backend_id)
        if changed:
            log.info("tool catalog: backend %s v%s list changed (%d tools)", backend_id, version, len(clean))
        return changed

    def _instructions_path(self, backend_id: str) -> Path:
        return self.cache_dir / f"instructions-{_safe_component(backend_id)}.json"

    def update_instructions(self, backend_id: str, instructions: str) -> None:
        """Cache the backend's ``initialize`` instructions (persisted for later sessions)."""
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
                        if data.get("backend_id") == backend_id and isinstance(data.get("instructions"), str):
                            value = data["instructions"]
                    except (OSError, ValueError, AttributeError) as e:
                        self._warn(f"ignoring unreadable instructions cache {path.name}: {type(e).__name__}")
                self._instructions[backend_id] = value
            return self._instructions[backend_id]
