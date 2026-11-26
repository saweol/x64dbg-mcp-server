"""The clean snapshots this gateway took, per profile and VM (``<jobs_root>/clean_snapshots.json``).

``provision`` / ``setup`` record the clean snapshot they take, ``snapshot refresh`` the new one
and the profile's clean snapshot it replaces. ``snapshot prune`` offers to delete the recorded
ones that are no longer the profile's clean snapshot and not protected: a snapshot VMware lists
but this file does not name is somebody else's and is never touched.

Format: ``{"version": 1, "snapshots": [{"profile", "vmx", "name", "recorded_at", "source"}]}``,
oldest first. Names compare case-insensitively (like the gateway's snapshot checks), .vmx paths
after ``normcase``/``abspath``. A file that cannot be read counts as empty and is never
overwritten (a warning is logged), so a damaged file cannot make prune forget what it lists
by being rewritten. Writes are atomic (temp file + rename, 0600).

Callers hold the jobs root (``JobStore`` process lock), so there is one writer at a time.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import tempfile
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

from . import platform as gw_platform

__all__ = ["LEDGER_FILE", "Entry", "entries", "path_for", "record"]

log = logging.getLogger(__name__)

LEDGER_FILE = "clean_snapshots.json"
_VERSION = 1
_MAX_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True)
class Entry:
    profile: str
    vmx: str
    name: str
    recorded_at: str
    source: str  # "provision" | "refresh" | "clean_snapshot" (the one a refresh replaced)


def path_for(jobs_root: Path | str) -> Path:
    return Path(jobs_root).expanduser() / LEDGER_FILE


def _same_vm(a: str, b: str) -> bool:
    def norm(p: str) -> str:
        return os.path.normcase(os.path.abspath(os.path.expanduser(p)))

    return norm(a) == norm(b)


def _load(path: Path) -> list[Entry] | None:
    """The entries, [] for a missing file, None for one that cannot be read."""
    try:
        with open(path, "rb") as f:
            raw = f.read(_MAX_BYTES + 1)
    except FileNotFoundError:
        return []
    except OSError as e:
        log.warning("cannot read %s (%s)", path, e.strerror or type(e).__name__)
        return None
    try:
        doc = json.loads(raw.decode("utf-8")) if len(raw) <= _MAX_BYTES else None
    except (UnicodeDecodeError, ValueError):
        doc = None
    rows = doc.get("snapshots") if isinstance(doc, dict) and doc.get("version") == _VERSION else None
    if not isinstance(rows, list):
        log.warning("%s is not a clean-snapshot ledger this version can read; it is left as it is", path)
        return None
    out: list[Entry] = []
    for row in rows:
        if isinstance(row, dict) and all(isinstance(row.get(k), str) for k in Entry.__dataclass_fields__):
            out.append(Entry(**{k: row[k] for k in Entry.__dataclass_fields__}))
    return out


def entries(jobs_root: Path | str, *, profile: str, vmx: str) -> list[Entry]:
    """The recorded clean snapshots of ``profile`` on ``vmx``, oldest first."""
    rows = _load(path_for(jobs_root)) or []
    return [e for e in rows if e.profile == profile and _same_vm(e.vmx, vmx)]


def _write(path: Path, rows: list[Entry]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps({"version": _VERSION, "snapshots": [asdict(e) for e in rows]}, indent=2).encode("utf-8")
    fd, temp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temp)
        raise
    gw_platform.secure_file(path)


def record(jobs_root: Path | str, *, profile: str, vmx: str, name: str, source: str,
           now: datetime | None = None) -> bool:
    """Add ``name``; False when it is recorded already or the ledger cannot be read (it is then
    left unchanged)."""
    path = path_for(jobs_root)
    rows = _load(path)
    if rows is None:
        return False
    folded = name.casefold()
    if any(e.profile == profile and _same_vm(e.vmx, vmx) and e.name.casefold() == folded for e in rows):
        return False
    stamp = (now or datetime.now(UTC)).astimezone(UTC).isoformat(timespec="seconds")
    _write(path, [*rows, Entry(profile, vmx, name, stamp, source)])
    return True
