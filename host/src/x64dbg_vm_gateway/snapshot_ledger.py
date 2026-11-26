"""The clean snapshots this gateway took or used, per profile and VM (``<jobs_root>/clean_snapshots.json``).

``provision`` / ``setup`` record the snapshot they take (:func:`record_taken`), ``snapshot
refresh`` the new one and, as having been the clean snapshot, the profile's clean snapshot it
replaces (:func:`mark_clean`). ``snapshot prune`` offers to delete the recorded snapshots that
were the profile's clean snapshot once (``was_clean``) and are not any more, never one that is
protected or the clean snapshot of a profile, and forgets what it deleted (:func:`forget`). A
snapshot taken but never made the clean one (a refresh without --set-clean) is not "old". A
snapshot VMware lists but this file does not name is somebody else's and is never touched.

Format: ``{"version": 1, "snapshots": [{"profile", "vmx", "name", "recorded_at", "source",
"was_clean"}]}`` in the order taken (a name taken again moves to the end: it is a new snapshot).
Names compare case-insensitively (like the gateway's snapshot checks), .vmx paths after
``normcase``/``realpath``. A file that cannot be read counts as empty and is never overwritten
(a warning is logged), so a damaged file cannot make prune forget what it lists by being
rewritten. Writes are atomic (temp file + rename, 0600).

Callers hold the jobs root (``JobStore`` process lock), so there is one writer at a time.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import tempfile
from collections.abc import Iterable
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from pathlib import Path

from . import platform as gw_platform

__all__ = ["LEDGER_FILE", "Entry", "entries", "forget", "mark_clean", "path_for", "record_taken"]

log = logging.getLogger(__name__)

LEDGER_FILE = "clean_snapshots.json"
_VERSION = 1
_MAX_BYTES = 4 * 1024 * 1024
_TEXT_FIELDS = ("profile", "vmx", "name", "recorded_at", "source")


@dataclass(frozen=True)
class Entry:
    profile: str
    vmx: str
    name: str
    recorded_at: str
    source: str  # "provision" | "refresh" | "clean_snapshot" (the one a refresh replaced)
    was_clean: bool = False  # it has been the profile's clean snapshot


def path_for(jobs_root: Path | str) -> Path:
    return Path(jobs_root).expanduser() / LEDGER_FILE


def _same_vm(a: str, b: str) -> bool:
    def norm(p: str) -> str:  # a symlink and its target are the same VM
        return os.path.normcase(os.path.realpath(os.path.expanduser(p)))

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
        if isinstance(row, dict) and all(isinstance(row.get(k), str) for k in _TEXT_FIELDS):
            out.append(Entry(**{k: row[k] for k in _TEXT_FIELDS}, was_clean=row.get("was_clean") is True))
    return out


def _mine(entry: Entry, profile: str, vmx: str) -> bool:
    return entry.profile == profile and _same_vm(entry.vmx, vmx)


def entries(jobs_root: Path | str, *, profile: str, vmx: str) -> list[Entry]:
    """The recorded snapshots of ``profile`` on ``vmx``, oldest first."""
    return [e for e in _load(path_for(jobs_root)) or [] if _mine(e, profile, vmx)]


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


def _stamp(now: datetime | None) -> str:
    return (now or datetime.now(UTC)).astimezone(UTC).isoformat(timespec="seconds")


def record_taken(jobs_root: Path | str, *, profile: str, vmx: str, name: str, source: str, clean: bool,
                 now: datetime | None = None) -> bool:
    """A snapshot was just taken under ``name`` (``clean``: it is the profile's clean snapshot):
    an entry of the same name (an earlier snapshot) is replaced by a new one at the end. False
    when the ledger cannot be read (it is then left unchanged)."""
    path = path_for(jobs_root)
    rows = _load(path)
    if rows is None:
        return False
    folded = name.casefold()
    kept = [e for e in rows if not (_mine(e, profile, vmx) and e.name.casefold() == folded)]
    _write(path, [*kept, Entry(profile, vmx, name, _stamp(now), source, was_clean=clean)])
    return True


def mark_clean(jobs_root: Path | str, *, profile: str, vmx: str, name: str,
               now: datetime | None = None) -> bool:
    """``name`` is (or was) the profile's clean snapshot: flag its entry, or add one (source
    "clean_snapshot"). False when nothing changed or the ledger cannot be read."""
    path = path_for(jobs_root)
    rows = _load(path)
    if rows is None:
        return False
    folded = name.casefold()
    for i, e in enumerate(rows):
        if _mine(e, profile, vmx) and e.name.casefold() == folded:
            if e.was_clean:
                return False
            rows[i] = replace(e, was_clean=True)
            break
    else:
        rows.append(Entry(profile, vmx, name, _stamp(now), "clean_snapshot", was_clean=True))
    _write(path, rows)
    return True


def forget(jobs_root: Path | str, *, profile: str, vmx: str, names: Iterable[str]) -> None:
    """Drop the entries of ``names`` (snapshots that were deleted); a ledger that cannot be read
    is left unchanged."""
    path = path_for(jobs_root)
    rows = _load(path)
    folded = {n.casefold() for n in names}
    if not rows or not folded:
        return
    kept = [e for e in rows if not (_mine(e, profile, vmx) and e.name.casefold() in folded)]
    if len(kept) != len(rows):
        _write(path, kept)
