"""Sample upload, artifact collection and safe archive extraction (plan 5.3, 6.3).

Upload: ``<in>\\<sha12>.part`` -> guest-side SHA-256 written to a file and
copied back (runProgramInGuest returns no output) -> rename to
``<in>\\<sha12>.<exe|dll|bin>``.

Collect: zip the guest ``out`` directory with ``Compress-Archive`` (vmrun cannot
copy directories), copy the zip and any extra guest files to the host job
directory, extract the zip with :func:`safe_extract` and write
``artifacts/manifest.json`` atomically. Host layout::

    <host_job_dir>/artifacts/
        manifest.json
        raw/out.zip                       original archive, kept as received
        raw/extra/NNNN_<sanitized-name>   extra guest files
        files/NNNN_<sha12>                extracted members (names only in the manifest)

On POSIX hosts directories are 0700 and files 0600 (never executable). On a
Windows host the caller should pass ``extract=False`` and keep the archive,
optionally re-packed with :func:`encrypt_archive` (plan 6.3).

Thread-safety: every function is stateless. Concurrent calls that target the
same guest directory or the same host job directory are not safe (names are
derived from content hashes and indexes); the job layer serializes per job.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import lzma
import os
import re
import secrets
import shutil
import stat
import tempfile
import zipfile
import zlib
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path, PureWindowsPath
from types import MappingProxyType
from typing import Any

from .contracts import Clock, GuestChannel, Secret, SystemClock
from .errors import (
    GatewayError,
    IntegrityError,
    PathNotAllowed,
    TransferError,
    UnsafeArchiveError,
    VmrunError,
)
from .guest import GUEST_ENV_ERRORS, POWERSHELL_EXE, is_reserved_name, validate_guest_path
from .pe import sha256_file

__all__ = [
    "DEFAULT_EXTRACT_LIMITS",
    "MANIFEST_SCHEMA_VERSION",
    "ExtractLimits",
    "ExtractedEntry",
    "Manifest",
    "ManifestEntry",
    "collect_artifacts",
    "encrypt_archive",
    "safe_extract",
    "upload_sample",
]

MANIFEST_SCHEMA_VERSION = 1
MANIFEST_NAME = "manifest.json"

_KiB = 1024
_MiB = 1024 * _KiB
_GiB = 1024 * _MiB
_COPY_CHUNK = _MiB
_HASH_FILE_MAX = 4 * _KiB  # a SHA-256 hex line is 66 bytes; anything larger is garbage
_SHA256_RE = re.compile(r"[0-9a-fA-F]{64}")
_PS_PREFIX = ("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command")
# Characters PowerShell interprets as wildcards / escapes in -Path / -FilePath arguments.
_PS_WILDCARD_CHARS = frozenset("[]`")
_EXT_BY_KIND = MappingProxyType({"exe": "exe", "dotnet-exe": "exe", "dll": "dll", "dotnet-dll": "dll"})
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_ZIP_FLAG_ENCRYPTED = 0x1
_BASENAME_MAX = 64
_TEXT_LIMIT = 300

_SYSTEM_CLOCK = SystemClock()  # stateless default instance


# ── small helpers ───────────────────────────────────────────────────
def _clip(text: str, limit: int = _TEXT_LIMIT) -> str:
    return text if len(text) <= limit else text[:limit] + "..."


def _is_posix() -> bool:
    return os.name == "posix"


def _open_flags() -> int:
    return (os.O_WRONLY | os.O_CREAT | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))


def _chmod(path: Path, mode: int) -> None:
    if _is_posix():
        os.chmod(path, mode)


def _make_private_dir(path: Path) -> None:
    if path.is_symlink():
        raise TransferError("refusing to use a symlinked host directory", stage="host_fs",
                            details={"path": str(path)})
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    _chmod(path, 0o700)


def _reset_dir(path: Path) -> None:
    """Remove ``path`` (a previous extraction) and recreate it empty and private."""
    if path.is_symlink() or (path.exists() and not path.is_dir()):
        path.unlink()
    elif path.exists():
        shutil.rmtree(path)
    _make_private_dir(path)


def _fsync_dir(path: Path) -> None:
    if not _is_posix():
        return
    with contextlib.suppress(OSError):
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _write_json_atomic(path: Path, doc: Any) -> None:
    """Write ``doc`` as JSON via tmp file + fsync + os.replace (+ directory fsync)."""
    data = json.dumps(doc, indent=2, ensure_ascii=True).encode("ascii")
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    fd = os.open(tmp, _open_flags(), 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        _chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise
    _fsync_dir(path.parent)


def _jsonable(value: Any) -> Any:
    """Round-trip through JSON so the manifest object equals what is written to disk."""
    return json.loads(json.dumps(value, default=str))


def _check_sha256(value: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise TransferError("sha256 must be 64 hex characters", stage="upload")
    return value.lower()


def _ps_safe_dir(path: str, *, must_be_under: Sequence[str] | None = None) -> str:
    """Validate a guest directory that is interpolated into a PowerShell command."""
    norm = validate_guest_path(path, must_be_under=must_be_under)
    if any(ch in _PS_WILDCARD_CHARS for ch in norm):
        raise PathNotAllowed(f"guest directory contains PowerShell wildcard characters: {norm!r}",
                             stage="validate", details={"reason": "powershell-wildcard", "path": norm})
    return norm


def _gjoin(directory: str, name: str) -> str:
    return str(PureWindowsPath(directory) / name)


def _is_within(path: str, root: str) -> bool:
    p, r = path.lower(), root.lower().rstrip("\\")
    return p == r or p.startswith(r + "\\")


def _delete_guest_if_exists(channel: GuestChannel, path: str) -> None:
    if channel.file_exists(path):
        channel.delete_file(path)


def _ps(channel: GuestChannel, powershell: str, command: str, timeout_s: float) -> int | None:
    return channel.run_program(powershell, [*_PS_PREFIX, command], wait=True, timeout_s=timeout_s)


# ── upload ──────────────────────────────────────────────────────────
def _parse_hash_file(path: Path) -> str | None:
    with path.open("rb") as f:
        data = f.read(_HASH_FILE_MAX + 1)
    if len(data) > _HASH_FILE_MAX:
        return None
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        text = data.decode("utf-16", errors="replace")
    else:
        if data.startswith(b"\xef\xbb\xbf"):
            data = data[3:]
        text = data.decode("ascii", errors="replace")
    text = text.strip().strip("﻿").strip()
    return text.lower() if _SHA256_RE.fullmatch(text) else None


def _guest_sha256(channel: GuestChannel, powershell: str, part: str, hash_path: str, local: Path,
                  timeout_s: float) -> str | None:
    """Hash ``part`` in the guest; None when the hash could not be produced or read back."""
    command = (f"(Get-FileHash -Algorithm SHA256 -LiteralPath '{part}').Hash"
               f" | Out-File -Encoding ascii -FilePath '{hash_path}'")
    if _ps(channel, powershell, command, timeout_s) != 0:
        return None
    with contextlib.suppress(FileNotFoundError):
        local.unlink()
    try:
        channel.copy_from_guest(hash_path, local)
    except VmrunError as exc:
        if isinstance(exc, GUEST_ENV_ERRORS):
            raise
        return None  # hash file missing: hashing failed in the guest
    try:
        return _parse_hash_file(local)
    except FileNotFoundError:
        return None


def upload_sample(
    channel: GuestChannel,
    host_path: str | os.PathLike[str],
    guest_in_dir: str,
    *,
    sha256: str,
    kind: str,
    clock: Clock = _SYSTEM_CLOCK,
    max_attempts: int = 3,
    powershell: str = POWERSHELL_EXE,
    hash_timeout_s: float = 600.0,
) -> str:
    """Upload a sample and return its verified guest path ``<in>\\<sha12>.<ext>``.

    The host file is re-hashed first (it must still match ``sha256``). Each
    attempt copies to ``<sha12>.part``, hashes it in the guest and compares; a
    mismatch deletes the part and retries after a short back-off. After
    ``max_attempts`` failures raises IntegrityError. Guest/vmrun errors other
    than a missing hash file propagate unchanged (no retry).
    """
    if max_attempts < 1:
        raise ValueError("max_attempts must be >= 1")
    expected = _check_sha256(sha256)
    in_dir = _ps_safe_dir(guest_in_dir)
    src = Path(host_path)
    if not src.is_file():
        raise TransferError("sample is not a regular host file", stage="upload",
                            details={"host_path": str(src)})
    actual = sha256_file(src)
    if actual != expected:
        raise IntegrityError("host sample does not match the expected sha256", stage="upload",
                             details={"expected": expected, "actual": actual})

    sha12 = expected[:12]
    part = _gjoin(in_dir, f"{sha12}.part")
    hash_path = _gjoin(in_dir, f"{sha12}.sha256")
    final = _gjoin(in_dir, f"{sha12}.{_EXT_BY_KIND.get(kind, 'bin')}")

    channel.mkdir(in_dir)
    observed: list[str] = []
    verified = False
    with tempfile.TemporaryDirectory(prefix="x64gw-hash-") as td:
        local = Path(td) / "guest.sha256"
        for attempt in range(1, max_attempts + 1):
            if attempt > 1:
                clock.sleep(min(2.0 ** (attempt - 2), 8.0))
            _delete_guest_if_exists(channel, hash_path)  # never trust a stale result
            channel.copy_to_guest(src, part)
            got = _guest_sha256(channel, powershell, part, hash_path, local, hash_timeout_s)
            if got == expected:
                verified = True
                break
            observed.append(got or "unavailable")
            _delete_guest_if_exists(channel, part)
    if not verified:
        with contextlib.suppress(VmrunError):
            _delete_guest_if_exists(channel, hash_path)
        raise IntegrityError(
            f"guest copy of {sha12} failed SHA-256 verification {max_attempts} time(s)",
            stage="upload",
            details={"attempts": max_attempts, "expected": expected, "observed": observed},
        )

    if channel.file_exists(final):
        channel.delete_file(final)
    channel.rename(part, final)
    with contextlib.suppress(VmrunError):
        _delete_guest_if_exists(channel, hash_path)
    return final


# ── safe extraction ─────────────────────────────────────────────────
@dataclass(frozen=True)
class ExtractLimits:
    """Upper bounds for :func:`safe_extract`. Byte limits apply to bytes actually decompressed.

    ``max_ratio`` is checked per entry once the entry has produced more than
    ``ratio_min_bytes`` (small, highly compressible files are harmless). Memory
    dumps with large zero-filled regions can compress better than 200:1; raise
    ``max_ratio`` if that becomes a problem, the byte limits still apply.
    """

    max_files: int = 10_000
    max_total_bytes: int = 4 * _GiB
    max_file_bytes: int = 2 * _GiB
    max_ratio: float = 200
    ratio_min_bytes: int = _MiB

    def __post_init__(self) -> None:
        if min(self.max_files, self.max_total_bytes, self.max_file_bytes) < 0 or self.max_ratio <= 0 \
                or self.ratio_min_bytes < 0:
            raise ValueError("extract limits must be non-negative (max_ratio positive)")


DEFAULT_EXTRACT_LIMITS = ExtractLimits()


@dataclass(frozen=True)
class ExtractedEntry:
    """One archive member. ``size`` is the extracted byte count for ``ok`` entries and the
    header-declared size otherwise. ``status``: ``ok`` | ``skipped:directory`` |
    ``rejected:<reason>``."""

    original_name: str
    stored_name: str | None
    size: int
    sha256: str | None
    status: str


class _EntryRejected(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _name_problem(name: str) -> str | None:
    """Reason an archive member name is unsafe, or None."""
    if not name:
        return "empty-name"
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in name):
        return "invalid-char"
    s = name.replace("\\", "/")
    if s.startswith("//"):
        return "unc"
    if s.startswith("/"):
        return "absolute"
    if len(s) >= 2 and s[1] == ":" and s[0].isascii() and s[0].isalpha():
        return "drive"
    if ":" in s:
        return "ads"
    components = [c for c in s.split("/") if c]
    if not components:
        return "empty-name"
    if ".." in components:
        return "traversal"
    for comp in components:
        if comp[-1] in ". ":
            return "trailing-dot-space"
        if is_reserved_name(comp):
            return "reserved-name"
    return None


def _dup_key(name: str) -> str:
    return "/".join(c for c in name.replace("\\", "/").split("/") if c).casefold()


def _is_link(info: zipfile.ZipInfo) -> bool:
    mode = info.external_attr >> 16
    if stat.S_ISLNK(mode):
        return True
    return bool(info.external_attr & _FILE_ATTRIBUTE_REPARSE_POINT)  # Windows symlink / junction


def _within(path: str, root_real: str) -> bool:
    real = os.path.realpath(path)
    return os.path.dirname(real) == root_real


def _extract_member(zf: zipfile.ZipFile, info: zipfile.ZipInfo, index: int, dest: Path, dest_real: str,
                    limits: ExtractLimits, total_before: int,
                    archive_size: int) -> tuple[ExtractedEntry, int]:
    """Extract one member; returns the entry and the number of bytes decompressed.

    Bytes decompressed for a member that is later rejected still count against
    ``max_total_bytes`` so a stream of corrupt members cannot reset the budget.
    """
    tmp = dest / f".{index:04d}.{secrets.token_hex(6)}.partial"
    denom = max(1, min(info.compress_size, archive_size))
    digest = hashlib.sha256()
    written = 0
    try:
        fd = os.open(tmp, _open_flags(), 0o600)
        with os.fdopen(fd, "wb") as out:
            if hasattr(os, "fchmod"):
                os.fchmod(out.fileno(), 0o600)
            try:
                src = zf.open(info)
            except NotImplementedError as exc:
                raise _EntryRejected("unsupported-compression") from exc
            except RuntimeError as exc:  # encrypted, password required
                raise _EntryRejected("encrypted") from exc
            except (zipfile.BadZipFile, ValueError, EOFError, OSError, zlib.error) as exc:
                raise _EntryRejected("corrupt") from exc
            with src:
                while True:
                    want = min(_COPY_CHUNK, limits.max_file_bytes - written + 1,
                               limits.max_total_bytes - total_before - written + 1)
                    try:
                        chunk = src.read(max(want, 1))
                    except (zipfile.BadZipFile, zlib.error, lzma.LZMAError, EOFError, OSError,
                            ValueError) as exc:
                        # The failing read may already have decompressed (and discarded) data,
                        # e.g. a CRC error is raised by the read that returns the last bytes.
                        # zipfile never yields more than the declared size, so charge that.
                        written = max(written, min(info.file_size, limits.max_file_bytes))
                        raise _EntryRejected("corrupt") from exc
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > limits.max_file_bytes:
                        raise _EntryRejected("too-large")
                    if total_before + written > limits.max_total_bytes:
                        raise UnsafeArchiveError(
                            "archive exceeds the total extracted size limit", stage="extract",
                            details={"reason": "total-bytes", "entry_index": index,
                                     "limit": limits.max_total_bytes})
                    if written > limits.ratio_min_bytes and written / denom > limits.max_ratio:
                        raise UnsafeArchiveError(
                            "archive member exceeds the compression ratio limit", stage="extract",
                            details={"reason": "ratio", "entry_index": index, "limit": limits.max_ratio})
                    digest.update(chunk)
                    out.write(chunk)
            out.flush()
            os.fsync(out.fileno())
    except _EntryRejected as rej:
        _unlink_quiet(tmp)
        return ExtractedEntry(info.filename, None, info.file_size, None, f"rejected:{rej.reason}"), written
    except OSError as exc:  # host-side write failure
        _unlink_quiet(tmp)
        raise TransferError(f"host write failed while extracting: {exc.strerror or exc}", stage="extract",
                            details={"entry_index": index}) from exc
    except BaseException:
        _unlink_quiet(tmp)
        raise

    sha = digest.hexdigest()
    stored = f"{index:04d}_{sha[:12]}"
    final = dest / stored
    os.replace(tmp, final)  # replaces a pre-existing link itself, never its target
    if not _within(str(final), dest_real):
        _unlink_quiet(final)
        return ExtractedEntry(info.filename, None, written, None, "rejected:escape"), written
    return ExtractedEntry(info.filename, stored, written, sha, "ok"), written


def _unlink_quiet(path: Path) -> None:
    with contextlib.suppress(FileNotFoundError):
        os.unlink(path)


def _open_zip(zip_path: Path) -> zipfile.ZipFile:
    try:
        return zipfile.ZipFile(zip_path)
    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError, ValueError, EOFError,
            NotImplementedError) as exc:
        raise TransferError(f"not a readable zip archive: {zip_path.name}", stage="extract",
                            details={"error": type(exc).__name__}) from exc


def _extract_into(zip_path: Path, dest: Path, limits: ExtractLimits, out: list[ExtractedEntry]) -> None:
    """Extract into ``dest``, appending one entry per member to ``out`` as it goes.

    ``out`` keeps the entries finished before an UnsafeArchiveError abort.
    """
    with _open_zip(zip_path) as zf:
        infos = zf.infolist()
        n_files = sum(1 for i in infos if not i.is_dir())
        if n_files > limits.max_files:
            raise UnsafeArchiveError("archive has too many members", stage="extract",
                                     details={"reason": "file-count", "files": n_files,
                                              "limit": limits.max_files})
        _make_private_dir(dest)
        dest_real = os.path.realpath(dest)
        archive_size = zip_path.stat().st_size
        seen: set[str] = set()
        total = 0
        for index, info in enumerate(infos):
            name = info.filename
            reason = _name_problem(name)
            key = _dup_key(name)
            if reason is None and key in seen:
                reason = "duplicate"
            seen.add(key)
            if reason is None and _is_link(info):
                reason = "symlink"
            if reason is None and info.is_dir():
                out.append(ExtractedEntry(name, None, 0, None, "skipped:directory"))
                continue
            if reason is None and info.flag_bits & _ZIP_FLAG_ENCRYPTED:
                reason = "encrypted"
            if reason is None and info.file_size > limits.max_file_bytes:
                reason = "too-large"
            if reason is not None:
                out.append(ExtractedEntry(name, None, info.file_size, None, f"rejected:{reason}"))
                continue
            entry, consumed = _extract_member(zf, info, index, dest, dest_real, limits, total, archive_size)
            total += consumed
            out.append(entry)


def safe_extract(zip_path: str | os.PathLike[str], dest_dir: str | os.PathLike[str],
                 limits: ExtractLimits = DEFAULT_EXTRACT_LIMITS) -> list[ExtractedEntry]:
    """Extract ``zip_path`` into the flat directory ``dest_dir`` without trusting the archive.

    Members are stored as ``NNNN_<sha12>`` (NNNN = member index); original names
    only appear in the returned entries. Unsafe members are skipped with status
    ``rejected:<reason>`` (absolute, drive, unc, traversal, ads, reserved-name,
    trailing-dot-space, invalid-char, duplicate, symlink, encrypted, too-large,
    corrupt, unsupported-compression). Exceeding the member count, the total
    size or the compression ratio aborts with UnsafeArchiveError after removing
    the partial output of the current member; earlier members stay on disk.
    A file that is not a readable zip raises TransferError.
    """
    entries: list[ExtractedEntry] = []
    _extract_into(Path(zip_path), Path(dest_dir), limits, entries)
    return entries


# ── collection ──────────────────────────────────────────────────────
@dataclass(frozen=True)
class ManifestEntry:
    """``source``: ``out`` (member of the guest out.zip, ``original_path`` is the member
    name relative to the out dir) or ``extra`` (guest file copied on its own,
    ``original_path`` is the guest path). ``stored_name`` is relative to
    ``<host_job_dir>/artifacts`` with ``/`` separators. ``status``: ``ok`` |
    ``archived`` (kept in raw/out.zip, not extracted) | ``skipped:<why>`` |
    ``rejected:<reason>`` | ``failed:<error code>``."""

    source: str
    original_path: str
    stored_name: str | None
    size: int
    sha256: str | None
    status: str


@dataclass
class Manifest:
    schema_version: int
    job_dir: str
    collected_at: str
    guest_out_dir: str
    guest_job_dir: str
    raw_zip: str | None
    raw_zip_sha256: str | None
    raw_zip_size: int | None
    extracted: bool
    partial: bool
    entries: list[ManifestEntry]
    errors: list[dict[str, Any]]
    module_map: Any
    screenshot: dict[str, Any] | None
    manifest_path: str

    def to_dict(self) -> dict[str, Any]:
        """The JSON document written to ``manifest.json`` (``manifest_path`` excluded)."""
        return {
            "schema_version": self.schema_version,
            "job_dir": self.job_dir,
            "collected_at": self.collected_at,
            "guest_out_dir": self.guest_out_dir,
            "guest_job_dir": self.guest_job_dir,
            "raw_zip": self.raw_zip,
            "raw_zip_sha256": self.raw_zip_sha256,
            "raw_zip_size": self.raw_zip_size,
            "extracted": self.extracted,
            "partial": self.partial,
            "errors": [dict(e) for e in self.errors],
            "entries": [asdict(e) for e in self.entries],
            "module_map": self.module_map,
            "screenshot": None if self.screenshot is None else dict(self.screenshot),
        }


def _sanitize_basename(name: str) -> str:
    """Host-safe file name: ``[A-Za-z0-9._-]`` only, no leading dots, at most 64 chars."""
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", name).lstrip(".")
    if not s:
        return "file"
    if len(s) > _BASENAME_MAX:
        stem, dot, ext = s.rpartition(".")
        if dot and stem and 0 < len(ext) <= 16:
            s = stem[: _BASENAME_MAX - len(ext) - 1] + "." + ext
        else:
            s = s[:_BASENAME_MAX]
    return s


def _error(stage: str, code: str, message: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
    err: dict[str, Any] = {"stage": stage, "code": code, "message": _clip(message)}
    if details:
        err["details"] = _jsonable(details)
    return err


def _fetch(channel: GuestChannel, guest_path: str, dst: Path) -> tuple[str, int]:
    """Copy a guest file to ``dst`` via ``dst.part`` + rename; returns (sha256, size)."""
    part = dst.with_name(dst.name + ".part")
    _unlink_quiet(part)
    try:
        channel.copy_from_guest(guest_path, part)
        _chmod(part, 0o600)
        os.replace(part, dst)
    except BaseException:
        _unlink_quiet(part)
        raise
    return sha256_file(dst), dst.stat().st_size


def _screenshot_record(screenshot: str | os.PathLike[str] | None, job: Path) -> dict[str, Any] | None:
    if screenshot is None:
        return None
    sp = Path(screenshot)
    shown = str(sp)
    with contextlib.suppress(ValueError):
        shown = sp.resolve().relative_to(job.resolve()).as_posix()
    if not sp.is_file():
        return {"path": shown, "status": "missing"}
    return {"path": shown, "sha256": sha256_file(sp), "size": sp.stat().st_size}


def _list_archive(zip_path: Path) -> list[ManifestEntry]:
    with _open_zip(zip_path) as zf:
        return [ManifestEntry("out", i.filename, None, i.file_size, None,
                              "skipped:directory" if i.is_dir() else "archived") for i in zf.infolist()]


def collect_artifacts(
    channel: GuestChannel,
    *,
    guest_out_dir: str,
    guest_job_dir: str,
    host_job_dir: str | os.PathLike[str],
    extra_guest_paths: Iterable[str] = (),
    allowed_guest_roots: str | Sequence[str],
    limits: ExtractLimits = DEFAULT_EXTRACT_LIMITS,
    extract: bool = True,
    module_map: Any = None,
    screenshot: str | os.PathLike[str] | None = None,
    clock: Clock = _SYSTEM_CLOCK,
    powershell: str = POWERSHELL_EXE,
    zip_timeout_s: float = 1800.0,
) -> Manifest:
    """Collect the guest out directory (+ extra guest files) into ``host_job_dir/artifacts``.

    Invalid guest directories raise PathNotAllowed before anything runs. Every
    later failure (zip, copy, one extra path, extraction abort) is recorded in
    ``errors`` / entry statuses and makes ``partial`` True; a manifest is always
    written. ``module_map`` must be JSON-serializable (other values are
    stringified). The guest out.zip is left in place for a retry.
    """
    roots = [allowed_guest_roots] if isinstance(allowed_guest_roots, str) else list(allowed_guest_roots)
    out_dir = _ps_safe_dir(guest_out_dir, must_be_under=roots)
    job_dir = _ps_safe_dir(guest_job_dir, must_be_under=roots)
    zip_guest = _gjoin(job_dir, "out.zip")
    if _is_within(zip_guest, out_dir):
        raise PathNotAllowed("out.zip would be created inside the directory being zipped",
                             stage="validate", details={"reason": "zip-inside-out-dir"})

    job = Path(os.path.abspath(host_job_dir))
    art = job / "artifacts"
    raw = art / "raw"
    _make_private_dir(art)
    _make_private_dir(raw)
    errors: list[dict[str, Any]] = []
    out_entries: list[ManifestEntry] = []
    extra_entries: list[ManifestEntry] = []
    raw_zip: Path | None = None
    raw_sha: str | None = None
    raw_size: int | None = None

    # 1. zip the out dir in the guest and fetch the archive
    has_content = False
    try:
        if not channel.dir_exists(out_dir):
            errors.append(_error("out_dir", "GUEST_OP_FAILED", "guest out dir does not exist"))
        else:
            has_content = bool(channel.list_dir(out_dir))
    except GatewayError as exc:
        errors.append(_error("out_dir", exc.code, exc.message))
    if has_content:
        command = (f"Compress-Archive -Path '{out_dir.rstrip(chr(92))}\\*' "
                   f"-DestinationPath '{zip_guest}' -Force")
        try:
            rc = _ps(channel, powershell, command, zip_timeout_s)
        except GatewayError as exc:
            errors.append(_error("zip", exc.code, exc.message))
        else:
            if rc != 0:
                errors.append(_error("zip", TransferError.code, f"Compress-Archive exited with code {rc}"))
            else:
                try:
                    raw_sha, raw_size = _fetch(channel, zip_guest, raw / "out.zip")
                    raw_zip = raw / "out.zip"
                except GatewayError as exc:
                    errors.append(_error("fetch", exc.code, exc.message))
                except OSError as exc:
                    errors.append(_error("fetch", TransferError.code, f"host write failed: {exc.strerror}"))

    # 2. extra guest files, each validated against the allowed roots
    for index, guest_path in enumerate(extra_guest_paths):
        shown = _clip(str(guest_path))
        try:
            validated = validate_guest_path(guest_path, must_be_under=roots)
            stored = f"raw/extra/{index:04d}_{_sanitize_basename(PureWindowsPath(validated).name)}"
            _make_private_dir(raw / "extra")
            sha, size = _fetch(channel, validated, art / stored)
            extra_entries.append(ManifestEntry("extra", validated, stored, size, sha, "ok"))
        except GatewayError as exc:
            extra_entries.append(ManifestEntry("extra", shown, None, 0, None, f"failed:{exc.code}"))
        except OSError:
            extra_entries.append(ManifestEntry("extra", shown, None, 0, None, f"failed:{TransferError.code}"))

    # 3. extract (or just list) the archive
    extracted = False
    if raw_zip is not None:
        try:
            if extract:
                extracted = True
                files = art / "files"
                _reset_dir(files)
                members: list[ExtractedEntry] = []
                try:
                    _extract_into(raw_zip, files, limits, members)
                finally:
                    out_entries.extend(
                        ManifestEntry("out", m.original_name,
                                      None if m.stored_name is None else f"files/{m.stored_name}",
                                      m.size, m.sha256, m.status) for m in members)
            else:
                out_entries.extend(_list_archive(raw_zip))
        except GatewayError as exc:
            errors.append(_error("extract", exc.code, exc.message, exc.details))

    entries = out_entries + extra_entries
    partial = bool(errors) or any(e.status.startswith("failed:") for e in entries)
    manifest = Manifest(
        schema_version=MANIFEST_SCHEMA_VERSION,
        job_dir=str(job),
        collected_at=clock.now_iso(),
        guest_out_dir=out_dir,
        guest_job_dir=job_dir,
        raw_zip=None if raw_zip is None else "raw/out.zip",
        raw_zip_sha256=raw_sha,
        raw_zip_size=raw_size,
        extracted=extracted,
        partial=partial,
        entries=entries,
        errors=errors,
        module_map=_jsonable(module_map),
        screenshot=_screenshot_record(screenshot, job),
        manifest_path=str(art / MANIFEST_NAME),
    )
    _write_json_atomic(art / MANIFEST_NAME, manifest.to_dict())
    return manifest


# ── optional AES re-pack (Windows hosts, plan 6.3) ──────────────────
#: Conventional password for archives that hold malware; it is a marker, not a secret.
MALWARE_ARCHIVE_PASSWORD = "infected"  # noqa: S105


def encrypt_archive(src_zip: str | os.PathLike[str], dst_zip: str | os.PathLike[str],
                    password: str | Secret = MALWARE_ARCHIVE_PASSWORD, *,
                    limits: ExtractLimits = DEFAULT_EXTRACT_LIMITS) -> None:
    """Re-pack ``src_zip`` as an AES-256 encrypted zip at ``dst_zip`` (needs ``pyzipper``).

    Members are streamed (never fully in memory) and counted against
    ``limits.max_total_bytes`` / ``max_file_bytes`` so a bomb cannot fill the disk.
    The password is never logged or put into exception text.
    """
    try:
        import pyzipper  # type: ignore[import-not-found]
    except ImportError as exc:
        raise TransferError("AES archive support needs the optional 'pyzipper' package", stage="encrypt",
                            hint="install the 'aeszip' extra (uv sync --extra aeszip)") from exc
    secret = password.reveal() if isinstance(password, Secret) else password
    dst = Path(dst_zip)
    tmp = dst.with_name(f".{dst.name}.{secrets.token_hex(6)}.tmp")
    total = 0
    try:
        with _open_zip(Path(src_zip)) as zin, pyzipper.AESZipFile(
                tmp, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zout:
            zout.setpassword(secret.encode("utf-8"))
            for info in zin.infolist():
                if info.is_dir():
                    continue
                if info.file_size > limits.max_file_bytes:
                    raise UnsafeArchiveError("archive member too large to re-pack", stage="encrypt",
                                             details={"reason": "too-large"})
                written = 0
                with zin.open(info) as src, zout.open(info.filename, "w") as out:
                    while chunk := src.read(_COPY_CHUNK):
                        written += len(chunk)
                        total += len(chunk)
                        if written > limits.max_file_bytes or total > limits.max_total_bytes:
                            raise UnsafeArchiveError("archive exceeds the size limit while re-packing",
                                                     stage="encrypt", details={"reason": "total-bytes"})
                        out.write(chunk)
        _chmod(tmp, 0o600)
        os.replace(tmp, dst)
    except BaseException:
        _unlink_quiet(tmp)
        raise
