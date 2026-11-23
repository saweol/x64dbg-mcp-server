"""Sample upload, artifact collection and safe archive extraction (plan 5.3, 6.3).

Upload: ``<in>\\<sha12>.part`` -> guest-side SHA-256 written to a file and
copied back (runProgramInGuest returns no output) -> rename to
``<in>\\<sha12>.<exe|dll|bin>``.

Collect: zip the guest ``out`` directory (vmrun cannot copy directories) with
``Compress-Archive``, falling back to the built-in ``tar.exe`` and finally to
per-file copies; copy the zip and any extra guest files to the host job
directory with size limits (:class:`FetchLimits`: guest-side size probe, host
free-space reserve, post-copy size check), extract the zip with
:func:`safe_extract` and write ``artifacts/manifest.json`` atomically. The
output of an earlier collection waits in ``artifacts.prev/`` until the new
manifest is written. Host layout::

    <host_job_dir>/artifacts/
        manifest.json
        raw/out.zip                       original archive, kept as received
        raw/extra/NNNN_<sanitized-name>   extra guest files
        files/NNNN_<sha12>                extracted members or per-file copies
                                          (names only in the manifest)

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
from collections.abc import Iterable, Iterator, Sequence
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
from .guest import GUEST_ENV_ERRORS, POWERSHELL_EXE, fold_case, is_reserved_name, validate_guest_path
from .pe import sha256_file

__all__ = [
    "DEFAULT_EXTRACT_LIMITS",
    "DEFAULT_FETCH_LIMITS",
    "MANIFEST_SCHEMA_VERSION",
    "TAR_EXE",
    "ExtractLimits",
    "ExtractedEntry",
    "FetchLimits",
    "Manifest",
    "ManifestEntry",
    "collect_artifacts",
    "encrypt_archive",
    "safe_extract",
    "upload_sample",
]

MANIFEST_SCHEMA_VERSION = 1
MANIFEST_NAME = "manifest.json"

#: Built-in bsdtar of Windows 10 1803+ (no 2 GB limit, unlike Compress-Archive in PowerShell 5.1).
TAR_EXE = "C:\\Windows\\System32\\tar.exe"

_KiB = 1024
_MiB = 1024 * _KiB
_GiB = 1024 * _MiB
_COPY_CHUNK = _MiB
_HASH_FILE_MAX = 4 * _KiB  # a SHA-256 hex line is 66 bytes; anything larger is garbage
_SIZE_FILE_MAX = 256  # a decimal file length plus line ending (any encoding)
_PROBE_TIMEOUT_S = 120.0  # PowerShell start-up in a loaded guest can take several seconds
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
    """Round-trip through JSON so the manifest object equals what is written to disk.

    Never raises: a value JSON cannot hold is replaced by a clipped ``repr``.
    """
    try:
        return json.loads(json.dumps(value, default=str, allow_nan=False))
    except (TypeError, ValueError, RecursionError):
        return {"unserializable": _clip(repr(value))}


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
    p, r = fold_case(path), fold_case(root).rstrip("\\")
    return p == r or p.startswith(r + "\\")


def _delete_guest_if_exists(channel: GuestChannel, path: str) -> None:
    if channel.file_exists(path):
        channel.delete_file(path)


def _ps(channel: GuestChannel, powershell: str, command: str, timeout_s: float) -> int | None:
    return channel.run_program(powershell, [*_PS_PREFIX, command], wait=True, timeout_s=timeout_s)


def _exit_problem(rc: int | None) -> str:
    """Short diagnostic for a failed run_program result (it returns None without an exit code)."""
    return "no-exit-code" if rc is None else f"exit-code-{rc}"


def _exit_text(tool: str, rc: int | None) -> str:
    return f"{tool} returned no exit code" if rc is None else f"{tool} exited with code {rc}"


# ── upload ──────────────────────────────────────────────────────────
def _read_small_text(path: Path, limit: int) -> str | None:
    """Text of a small result file written by PowerShell (ASCII, UTF-8 BOM or UTF-16), stripped.

    None when the file is larger than ``limit`` bytes (only ``limit + 1`` bytes are read).
    """
    with path.open("rb") as f:
        data = f.read(limit + 1)
    if len(data) > limit:
        return None
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        text = data.decode("utf-16", errors="replace")
    else:
        if data.startswith(b"\xef\xbb\xbf"):
            data = data[3:]
        text = data.decode("ascii", errors="replace")
    return text.strip().strip("\ufeff").strip()


def _parse_hash_file(path: Path) -> str | None:
    text = _read_small_text(path, _HASH_FILE_MAX)
    return text.lower() if text is not None and _SHA256_RE.fullmatch(text) else None


def _guest_sha256(channel: GuestChannel, powershell: str, part: str, hash_path: str, local: Path,
                  timeout_s: float) -> tuple[str | None, str]:
    """Hash ``part`` in the guest.

    Returns ``(hash, "")`` or ``(None, problem)`` when the hash could not be produced
    or read back (``exit-code-N``, ``no-exit-code``, ``no-hash-file``,
    ``unreadable-hash-file``). A missing hash says nothing about the copied bytes,
    only about the guest tooling.
    """
    command = (f"(Get-FileHash -Algorithm SHA256 -LiteralPath '{part}').Hash"
               f" | Out-File -Encoding ascii -FilePath '{hash_path}'")
    rc = _ps(channel, powershell, command, timeout_s)
    if rc != 0:
        return None, _exit_problem(rc)
    _unlink_quiet(local)
    try:
        channel.copy_from_guest(hash_path, local)
    except VmrunError as exc:
        if isinstance(exc, GUEST_ENV_ERRORS):
            raise
        return None, "no-hash-file"  # hashing failed in the guest
    try:
        value = _parse_hash_file(local)
    except FileNotFoundError:
        return None, "no-hash-file"
    return (value, "") if value is not None else (None, "unreadable-hash-file")


def _cleanup_guest(channel: GuestChannel, *paths: str) -> None:
    """Best-effort removal of guest files after a failed upload; never raises a GatewayError."""
    for path in paths:
        with contextlib.suppress(GatewayError):
            _delete_guest_if_exists(channel, path)


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

    The host file is re-hashed first (it must still match ``sha256``). The sample
    is copied to ``<sha12>.part`` and hashed in the guest, up to ``max_attempts``
    rounds with a short back-off between them:

    - hash read back and different: the part is deleted and re-copied next round;
    - hash unavailable (PowerShell failed, no/garbled hash file): only the hash
      step is repeated, the part is not re-copied.

    A ``<sha12>.part`` left by an earlier, aborted upload is deleted before the
    first copy, and the hash file before every hash step.

    After the last round raises IntegrityError if any round read a different
    hash, otherwise TransferError (the guest could not hash the file at all). On
    success an existing final file is replaced. Guest/vmrun errors other than a
    missing hash file propagate unchanged (no retry); before they do, the part
    and hash files are removed best-effort unless the error means the guest is
    unreachable (``GUEST_ENV_ERRORS``). The replace step deletes the old final
    file before the rename, so a failed rename leaves neither file.
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
    mismatch_seen = False
    try:
        _delete_guest_if_exists(channel, part)  # never append to / trust a stale part
        with tempfile.TemporaryDirectory(prefix="x64gw-hash-") as td:
            local = Path(td) / "guest.sha256"
            need_copy = True
            for attempt in range(1, max_attempts + 1):
                if attempt > 1:
                    clock.sleep(min(2.0 ** (attempt - 2), 8.0))
                if need_copy:
                    channel.copy_to_guest(src, part)
                    need_copy = False
                _delete_guest_if_exists(channel, hash_path)  # never trust a stale result
                got, problem = _guest_sha256(channel, powershell, part, hash_path, local, hash_timeout_s)
                if got == expected:
                    if channel.file_exists(final):
                        channel.delete_file(final)
                    channel.rename(part, final)
                    _cleanup_guest(channel, hash_path)
                    return final
                if got is None:
                    observed.append(f"unavailable:{problem}")
                    continue  # tooling problem: re-run the hash step on the same part
                observed.append(got)
                mismatch_seen = True
                need_copy = True
                _delete_guest_if_exists(channel, part)
    except GatewayError as exc:
        if not isinstance(exc, GUEST_ENV_ERRORS):
            _cleanup_guest(channel, part, hash_path)
        raise

    _cleanup_guest(channel, part, hash_path)
    details = {"attempts": max_attempts, "expected": expected, "observed": observed}
    if mismatch_seen:
        raise IntegrityError(f"guest copy of {sha12} failed SHA-256 verification {max_attempts} time(s)",
                             stage="upload", details=details)
    raise TransferError(
        f"the guest could not compute the SHA-256 of {sha12} ({max_attempts} attempt(s))",
        stage="upload",
        hint=f"check that Windows PowerShell runs in the guest at {powershell} for the guest user "
             "(Get-FileHash needs PowerShell 4+); 'observed' holds the exit codes",
        details={**details, "powershell": powershell},
    )


# ── safe extraction ─────────────────────────────────────────────────
@dataclass(frozen=True)
class ExtractLimits:
    """Upper bounds for :func:`safe_extract`. Byte limits apply to bytes actually decompressed.

    - ``max_files``: archive members of every kind (files, directories, rejected
      entries); more aborts before anything is written.
    - ``max_total_bytes``: bytes decompressed over the whole archive, including
      members rejected part-way; exceeding it aborts.
    - ``max_file_bytes``: one member; a larger member is rejected (``too-large``).
    - ``max_ratio``: decompressed / compressed size of one member, checked once the
      member has produced more than ``ratio_min_bytes`` (small, highly compressible
      files are harmless). A violating member is rejected (``rejected:ratio``) and
      the rest of the archive is still extracted. This is a deliberate deviation
      from plan 5.3, which lists the ratio with the archive-wide caps: sparse memory
      dumps (large zero-filled regions) routinely compress better than 200:1, and
      aborting would also drop every log after such a dump. The byte budget of
      ``max_total_bytes`` still applies to what a rejected member decompressed.
      Raise ``max_ratio`` to keep such dumps (they stay in the raw archive either way).

    The compressed size a member declares is only trusted after checking that it
    does not overlap the next member or the central directory (``overlap``).
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
    """One archive member; ``original_name`` is the raw name stored in the archive (separators
    untouched). ``size`` is the extracted byte count for ``ok`` entries and the
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
    if "." in components:
        return "dot-component"
    for comp in components:
        if comp[-1] in ". ":
            return "trailing-dot-space"
        if is_reserved_name(comp):
            return "reserved-name"
    return None


def _dup_key(name: str) -> str:
    return fold_case("/".join(c for c in name.replace("\\", "/").split("/") if c))


def _is_dir_entry(info: zipfile.ZipInfo) -> bool:
    """Directory member, also with the ``\\`` separator Windows PowerShell 5.1 writes.

    ``ZipInfo.is_dir`` only recognises ``\\`` on hosts whose ``os.altsep`` is ``/``.
    """
    return info.is_dir() or info.filename.replace("\\", "/").endswith("/")


def _overlapping_members(infos: Sequence[zipfile.ZipInfo], start_dir: int) -> frozenset[int]:
    """Indexes of members whose declared compressed data runs into the next local header.

    A member's data starts after its local header, so in a well-formed archive
    ``header_offset + compress_size`` never exceeds the next member's header
    offset (or the start of the central directory). Overlapping members are the
    building block of zip bombs (CVE-2024-0450) and would also let a member
    inflate its ``compress_size`` to dodge the ratio check. zipfile detects this
    itself only from Python 3.11.8 / 3.12.2 on, so it is checked here as well.
    """
    order = sorted(range(len(infos)), key=lambda i: infos[i].header_offset)
    bad: set[int] = set()
    for pos, i in enumerate(order):
        end = infos[order[pos + 1]].header_offset if pos + 1 < len(order) else start_dir
        if infos[i].header_offset + infos[i].compress_size > end:
            bad.add(i)
    return frozenset(bad)


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
    ``max_total_bytes`` so a stream of corrupt or over-ratio members cannot reset
    the budget. ``info.compress_size`` has already been checked for overlap.
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
                        raise _EntryRejected("ratio")
                    digest.update(chunk)
                    out.write(chunk)
            out.flush()
            os.fsync(out.fileno())
        sha = digest.hexdigest()
        stored = f"{index:04d}_{sha[:12]}"
        final = dest / stored
        os.replace(tmp, final)  # replaces a pre-existing link itself, never its target
        if not _within(str(final), dest_real):
            _unlink_quiet(final)
            return ExtractedEntry(info.filename, None, written, None, "rejected:escape"), written
        return ExtractedEntry(info.filename, stored, written, sha, "ok"), written
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


def _require_empty_dir(dest: Path) -> None:
    """Raise TransferError ``dest-not-empty`` unless ``dest`` is missing or empty."""
    try:
        it = os.scandir(dest)
    except FileNotFoundError:
        return
    with it:
        if next(it, None) is not None:
            raise TransferError("extraction directory is not empty", stage="extract",
                                details={"reason": "dest-not-empty", "path": str(dest)})


def _strip_dot(name: str) -> str:
    """Drop the single leading ``./`` that ``tar -C <dir> .`` puts in front of every member name."""
    if len(name) > 2 and name[0] == "." and name[1] in "/\\":
        return name[2:]
    return name


def _member_path(name: str, strip_dot_prefix: bool = False) -> str:
    """Member name as recorded in the manifest: ``/`` separators, tar's ``./`` prefix removed."""
    path = name.replace("\\", "/")
    return _strip_dot(path) if strip_dot_prefix else path


def _extract_into(zip_path: Path, dest: Path, limits: ExtractLimits, out: list[ExtractedEntry], *,
                  strip_dot_prefix: bool = False) -> None:
    """Extract into ``dest`` (absent or empty), appending one entry per member to ``out``.

    ``out`` keeps the entries finished before an UnsafeArchiveError abort; the
    abort also records their number in ``details["entries_done"]``. With
    ``strip_dot_prefix`` (archives written by ``tar -C <dir> .``) one leading
    ``./`` is removed before the name checks and the bare ``./`` root member is a
    skipped directory; any further ``.`` component is still rejected.
    """
    with _open_zip(zip_path) as zf:
        infos = zf.infolist()
        if len(infos) > limits.max_files:
            raise UnsafeArchiveError("archive has too many members", stage="extract",
                                     details={"reason": "file-count", "files": len(infos),
                                              "limit": limits.max_files})
        _require_empty_dir(dest)  # before touching it: a foreign directory keeps its mode
        _make_private_dir(dest)
        dest_real = os.path.realpath(dest)
        archive_size = zip_path.stat().st_size
        overlapping = _overlapping_members(infos, getattr(zf, "start_dir", archive_size))
        seen: set[str] = set()
        total = 0
        try:
            for index, info in enumerate(infos):
                name = info.filename
                if strip_dot_prefix and name.replace("\\", "/") == "./":
                    out.append(ExtractedEntry(name, None, 0, None, "skipped:directory"))
                    continue
                checked = _strip_dot(name) if strip_dot_prefix else name
                reason = _name_problem(checked)
                key = _dup_key(checked)
                if reason is None and key in seen:
                    reason = "duplicate"
                seen.add(key)
                if reason is None and _is_link(info):
                    reason = "symlink"
                if reason is None and _is_dir_entry(info):
                    out.append(ExtractedEntry(name, None, 0, None, "skipped:directory"))
                    continue
                if reason is None and index in overlapping:
                    reason = "overlap"
                if reason is None and info.flag_bits & _ZIP_FLAG_ENCRYPTED:
                    reason = "encrypted"
                if reason is None and info.file_size > limits.max_file_bytes:
                    reason = "too-large"
                if reason is not None:
                    out.append(ExtractedEntry(name, None, info.file_size, None, f"rejected:{reason}"))
                    continue
                entry, consumed = _extract_member(zf, info, index, dest, dest_real, limits, total,
                                                  archive_size)
                total += consumed
                out.append(entry)
        except UnsafeArchiveError as exc:
            exc.details.setdefault("entries_done", len(out))
            raise


def safe_extract(zip_path: str | os.PathLike[str], dest_dir: str | os.PathLike[str],
                 limits: ExtractLimits = DEFAULT_EXTRACT_LIMITS, *,
                 entries_out: list[ExtractedEntry] | None = None) -> list[ExtractedEntry]:
    """Extract ``zip_path`` into the flat directory ``dest_dir`` without trusting the archive.

    ``dest_dir`` must not exist or be empty (TransferError ``dest-not-empty``
    otherwise), so every file in it belongs to this extraction. Members are
    stored as ``NNNN_<sha12>`` (NNNN = member index); original names only appear
    in the returned entries (``original_name`` is the raw member name). Unsafe
    members are skipped with status ``rejected:<reason>`` (absolute, drive, unc,
    traversal, dot-component, ads, reserved-name, trailing-dot-space,
    invalid-char, duplicate, symlink, overlap, encrypted, too-large, ratio,
    corrupt, unsupported-compression). Duplicates are names that differ only by
    per-character case (:func:`guest.fold_case`). A member over ``max_ratio`` is
    only rejected, not an abort: a deliberate deviation from plan 5.3 so that
    sparse memory dumps do not cost the rest of the archive (see
    :class:`ExtractLimits`). Exceeding the member count or the total size aborts
    with UnsafeArchiveError after removing the partial output of the current
    member; earlier members stay on disk. Pass
    ``entries_out`` to keep their entries: it is filled as members finish and
    is the list returned on success. A file that is not a readable zip raises
    TransferError.
    """
    entries: list[ExtractedEntry] = [] if entries_out is None else entries_out
    _extract_into(Path(zip_path), Path(dest_dir), limits, entries)
    return entries


# ── collection ──────────────────────────────────────────────────────
@dataclass(frozen=True)
class FetchLimits:
    """Bounds for guest -> host copies in :func:`collect_artifacts` (out.zip and extra files).

    ``max_file_bytes``: largest file kept on the host. ``min_host_free_bytes``: free
    space that must remain on the host file system once the copy has landed.
    """

    max_file_bytes: int = 4 * _GiB
    min_host_free_bytes: int = 1 * _GiB

    def __post_init__(self) -> None:
        if self.max_file_bytes < 0 or self.min_host_free_bytes < 0:
            raise ValueError("fetch limits must be non-negative")


DEFAULT_FETCH_LIMITS = FetchLimits()


@dataclass(frozen=True)
class ManifestEntry:
    """``source``: ``out`` (a file or directory of the guest out dir; ``original_path`` is
    its path relative to the out dir with ``/`` separators, directories end in ``/``)
    or ``extra`` (guest file copied on its own, ``original_path`` is the validated
    guest path). Archive member names are normalised here (``\\`` -> ``/``, the
    ``./`` prefix of tar.exe removed); :class:`ExtractedEntry` keeps the raw name.
    ``stored_name`` is relative to ``<host_job_dir>/artifacts`` with ``/``
    separators. ``status``: ``ok`` | ``archived`` (kept in raw/out.zip, not
    extracted) | ``skipped:<why>`` | ``rejected:<reason>`` | ``failed:<error code>``."""

    source: str
    original_path: str
    stored_name: str | None
    size: int
    sha256: str | None
    status: str


@dataclass
class Manifest:
    """What :func:`collect_artifacts` collected; :meth:`to_dict` is the ``manifest.json`` document.

    ``archive_method`` says how the out dir reached the host: ``compress-archive``
    or ``tar`` (guest-side zip kept as ``raw_zip``), ``copy`` (per-file copies
    straight into ``files/``), or None (empty or missing out dir, or no method
    worked). ``archive_attempts`` lists every method tried, in order, as
    ``{"method", "status": "ok" | "failed", "error"?}``; a failed method followed
    by one that worked does not make the manifest ``partial``. ``extracted`` is
    True when ``files/`` holds the out-dir files (extracted archive or copies).
    """

    schema_version: int
    job_dir: str
    collected_at: str
    guest_out_dir: str
    guest_job_dir: str
    raw_zip: str | None
    raw_zip_sha256: str | None
    raw_zip_size: int | None
    archive_method: str | None
    archive_attempts: list[dict[str, Any]]
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
            "archive_method": self.archive_method,
            "archive_attempts": [dict(a) for a in self.archive_attempts],
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


def _module_map_json(value: Any) -> Any:
    """``value`` as it will appear in manifest.json; raises TransferError if JSON cannot hold it.

    Values json cannot encode (paths, sets, ...) are stringified and tuples become
    lists; non-string keys of other types, reference cycles and NaN/Infinity raise.
    """
    try:
        return json.loads(json.dumps(value, default=str, allow_nan=False))
    except (TypeError, ValueError, RecursionError) as exc:
        raise TransferError("module_map is not JSON-serializable", stage="validate",
                            details={"reason": "module-map-not-json", "error": type(exc).__name__}) from exc


def _remove_path(path: Path) -> None:
    """Remove a file, symlink or directory tree (never following a link); missing is fine."""
    if path.is_symlink() or (path.exists() and not path.is_dir()):
        _unlink_quiet(path)
    elif path.is_dir():
        shutil.rmtree(path)


#: What one collection writes under ``artifacts/`` (the manifest last). Anything else
#: there (e.g. a screenshot the caller saved) is not touched.
_OWNED = ("files", "raw/out.zip", "raw/extra", MANIFEST_NAME)


def _stash_dirs(art: Path) -> tuple[Path, Path]:
    """``artifacts.prev`` (complete stash of the previous output) and ``artifacts.prev.tmp``."""
    return art.with_name(art.name + ".prev"), art.with_name(art.name + ".prev.tmp")


def _move_owned(src_root: Path, dst_root: Path) -> None:
    for rel in _OWNED:
        src = src_root / rel
        if os.path.lexists(src):
            dst = dst_root / rel
            _make_private_dir(dst.parent)
            _remove_path(dst)
            os.replace(src, dst)


def _remove_owned(root: Path) -> None:
    for rel in (*_OWNED, "raw/out.zip.part"):
        _remove_path(root / rel)


def _recover_previous(art: Path) -> None:
    """Bring ``art`` back to one consistent collection after an interrupted run.

    ``artifacts.prev.tmp`` is a stash that was being filled or emptied: its items
    go back into ``art``. ``artifacts.prev`` is a complete stash: if ``art`` holds
    a manifest the newer collection was committed and the stash is dropped;
    otherwise the uncommitted output is removed and the stash goes back. Every
    step is a rename or a removal, so a run killed during recovery is recovered
    by the next call.
    """
    prev, staging = _stash_dirs(art)
    if os.path.lexists(staging):
        _move_owned(staging, art)
        _remove_path(staging)
    if not os.path.lexists(prev):
        return
    if (art / MANIFEST_NAME).is_file():
        _remove_path(prev)
        return
    _remove_owned(art)
    os.replace(prev, staging)
    _move_owned(staging, art)
    _remove_path(staging)


def _stash_previous(art: Path) -> None:
    """Move the output of an earlier collection to ``artifacts.prev`` (kept until the new manifest)."""
    _recover_previous(art)
    _remove_path(art / "raw" / "out.zip.part")
    if not any(os.path.lexists(art / rel) for rel in _OWNED):
        return
    prev, staging = _stash_dirs(art)
    _make_private_dir(staging)
    _move_owned(art, staging)
    os.replace(staging, prev)


def _restore_previous(art: Path) -> None:
    """Undo a collection that failed before its manifest was written."""
    _remove_owned(art)
    _recover_previous(art)


def _drop_previous(art: Path) -> None:
    with contextlib.suppress(OSError):
        _remove_path(_stash_dirs(art)[0])


def _host_free_bytes(path: Path) -> int:
    return shutil.disk_usage(path).free


def _read_size_file(path: Path) -> int | None:
    text = _read_small_text(path, _SIZE_FILE_MAX)
    return int(text) if text is not None and text.isascii() and text.isdigit() else None


class _BoundedFetch:
    """Guest -> host copies with size limits, for one :func:`collect_artifacts` call.

    vmrun cannot stop a copy part-way, so the size is bounded three ways:

    1. a guest-side size probe (``Get-Item ... .Length`` written to a file in the
       guest job dir and copied back) refuses files over ``max_file_bytes``
       before copying them. The guest controls this answer, so it only stops
       honest large files early; when it is unavailable the copy goes ahead;
    2. the host must keep ``min_host_free_bytes`` free after the probed size;
    3. what actually arrived is measured and deleted when over the limit.

    A guest that grows a file after the probe can still use host disk space up to
    the free space during the copy; step 3 removes the result. Not thread-safe:
    use one instance per call (it owns a scratch directory).
    """

    def __init__(self, channel: GuestChannel, powershell: str, guest_job_dir: str, limits: FetchLimits,
                 scratch: Path) -> None:
        self._channel = channel
        self._powershell = powershell
        self._job_dir = guest_job_dir
        self._limits = limits
        self._scratch = scratch

    def _too_large(self, size: int, **extra: Any) -> TransferError:
        return TransferError("guest file exceeds the fetch size limit", stage="fetch",
                             details={"reason": "too-large", "size": size,
                                      "limit": self._limits.max_file_bytes, **extra})

    def _check_free(self, directory: Path, incoming: int) -> None:
        free = _host_free_bytes(directory)
        needed = self._limits.min_host_free_bytes + incoming
        if free < needed:
            raise TransferError("not enough free host disk space for the guest file", stage="fetch",
                                details={"reason": "host-disk-space", "free": free, "needed": needed})

    def probe_size(self, guest_path: str) -> int | None:
        """Size the guest reports for ``guest_path``; None if the probe did not work."""
        result = _gjoin(self._job_dir, f".x64gw-size-{secrets.token_hex(6)}.txt")
        command = (f"(Get-Item -LiteralPath '{guest_path}' -Force).Length"
                   f" | Out-File -Encoding ascii -FilePath '{result}'")
        local = self._scratch / "size.txt"
        size: int | None = None
        try:
            if _ps(self._channel, self._powershell, command, _PROBE_TIMEOUT_S) == 0:
                _unlink_quiet(local)
                self._channel.copy_from_guest(result, local)
                size = _read_size_file(local)
        except GatewayError as exc:
            if isinstance(exc, GUEST_ENV_ERRORS):
                raise
        finally:
            _unlink_quiet(local)
        with contextlib.suppress(GatewayError):
            self._channel.delete_file(result)
        return size

    def fetch(self, guest_path: str, dst: Path) -> tuple[str, int]:
        """Copy a guest file to ``dst`` via ``dst.part`` + rename; returns (sha256, size).

        Raises TransferError (``details["reason"]``: ``too-large`` / ``host-disk-space``),
        guest errors from the channel, or OSError for host file-system failures.
        """
        self._check_free(dst.parent, 0)
        probed = self.probe_size(guest_path)
        if probed is not None and probed > self._limits.max_file_bytes:
            raise self._too_large(probed)
        self._check_free(dst.parent, probed or 0)
        part = dst.with_name(dst.name + ".part")
        _unlink_quiet(part)
        try:
            self._channel.copy_from_guest(guest_path, part)
            got = part.stat().st_size
            if got > self._limits.max_file_bytes:
                raise self._too_large(got, probed=probed)
            _chmod(part, 0o600)
            os.replace(part, dst)
        except BaseException:
            _unlink_quiet(part)
            raise
        return sha256_file(dst), dst.stat().st_size


def _screenshot_record(screenshot: str | os.PathLike[str] | None, job: Path) -> dict[str, Any] | None:
    """Manifest record for the screenshot: sha256/size, or ``status`` missing / error."""
    if screenshot is None:
        return None
    sp = Path(screenshot)
    shown = str(sp)
    with contextlib.suppress(ValueError, OSError):
        shown = sp.resolve().relative_to(job.resolve()).as_posix()
    try:
        if not sp.is_file():
            return {"path": shown, "status": "missing"}
        return {"path": shown, "sha256": sha256_file(sp), "size": sp.stat().st_size}
    except OSError as exc:
        return {"path": shown, "status": "error", "error": _clip(str(exc.strerror or exc))}


def _list_archive(zip_path: Path, strip_dot_prefix: bool = False) -> list[ManifestEntry]:
    with _open_zip(zip_path) as zf:
        return [ManifestEntry("out", _member_path(i.filename, strip_dot_prefix), None, i.file_size, None,
                              "skipped:directory" if _is_dir_entry(i) else "archived")
                for i in zf.infolist()]


def _gateway_details(exc: GatewayError) -> dict[str, Any] | None:
    # Only this module's own errors: vmrun error details carry argv/stdout noise.
    return exc.details if isinstance(exc, TransferError) else None


def _make_guest_archive(channel: GuestChannel, method: str, out_dir: str, zip_guest: str, powershell: str,
                        tar: str, timeout_s: float) -> tuple[dict[str, Any] | None, bool]:
    """Zip ``out_dir`` into ``zip_guest`` with ``method``; returns (error or None, guest unreachable)."""
    stage = "zip" if method == "compress-archive" else "tar"
    try:
        if method == "compress-archive":
            tool = "Compress-Archive"
            command = (f"Compress-Archive -Path '{out_dir.rstrip(chr(92))}\\*' "
                       f"-DestinationPath '{zip_guest}' -Force")
            rc = _ps(channel, powershell, command, timeout_s)
        else:
            tool = "tar.exe"
            # Whatever a failed earlier attempt left behind must never pass for tar's archive.
            _delete_guest_if_exists(channel, zip_guest)
            rc = channel.run_program(tar, ["-a", "-c", "-f", zip_guest, "-C", out_dir, "."], wait=True,
                                     timeout_s=timeout_s)
    except GatewayError as exc:
        return _error(stage, exc.code, exc.message, _gateway_details(exc)), isinstance(exc, GUEST_ENV_ERRORS)
    if rc != 0:
        return _error(stage, TransferError.code, _exit_text(tool, rc)), False
    return None, False


def _copy_out_tree(channel: GuestChannel, fetcher: _BoundedFetch, out_dir: str, top_names: list[str],
                   files: Path, limits: ExtractLimits, entries: list[ManifestEntry],
                   errors: list[dict[str, Any]]) -> None:
    """Last-resort fallback: copy each file under ``out_dir`` to ``files/NNNN_<sha12>``.

    The tree is walked with list_dir / dir_exists (depth first, names sorted) and
    every guest path must validate under ``out_dir`` (lexically). Each file goes
    through ``fetcher`` (its FetchLimits). As for an extracted archive,
    ``limits.max_files`` bounds the entries (files and directories) and
    ``limits.max_total_bytes`` the bytes kept: the file that crosses the budget is
    removed (``rejected:total-bytes``) and the walk stops. Other failures are
    recorded per entry (``failed:<code>``) and in ``errors`` (stage ``copy``); a
    guest environment error stops the walk. The guest resolves junctions and
    symbolic links the lexical check cannot see (as Compress-Archive does); a
    junction loop ends at ``max_files`` or at MAX_PATH (``too-long`` paths fail).
    """
    stack: list[tuple[str, str, Iterator[str]]] = [("", out_dir, iter(sorted(top_names)))]
    index = total = 0
    while stack:
        rel_dir, guest_dir, names = stack[-1]
        name = next(names, None)
        if name is None:
            stack.pop()
            continue
        if name in (".", ".."):
            continue
        if index >= limits.max_files:
            errors.append(_error("copy", TransferError.code, "out dir has too many entries",
                                 {"reason": "file-count", "limit": limits.max_files}))
            return
        rel = rel_dir + name
        tmp = files / f".{index:04d}.fetch"
        try:
            guest = validate_guest_path(_gjoin(guest_dir, name), must_be_under=out_dir)
            if channel.dir_exists(guest):
                children = channel.list_dir(guest)
                entries.append(ManifestEntry("out", rel + "/", None, 0, None, "skipped:directory"))
                stack.append((rel + "/", guest, iter(sorted(children))))
                continue
            sha, size = fetcher.fetch(guest, tmp)
            if total + size > limits.max_total_bytes:
                entries.append(ManifestEntry("out", rel, None, size, None, "rejected:total-bytes"))
                errors.append(_error("copy", TransferError.code, "out dir exceeds the total size limit",
                                     {"reason": "total-bytes", "path": rel, "limit": limits.max_total_bytes}))
                return
            total += size
            stored = f"{index:04d}_{sha[:12]}"
            os.replace(tmp, files / stored)
            entries.append(ManifestEntry("out", rel, f"files/{stored}", size, sha, "ok"))
        except GatewayError as exc:
            entries.append(ManifestEntry("out", rel, None, 0, None, f"failed:{exc.code}"))
            errors.append(_error("copy", exc.code, exc.message,
                                 {**(_gateway_details(exc) or {}), "path": rel}))
            if isinstance(exc, GUEST_ENV_ERRORS):
                return
        except OSError as exc:
            entries.append(ManifestEntry("out", rel, None, 0, None, f"failed:{TransferError.code}"))
            errors.append(_error("copy", TransferError.code, f"host write failed: {exc.strerror or exc}",
                                 {"path": rel}))
        finally:
            _unlink_quiet(tmp)
            index += 1


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
    tar: str = TAR_EXE,
    zip_timeout_s: float = 1800.0,
    fetch_limits: FetchLimits = DEFAULT_FETCH_LIMITS,
) -> Manifest:
    """Collect the guest out directory (+ extra guest files) into ``host_job_dir/artifacts``.

    Before any guest work: invalid guest directories raise PathNotAllowed, a
    ``module_map`` that JSON cannot hold raises TransferError (values json cannot
    encode are stringified), and host directory problems raise TransferError.

    The out dir reaches the host by the first method that works
    (``Manifest.archive_method``; every try is in ``archive_attempts``):

    1. ``Compress-Archive`` into ``<guest_job_dir>\\out.zip`` (PowerShell 5.1 fails
       on files over 2 GB and on files another process holds open);
    2. ``<tar> -a -c -f <zip> -C <out> .`` (built-in bsdtar, Windows 10 1803+, no
       2 GB limit); the ``./`` prefix it gives every member is removed from the
       recorded names;
    3. per-file copies of the out tree straight into ``files/`` (see
       ``_copy_out_tree``: ``fetch_limits`` per file, ``limits`` for the tree).
       Skipped when ``extract`` is False, because it would leave loose guest
       files on the host.

    An archive that was created but cannot be fetched (too large, copy error)
    goes straight to step 3. A guest environment error (VM, Tools, credentials)
    ends the chain. Guest -> host copies are bounded by ``fetch_limits`` (see
    :class:`_BoundedFetch`). The guest out.zip is left in place for a retry.

    The output of an earlier collection of the same job (manifest, files/,
    raw/out.zip, raw/extra/) is moved to ``<host_job_dir>/artifacts.prev`` before
    any guest work and deleted once the new manifest is written, so what is on
    disk always matches the manifest; if this call raises, the earlier output is
    put back (a run that was killed part-way is repaired by the next call).
    Other files in ``artifacts/`` are left alone. Every failure after that point
    (archiving, copies, size limits, one extra path, extraction abort, host I/O,
    screenshot) is recorded in ``errors`` / entry statuses and makes ``partial``
    True; the manifest is then always written (a failure to write it raises
    TransferError).

    ``allowed_guest_roots`` is a lexical check (see validate_guest_path): a
    junction or symlink the guest created under an allowed root can still point
    elsewhere in the guest.
    """
    roots = [allowed_guest_roots] if isinstance(allowed_guest_roots, str) else list(allowed_guest_roots)
    out_dir = _ps_safe_dir(guest_out_dir, must_be_under=roots)
    job_dir = _ps_safe_dir(guest_job_dir, must_be_under=roots)
    zip_guest = _gjoin(job_dir, "out.zip")
    if _is_within(zip_guest, out_dir):
        raise PathNotAllowed("out.zip would be created inside the directory being zipped",
                             stage="validate", details={"reason": "zip-inside-out-dir"})
    module_map_doc = _module_map_json(module_map)

    job = Path(os.path.abspath(host_job_dir))
    art = job / "artifacts"
    try:
        _make_private_dir(art)  # refuses a symlinked directory before anything is moved
        _stash_previous(art)
        _make_private_dir(art / "raw")
    except OSError as exc:
        if art.is_dir() and not art.is_symlink():
            with contextlib.suppress(OSError, GatewayError):
                _recover_previous(art)
        raise TransferError(f"cannot prepare the host artifacts directory: {exc.strerror or exc}",
                            stage="host_fs", details={"path": str(art)}) from exc
    try:
        manifest = _collect_into(
            channel, out_dir=out_dir, job_dir=job_dir, zip_guest=zip_guest, roots=roots, job=job, art=art,
            extra_guest_paths=extra_guest_paths, limits=limits, extract=extract,
            module_map_doc=module_map_doc, screenshot=screenshot, clock=clock, powershell=powershell,
            tar=tar, zip_timeout_s=zip_timeout_s, fetch_limits=fetch_limits)
    except BaseException:
        with contextlib.suppress(OSError, GatewayError):
            _restore_previous(art)
        raise
    _drop_previous(art)
    return manifest


def _collect_into(channel: GuestChannel, *, out_dir: str, job_dir: str, zip_guest: str, roots: list[str],
                  job: Path, art: Path, extra_guest_paths: Iterable[str], limits: ExtractLimits,
                  extract: bool, module_map_doc: Any, screenshot: str | os.PathLike[str] | None,
                  clock: Clock, powershell: str, tar: str, zip_timeout_s: float,
                  fetch_limits: FetchLimits) -> Manifest:
    """Body of :func:`collect_artifacts` once the host directories are ready."""
    raw = art / "raw"
    files = art / "files"
    errors: list[dict[str, Any]] = []
    out_entries: list[ManifestEntry] = []
    extra_entries: list[ManifestEntry] = []
    attempts: list[dict[str, Any]] = []
    method: str | None = None
    extracted = False
    raw_zip: Path | None = None
    raw_sha: str | None = None
    raw_size: int | None = None

    with tempfile.TemporaryDirectory(prefix="x64gw-probe-") as scratch:
        fetcher = _BoundedFetch(channel, powershell, job_dir, fetch_limits, Path(scratch))

        # 1. the out dir: guest-side zip (Compress-Archive, then tar.exe) or per-file copies
        top_names: list[str] = []
        try:
            if not channel.dir_exists(out_dir):
                errors.append(_error("out_dir", "GUEST_OP_FAILED", "guest out dir does not exist"))
            else:
                top_names = channel.list_dir(out_dir)
        except GatewayError as exc:
            errors.append(_error("out_dir", exc.code, exc.message))
        guest_down = False
        if top_names:
            for archiver in ("compress-archive", "tar"):
                failure, guest_down = _make_guest_archive(channel, archiver, out_dir, zip_guest, powershell,
                                                          tar, zip_timeout_s)
                if failure is None:
                    try:
                        raw_sha, raw_size = fetcher.fetch(zip_guest, raw / "out.zip")
                    except GatewayError as exc:
                        failure = _error("fetch", exc.code, exc.message, _gateway_details(exc))
                        guest_down = isinstance(exc, GUEST_ENV_ERRORS)
                    except OSError as exc:
                        failure = _error("fetch", TransferError.code,
                                         f"host write failed: {exc.strerror or exc}")
                    else:
                        raw_zip, method = raw / "out.zip", archiver
                        attempts.append({"method": archiver, "status": "ok"})
                        break
                attempts.append({"method": archiver, "status": "failed", "error": failure})
                if guest_down or failure["stage"] == "fetch":
                    break  # an archive that exists but cannot be fetched would not fare better from tar
            if method is None and not guest_down:
                copy_error: dict[str, Any] | None = None
                if not extract:
                    copy_error = _error("copy", TransferError.code,
                                        "per-file copies need extract=True "
                                        "(they would leave loose guest files on the host)",
                                        {"reason": "copy-needs-extract"})
                else:
                    try:
                        _make_private_dir(files)
                    except OSError as exc:
                        copy_error = _error("copy", TransferError.code,
                                            f"host file system error: {exc.strerror or exc}")
                if copy_error is not None:
                    attempts.append({"method": "copy", "status": "failed", "error": copy_error})
                else:
                    copy_limits = FetchLimits(
                        max_file_bytes=min(fetch_limits.max_file_bytes, limits.max_file_bytes),
                        min_host_free_bytes=fetch_limits.min_host_free_bytes)
                    copier = _BoundedFetch(channel, powershell, job_dir, copy_limits, Path(scratch))
                    _copy_out_tree(channel, copier, out_dir, top_names, files, limits, out_entries, errors)
                    method, extracted = "copy", True
                    attempts.append({"method": "copy", "status": "ok"})
            if method is None:
                errors.extend(a["error"] for a in attempts)

        # 2. extra guest files, each validated against the allowed roots
        for index, guest_path in enumerate(extra_guest_paths):
            shown = _clip(str(guest_path))
            try:
                validated = validate_guest_path(guest_path, must_be_under=roots)
                stored = f"raw/extra/{index:04d}_{_sanitize_basename(PureWindowsPath(validated).name)}"
                _make_private_dir(raw / "extra")
                sha, size = fetcher.fetch(validated, art / stored)
                extra_entries.append(ManifestEntry("extra", validated, stored, size, sha, "ok"))
            except GatewayError as exc:
                extra_entries.append(ManifestEntry("extra", shown, None, 0, None, f"failed:{exc.code}"))
                errors.append(_error("extra", exc.code, exc.message,
                                     {**(_gateway_details(exc) or {}), "index": index}))
            except OSError as exc:
                extra_entries.append(ManifestEntry("extra", shown, None, 0, None,
                                                   f"failed:{TransferError.code}"))
                errors.append(_error("extra", TransferError.code, f"host write failed: {exc.strerror or exc}",
                                     {"index": index}))

    # 3. extract (or just list) the archive
    if raw_zip is not None:
        strip = method == "tar"
        try:
            if extract:
                extracted = True
                _reset_dir(files)
                members: list[ExtractedEntry] = []
                try:
                    _extract_into(raw_zip, files, limits, members, strip_dot_prefix=strip)
                finally:
                    out_entries.extend(
                        ManifestEntry("out", _member_path(m.original_name, strip),
                                      None if m.stored_name is None else f"files/{m.stored_name}",
                                      m.size, m.sha256, m.status) for m in members)
            else:
                out_entries.extend(_list_archive(raw_zip, strip))
        except GatewayError as exc:
            errors.append(_error("extract", exc.code, exc.message, exc.details))
        except OSError as exc:
            errors.append(_error("extract", TransferError.code,
                                 f"host file system error while extracting: {exc.strerror or exc}"))

    shot = _screenshot_record(screenshot, job)
    if shot is not None and shot.get("status") == "error":
        errors.append(_error("screenshot", TransferError.code,
                             f"cannot read the screenshot: {shot['error']}"))

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
        archive_method=method,
        archive_attempts=attempts,
        extracted=extracted,
        partial=partial,
        entries=entries,
        errors=errors,
        module_map=module_map_doc,
        screenshot=shot,
        manifest_path=str(art / MANIFEST_NAME),
    )
    try:
        _write_json_atomic(art / MANIFEST_NAME, manifest.to_dict())
    except OSError as exc:
        raise TransferError(f"cannot write the manifest: {exc.strerror or exc}", stage="manifest",
                            details={"path": manifest.manifest_path}) from exc
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
                if _is_dir_entry(info):
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
