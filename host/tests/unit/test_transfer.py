"""Tests for upload / safe extraction / artifact collection.

Every archive here is built in-test from synthetic bytes. Hostile archives
(zip-slip, ADS, reserved names, symlinks, bombs, lying headers) are crafted
with ``zipfile.ZipInfo`` and, where needed, by patching header fields.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import re
import stat
import struct
import zipfile
from pathlib import Path, PureWindowsPath

import pytest

from tests.fakes.fake_guest import FakeGuest
from x64dbg_vm_gateway.errors import (
    GuestOperationError,
    IntegrityError,
    PathNotAllowed,
    TransferError,
    UnsafeArchiveError,
)
from x64dbg_vm_gateway.transfer import (
    DEFAULT_EXTRACT_LIMITS,
    ExtractedEntry,
    ExtractLimits,
    Manifest,
    collect_artifacts,
    encrypt_archive,
    safe_extract,
    upload_sample,
)

POSIX = os.name == "posix"
PS_PREFIX = ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command"]
IN_DIR = "C:\\mcp\\jobs\\j1\\in"
JOB_DIR = "C:\\mcp\\jobs\\j1"
OUT_DIR = "C:\\mcp\\jobs\\j1\\out"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ── fake guest-side PowerShell ──────────────────────────────────────
_HASH_RE = re.compile(r"-LiteralPath '([^']+)'\)\.Hash \| Out-File -Encoding ascii -FilePath '([^']+)'$")
_ZIP_RE = re.compile(r"^Compress-Archive -Path '([^']+)\\\*' -DestinationPath '([^']+)' -Force$")


class GuestPowerShell:
    """Emulates the two PowerShell one-liners the transfer module runs in the guest."""

    def __init__(self, guest: FakeGuest) -> None:
        self.guest = guest
        self.hash_results: list[str | None] = []  # queued overrides; None = do not write the file
        self.exit_codes: list[int] = []
        self.hash_encoding = "ascii"
        self.commands: list[str] = []

    def __call__(self, exe: str, args: tuple, **_kw) -> int:
        assert exe.lower().endswith("\\powershell.exe")
        assert list(args[:5]) == PS_PREFIX and len(args) == 6
        cmd = args[5]
        self.commands.append(cmd)
        code = self.exit_codes.pop(0) if self.exit_codes else 0
        if m := _HASH_RE.search(cmd):
            assert cmd.startswith("(Get-FileHash -Algorithm SHA256 -LiteralPath '")
            src, dst = m.groups()
            override = self.hash_results.pop(0) if self.hash_results else "real"
            if override is None:
                return code
            digest = _sha(self.guest.read(src)).upper() if override == "real" else override
            if self.hash_encoding == "utf8-bom":
                body = b"\xef\xbb\xbf" + digest.lower().encode() + b"  \r\n"
            elif self.hash_encoding == "utf16":
                body = (digest + "\r\n").encode("utf-16")
            else:
                body = (digest + "\r\n").encode("ascii")
            self.guest.write(dst, body)
            return code
        if m := _ZIP_RE.match(cmd):
            src_dir, dst = m.groups()
            if code != 0:
                return code
            prefix = str(PureWindowsPath(src_dir)).lower() + "\\"
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                for key, data in sorted(self.guest.files.items()):
                    if key.startswith(prefix):
                        zf.writestr(key[len(prefix):].replace("\\", "/"), data)
            self.guest.write(dst, buf.getvalue())
            return code
        raise AssertionError(f"unexpected PowerShell command: {cmd}")


@pytest.fixture
def ps(fake_guest) -> GuestPowerShell:
    p = GuestPowerShell(fake_guest)
    fake_guest.on_run_program = p
    return p


@pytest.fixture
def sample(tmp_path) -> tuple[Path, bytes, str]:
    data = b"MZ" + bytes(range(256)) * 40
    p = tmp_path / "sample.exe"
    p.write_bytes(data)
    return p, data, _sha(data)


# ── upload_sample ───────────────────────────────────────────────────
def test_upload_sample_happy_path(fake_guest, ps, sample, fake_clock):
    path, data, sha = sample
    final = upload_sample(fake_guest, path, IN_DIR, sha256=sha, kind="exe", clock=fake_clock)
    assert final == f"{IN_DIR}\\{sha[:12]}.exe"
    assert fake_guest.read(final) == data
    assert not fake_guest.file_exists(f"{IN_DIR}\\{sha[:12]}.part")
    assert not fake_guest.file_exists(f"{IN_DIR}\\{sha[:12]}.sha256")
    assert fake_guest.calls_of("mkdir")[0][0] == (IN_DIR,)
    (copy_args, _), = fake_guest.calls_of("copy_to_guest")
    assert copy_args[1] == f"{IN_DIR}\\{sha[:12]}.part"
    assert ps.commands == [
        f"(Get-FileHash -Algorithm SHA256 -LiteralPath '{IN_DIR}\\{sha[:12]}.part').Hash"
        f" | Out-File -Encoding ascii -FilePath '{IN_DIR}\\{sha[:12]}.sha256'"
    ]
    (_, kw), = fake_guest.calls_of("run_program")
    assert kw["wait"] is True
    assert fake_clock.sleeps == []


@pytest.mark.parametrize(
    ("kind", "ext"),
    [("exe", "exe"), ("dotnet-exe", "exe"), ("dll", "dll"), ("dotnet-dll", "dll"), ("non-pe", "bin"),
     ("weird", "bin")],
)
def test_upload_sample_extension_by_kind(fake_guest, ps, sample, kind, ext):
    path, _, sha = sample
    assert upload_sample(fake_guest, path, IN_DIR, sha256=sha, kind=kind).endswith(f"\\{sha[:12]}.{ext}")


def test_upload_sample_accepts_uppercase_sha(fake_guest, ps, sample):
    path, _, sha = sample
    assert upload_sample(fake_guest, path, IN_DIR, sha256=sha.upper(), kind="exe").endswith(
        f"\\{sha[:12]}.exe")


@pytest.mark.parametrize("enc", ["utf8-bom", "utf16"])
def test_upload_sample_hash_file_bom_and_case(fake_guest, ps, sample, enc):
    path, _, sha = sample
    ps.hash_encoding = enc
    assert upload_sample(fake_guest, path, IN_DIR, sha256=sha, kind="exe").endswith(".exe")


def test_upload_sample_retries_on_mismatch(fake_guest, ps, sample, fake_clock):
    path, data, sha = sample
    ps.hash_results = ["0" * 64]
    final = upload_sample(fake_guest, path, IN_DIR, sha256=sha, kind="dll", clock=fake_clock)
    assert fake_guest.read(final) == data
    assert len(fake_guest.calls_of("copy_to_guest")) == 2
    deleted = [a[0] for a, _ in fake_guest.calls_of("delete_file")]
    assert f"{IN_DIR}\\{sha[:12]}.part" in deleted
    assert len(fake_clock.sleeps) == 1 and fake_clock.sleeps[0] > 0


def test_upload_sample_gives_up_after_max_attempts(fake_guest, ps, sample, fake_clock):
    path, _, sha = sample
    ps.hash_results = ["f" * 64] * 3
    with pytest.raises(IntegrityError) as ei:
        upload_sample(fake_guest, path, IN_DIR, sha256=sha, kind="exe", clock=fake_clock)
    assert ei.value.code == "INTEGRITY_MISMATCH"
    assert ei.value.details["attempts"] == 3
    assert len(fake_guest.calls_of("run_program")) == 3
    assert not fake_guest.file_exists(f"{IN_DIR}\\{sha[:12]}.part")
    assert not fake_guest.file_exists(f"{IN_DIR}\\{sha[:12]}.exe")
    assert len(fake_clock.sleeps) == 2


def test_upload_sample_max_attempts_one(fake_guest, ps, sample, fake_clock):
    path, _, sha = sample
    ps.hash_results = ["f" * 64]
    with pytest.raises(IntegrityError):
        upload_sample(fake_guest, path, IN_DIR, sha256=sha, kind="exe", clock=fake_clock, max_attempts=1)
    assert len(fake_guest.calls_of("copy_to_guest")) == 1
    assert fake_clock.sleeps == []


def test_upload_sample_does_not_trust_stale_hash_file(fake_guest, ps, sample, fake_clock):
    """A correct .sha256 left over from earlier must not validate a copy whose hashing failed."""
    path, _, sha = sample
    fake_guest.write(f"{IN_DIR}\\{sha[:12]}.sha256", sha.upper().encode() + b"\r\n")
    ps.hash_results = [None, None, None]  # PowerShell "succeeds" but writes nothing
    with pytest.raises(IntegrityError):
        upload_sample(fake_guest, path, IN_DIR, sha256=sha, kind="exe", clock=fake_clock)


def test_upload_sample_powershell_failure_counts_as_attempt(fake_guest, ps, sample, fake_clock):
    path, data, sha = sample
    ps.exit_codes = [1]
    final = upload_sample(fake_guest, path, IN_DIR, sha256=sha, kind="exe", clock=fake_clock)
    assert fake_guest.read(final) == data
    assert len(fake_guest.calls_of("run_program")) == 2


def test_upload_sample_garbage_hash_file_is_a_mismatch(fake_guest, ps, sample, fake_clock):
    path, _, sha = sample
    ps.hash_results = ["not-a-hash", "x" * 5000, "real"]
    assert upload_sample(fake_guest, path, IN_DIR, sha256=sha, kind="exe", clock=fake_clock)


def test_upload_sample_replaces_existing_final(fake_guest, ps, sample):
    path, data, sha = sample
    fake_guest.write(f"{IN_DIR}\\{sha[:12]}.exe", b"old junk")
    final = upload_sample(fake_guest, path, IN_DIR, sha256=sha, kind="exe")
    assert fake_guest.read(final) == data


def test_upload_sample_host_hash_mismatch_fails_before_copy(fake_guest, ps, sample):
    path, _, _ = sample
    with pytest.raises(IntegrityError):
        upload_sample(fake_guest, path, IN_DIR, sha256="a" * 64, kind="exe")
    assert fake_guest.calls_of("copy_to_guest") == []


@pytest.mark.parametrize("bad", ["", "abc", "g" * 64, "a" * 63, "a" * 65])
def test_upload_sample_rejects_malformed_sha(fake_guest, ps, sample, bad):
    path, _, _ = sample
    with pytest.raises(TransferError):
        upload_sample(fake_guest, path, IN_DIR, sha256=bad, kind="exe")
    assert fake_guest.calls == []


@pytest.mark.parametrize("bad_dir", ["C:\\mcp\\jobs\\j'1\\in", "in", "C:\\a\\..\\b", "C:\\a[1]\\in",
                                     "C:\\a`b\\in"])
def test_upload_sample_rejects_unsafe_guest_dir(fake_guest, ps, sample, bad_dir):
    path, _, sha = sample
    with pytest.raises(PathNotAllowed):
        upload_sample(fake_guest, path, bad_dir, sha256=sha, kind="exe")
    assert fake_guest.calls == []


def test_upload_sample_missing_host_file(fake_guest, ps, tmp_path):
    with pytest.raises(TransferError):
        upload_sample(fake_guest, tmp_path / "nope.exe", IN_DIR, sha256="a" * 64, kind="exe")


def test_upload_sample_copy_error_propagates(fake_guest, ps, sample, fake_clock):
    path, _, sha = sample
    fake_guest.fail_next("copy_to_guest", GuestOperationError("Error: disk full"))
    with pytest.raises(GuestOperationError):
        upload_sample(fake_guest, path, IN_DIR, sha256=sha, kind="exe", clock=fake_clock)


def test_upload_sample_rejects_bad_max_attempts(fake_guest, ps, sample):
    path, _, sha = sample
    with pytest.raises(ValueError):
        upload_sample(fake_guest, path, IN_DIR, sha256=sha, kind="exe", max_attempts=0)


# ── zip helpers ─────────────────────────────────────────────────────
def make_zip(path: Path, entries: list[tuple[str | zipfile.ZipInfo, bytes]],
             compression: int = zipfile.ZIP_DEFLATED) -> Path:
    with zipfile.ZipFile(path, "w", compression) as zf:
        for name, data in entries:
            if isinstance(name, zipfile.ZipInfo):
                zf.writestr(name, data)
            else:
                zf.writestr(zipfile.ZipInfo(name), data, compress_type=compression)
    return path


def _unix_info(name: str, mode: int) -> zipfile.ZipInfo:
    zi = zipfile.ZipInfo(name)
    zi.create_system = 3
    zi.external_attr = (mode & 0xFFFF) << 16
    return zi


def _listing(dest: Path) -> set[str]:
    return {p.name for p in dest.iterdir()} if dest.exists() else set()


def _assert_mode(p: Path, mode: int) -> None:
    if POSIX:
        assert stat.S_IMODE(p.stat().st_mode) == mode, oct(p.stat().st_mode)


# ── safe_extract ────────────────────────────────────────────────────
def test_extract_limits_defaults():
    lim = ExtractLimits()
    assert lim == DEFAULT_EXTRACT_LIMITS
    assert (lim.max_files, lim.max_total_bytes, lim.max_file_bytes, lim.max_ratio) == \
        (10000, 4 * 1024**3, 2 * 1024**3, 200)


def test_safe_extract_happy_path(tmp_path):
    a, b, c = b"alpha" * 10, os.urandom(3000), b"log line\n" * 50
    z = make_zip(tmp_path / "o.zip", [("a.txt", a), ("dir/b.bin", b), ("dir\\c.log", c)])
    dest = tmp_path / "files"
    entries = safe_extract(z, dest, ExtractLimits())
    assert [e.original_name for e in entries] == ["a.txt", "dir/b.bin", "dir\\c.log"]
    assert all(isinstance(e, ExtractedEntry) and e.status == "ok" for e in entries)
    for i, (e, data) in enumerate(zip(entries, (a, b, c), strict=True)):
        assert e.stored_name == f"{i:04d}_{_sha(data)[:12]}"
        assert e.size == len(data) and e.sha256 == _sha(data)
        assert (dest / e.stored_name).read_bytes() == data
        _assert_mode(dest / e.stored_name, 0o600)
    _assert_mode(dest, 0o700)
    assert _listing(dest) == {e.stored_name for e in entries}


def test_safe_extract_never_executable(tmp_path):
    z = make_zip(tmp_path / "o.zip", [(_unix_info("run.sh", stat.S_IFREG | 0o4777), b"#!/bin/sh\n")])
    (e,) = safe_extract(z, tmp_path / "d", ExtractLimits())
    assert e.status == "ok"
    _assert_mode(tmp_path / "d" / e.stored_name, 0o600)


def test_safe_extract_skips_directory_entries(tmp_path):
    z = make_zip(tmp_path / "o.zip", [("sub/", b""), ("sub/x.txt", b"x")])
    entries = safe_extract(z, tmp_path / "d", ExtractLimits())
    assert [e.status for e in entries] == ["skipped:directory", "ok"]
    assert len(_listing(tmp_path / "d")) == 1


@pytest.mark.parametrize(
    ("name", "reason"),
    [
        ("/etc/passwd", "absolute"),
        ("\\windows\\x", "absolute"),
        ("C:/x.txt", "drive"),
        ("c:x.txt", "drive"),
        ("\\\\srv\\share\\x", "unc"),
        ("//srv/share/x", "unc"),
        ("../x", "traversal"),
        ("a/../../x", "traversal"),
        ("a\\..\\..\\x", "traversal"),
        ("a/b.txt:evil", "ads"),
        ("a/b.txt::$DATA", "ads"),
        ("CON", "reserved-name"),
        ("dir/nul.txt", "reserved-name"),
        ("com1.log", "reserved-name"),
        ("x.", "trailing-dot-space"),
        ("x ", "trailing-dot-space"),
        ("dir./x", "trailing-dot-space"),
        ("./x", "trailing-dot-space"),
        ("a\x01b", "invalid-char"),
        ("a\nb", "invalid-char"),
    ],
)
def test_safe_extract_rejects_bad_names(tmp_path, name, reason):
    z = make_zip(tmp_path / "o.zip", [(name, b"evil"), ("good.txt", b"good")])
    dest = tmp_path / "d"
    bad, good = safe_extract(z, dest, ExtractLimits())
    assert bad.status == f"rejected:{reason}", bad
    assert bad.stored_name is None and bad.sha256 is None
    assert good.status == "ok"
    assert _listing(dest) == {good.stored_name}
    assert not (tmp_path / "x").exists() and not (tmp_path / "x.txt").exists()


def test_safe_extract_rejects_case_insensitive_duplicates(tmp_path):
    z = make_zip(tmp_path / "o.zip", [("Readme.txt", b"1"), ("README.TXT", b"2"), ("dir/A", b"3"),
                                      ("DIR\\a", b"4")])
    entries = safe_extract(z, tmp_path / "d", ExtractLimits())
    assert [e.status for e in entries] == ["ok", "rejected:duplicate", "ok", "rejected:duplicate"]


def test_safe_extract_rejects_unix_symlink(tmp_path):
    z = make_zip(tmp_path / "o.zip", [(_unix_info("link", stat.S_IFLNK | 0o777), b"/etc/passwd"),
                                      ("ok.txt", b"ok")])
    link, ok = safe_extract(z, tmp_path / "d", ExtractLimits())
    assert link.status == "rejected:symlink"
    assert ok.status == "ok"
    assert len(_listing(tmp_path / "d")) == 1


def test_safe_extract_rejects_windows_reparse_point(tmp_path):
    zi = zipfile.ZipInfo("junction")
    zi.create_system = 0
    zi.external_attr = 0x400 | 0x10  # FILE_ATTRIBUTE_REPARSE_POINT | DIRECTORY
    z = make_zip(tmp_path / "o.zip", [(zi, b"C:\\Windows")])
    (e,) = safe_extract(z, tmp_path / "d", ExtractLimits())
    assert e.status == "rejected:symlink"


def test_safe_extract_rejects_encrypted_entry(tmp_path):
    # zipfile clears flag_bits on write, so set the "encrypted" bit afterwards.
    z = make_zip(tmp_path / "o.zip", [("enc.bin", b"ciphertext?"), ("ok", b"1")])
    _patch_header(z, "enc.bin", flag_or=0x1)
    with zipfile.ZipFile(z) as zf:
        assert zf.getinfo("enc.bin").flag_bits & 0x1
    enc, ok = safe_extract(z, tmp_path / "d", ExtractLimits())
    assert enc.status == "rejected:encrypted" and ok.status == "ok"


def test_safe_extract_too_many_files_aborts_before_writing(tmp_path):
    z = make_zip(tmp_path / "o.zip", [(f"f{i}", b"x") for i in range(6)])
    dest = tmp_path / "d"
    with pytest.raises(UnsafeArchiveError) as ei:
        safe_extract(z, dest, ExtractLimits(max_files=5))
    assert ei.value.code == "UNSAFE_ARCHIVE"
    assert _listing(dest) == set()


def test_safe_extract_total_bytes_abort_removes_partial(tmp_path):
    a, b = os.urandom(600), os.urandom(600)
    z = make_zip(tmp_path / "o.zip", [("a", a), ("b", b)])
    dest = tmp_path / "d"
    with pytest.raises(UnsafeArchiveError) as ei:
        safe_extract(z, dest, ExtractLimits(max_total_bytes=1000))
    assert ei.value.details["reason"] == "total-bytes"
    assert _listing(dest) == {f"0000_{_sha(a)[:12]}"}  # first entry kept, partial second removed


def test_safe_extract_per_file_limit_rejects_entry_only(tmp_path):
    big, small = os.urandom(200), b"small"
    z = make_zip(tmp_path / "o.zip", [("big", big), ("small", small)])
    dest = tmp_path / "d"
    e_big, e_small = safe_extract(z, dest, ExtractLimits(max_file_bytes=100))
    assert e_big.status == "rejected:too-large" and e_big.stored_name is None
    assert e_small.status == "ok"
    assert _listing(dest) == {e_small.stored_name}


def test_safe_extract_ratio_bomb_aborts(tmp_path):
    z = make_zip(tmp_path / "o.zip", [("bomb.bin", b"\0" * (4 * 1024 * 1024))])
    dest = tmp_path / "d"
    with pytest.raises(UnsafeArchiveError) as ei:
        safe_extract(z, dest, ExtractLimits())
    assert ei.value.details["reason"] == "ratio"
    assert _listing(dest) == set()


def test_safe_extract_small_compressible_file_is_fine(tmp_path):
    z = make_zip(tmp_path / "o.zip", [("zeros.bin", b"\0" * 64 * 1024)])
    (e,) = safe_extract(z, tmp_path / "d", ExtractLimits())
    assert e.status == "ok"


def _patch_header(path: Path, member: str, *, uncompressed: int | None = None, flag_or: int = 0) -> None:
    """Rewrite header fields of ``member`` in both the local and the central directory header.

    Local header: flags @6, uncompressed size @22. Central header: flags @8,
    uncompressed size @24, name length @28, name @46.
    """
    raw = bytearray(path.read_bytes())
    with zipfile.ZipFile(path) as zf:
        lh = zf.getinfo(member).header_offset
    assert raw[lh:lh + 4] == b"PK\x03\x04"
    if uncompressed is not None:
        struct.pack_into("<I", raw, lh + 22, uncompressed)
    raw[lh + 6] |= flag_or
    cd = raw.find(b"PK\x01\x02")
    while cd != -1:
        name_len = struct.unpack_from("<H", raw, cd + 28)[0]
        if bytes(raw[cd + 46:cd + 46 + name_len]) == member.encode():
            if uncompressed is not None:
                struct.pack_into("<I", raw, cd + 24, uncompressed)
            raw[cd + 8] |= flag_or
            break
        cd = raw.find(b"PK\x01\x02", cd + 4)
    else:
        raise AssertionError(f"central directory entry not found: {member}")
    path.write_bytes(bytes(raw))


def _patch_sizes(path: Path, member: str, *, uncompressed: int) -> None:
    _patch_header(path, member, uncompressed=uncompressed)


def test_safe_extract_does_not_trust_small_declared_size(tmp_path):
    real = os.urandom(5000)
    z = make_zip(tmp_path / "o.zip", [("liar.bin", real), ("ok", b"ok")])
    _patch_sizes(z, "liar.bin", uncompressed=10)
    dest = tmp_path / "d"
    liar, ok = safe_extract(z, dest, ExtractLimits(max_file_bytes=100))
    assert liar.status.startswith("rejected:")
    assert liar.status != "ok"
    assert ok.status == "ok"
    for p in dest.iterdir():
        assert p.stat().st_size <= 100


def test_safe_extract_huge_declared_size_is_rejected(tmp_path):
    z = make_zip(tmp_path / "o.zip", [("claims-huge.bin", b"tiny")])
    _patch_sizes(z, "claims-huge.bin", uncompressed=0xFFFFFFF0)
    (e,) = safe_extract(z, tmp_path / "d", ExtractLimits(max_file_bytes=1000))
    assert e.status == "rejected:too-large"


def test_safe_extract_corrupt_entry_is_rejected_and_removed(tmp_path):
    data = os.urandom(4000)
    z = make_zip(tmp_path / "o.zip", [("c.bin", data), ("ok", b"ok")], compression=zipfile.ZIP_STORED)
    raw = bytearray(z.read_bytes())
    pos = raw.find(data[:32])
    raw[pos + 100] ^= 0xFF  # corrupt the stored payload -> CRC mismatch
    z.write_bytes(bytes(raw))
    dest = tmp_path / "d"
    c, ok = safe_extract(z, dest, ExtractLimits())
    assert c.status == "rejected:corrupt"
    assert ok.status == "ok"
    assert _listing(dest) == {ok.stored_name}


def _corrupt_stored_zip(path: Path, blobs: list[bytes], n_corrupt: int) -> Path:
    z = make_zip(path, [(f"m{i}", b) for i, b in enumerate(blobs)], compression=zipfile.ZIP_STORED)
    raw = bytearray(z.read_bytes())
    for blob in blobs[:n_corrupt]:
        raw[raw.find(blob[:32]) + 300] ^= 0xFF  # CRC mismatch, detected only after the full read
    z.write_bytes(bytes(raw))
    return z


def test_safe_extract_counts_bytes_of_rejected_members(tmp_path):
    blobs = [os.urandom(600) for _ in range(3)]
    z = _corrupt_stored_zip(tmp_path / "o.zip", blobs, n_corrupt=2)
    statuses = [e.status for e in safe_extract(z, tmp_path / "ok", ExtractLimits(max_total_bytes=5000))]
    assert statuses == ["rejected:corrupt", "rejected:corrupt", "ok"]
    # Corrupt members still consumed decompression budget: 600 + 600 > 1000.
    with pytest.raises(UnsafeArchiveError) as ei:
        safe_extract(z, tmp_path / "tight", ExtractLimits(max_total_bytes=1000))
    assert ei.value.details["reason"] == "total-bytes"


def test_safe_extract_not_a_zip(tmp_path):
    p = tmp_path / "o.zip"
    p.write_bytes(b"this is not a zip")
    with pytest.raises(TransferError) as ei:
        safe_extract(p, tmp_path / "d", ExtractLimits())
    assert ei.value.code == "TRANSFER_FAILED"


def test_safe_extract_empty_zip(tmp_path):
    z = make_zip(tmp_path / "o.zip", [])
    assert safe_extract(z, tmp_path / "d", ExtractLimits()) == []
    assert (tmp_path / "d").is_dir()


@pytest.mark.skipif(not POSIX, reason="symlink creation needs POSIX privileges")
def test_safe_extract_replaces_preplanted_symlink_without_following(tmp_path):
    data = b"payload"
    z = make_zip(tmp_path / "o.zip", [("x", data)])
    dest = tmp_path / "d"
    dest.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"untouched")
    (dest / f"0000_{_sha(data)[:12]}").symlink_to(outside)
    (e,) = safe_extract(z, dest, ExtractLimits())
    assert e.status == "ok"
    assert outside.read_bytes() == b"untouched"
    stored = dest / e.stored_name
    assert not stored.is_symlink() and stored.read_bytes() == data


def test_safe_extract_leaves_no_temp_files(tmp_path):
    z = make_zip(tmp_path / "o.zip", [("a", b"1"), ("../b", b"2"), ("c", os.urandom(300))])
    dest = tmp_path / "d"
    safe_extract(z, dest, ExtractLimits(max_file_bytes=100))
    assert all(re.fullmatch(r"\d{4}_[0-9a-f]{12}", n) for n in _listing(dest))


# ── collect_artifacts ───────────────────────────────────────────────
def _seed_out(guest: FakeGuest, files: dict[str, bytes]) -> None:
    guest.mkdir(OUT_DIR)
    for name, data in files.items():
        guest.write(f"{OUT_DIR}\\{name}", data)


def _collect(guest, tmp_path, clock, **kw) -> Manifest:
    args = {
        "guest_out_dir": OUT_DIR,
        "guest_job_dir": JOB_DIR,
        "host_job_dir": tmp_path / "job",
        "allowed_guest_roots": [JOB_DIR],
        "clock": clock,
    }
    args.update(kw)
    return collect_artifacts(guest, **args)


def _load_manifest(tmp_path) -> dict:
    return json.loads((tmp_path / "job" / "artifacts" / "manifest.json").read_text(encoding="utf-8"))


def test_collect_happy_path(fake_guest, ps, tmp_path, fake_clock):
    dump, log = os.urandom(2048), b"log\n" * 10
    _seed_out(fake_guest, {"dump.bin": dump, "logs\\x64dbg.log": log})
    mm = [{"name": "sample.exe", "base": "0x140000000", "size": 4096}]
    shot = tmp_path / "shot.png"
    shot.write_bytes(b"\x89PNG fake")
    m = _collect(fake_guest, tmp_path, fake_clock, module_map=mm, screenshot=shot)

    art = tmp_path / "job" / "artifacts"
    raw_zip = art / "raw" / "out.zip"
    assert raw_zip.is_file()
    assert m.raw_zip_sha256 == _sha(raw_zip.read_bytes())
    assert not m.partial and m.errors == []
    assert m.collected_at == fake_clock.now_iso()
    ok = {e.original_path: e for e in m.entries if e.status == "ok"}
    assert set(ok) == {"dump.bin", "logs/x64dbg.log"}
    assert (art / ok["dump.bin"].stored_name).read_bytes() == dump
    assert ok["dump.bin"].stored_name.startswith("files/")
    assert ok["dump.bin"].sha256 == _sha(dump) and ok["dump.bin"].size == len(dump)
    assert all(e.source == "out" for e in m.entries)

    assert ps.commands == [
        f"Compress-Archive -Path '{OUT_DIR}\\*' -DestinationPath '{JOB_DIR}\\out.zip' -Force"
    ]

    doc = _load_manifest(tmp_path)
    assert doc == m.to_dict()
    for key in ("schema_version", "job_dir", "collected_at", "entries", "module_map", "screenshot",
                "raw_zip_sha256", "partial"):
        assert key in doc
    assert doc["module_map"] == mm
    assert doc["screenshot"]["sha256"] == _sha(b"\x89PNG fake")
    assert doc["job_dir"] == str(tmp_path / "job")
    assert {"original_path", "stored_name", "size", "sha256", "status"} <= set(doc["entries"][0])
    assert m.manifest_path == str(art / "manifest.json")
    _assert_mode(art / "manifest.json", 0o600)
    _assert_mode(raw_zip, 0o600)
    for d in (art, art / "raw", art / "files"):
        _assert_mode(d, 0o700)
    assert [p.name for p in art.iterdir() if p.name.startswith(".") or p.suffix == ".tmp"] == []


def test_collect_empty_out_dir(fake_guest, ps, tmp_path, fake_clock):
    fake_guest.mkdir(OUT_DIR)
    m = _collect(fake_guest, tmp_path, fake_clock)
    assert m.entries == [] and not m.partial
    assert m.raw_zip_sha256 is None
    assert fake_guest.calls_of("run_program") == []
    doc = _load_manifest(tmp_path)
    assert doc["entries"] == [] and doc["raw_zip_sha256"] is None


def test_collect_missing_out_dir_is_partial(fake_guest, ps, tmp_path, fake_clock):
    m = _collect(fake_guest, tmp_path, fake_clock)
    assert m.partial and m.entries == []
    assert m.errors and m.errors[0]["stage"] == "out_dir"
    assert _load_manifest(tmp_path)["partial"] is True


def test_collect_extras_and_partial_failures(fake_guest, ps, tmp_path, fake_clock):
    _seed_out(fake_guest, {"a.txt": b"a"})
    fake_guest.write(f"{JOB_DIR}\\extra\\mem dump;1.bin", b"extra-bytes")
    extras = [
        f"{JOB_DIR}\\extra\\mem dump;1.bin",
        "C:\\Windows\\System32\\config\\SAM",  # outside allowed roots
        f"{JOB_DIR}\\missing.bin",  # guest copy fails
        "C:\\a\\..\\b",  # invalid path
    ]
    m = _collect(fake_guest, tmp_path, fake_clock, extra_guest_paths=extras)
    ex = [e for e in m.entries if e.source == "extra"]
    assert [e.status for e in ex] == ["ok", "failed:PATH_NOT_ALLOWED", "failed:GUEST_OP_FAILED",
                                      "failed:PATH_NOT_ALLOWED"]
    assert ex[0].stored_name == "raw/extra/0000_mem_dump_1.bin"
    art = tmp_path / "job" / "artifacts"
    assert (art / ex[0].stored_name).read_bytes() == b"extra-bytes"
    _assert_mode(art / ex[0].stored_name, 0o600)
    assert ex[0].sha256 == _sha(b"extra-bytes") and ex[0].original_path == extras[0]
    assert m.partial is True
    assert any(e.status == "ok" and e.source == "out" for e in m.entries)
    assert _load_manifest(tmp_path)["partial"] is True
    # the rejected guest path never reached the guest channel
    copied = [a[0] for a, _ in fake_guest.calls_of("copy_from_guest")]
    assert "C:\\Windows\\System32\\config\\SAM" not in copied


@pytest.mark.parametrize(
    ("raw", "stored"),
    [("..", "0000_file"), ("....", "0000_file"), ("a" * 200 + ".bin", "0000_" + "a" * 60 + ".bin"),
     ("x.exe", "0000_x.exe")],
)
def test_collect_extra_name_sanitizing(raw, stored):
    from x64dbg_vm_gateway.transfer import _sanitize_basename

    assert "0000_" + _sanitize_basename(raw) == stored


def test_collect_without_extract_lists_archive(fake_guest, ps, tmp_path, fake_clock):
    _seed_out(fake_guest, {"a.txt": b"a", "b.bin": b"bb"})
    m = _collect(fake_guest, tmp_path, fake_clock, extract=False)
    assert {e.status for e in m.entries} == {"archived"}
    assert {e.original_path for e in m.entries} == {"a.txt", "b.bin"}
    assert all(e.stored_name is None for e in m.entries)
    assert not (tmp_path / "job" / "artifacts" / "files").exists()
    assert m.extracted is False and m.raw_zip_sha256


def test_collect_zip_bomb_is_recorded_not_raised(fake_guest, ps, tmp_path, fake_clock):
    _seed_out(fake_guest, {"bomb.bin": b"\0" * (4 * 1024 * 1024)})
    m = _collect(fake_guest, tmp_path, fake_clock)
    assert m.partial
    assert any(err["code"] == "UNSAFE_ARCHIVE" for err in m.errors)
    assert (tmp_path / "job" / "artifacts" / "raw" / "out.zip").is_file()  # raw zip preserved


def test_collect_compress_failure_is_partial(fake_guest, ps, tmp_path, fake_clock):
    _seed_out(fake_guest, {"a.txt": b"a"})
    fake_guest.write(f"{JOB_DIR}\\x.log", b"x")
    ps.exit_codes = [1]
    m = _collect(fake_guest, tmp_path, fake_clock, extra_guest_paths=[f"{JOB_DIR}\\x.log"])
    assert m.partial and m.raw_zip_sha256 is None
    assert any(err["stage"] == "zip" for err in m.errors)
    assert [e.status for e in m.entries if e.source == "extra"] == ["ok"]


def test_collect_zip_copy_failure_is_partial(fake_guest, ps, tmp_path, fake_clock):
    _seed_out(fake_guest, {"a.txt": b"a"})
    fake_guest.fail_next("copy_from_guest", GuestOperationError("Error: copy failed"))
    m = _collect(fake_guest, tmp_path, fake_clock)
    assert m.partial and m.raw_zip_sha256 is None
    assert not list((tmp_path / "job" / "artifacts" / "raw").glob("*.part"))


def test_collect_retry_replaces_previous_extraction(fake_guest, ps, tmp_path, fake_clock):
    _seed_out(fake_guest, {"a.txt": b"first"})
    _collect(fake_guest, tmp_path, fake_clock)
    fake_guest.files.clear()
    _seed_out(fake_guest, {"b.txt": b"second"})
    m = _collect(fake_guest, tmp_path, fake_clock)
    files = tmp_path / "job" / "artifacts" / "files"
    assert _listing(files) == {e.stored_name.split("/", 1)[1] for e in m.entries if e.status == "ok"}
    assert len(_listing(files)) == 1


@pytest.mark.parametrize(
    "kw",
    [
        {"guest_out_dir": "C:\\elsewhere\\out"},
        {"guest_out_dir": "C:\\mcp\\jobs\\j1\\..\\out"},
        {"guest_job_dir": "C:\\mcp\\jobs\\j'1"},
        {"guest_out_dir": JOB_DIR},  # out.zip would land inside the zipped directory
        {"guest_out_dir": "C:\\mcp\\jobs\\j1\\o[ut]"},
    ],
)
def test_collect_rejects_bad_guest_dirs(fake_guest, ps, tmp_path, fake_clock, kw):
    with pytest.raises(PathNotAllowed):
        _collect(fake_guest, tmp_path, fake_clock, **kw)
    assert fake_guest.calls_of("run_program") == []


def test_collect_records_missing_screenshot(fake_guest, ps, tmp_path, fake_clock):
    fake_guest.mkdir(OUT_DIR)
    m = _collect(fake_guest, tmp_path, fake_clock, screenshot=tmp_path / "nope.png")
    assert m.screenshot["status"] == "missing"


# ── encrypt_archive (optional, needs pyzipper) ──────────────────────
HAVE_PYZIPPER = importlib.util.find_spec("pyzipper") is not None


@pytest.mark.skipif(not HAVE_PYZIPPER, reason="pyzipper not installed (extra 'aeszip')")
def test_encrypt_archive_roundtrip(tmp_path):
    import pyzipper

    src = make_zip(tmp_path / "src.zip", [("a.bin", os.urandom(5000)), ("d/b.txt", b"hello")])
    dst = tmp_path / "enc.zip"
    encrypt_archive(src, dst)
    with zipfile.ZipFile(src) as plain, pyzipper.AESZipFile(dst) as enc:
        enc.setpassword(b"infected")
        assert sorted(enc.namelist()) == sorted(plain.namelist())
        for n in plain.namelist():
            assert enc.read(n) == plain.read(n)
            assert enc.getinfo(n).flag_bits & 0x1
    with zipfile.ZipFile(dst) as zf, pytest.raises(Exception):  # noqa: B017 - any failure without key
        zf.read("a.bin")


@pytest.mark.skipif(HAVE_PYZIPPER, reason="only meaningful without pyzipper")
def test_encrypt_archive_without_pyzipper_raises(tmp_path):
    src = make_zip(tmp_path / "src.zip", [("a", b"1")])
    with pytest.raises(TransferError) as ei:
        encrypt_archive(src, tmp_path / "enc.zip")
    assert "aeszip" in (ei.value.hint or "")


@pytest.mark.skipif(not HAVE_PYZIPPER, reason="pyzipper not installed (extra 'aeszip')")
def test_encrypt_archive_secret_password_and_limits(tmp_path):
    import pyzipper

    from x64dbg_vm_gateway.contracts import Secret

    src = make_zip(tmp_path / "src.zip", [("a.bin", b"A" * 5000)])
    dst = tmp_path / "enc.zip"
    encrypt_archive(src, dst, Secret("s3cret-pw"))
    with pyzipper.AESZipFile(dst) as enc:
        enc.setpassword(b"s3cret-pw")
        assert enc.read("a.bin") == b"A" * 5000
    with pytest.raises(UnsafeArchiveError):
        encrypt_archive(src, tmp_path / "small.zip", limits=ExtractLimits(max_total_bytes=1000))
    assert not (tmp_path / "small.zip").exists()
    assert [p.name for p in tmp_path.iterdir() if p.name.endswith(".tmp")] == []


def test_collect_leaves_no_part_or_temp_files_after_partial_run(fake_guest, ps, tmp_path, fake_clock):
    _seed_out(fake_guest, {"a.txt": b"a"})
    m = _collect(fake_guest, tmp_path, fake_clock, extra_guest_paths=[f"{JOB_DIR}\\missing.bin"])
    art = tmp_path / "job" / "artifacts"
    leftovers = [p for p in art.rglob("*") if p.name.endswith((".part", ".tmp", ".partial"))]
    assert leftovers == [] and m.partial
