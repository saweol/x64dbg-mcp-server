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
from tests.fakes.fake_vmrun import FakeVmrunRunner
from x64dbg_vm_gateway import transfer
from x64dbg_vm_gateway.contracts import VmrunResult
from x64dbg_vm_gateway.errors import (
    GuestOperationError,
    IntegrityError,
    PathNotAllowed,
    ToolsNotRunning,
    TransferError,
    UnsafeArchiveError,
)
from x64dbg_vm_gateway.guest import VixChannel
from x64dbg_vm_gateway.transfer import (
    DEFAULT_EXTRACT_LIMITS,
    ExtractedEntry,
    ExtractLimits,
    FetchLimits,
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
_SIZE_RE = re.compile(
    r"^\(Get-Item -LiteralPath '([^']+)' -Force\)\.Length \| Out-File -Encoding ascii -FilePath '([^']+)'$")


class GuestPowerShell:
    """Emulates the PowerShell one-liners the transfer module runs in the guest."""

    def __init__(self, guest: FakeGuest) -> None:
        self.guest = guest
        self.hash_results: list[str | None] = []  # queued overrides; None = do not write the file
        self.size_results: list[str | None] = []  # queued overrides; None = probe fails (exit 1)
        self.exit_codes: list[int] = []
        self.hash_encoding = "ascii"
        self.backslash_names = False  # Windows PowerShell 5.1 writes '\' separators
        self.commands: list[str] = []

    def _content(self, guest_path: str) -> bytes | None:
        try:
            return self.guest.read(guest_path)
        except KeyError:
            return None

    def __call__(self, exe: str, args: tuple, **_kw) -> int:
        assert exe.lower().endswith("\\powershell.exe")
        assert list(args[:5]) == PS_PREFIX and len(args) == 6
        cmd = args[5]
        self.commands.append(cmd)
        if m := _SIZE_RE.match(cmd):
            src, dst = m.groups()
            override = self.size_results.pop(0) if self.size_results else "real"
            if override is None:
                return 1
            if override == "real":
                data = self._content(src)
                if data is None:
                    return 1
                override = str(len(data))
            self.guest.write(dst, (override + "\r\n").encode("ascii"))
            return 0
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
            sep = "\\" if self.backslash_names else "/"
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                for key, data in sorted(self.guest.files.items()):
                    if key.startswith(prefix):
                        zf.writestr(key[len(prefix):].replace("\\", sep), data)
                # Empty directories become explicit directory entries.
                for d in sorted(self.guest.dirs):
                    if d.startswith(prefix) and not any(k.startswith(d + "\\") for k in self.guest.files):
                        zf.writestr(zipfile.ZipInfo(d[len(prefix):].replace("\\", sep) + sep), b"")
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
    with pytest.raises(TransferError) as ei:
        upload_sample(fake_guest, path, IN_DIR, sha256=sha, kind="exe", clock=fake_clock)
    assert not isinstance(ei.value, IntegrityError)
    assert not fake_guest.file_exists(f"{IN_DIR}\\{sha[:12]}.exe")


def test_upload_sample_hash_tool_failure_retries_the_hash_only(fake_guest, ps, sample, fake_clock):
    """A failed Get-FileHash run says nothing about the copy: re-hash, do not re-upload."""
    path, data, sha = sample
    ps.exit_codes = [1]
    final = upload_sample(fake_guest, path, IN_DIR, sha256=sha, kind="exe", clock=fake_clock)
    assert fake_guest.read(final) == data
    assert len(fake_guest.calls_of("run_program")) == 2
    assert len(fake_guest.calls_of("copy_to_guest")) == 1
    assert len(fake_clock.sleeps) == 1


def test_upload_sample_hash_tool_never_works_is_a_transfer_error(fake_guest, ps, sample, fake_clock):
    path, _, sha = sample
    ps.exit_codes = [1, 1, 1]
    with pytest.raises(TransferError) as ei:
        upload_sample(fake_guest, path, IN_DIR, sha256=sha, kind="exe", clock=fake_clock)
    err = ei.value
    assert not isinstance(err, IntegrityError)
    assert err.code == "TRANSFER_FAILED" and err.stage == "upload"
    assert "PowerShell" in (err.hint or "")
    assert err.details["attempts"] == 3
    assert all(o.startswith("unavailable") for o in err.details["observed"])
    assert "exit-code-1" in err.details["observed"][0]
    assert len(fake_guest.calls_of("copy_to_guest")) == 1
    assert not fake_guest.file_exists(f"{IN_DIR}\\{sha[:12]}.part")
    assert not fake_guest.file_exists(f"{IN_DIR}\\{sha[:12]}.sha256")


def test_upload_sample_any_observed_mismatch_is_an_integrity_error(fake_guest, ps, sample, fake_clock):
    path, _, sha = sample
    ps.hash_results = ["0" * 64, None, None]
    with pytest.raises(IntegrityError) as ei:
        upload_sample(fake_guest, path, IN_DIR, sha256=sha, kind="exe", clock=fake_clock)
    assert ei.value.details["observed"][0] == "0" * 64
    assert len(fake_guest.calls_of("copy_to_guest")) == 2  # re-copied only after the mismatch
    assert not fake_guest.file_exists(f"{IN_DIR}\\{sha[:12]}.part")


def test_upload_sample_garbage_hash_file_is_retried(fake_guest, ps, sample, fake_clock):
    path, _, sha = sample
    ps.hash_results = ["not-a-hash", "x" * 5000, "real"]
    assert upload_sample(fake_guest, path, IN_DIR, sha256=sha, kind="exe", clock=fake_clock)
    assert len(fake_guest.calls_of("copy_to_guest")) == 1


def test_upload_sample_rename_failure_removes_the_part(fake_guest, ps, sample, fake_clock):
    path, _, sha = sample
    fake_guest.fail_next("rename", GuestOperationError("Error: Access is denied"))
    with pytest.raises(GuestOperationError):
        upload_sample(fake_guest, path, IN_DIR, sha256=sha, kind="exe", clock=fake_clock)
    assert not fake_guest.file_exists(f"{IN_DIR}\\{sha[:12]}.part")
    assert not fake_guest.file_exists(f"{IN_DIR}\\{sha[:12]}.sha256")


def test_upload_sample_guest_error_mid_attempt_removes_the_part(fake_guest, ps, sample, fake_clock):
    path, _, sha = sample
    fake_guest.fail_next("run_program", GuestOperationError("Error: A file was not found"))
    with pytest.raises(GuestOperationError):
        upload_sample(fake_guest, path, IN_DIR, sha256=sha, kind="exe", clock=fake_clock)
    assert not fake_guest.file_exists(f"{IN_DIR}\\{sha[:12]}.part")


def test_upload_sample_environment_error_skips_guest_cleanup(fake_guest, ps, sample, fake_clock):
    """With the VM / Tools gone every cleanup call would just fail (or time out) again."""
    path, _, sha = sample
    fake_guest.fail_next("run_program", ToolsNotRunning("Error: The VMware Tools are not running"))
    with pytest.raises(ToolsNotRunning):
        upload_sample(fake_guest, path, IN_DIR, sha256=sha, kind="exe", clock=fake_clock)
    methods = [m for m, _, _ in fake_guest.calls]
    assert methods[methods.index("run_program"):] == ["run_program"]


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


def test_safe_extract_ratio_bomb_is_rejected_per_member(tmp_path):
    small = b"small"
    z = make_zip(tmp_path / "o.zip", [("bomb.bin", b"\0" * (4 * 1024 * 1024)), ("small", small)])
    dest = tmp_path / "d"
    bomb, ok = safe_extract(z, dest, ExtractLimits())
    assert bomb.status == "rejected:ratio" and bomb.stored_name is None and bomb.sha256 is None
    assert ok.status == "ok"
    assert _listing(dest) == {ok.stored_name}


def test_safe_extract_sparse_dump_does_not_stop_later_members(tmp_path):
    """A memory dump with zero-filled regions compresses past 200:1; logs after it must survive."""
    dump = os.urandom(4096) + b"\0" * (8 * 1024 * 1024)
    z = make_zip(tmp_path / "o.zip", [("notes.txt", b"n"), ("region_dump.bin", dump),
                                      ("x64dbg.log", b"log")])
    dest = tmp_path / "d"
    entries = safe_extract(z, dest, ExtractLimits())
    assert [e.status for e in entries] == ["ok", "rejected:ratio", "ok"]
    assert (dest / entries[2].stored_name).read_bytes() == b"log"
    assert safe_extract(z, tmp_path / "loose", ExtractLimits(max_ratio=10_000))[1].status == "ok"


def test_safe_extract_ratio_rejections_still_consume_the_byte_budget(tmp_path):
    mib = 1024 * 1024
    z = make_zip(tmp_path / "o.zip", [("b1", b"\0" * (4 * mib)), ("b2", b"\0" * (4 * mib))])
    with pytest.raises(UnsafeArchiveError) as ei:
        safe_extract(z, tmp_path / "d", ExtractLimits(max_total_bytes=3 * mib))
    assert ei.value.details["reason"] == "total-bytes"


def _patch_cd_compressed_size(path: Path, member: str, compressed: int) -> None:
    """Rewrite the central-directory compressed size (offset 20) of ``member``."""
    raw = bytearray(path.read_bytes())
    cd = raw.find(b"PK\x01\x02")
    while cd != -1:
        name_len = struct.unpack_from("<H", raw, cd + 28)[0]
        if bytes(raw[cd + 46:cd + 46 + name_len]) == member.encode():
            struct.pack_into("<I", raw, cd + 20, compressed)
            path.write_bytes(bytes(raw))
            return
        cd = raw.find(b"PK\x01\x02", cd + 4)
    raise AssertionError(f"central directory entry not found: {member}")


def _overlap_bomb(path: Path) -> Path:
    """A bomb whose declared compressed size spans the rest of the archive (overlapping entries).

    With the honest size the member is ~1000:1; with the inflated size it looks like ~80:1.
    """
    z = make_zip(path, [("a.bin", b"\0" * (8 * 1024 * 1024)), ("pad.bin", os.urandom(100_000))])
    with zipfile.ZipFile(z) as zf:
        start_dir = zf.start_dir
    _patch_cd_compressed_size(z, "a.bin", start_dir - 40)
    return z


def test_safe_extract_rejects_overlapping_members(tmp_path):
    a, pad = safe_extract(_overlap_bomb(tmp_path / "o.zip"), tmp_path / "d", ExtractLimits())
    assert a.status == "rejected:overlap"
    assert pad.status == "ok"


def test_safe_extract_overlap_check_does_not_rely_on_the_zipfile_version(tmp_path, monkeypatch):
    """zipfile before 3.11.8 / 3.12.2 (CVE-2024-0450) does not detect overlapping entries itself."""
    real = zipfile.ZipFile._RealGetContents

    def without_stdlib_check(self):
        real(self)
        for info in self.filelist:
            info._end_offset = None

    monkeypatch.setattr(zipfile.ZipFile, "_RealGetContents", without_stdlib_check)
    a, pad = safe_extract(_overlap_bomb(tmp_path / "o.zip"), tmp_path / "d", ExtractLimits())
    assert a.status == "rejected:overlap"
    assert pad.status == "ok"


class _NonSeekable(io.RawIOBase):
    """Write-only stream without tell/seek: zipfile then writes data descriptors."""

    def __init__(self) -> None:
        self.buf = bytearray()

    def writable(self) -> bool:
        return True

    def write(self, b) -> int:
        self.buf += bytes(b)
        return len(b)


def test_safe_extract_overlap_check_accepts_streamed_archives(tmp_path):
    stream = _NonSeekable()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as zf:
        for i in range(3):
            with zf.open(f"m{i}.bin", "w") as f:
                f.write(os.urandom(3000) + b"x" * 5000)
    z = tmp_path / "streamed.zip"
    z.write_bytes(bytes(stream.buf))
    with zipfile.ZipFile(z) as zf:
        assert all(i.flag_bits & 0x08 for i in zf.infolist())  # data descriptors present
    assert [e.status for e in safe_extract(z, tmp_path / "d", ExtractLimits())] == ["ok"] * 3


def test_safe_extract_counts_directory_members_against_max_files(tmp_path):
    z = make_zip(tmp_path / "o.zip", [(f"d{i}/", b"") for i in range(20)])
    with pytest.raises(UnsafeArchiveError) as ei:
        safe_extract(z, tmp_path / "d", ExtractLimits(max_files=5))
    assert ei.value.details["reason"] == "file-count"
    assert ei.value.details["files"] == 20


def test_safe_extract_backslash_directory_entry_is_a_directory(tmp_path):
    """Windows PowerShell 5.1 Compress-Archive writes '\\' separators, also for directories."""
    z = make_zip(tmp_path / "o.zip", [("emptydir\\", b""), ("sub\\x.txt", b"x")])
    dest = tmp_path / "d"
    d, f = safe_extract(z, dest, ExtractLimits())
    assert (d.status, d.stored_name) == ("skipped:directory", None)
    assert f.status == "ok"
    assert _listing(dest) == {f.stored_name}


def test_safe_extract_refuses_a_non_empty_destination(tmp_path):
    z = make_zip(tmp_path / "o.zip", [("a", b"1")])
    dest = tmp_path / "d"
    dest.mkdir()
    (dest / "0000_previous").write_bytes(b"old")
    with pytest.raises(TransferError) as ei:
        safe_extract(z, dest, ExtractLimits())
    assert ei.value.details["reason"] == "dest-not-empty"
    assert _listing(dest) == {"0000_previous"}


def test_safe_extract_reports_completed_entries_on_abort(tmp_path):
    a, b = os.urandom(600), os.urandom(600)
    z = make_zip(tmp_path / "o.zip", [("first.bin", a), ("second.bin", b)])
    dest = tmp_path / "d"
    done: list[ExtractedEntry] = []
    with pytest.raises(UnsafeArchiveError) as ei:
        safe_extract(z, dest, ExtractLimits(max_total_bytes=1000), entries_out=done)
    assert ei.value.details["entries_done"] == 1
    assert [(e.original_name, e.status) for e in done] == [("first.bin", "ok")]
    assert _listing(dest) == {done[0].stored_name}
    assert (dest / done[0].stored_name).read_bytes() == a


def test_safe_extract_entries_out_matches_the_return_value(tmp_path):
    z = make_zip(tmp_path / "o.zip", [("a", b"1"), ("../b", b"2")])
    done: list[ExtractedEntry] = []
    assert safe_extract(z, tmp_path / "d", ExtractLimits(), entries_out=done) == done


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
def test_safe_extract_refuses_preplanted_symlink_destination(tmp_path):
    data = b"payload"
    z = make_zip(tmp_path / "o.zip", [("x", data)])
    dest = tmp_path / "d"
    dest.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"untouched")
    (dest / f"0000_{_sha(data)[:12]}").symlink_to(outside)
    with pytest.raises(TransferError):
        safe_extract(z, dest, ExtractLimits())
    assert outside.read_bytes() == b"untouched"


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

    compress, probe = ps.commands
    assert compress == f"Compress-Archive -Path '{OUT_DIR}\\*' -DestinationPath '{JOB_DIR}\\out.zip' -Force"
    m_probe = _SIZE_RE.match(probe)
    assert m_probe and m_probe.group(1) == f"{JOB_DIR}\\out.zip"
    assert PureWindowsPath(m_probe.group(2)).parent == PureWindowsPath(JOB_DIR)
    assert not fake_guest.file_exists(m_probe.group(2))  # probe result removed from the guest

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


def test_collect_zip_bomb_member_is_rejected_not_raised(fake_guest, ps, tmp_path, fake_clock):
    _seed_out(fake_guest, {"bomb.bin": b"\0" * (4 * 1024 * 1024), "x64dbg.log": b"log"})
    m = _collect(fake_guest, tmp_path, fake_clock)
    status = {e.original_path: e.status for e in m.entries}
    assert status == {"bomb.bin": "rejected:ratio", "x64dbg.log": "ok"}
    assert (tmp_path / "job" / "artifacts" / "raw" / "out.zip").is_file()  # raw zip preserved


def test_collect_total_size_abort_is_recorded_not_raised(fake_guest, ps, tmp_path, fake_clock):
    _seed_out(fake_guest, {"a.bin": os.urandom(600), "b.bin": os.urandom(600)})
    m = _collect(fake_guest, tmp_path, fake_clock, limits=ExtractLimits(max_total_bytes=1000))
    assert m.partial
    (err,) = [e for e in m.errors if e["stage"] == "extract"]
    assert err["code"] == "UNSAFE_ARCHIVE" and err["details"]["reason"] == "total-bytes"
    assert [e.status for e in m.entries] == ["ok"]  # the member finished before the abort is kept


def test_collect_compress_failure_is_partial(fake_guest, ps, tmp_path, fake_clock):
    _seed_out(fake_guest, {"a.txt": b"a"})
    fake_guest.write(f"{JOB_DIR}\\x.log", b"x")
    ps.exit_codes = [1]
    m = _collect(fake_guest, tmp_path, fake_clock, extra_guest_paths=[f"{JOB_DIR}\\x.log"])
    assert m.partial and m.raw_zip_sha256 is None
    assert any(err["stage"] == "zip" for err in m.errors)
    assert [e.status for e in m.entries if e.source == "extra"] == ["ok"]


def _fail_copies_of(guest: FakeGuest, suffix: str, exc: Exception | None = None,
                    write: bytes | None = None) -> None:
    """Make copy_from_guest of guest paths ending in ``suffix`` fail (optionally after writing)."""
    real = guest.copy_from_guest

    def copy_from_guest(guest_path: str, host_path: Path) -> None:
        if guest_path.lower().endswith(suffix.lower()):
            guest.calls.append(("copy_from_guest", (guest_path, host_path), {}))
            if write is not None:
                Path(host_path).write_bytes(write)
            raise exc or GuestOperationError("Error: copy failed")
        real(guest_path, host_path)

    guest.copy_from_guest = copy_from_guest  # type: ignore[method-assign]


def test_collect_zip_copy_failure_is_partial(fake_guest, ps, tmp_path, fake_clock):
    _seed_out(fake_guest, {"a.txt": b"a"})
    _fail_copies_of(fake_guest, "\\out.zip", write=b"half a zip")
    m = _collect(fake_guest, tmp_path, fake_clock)
    assert m.partial and m.raw_zip_sha256 is None
    assert any(err["stage"] == "fetch" and err["code"] == "GUEST_OP_FAILED" for err in m.errors)
    assert not list((tmp_path / "job" / "artifacts" / "raw").glob("*.part"))
    assert not (tmp_path / "job" / "artifacts" / "raw" / "out.zip").exists()


# ── collect: bounded guest -> host copies (review F1) ───────────────
def _extra_status(m: Manifest) -> list[str]:
    return [e.status for e in m.entries if e.source == "extra"]


def test_collect_extra_over_the_size_limit_is_not_copied(fake_guest, ps, tmp_path, fake_clock):
    _seed_out(fake_guest, {"a.txt": b"a"})
    big = f"{JOB_DIR}\\dumps\\full.dmp"
    fake_guest.write(big, os.urandom(500))
    m = _collect(fake_guest, tmp_path, fake_clock, extra_guest_paths=[big],
                 fetch_limits=FetchLimits(max_file_bytes=400))
    assert _extra_status(m) == ["failed:TRANSFER_FAILED"]
    assert m.partial
    (err,) = [e for e in m.errors if e["stage"] == "extra"]
    assert err["details"]["reason"] == "too-large" and err["details"]["size"] == 500
    copied = [a[0] for a, _ in fake_guest.calls_of("copy_from_guest")]
    assert big not in copied  # refused before the copy
    assert not (tmp_path / "job" / "artifacts" / "raw" / "extra").exists() or \
        _listing(tmp_path / "job" / "artifacts" / "raw" / "extra") == set()


def test_collect_lying_size_probe_is_caught_after_the_copy(fake_guest, ps, tmp_path, fake_clock):
    """The guest controls the probe output; the host re-checks what actually arrived."""
    fake_guest.mkdir(OUT_DIR)
    big = f"{JOB_DIR}\\dumps\\full.dmp"
    fake_guest.write(big, os.urandom(500))
    ps.size_results = ["10"]
    m = _collect(fake_guest, tmp_path, fake_clock, extra_guest_paths=[big],
                 fetch_limits=FetchLimits(max_file_bytes=400))
    assert _extra_status(m) == ["failed:TRANSFER_FAILED"]
    (err,) = [e for e in m.errors if e["stage"] == "extra"]
    assert err["details"]["reason"] == "too-large"
    art = tmp_path / "job" / "artifacts"
    assert [p for p in art.rglob("*") if p.is_file() and p.name != "manifest.json"] == []


def test_collect_out_zip_over_the_size_limit_is_not_copied(fake_guest, ps, tmp_path, fake_clock):
    _seed_out(fake_guest, {"dump.bin": os.urandom(3000)})
    m = _collect(fake_guest, tmp_path, fake_clock, fetch_limits=FetchLimits(max_file_bytes=1000))
    assert m.partial and m.raw_zip is None and m.entries == []
    (err,) = [e for e in m.errors if e["stage"] == "fetch"]
    assert err["code"] == "TRANSFER_FAILED" and err["details"]["reason"] == "too-large"
    assert not (tmp_path / "job" / "artifacts" / "raw" / "out.zip").exists()
    copied = [a[0] for a, _ in fake_guest.calls_of("copy_from_guest")]
    assert f"{JOB_DIR}\\out.zip" not in copied


def test_collect_refuses_copies_that_would_fill_the_host_disk(fake_guest, ps, tmp_path, fake_clock):
    _seed_out(fake_guest, {"a.txt": b"a"})
    fake_guest.write(f"{JOB_DIR}\\x.log", b"x")
    m = _collect(fake_guest, tmp_path, fake_clock, extra_guest_paths=[f"{JOB_DIR}\\x.log"],
                 fetch_limits=FetchLimits(min_host_free_bytes=1 << 62))
    assert m.raw_zip is None and _extra_status(m) == ["failed:TRANSFER_FAILED"]
    reasons = {e["details"]["reason"] for e in m.errors if e["stage"] in ("fetch", "extra")}
    assert reasons == {"host-disk-space"}
    copied = [a[0] for a, _ in fake_guest.calls_of("copy_from_guest")]
    assert f"{JOB_DIR}\\out.zip" not in copied and f"{JOB_DIR}\\x.log" not in copied


def test_collect_unavailable_size_probe_falls_back_to_host_checks(fake_guest, ps, tmp_path, fake_clock):
    _seed_out(fake_guest, {"a.txt": b"a"})
    ps.size_results = [None]
    m = _collect(fake_guest, tmp_path, fake_clock)
    assert not m.partial and [e.status for e in m.entries] == ["ok"]


def test_fetch_limits_validation():
    assert FetchLimits() == FetchLimits(max_file_bytes=4 * 1024**3, min_host_free_bytes=1024**3)
    with pytest.raises(ValueError):
        FetchLimits(max_file_bytes=-1)
    with pytest.raises(ValueError):
        FetchLimits(min_host_free_bytes=-1)


# ── collect: stale output, host errors, PowerShell 5.1 names ───────
def _stale_check(tmp_path, m: Manifest) -> None:
    art = tmp_path / "job" / "artifacts"
    on_disk = {p.relative_to(art).as_posix() for p in art.rglob("*") if p.is_file()} - {"manifest.json"}
    in_manifest = {e.stored_name for e in m.entries if e.stored_name}
    if m.raw_zip:
        in_manifest.add(m.raw_zip)
    assert on_disk == in_manifest


def test_collect_retry_with_empty_out_dir_drops_previous_output(fake_guest, ps, tmp_path, fake_clock):
    _seed_out(fake_guest, {"a.txt": b"first"})
    fake_guest.write(f"{JOB_DIR}\\x.log", b"x")
    _collect(fake_guest, tmp_path, fake_clock, extra_guest_paths=[f"{JOB_DIR}\\x.log"])
    fake_guest.files.clear()
    m = _collect(fake_guest, tmp_path, fake_clock)
    assert m.raw_zip is None and m.entries == []
    _stale_check(tmp_path, m)


def test_collect_retry_with_failed_zip_drops_previous_output(fake_guest, ps, tmp_path, fake_clock):
    _seed_out(fake_guest, {"a.txt": b"first"})
    _collect(fake_guest, tmp_path, fake_clock)
    ps.exit_codes = [1]
    m = _collect(fake_guest, tmp_path, fake_clock)
    assert m.partial and m.raw_zip is None
    _stale_check(tmp_path, m)


@pytest.mark.parametrize("bad", [{(1, 2): 3}, "cycle", float("nan")])
def test_collect_module_map_is_checked_before_guest_work(fake_guest, ps, tmp_path, fake_clock, bad):
    if bad == "cycle":
        bad = []
        bad.append(bad)
    _seed_out(fake_guest, {"a.txt": b"a"})
    fake_guest.calls.clear()
    with pytest.raises(TransferError) as ei:
        _collect(fake_guest, tmp_path, fake_clock, module_map=bad)
    assert ei.value.details["reason"] == "module-map-not-json"
    assert fake_guest.calls == []


def test_collect_module_map_values_json_cannot_encode_are_stringified(fake_guest, ps, tmp_path,
                                                                     fake_clock):
    fake_guest.mkdir(OUT_DIR)
    m = _collect(fake_guest, tmp_path, fake_clock, module_map={"base": Path("/x"), "ids": (1, 2)})
    assert m.module_map == {"base": str(Path("/x")), "ids": [1, 2]}
    assert _load_manifest(tmp_path)["module_map"] == m.module_map


def test_collect_host_error_while_extracting_still_writes_manifest(fake_guest, ps, tmp_path, fake_clock,
                                                                  monkeypatch):
    _seed_out(fake_guest, {"a.txt": b"a"})

    def boom(*_a, **_k):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(transfer, "_extract_into", boom)
    m = _collect(fake_guest, tmp_path, fake_clock)
    assert m.partial
    (err,) = [e for e in m.errors if e["stage"] == "extract"]
    assert err["code"] == "TRANSFER_FAILED"
    assert _load_manifest(tmp_path)["partial"] is True


def test_collect_unreadable_screenshot_still_writes_manifest(fake_guest, ps, tmp_path, fake_clock,
                                                            monkeypatch):
    fake_guest.mkdir(OUT_DIR)
    shot = tmp_path / "shot.png"
    shot.write_bytes(b"png")
    real = transfer.sha256_file

    def sha(path, *a, **k):
        if Path(path) == shot:
            raise PermissionError(13, "Permission denied")
        return real(path, *a, **k)

    monkeypatch.setattr(transfer, "sha256_file", sha)
    m = _collect(fake_guest, tmp_path, fake_clock, screenshot=shot)
    assert m.screenshot is not None and m.screenshot["status"] == "error"
    assert any(e["stage"] == "screenshot" for e in m.errors)
    assert _load_manifest(tmp_path)["screenshot"]["status"] == "error"


def test_collect_powershell_51_backslash_names(fake_guest, ps, tmp_path, fake_clock):
    ps.backslash_names = True
    _seed_out(fake_guest, {"logs\\x64dbg.log": b"log", "dump.bin": b"d"})
    fake_guest.mkdir(f"{OUT_DIR}\\empty")
    m = _collect(fake_guest, tmp_path, fake_clock)
    status = {e.original_path: e.status for e in m.entries}
    assert status == {"dump.bin": "ok", "empty\\": "skipped:directory", "logs\\x64dbg.log": "ok"}
    listed = _collect(fake_guest, tmp_path, fake_clock, extract=False)
    assert {e.original_path: e.status for e in listed.entries}["empty\\"] == "skipped:directory"


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


# ── end-to-end through VixChannel + FakeVmrunRunner (review F14) ────
def _msvcrt_unquote(token: str) -> str:
    """Undo ``subprocess.list2cmdline`` for one argument (MSVCRT / CommandLineToArgvW rules)."""
    out: list[str] = []
    i, n = 0, len(token)
    while i < n:
        ch = token[i]
        if ch == "\\":
            j = i
            while j < n and token[j] == "\\":
                j += 1
            count = j - i
            if j < n and token[j] == '"':
                out.append("\\" * (count // 2))
                if count % 2:
                    out.append('"')
                    j += 1
            else:
                out.append("\\" * count)
            i = j
        elif ch == '"':
            i += 1  # quote toggles; the token never contains separators we need to honour
        else:
            out.append(ch)
            i += 1
    return "".join(out)


class VmrunGuestEmulator:
    """FakeVmrunRunner handler that answers guest commands from a FakeGuest + GuestPowerShell.

    Output and error texts follow the vmrun formats VixChannel parses.
    """

    _FLAGS = frozenset({"-noWait", "-activeWindow", "-interactive"})

    def __init__(self, guest: FakeGuest, ps: GuestPowerShell) -> None:
        self.guest = guest
        self.ps = ps
        self.program_args: list[tuple[str, ...]] = []

    @staticmethod
    def _not_found() -> GuestOperationError:
        return GuestOperationError("Error: A file was not found")

    def __call__(self, command: str, params: tuple[str, ...], guest: bool) -> VmrunResult:
        assert guest is True
        g = self.guest
        if command == "directoryExistsInGuest":
            ok = g.dir_exists(params[0])
            return VmrunResult(0, "The directory exists." if ok else "The directory does not exist.", "")
        if command == "fileExistsInGuest":
            ok = g.file_exists(params[0])
            return VmrunResult(0, "The file exists." if ok else "The file does not exist.", "")
        if command == "createDirectoryInGuest":
            g.mkdir(params[0])
        elif command == "listDirectoryInGuest":
            names = g.list_dir(params[0])
            return VmrunResult(0, "\n".join([f"Directory list: {len(names)}", *names]) + "\n", "")
        elif command in ("CopyFileFromHostToGuest", "CopyFileFromGuestToHost", "deleteFileInGuest",
                         "renameFileInGuest"):
            op = {"CopyFileFromHostToGuest": lambda: g.copy_to_guest(Path(params[0]), params[1]),
                  "CopyFileFromGuestToHost": lambda: g.copy_from_guest(params[0], Path(params[1])),
                  "deleteFileInGuest": lambda: g.delete_file(params[0]),
                  "renameFileInGuest": lambda: g.rename(params[0], params[1])}[command]
            try:
                op()
            except GuestOperationError:
                raise self._not_found() from None
        elif command == "runProgramInGuest":
            rest = [p for p in params if p not in self._FLAGS]
            program, args = rest[0], tuple(_msvcrt_unquote(a) for a in rest[1:])
            self.program_args.append(args)
            code = g.run_program(program, args)
            if code:
                raise GuestOperationError(f"Error: Guest program exited with non-zero exit code: {code}")
        else:
            raise AssertionError(f"unexpected vmrun command {command}")
        return VmrunResult(0, "", "")


@pytest.fixture
def vix(fake_guest, ps) -> tuple[VixChannel, VmrunGuestEmulator, FakeVmrunRunner]:
    runner = FakeVmrunRunner()
    emu = VmrunGuestEmulator(fake_guest, ps)
    runner.handler = emu
    return VixChannel(runner), emu, runner


def test_msvcrt_unquote_inverts_list2cmdline():
    import subprocess

    for s in ["plain", "a b", "", 'say "hi"', "C:\\a b\\", "x\\\\\"y", "(Get-Item 'C:\\a [1]').Length"]:
        assert _msvcrt_unquote(subprocess.list2cmdline([s])) == s


def test_upload_sample_through_vix_channel(vix, fake_guest, ps, sample, fake_clock):
    chan, emu, runner = vix
    path, data, sha = sample
    final = upload_sample(chan, path, IN_DIR, sha256=sha, kind="dll", clock=fake_clock)
    assert final == f"{IN_DIR}\\{sha[:12]}.dll"
    assert fake_guest.read(final) == data
    # The PowerShell command survived vmrun's argv joining and MSVCRT quoting unchanged.
    assert emu.program_args == [(*PS_PREFIX, ps.commands[0])]
    assert all(c["guest"] and c["timeout_s"] > 0 for c in runner.calls)
    assert not fake_guest.file_exists(f"{IN_DIR}\\{sha[:12]}.part")


def test_upload_sample_through_vix_channel_hash_tool_failure(vix, fake_guest, ps, sample, fake_clock):
    chan, _, _ = vix
    path, _, sha = sample
    ps.exit_codes = [5, 5, 5]
    with pytest.raises(TransferError) as ei:
        upload_sample(chan, path, IN_DIR, sha256=sha, kind="exe", clock=fake_clock)
    assert not isinstance(ei.value, IntegrityError)
    assert "exit-code-5" in ei.value.details["observed"][0]


def test_collect_through_vix_channel(vix, fake_guest, ps, tmp_path, fake_clock):
    chan, _, _ = vix
    dump, log = os.urandom(2048), b"log\n"
    _seed_out(fake_guest, {"dump [1].bin": dump, "logs\\x64dbg.log": log})
    fake_guest.write(f"{JOB_DIR}\\extra\\mem$1.dmp", b"extra")
    m = _collect(chan, tmp_path, fake_clock,
                 extra_guest_paths=[f"{JOB_DIR}\\extra\\mem$1.dmp", f"{JOB_DIR}\\missing.bin"])
    art = tmp_path / "job" / "artifacts"
    ok = {e.original_path: e for e in m.entries if e.status == "ok"}
    assert set(ok) == {"dump [1].bin", "logs/x64dbg.log", f"{JOB_DIR}\\extra\\mem$1.dmp"}
    assert (art / ok["dump [1].bin"].stored_name).read_bytes() == dump
    assert (art / ok[f"{JOB_DIR}\\extra\\mem$1.dmp"].stored_name).read_bytes() == b"extra"
    assert _extra_status(m) == ["ok", "failed:GUEST_OP_FAILED"]
    assert m.partial
    leftovers = [k for k in fake_guest.files if k.endswith(".txt") and "x64gw" in k]
    assert leftovers == []
