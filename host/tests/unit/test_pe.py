"""Tests for PE detection on tiny synthetic header blobs (no real binaries)."""

from __future__ import annotations

import hashlib
import random
import struct
from pathlib import Path

import pytest
from x64dbg_vm_gateway.pe import (
    COMIMAGE_FLAGS_32BITREQUIRED,
    COMIMAGE_FLAGS_ILONLY,
    PeInfo,
    detect_pe,
    sha256_file,
)

KINDS = {"exe", "dll", "dotnet-exe", "dotnet-dll", "non-pe"}


def make_pe(
    *,
    machine: int = 0x8664,
    dll: bool = False,
    magic: int | None = None,
    clr: bool = False,
    clr_flags: int = COMIMAGE_FLAGS_ILONLY,
    clr_dir: tuple[int, int] | None = None,
    e_lfanew: int = 0x80,
    nrva: int = 16,
    size_opt: int | None = None,
    nsec: int = 1,
    signature: bytes = b"PE\0\0",
) -> bytes:
    """Build a minimal, structurally valid PE image (headers + one raw section)."""
    if magic is None:
        magic = 0x20B if machine in (0x8664, 0xAA64) else 0x10B
    dd_rel = 112 if magic == 0x20B else 96
    if size_opt is None:
        size_opt = dd_rel + 8 * nrva

    assert e_lfanew >= 0x40, "builder only supports a full DOS header"
    dos = bytearray(e_lfanew)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, e_lfanew)

    chars = 0x0002 | (0x2000 if dll else 0)
    fh = signature + struct.pack("<HHIIIHH", machine, nsec, 0, 0, 0, size_opt, chars)

    opt = bytearray(size_opt)
    if size_opt >= 2:
        struct.pack_into("<H", opt, 0, magic)
    if dd_rel - 4 + 4 <= size_opt:
        struct.pack_into("<I", opt, dd_rel - 4, nrva)

    headers_len = len(dos) + len(fh) + size_opt + 40 * nsec
    raw_ptr = (headers_len + 0x1FF) & ~0x1FF
    sect_va, raw_size = 0x1000, 0x200

    if clr or clr_dir is not None:
        rva, size = clr_dir if clr_dir is not None else (sect_va + 8, 0x48)
        off = dd_rel + 14 * 8
        if off + 8 <= size_opt:
            struct.pack_into("<II", opt, off, rva, size)

    sects = bytearray()
    for i in range(nsec):
        sects += struct.pack("<8sIIIIIIHHI", b".text" if i == 0 else b".s%d" % i, 0x1000,
                             sect_va + 0x1000 * i, raw_size, raw_ptr + raw_size * i, 0, 0, 0, 0, 0x60000020)

    img = bytearray(dos + fh + opt + sects)
    img += b"\0" * (raw_ptr - len(img))
    raw = bytearray(raw_size * max(nsec, 1))
    if clr:
        # IMAGE_COR20_HEADER at RVA sect_va + 8: cb, major, minor, MetaData(8), Flags
        struct.pack_into("<IHHIII", raw, 8, 0x48, 2, 5, 0, 0, clr_flags)
    return bytes(img + raw)


def _write(tmp_path: Path, data: bytes, name: str = "s.bin") -> Path:
    p = tmp_path / name
    p.write_bytes(data)
    return p


@pytest.mark.parametrize(
    ("kwargs", "kind", "arch", "is_dll", "is_dotnet", "machine"),
    [
        ({"machine": 0x8664}, "exe", "x64", False, False, 0x8664),
        ({"machine": 0x14C}, "exe", "x32", False, False, 0x14C),
        ({"machine": 0x8664, "dll": True}, "dll", "x64", True, False, 0x8664),
        ({"machine": 0x14C, "dll": True}, "dll", "x32", True, False, 0x14C),
        ({"machine": 0x14C, "clr": True}, "dotnet-exe", "x32", False, True, 0x14C),
        ({"machine": 0x14C, "clr": True, "dll": True}, "dotnet-dll", "x32", True, True, 0x14C),
        ({"machine": 0x8664, "clr": True}, "dotnet-exe", "x64", False, True, 0x8664),
        ({"machine": 0xAA64}, "exe", None, False, False, 0xAA64),  # ARM64: unknown arch
        ({"machine": 0x1C4, "dll": True}, "dll", None, True, False, 0x1C4),  # ARMNT
    ],
)
def test_detect_pe_valid(tmp_path, kwargs, kind, arch, is_dll, is_dotnet, machine):
    info = detect_pe(_write(tmp_path, make_pe(**kwargs)))
    assert isinstance(info, PeInfo)
    assert (info.kind, info.arch, info.is_dll, info.is_dotnet, info.machine) == \
        (kind, arch, is_dll, is_dotnet, machine)


def test_detect_pe_accepts_str_path(tmp_path):
    assert detect_pe(str(_write(tmp_path, make_pe()))).kind == "exe"


def test_detect_pe_dotnet_clr_flags(tmp_path):
    anycpu = detect_pe(_write(tmp_path, make_pe(machine=0x14C, clr=True), "a"))
    assert anycpu.clr_flags == COMIMAGE_FLAGS_ILONLY
    assert anycpu.dotnet_anycpu is True
    x86 = detect_pe(_write(tmp_path, make_pe(
        machine=0x14C, clr=True, clr_flags=COMIMAGE_FLAGS_ILONLY | COMIMAGE_FLAGS_32BITREQUIRED), "b"))
    assert x86.dotnet_anycpu is False
    native = detect_pe(_write(tmp_path, make_pe(machine=0x14C), "c"))
    assert native.clr_flags is None and native.dotnet_anycpu is False


def test_detect_pe_clr_rva_outside_sections_keeps_dotnet_but_no_flags(tmp_path):
    info = detect_pe(_write(tmp_path, make_pe(machine=0x14C, clr_dir=(0x900000, 0x48))))
    assert info.kind == "dotnet-exe" and info.clr_flags is None


@pytest.mark.parametrize(
    ("clr_dir", "dotnet"),
    [((0, 0), False), ((0x1008, 0), False), ((0, 0x48), False), ((0x1008, 0x48), True)],
)
def test_detect_pe_clr_directory_must_be_present(tmp_path, clr_dir, dotnet):
    assert detect_pe(_write(tmp_path, make_pe(machine=0x14C, clr_dir=clr_dir))).is_dotnet is dotnet


def test_detect_pe_clr_index_beyond_number_of_rva_and_sizes(tmp_path):
    # NumberOfRvaAndSizes = 14 means directory index 14 does not exist even if bytes are set.
    data = bytearray(make_pe(machine=0x14C, clr=True))
    e = struct.unpack_from("<I", data, 0x3C)[0]
    struct.pack_into("<I", data, e + 24 + 92, 14)
    assert detect_pe(_write(tmp_path, bytes(data))).is_dotnet is False


def test_detect_pe_small_optional_header_has_no_clr(tmp_path):
    # Optional header holds only 10 data directories -> index 14 is outside it.
    info = detect_pe(_write(tmp_path, make_pe(machine=0x14C, nrva=10, clr=True)))
    assert info.kind == "exe" and not info.is_dotnet


def test_detect_pe_tiny_e_lfanew(tmp_path):
    # e_lfanew inside the DOS header (used by tiny PEs) is still a PE.
    assert detect_pe(_write(tmp_path, make_pe(e_lfanew=0x40))).kind == "exe"


NON_PE_CASES = {
    "empty": b"",
    "mz_only": b"MZ",
    "short_dos": b"MZ" + b"\0" * 30,
    "text": b"hello world\n" * 20,
    "elf": b"\x7fELF" + b"\0" * 200,
    "zip": b"PK\x03\x04" + b"\0" * 200,
}


@pytest.mark.parametrize("name", sorted(NON_PE_CASES))
def test_detect_pe_non_pe_inputs(tmp_path, name):
    info = detect_pe(_write(tmp_path, NON_PE_CASES[name]))
    assert info == PeInfo("non-pe", None, False, False, None)


def _patched(data: bytes, offset: int, fmt: str, value: int) -> bytes:
    b = bytearray(data)
    struct.pack_into(fmt, b, offset, value)
    return bytes(b)


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda d: _patched(d, 0x3C, "<I", len(d) + 100), id="e_lfanew_past_eof"),
        pytest.param(lambda d: _patched(d, 0x3C, "<I", 0xFFFFFFFF), id="e_lfanew_huge"),
        pytest.param(lambda d: _patched(d, 0x3C, "<I", len(d) - 10), id="e_lfanew_near_eof"),
        pytest.param(lambda d: d[:0x80 + 10], id="truncated_file_header"),
        pytest.param(lambda d: d[:0x80 + 24 + 50], id="truncated_optional_header"),
        pytest.param(lambda d: _patched(d, 0x80 + 24, "<H", 0x107), id="rom_magic"),
        pytest.param(lambda d: _patched(d, 0x80 + 24, "<H", 0), id="zero_magic"),
        pytest.param(lambda d: _patched(d, 0x80 + 20, "<H", 0), id="no_optional_header"),
        pytest.param(lambda d: _patched(d, 0x80 + 20, "<H", 40), id="optional_header_too_small"),
        pytest.param(lambda d: _patched(d, 0x80 + 20, "<H", 0xFFFF), id="optional_header_past_eof"),
        pytest.param(lambda d: _patched(d, 0x80 + 6, "<H", 0xFFFF), id="section_table_past_eof"),
        pytest.param(lambda d: d.replace(b"PE\0\0", b"PX\0\0", 1), id="bad_signature"),
        pytest.param(lambda d: b"ZM" + d[2:], id="bad_mz"),
    ],
)
def test_detect_pe_malformed_is_non_pe(tmp_path, mutate):
    info = detect_pe(_write(tmp_path, mutate(make_pe())))
    assert info.kind == "non-pe"
    assert info.arch is None and info.machine is None and not info.is_dll and not info.is_dotnet


def test_detect_pe_every_truncation_never_raises(tmp_path):
    full = make_pe(machine=0x14C, clr=True, dll=True)
    p = tmp_path / "t.bin"
    for n in range(len(full) + 1):
        p.write_bytes(full[:n])
        info = detect_pe(p)
        assert info.kind in KINDS


def test_detect_pe_random_mutations_never_raise(tmp_path):
    rng = random.Random(1337)
    base = bytearray(make_pe(machine=0x14C, clr=True))
    p = tmp_path / "m.bin"
    for _ in range(600):
        b = bytearray(base)
        for _ in range(rng.randint(1, 8)):
            pos = rng.randrange(0, 0x80 + 24 + 224 + 40)
            b[pos] = rng.randrange(256)
        p.write_bytes(bytes(b))
        info = detect_pe(p)
        assert info.kind in KINDS
        if info.kind == "non-pe":
            assert info.machine is None


def test_detect_pe_missing_file_raises_oserror(tmp_path):
    with pytest.raises(OSError):
        detect_pe(tmp_path / "missing.exe")


def test_sha256_file(tmp_path):
    data = bytes(range(256)) * 5000
    p = _write(tmp_path, data)
    assert sha256_file(p) == hashlib.sha256(data).hexdigest()
    assert sha256_file(p, chunk=7) == hashlib.sha256(data).hexdigest()
    assert sha256_file(str(p)) == hashlib.sha256(data).hexdigest()
    assert sha256_file(_write(tmp_path, b"", "e")) == hashlib.sha256(b"").hexdigest()


def test_sha256_file_rejects_bad_chunk(tmp_path):
    with pytest.raises(ValueError):
        sha256_file(_write(tmp_path, b"x"), chunk=0)
