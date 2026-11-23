"""PE header inspection used to route a sample (kind, bitness, DLL, .NET) and hash it.

:func:`detect_pe` never raises on malformed or truncated *content*: anything
the Windows loader would not map yields ``kind == "non-pe"``. Every read is
bounds-checked against the file size before it happens. Errors opening the
file itself (missing, permission denied) propagate as ``OSError``, because a
missing sample must not be silently classified.

Thread-safety: all functions are pure apart from reading the given file.
"""

from __future__ import annotations

import hashlib
import os
import struct
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

__all__ = [
    "COMIMAGE_FLAGS_32BITPREFERRED",
    "COMIMAGE_FLAGS_32BITREQUIRED",
    "COMIMAGE_FLAGS_ILONLY",
    "IMAGE_FILE_MACHINE_AMD64",
    "IMAGE_FILE_MACHINE_I386",
    "PeInfo",
    "detect_pe",
    "sha256_file",
]

IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_DLL = 0x2000
_PE32_MAGIC = 0x010B
_PE32_PLUS_MAGIC = 0x020B
_COM_DESCRIPTOR_INDEX = 14  # IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR (CLR header)

COMIMAGE_FLAGS_ILONLY = 0x00000001
COMIMAGE_FLAGS_32BITREQUIRED = 0x00000002
COMIMAGE_FLAGS_32BITPREFERRED = 0x00020000

_ARCH_BY_MACHINE = MappingProxyType({IMAGE_FILE_MACHINE_I386: "x32", IMAGE_FILE_MACHINE_AMD64: "x64"})
# Offset of the data directory array inside the optional header, per magic.
_DATA_DIR_OFFSET = MappingProxyType({_PE32_MAGIC: 96, _PE32_PLUS_MAGIC: 112})
_SECTION_HEADER_SIZE = 40
_COR20_FLAGS_END = 20  # IMAGE_COR20_HEADER.Flags is the u32 at offset 16

_ReadAt = Callable[[int, int], bytes | None]


@dataclass(frozen=True)
class PeInfo:
    """Result of :func:`detect_pe`.

    kind: ``exe`` | ``dll`` | ``dotnet-exe`` | ``dotnet-dll`` | ``non-pe``.
    arch: ``x32`` (machine 0x14c) | ``x64`` (machine 0x8664) | None (other machine or non-PE).
    machine: raw IMAGE_FILE_HEADER.Machine, None for non-PE.
    clr_flags: IMAGE_COR20_HEADER.Flags for .NET images when the CLR header is
        backed by file data, else None.
    """

    kind: str
    arch: str | None
    is_dll: bool
    is_dotnet: bool
    machine: int | None
    clr_flags: int | None = None

    @property
    def dotnet_anycpu(self) -> bool:
        """True for an IL-only i386 .NET image without 32BITREQUIRED.

        Such an image runs as a 64-bit process on 64-bit Windows, so ``arch``
        (taken from the Machine field) says ``x32`` while x64dbg is the debugger
        that can actually host it.
        """
        flags = self.clr_flags
        return (
            self.is_dotnet
            and self.machine == IMAGE_FILE_MACHINE_I386
            and flags is not None
            and bool(flags & COMIMAGE_FLAGS_ILONLY)
            and not flags & COMIMAGE_FLAGS_32BITREQUIRED
        )


NON_PE = PeInfo(kind="non-pe", arch=None, is_dll=False, is_dotnet=False, machine=None)


def _u16(b: bytes, off: int) -> int:
    return int(struct.unpack_from("<H", b, off)[0])


def _u32(b: bytes, off: int) -> int:
    return int(struct.unpack_from("<I", b, off)[0])


def _clr_flags(read_at: _ReadAt, table: bytes, nsec: int, rva: int) -> int | None:
    """Map the CLR header RVA to a file offset through the section table and read its Flags."""
    for i in range(nsec):
        base = i * _SECTION_HEADER_SIZE
        vsize, va, raw_size, raw_ptr = struct.unpack_from("<IIII", table, base + 8)
        if va <= rva < va + max(vsize, raw_size):
            delta = rva - va
            if delta + _COR20_FLAGS_END > raw_size:
                return None  # header not backed by raw data in the file
            hdr = read_at(raw_ptr + delta, _COR20_FLAGS_END)
            return None if hdr is None else _u32(hdr, 16)
    return None


def _parse(read_at: _ReadAt) -> PeInfo:
    dos = read_at(0, 64)
    if dos is None or dos[:2] != b"MZ":
        return NON_PE
    e_lfanew = _u32(dos, 0x3C)
    nt = read_at(e_lfanew, 24)
    if nt is None or nt[:4] != b"PE\0\0":
        return NON_PE
    machine, nsec, _ts, _symptr, _nsyms, size_opt, characteristics = struct.unpack_from("<HHIIIHH", nt, 4)
    if size_opt < 2:
        return NON_PE
    opt = read_at(e_lfanew + 24, size_opt)
    if opt is None:
        return NON_PE
    dd_off = _DATA_DIR_OFFSET.get(_u16(opt, 0))
    if dd_off is None or size_opt < dd_off:
        return NON_PE
    table_off = e_lfanew + 24 + size_opt
    table = read_at(table_off, nsec * _SECTION_HEADER_SIZE)
    if table is None:
        return NON_PE

    is_dll = bool(characteristics & IMAGE_FILE_DLL)
    is_dotnet = False
    clr_flags: int | None = None
    n_dirs = _u32(opt, dd_off - 4)  # NumberOfRvaAndSizes
    clr_off = dd_off + _COM_DESCRIPTOR_INDEX * 8
    if n_dirs > _COM_DESCRIPTOR_INDEX and clr_off + 8 <= size_opt:
        rva, size = struct.unpack_from("<II", opt, clr_off)
        if rva and size:
            is_dotnet = True
            clr_flags = _clr_flags(read_at, table, nsec, rva)

    kind = ("dotnet-" if is_dotnet else "") + ("dll" if is_dll else "exe")
    return PeInfo(kind=kind, arch=_ARCH_BY_MACHINE.get(machine), is_dll=is_dll, is_dotnet=is_dotnet,
                  machine=machine, clr_flags=clr_flags)


def detect_pe(path: str | os.PathLike[str]) -> PeInfo:
    """Classify the file at ``path``. Malformed content yields ``kind == "non-pe"``."""
    with open(path, "rb") as f:
        size = os.fstat(f.fileno()).st_size

        def read_at(off: int, n: int) -> bytes | None:
            if off < 0 or n < 0 or off + n > size:
                return None
            f.seek(off)
            data = f.read(n)
            return data if len(data) == n else None  # the file may shrink while we read

        try:
            return _parse(read_at)
        except (struct.error, ValueError, OverflowError):  # defensive: bounds are checked above
            return NON_PE


def sha256_file(path: str | os.PathLike[str], chunk: int = 1 << 20) -> str:
    """Lower-case hex SHA-256 of the file at ``path``, read in ``chunk``-byte blocks."""
    if chunk <= 0:
        raise ValueError("chunk must be positive")
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        while block := f.read(chunk):
            h.update(block)
    return h.hexdigest()
