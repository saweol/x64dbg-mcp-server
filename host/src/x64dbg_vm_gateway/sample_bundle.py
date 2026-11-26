"""The benign demo samples bundled with the package (``x64dbg-vm-gateway demo``).

``scripts/build-release.sh`` builds ``host/tests/vm/samples/hello.zig`` with Zig for x86_64
and x86 Windows (the samples of the real-VM E2E suite: print a marker, call kernel32.Sleep a few
times, write a small file next to themselves, exit 0; no network, no persistence) and copies the
two executables into the package as ``data/samples/e2e_sample_x86_64.exe`` and
``data/samples/e2e_sample_x86.exe`` before ``uv build``. They are not in git; hatch
``artifacts`` puts them into the wheel and the sdist when they are present. Without them
``demo`` says how to build them (``BUILD_HINT``).

The files are read through :mod:`importlib.resources`, so a zipped installation works too:
:func:`copy_sample` writes a private copy wherever the caller needs it.
"""

from __future__ import annotations

import os
import shutil
from collections.abc import Mapping
from importlib import resources
from importlib.resources.abc import Traversable
from pathlib import Path
from types import MappingProxyType

__all__ = ["BUILD_HINT", "SAMPLE_FILES", "bundle_root", "copy_sample", "find_sample", "missing_files"]

#: debugger architecture -> bundled sample (``tests/vm/samples/build.sh`` names)
SAMPLE_FILES: Mapping[str, str] = MappingProxyType({
    "x64": "e2e_sample_x86_64.exe",
    "x32": "e2e_sample_x86.exe",
})
BUILD_HINT = ("this installation has no bundled demo samples (release wheels carry them). In a source "
              "checkout build them with Zig 0.14: ZIG=/path/to/zig host/tests/vm/samples/build.sh "
              "host/src/x64dbg_vm_gateway/data/samples (or run scripts/build-release.sh), then reinstall")


def bundle_root() -> Traversable:
    """Where the bundled samples live inside the installed package."""
    return resources.files(__package__).joinpath("data").joinpath("samples")


def find_sample(arch: str, root: Traversable | None = None) -> Traversable | None:
    """The bundled sample for ``arch`` ("x64" / "x32"), or None when it is missing."""
    name = SAMPLE_FILES.get(arch)
    if name is None:
        raise ValueError(f"no demo sample for architecture {arch!r} (expected one of "
                         f"{', '.join(SAMPLE_FILES)})")
    entry = (bundle_root() if root is None else root).joinpath(name)
    return entry if entry.is_file() else None


def missing_files(root: Traversable | None = None) -> list[str]:
    """The bundled samples missing under ``root`` (default: :func:`bundle_root`)."""
    return [name for arch, name in SAMPLE_FILES.items() if find_sample(arch, root) is None]


def copy_sample(arch: str, dest_dir: Path, root: Traversable | None = None) -> Path:
    """Copy the sample for ``arch`` into ``dest_dir`` (0600 on POSIX; never executable here).
    FileNotFoundError when the bundle lacks it."""
    src = find_sample(arch, root)
    if src is None:
        raise FileNotFoundError(SAMPLE_FILES[arch])
    target = dest_dir / SAMPLE_FILES[arch]
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as dst, src.open("rb") as f:
        shutil.copyfileobj(f, dst)
    return target
