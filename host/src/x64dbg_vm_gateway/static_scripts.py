"""The static-tool sync scripts shipped inside the package.

``data/static/{common,ida,ghidra,radare2}/`` hold byte-identical copies of the repository's
``static/`` scripts (``tests/unit/test_static_scripts.py`` checks it, and
``scripts/build-release.sh`` checks the wheel), so an installed gateway carries the
script each static tool runs to import / export ``x64dbg-ida-sync/1`` documents. The
layout is the repository's: the Ghidra and radare2 scripts find the shared core in
``../common/``. ``x64dbg-vm-gateway static-scripts`` prints where they are or copies them.

The files are read through :mod:`importlib.resources`, so a zipped installation works too
(:func:`installed_root` is then None and :func:`copy_to` is the way to get them).
"""

from __future__ import annotations

import contextlib
import os
import tempfile
from importlib import resources
from importlib.resources.abc import Traversable
from pathlib import Path

from . import static_tools
from .errors import InvalidArgument, TransferError

__all__ = ["SCRIPT_FILES", "copy_to", "installed_root", "packaged", "relative_path", "scripts_root"]

#: the packaged scripts, relative to :func:`scripts_root` (and to the repository's ``static/``)
SCRIPT_FILES: tuple[str, ...] = (
    "common/x64dbg_sync_core.py",
    "ida/x64dbg_sync.py",
    "ghidra/x64dbg_sync_ghidra.py",
    "radare2/x64dbg_sync_r2.py",
)
_REPO_PREFIX = "static/"


def scripts_root() -> Traversable:
    """Where the scripts live inside the installed package."""
    return resources.files(__package__).joinpath("data").joinpath("static")


def installed_root() -> Path | None:
    """:func:`scripts_root` as a directory on disk, or None for a zipped installation."""
    root = scripts_root()
    return root if isinstance(root, Path) and root.is_dir() else None


def relative_path(sync_script: str) -> str:
    """``static/ida/x64dbg_sync.py`` (a registry ``sync_script``) -> ``ida/x64dbg_sync.py``."""
    if not sync_script.startswith(_REPO_PREFIX) or sync_script[len(_REPO_PREFIX):] not in SCRIPT_FILES:
        raise ValueError(f"not a packaged static script: {sync_script!r}")
    return sync_script[len(_REPO_PREFIX):]


def packaged(tool_id: str) -> Traversable:
    """The packaged sync script of static tool ``tool_id``."""
    return _join(scripts_root(), relative_path(static_tools.get_tool(tool_id).sync_script))


def _join(root: Traversable, rel: str) -> Traversable:
    node = root
    for part in rel.split("/"):
        node = node.joinpath(part)
    return node


def copy_to(dest: Path, *, force: bool = False) -> list[str]:
    """Copy the scripts into ``dest`` (created if needed) with the package layout; returns the
    copied paths relative to ``dest``. Refuses (InvalidArgument, nothing written) when one of
    the files already exists, unless ``force``: then each file is written to a temporary file
    and renamed over the old one (a symlink there is replaced, never written through)."""
    if dest.exists() and not dest.is_dir():
        raise InvalidArgument(f"{dest} is not a directory", stage="static-scripts",
                              details={"path": str(dest)})
    root = scripts_root()
    targets = [(rel, dest.joinpath(*rel.split("/"))) for rel in SCRIPT_FILES]
    existing = [rel for rel, target in targets if target.exists() or target.is_symlink()]
    if existing and not force:
        raise InvalidArgument(f"{', '.join(existing)} already exist in {dest}; refusing to overwrite",
                              stage="static-scripts",
                              hint="pass --force to replace them, or pick another --dest",
                              details={"path": str(dest), "existing": existing})
    try:
        for rel, target in targets:
            target.parent.mkdir(parents=True, exist_ok=True)
            data = _join(root, rel).read_bytes()
            if force:
                _replace(target, data)
            else:
                with open(target, "xb") as f:  # O_EXCL: never follows or replaces what appeared meanwhile
                    f.write(data)
    except OSError as e:
        raise TransferError(f"cannot copy the static scripts to {dest}: {e.strerror or e}",
                            stage="static-scripts", details={"path": str(dest)}) from None
    return [rel for rel, _target in targets]


def _replace(target: Path, data: bytes) -> None:
    fd, temp_name = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.chmod(temp_name, 0o644)
        os.replace(temp_name, target)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temp_name)
        raise
