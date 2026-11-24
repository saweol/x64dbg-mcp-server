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
import errno
import os
import secrets
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
    copied paths relative to ``dest``.

    Refuses (InvalidArgument, nothing written) when ``dest`` or a subdirectory it writes into
    (``common``, ``ida``, ...) is a symlink, or when one of the files already exists, unless
    ``force``. Every file is written to a temporary file next to it and renamed into place, so
    an interrupted copy never leaves a truncated script: without ``force`` the rename never
    replaces a file (one that appeared after the check stops the copy with InvalidArgument),
    with ``force`` it replaces the old file (a symlink there is replaced, never written
    through). In both modes the files get the mode of any new file (0o666 minus the umask). An
    OSError (PermissionError, a full disk, ...) becomes TransferError. A run that fails part-way
    can leave the files it copied before the failure in place; run it again with ``force``."""
    try:
        return _copy_to(dest, force)
    except OSError as e:
        where = f" ({e.filename})" if e.filename else ""
        raise TransferError(f"cannot copy the static scripts to {dest}: {e.strerror or e}{where}",
                            stage="static-scripts",
                            hint="check that you may write there, or pick another --dest (files copied "
                                 "before the error stay)",
                            details={"path": str(dest)}) from None


def _copy_to(dest: Path, force: bool) -> list[str]:
    if _is_link(dest):
        raise _symlink_refused(dest, [str(dest)])
    if dest.exists() and not dest.is_dir():
        raise InvalidArgument(f"{dest} is not a directory", stage="static-scripts",
                              details={"path": str(dest)})
    linked = [sub for sub in _SUBDIRS if _is_link(dest.joinpath(sub))]
    if linked:
        raise _symlink_refused(dest, linked)
    targets = [(rel, dest.joinpath(*rel.split("/"))) for rel in SCRIPT_FILES]
    existing = [rel for rel, target in targets if target.exists() or target.is_symlink()]
    if existing and not force:
        raise _exists_refused(dest, existing)
    root = scripts_root()
    for rel, target in targets:
        target.parent.mkdir(parents=True, exist_ok=True)
        if _is_link(target.parent):  # appeared after the check above
            raise _symlink_refused(dest, [rel.split("/")[0]])
        temp = _write_temp(target.parent, target.name, _join(root, rel).read_bytes())
        try:
            if force:
                os.replace(temp, target)
            else:
                _rename_new(temp, target)
        except BaseException as e:
            with contextlib.suppress(OSError):
                os.unlink(temp)
            if isinstance(e, FileExistsError):
                raise _exists_refused(dest, [rel]) from None
            raise
    return [rel for rel, _target in targets]


#: the subdirectories of the layout (each holds scripts)
_SUBDIRS: tuple[str, ...] = tuple(sorted({rel.split("/")[0] for rel in SCRIPT_FILES}))
_O_BINARY = getattr(os, "O_BINARY", 0)  # Windows: no newline translation


def _is_link(path: Path) -> bool:
    """A symlink, or a Windows junction (Python 3.12+ can tell)."""
    is_junction = getattr(path, "is_junction", None)
    return path.is_symlink() or (is_junction is not None and is_junction())


def _symlink_refused(dest: Path, linked: list[str]) -> InvalidArgument:
    return InvalidArgument(f"{', '.join(linked)} in {dest} is a symlink; refusing to write through it",
                           stage="static-scripts",
                           hint="give a --dest whose directories are real directories",
                           details={"path": str(dest), "symlinks": linked})


def _exists_refused(dest: Path, existing: list[str]) -> InvalidArgument:
    return InvalidArgument(f"{', '.join(existing)} already exist in {dest}; refusing to overwrite",
                           stage="static-scripts",
                           hint="pass --force to replace them, or pick another --dest",
                           details={"path": str(dest), "existing": existing})


def _write_temp(directory: Path, name: str, data: bytes) -> Path:
    """A new file holding ``data`` beside ``name`` in ``directory``, created with mode 0o666 so
    that the umask applies as for any new file; flushed to disk before it is renamed."""
    for _attempt in range(100):
        temp = directory / f".{name}.{secrets.token_hex(6)}.tmp"
        try:
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_BINARY, 0o666)
        except FileExistsError:
            continue
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(temp)
            raise
        return temp
    raise FileExistsError(errno.EEXIST, "no free temporary file name", str(directory))


def _rename_new(temp: Path, target: Path) -> None:
    """Rename ``temp`` to ``target`` unless ``target`` exists (FileExistsError then): os.rename
    refuses an existing target on Windows; elsewhere a hard link does, and a file system without
    hard links falls back to a check right before os.rename."""
    if os.name == "nt":
        os.rename(temp, target)
        return
    try:
        os.link(temp, target)
    except FileExistsError:
        raise
    except OSError:  # no hard links here (FAT, some network file systems)
        if os.path.lexists(target):
            raise FileExistsError(errno.EEXIST, "File exists", str(target)) from None
        os.rename(temp, target)
        return
    os.unlink(temp)
