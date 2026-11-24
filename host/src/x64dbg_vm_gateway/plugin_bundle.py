"""The x64dbg-MCP plugin build bundled with the package.

``scripts/build-release.sh`` builds the plugin with Zig and, before ``uv build``,
copies it into the package as ``data/plugin/x64/x64dbg-MCP-Server.dp64`` and
``data/plugin/x32/x64dbg-MCP-Server.dp32`` (plus ``data/plugin/VERSION``, the
plugin version from build.zig.zon). The binaries are not in git; hatch
``artifacts`` puts them into the wheel and the sdist when they are present. A
wheel built without that step simply has no bundle, and ``install-plugin`` then
needs ``--dist``.

The files are read through :mod:`importlib.resources`, so a zipped installation
works too: :func:`materialize` copies them into a temporary directory laid out
like ``zig build --prefix DIR`` (``<arch>/plugins/<file>``), which is what
``provision.install_plugin`` takes as ``dist_dir``.
"""

from __future__ import annotations

import contextlib
import re
import shutil
import tempfile
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from importlib import resources
from importlib.resources.abc import Traversable
from pathlib import Path
from types import MappingProxyType
from typing import Any

__all__ = ["PLUGIN_FILES", "VERSION_FILE", "PluginBundle", "bundle_root", "find_bundle", "materialize",
           "missing_files"]

#: architecture -> plugin file name (the names ``provision.ARCH_SPECS`` installs)
PLUGIN_FILES: Mapping[str, str] = MappingProxyType({
    "x64": "x64dbg-MCP-Server.dp64",
    "x32": "x64dbg-MCP-Server.dp32",
})
VERSION_FILE = "VERSION"
_VERSION_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+-]{0,31}$")
_MAX_VERSION_BYTES = 256


def bundle_root() -> Traversable:
    """Where the bundled build lives inside the installed package."""
    return resources.files(__package__).joinpath("data").joinpath("plugin")


@dataclass(frozen=True)
class PluginBundle:
    root: Traversable
    version: str | None

    def file(self, arch: str) -> Traversable:
        return self.root.joinpath(arch).joinpath(PLUGIN_FILES[arch])

    def describe(self) -> dict[str, Any]:
        return {"source": "bundled", "version": self.version}


def missing_files(root: Traversable | None = None) -> list[str]:
    """The bundle files missing under ``root`` (default: :func:`bundle_root`), as ``arch/file``."""
    base = bundle_root() if root is None else root
    return [f"{arch}/{name}" for arch, name in PLUGIN_FILES.items()
            if not base.joinpath(arch).joinpath(name).is_file()]


def _read_version(root: Traversable) -> str | None:
    entry = root.joinpath(VERSION_FILE)
    try:
        if not entry.is_file():
            return None
        with entry.open("rb") as f:
            raw = f.read(_MAX_VERSION_BYTES + 1)
    except OSError:
        return None
    if len(raw) > _MAX_VERSION_BYTES:
        return None
    text = raw.decode("utf-8", errors="replace").strip()
    return text if _VERSION_RE.match(text) else None


def find_bundle(root: Traversable | None = None) -> PluginBundle | None:
    """The bundled build, or None when any architecture's file is missing (install_plugin
    needs both)."""
    base = bundle_root() if root is None else root
    if missing_files(base):
        return None
    return PluginBundle(base, _read_version(base))


@contextlib.contextmanager
def materialize(bundle: PluginBundle) -> Iterator[Path]:
    """A temporary directory holding ``<arch>/plugins/<file>`` copies; removed on exit."""
    with tempfile.TemporaryDirectory(prefix="x64dbg-gw-plugin-") as tmp:
        dist = Path(tmp)
        for arch, name in PLUGIN_FILES.items():
            target = dist / arch / "plugins" / name
            target.parent.mkdir(parents=True)
            with bundle.file(arch).open("rb") as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst)
        yield dist
