"""Host-OS abstraction layer (plan 5.2 "vmrun discovery", 6.3 "host OS handling").

Everything that differs between Linux, Windows and macOS hosts lives here so the
rest of the gateway stays OS-agnostic. Every function takes the OS name
(``platform.system()`` spelling: "Linux", "Windows", "Darwin") and its I/O
primitives as injectable parameters, so all three OSes are testable on any host.

Thread-safety: all functions are pure apart from the injected I/O callables and
are safe to call concurrently.
"""

from __future__ import annotations

import codecs
import ntpath
import os
import platform as _stdlib_platform
import shutil
import subprocess
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from .errors import ConfigError, VmrunNotFound

LINUX_VMRUN = "/usr/bin/vmrun"
MACOS_VMRUN = "/Applications/VMware Fusion.app/Contents/Library/vmrun"
WINDOWS_VMRUN_DEFAULT = "C:\\Program Files (x86)\\VMware\\VMware Workstation\\vmrun.exe"
WINDOWS_REGISTRY_KEYS = (
    "SOFTWARE\\WOW6432Node\\VMware, Inc.\\VMware Workstation",
    "SOFTWARE\\VMware, Inc.\\VMware Workstation",
)
WINDOWS_REGISTRY_VALUE = "InstallPath"

# subprocess.CREATE_NO_WINDOW only exists on Windows builds of Python.
CREATE_NO_WINDOW = 0x08000000

VMRUN_TYPES = ("ws", "fusion")

RegistryReader = Callable[[str, str], "str | None"]
Which = Callable[..., "str | None"]


def host_system(system: str | None = None) -> str:
    """Return ``system`` or the running interpreter's OS name."""
    return system or _stdlib_platform.system()


# ── vmrun discovery ─────────────────────────────────────────────────
def _windows_registry_reader(key: str, value: str) -> str | None:
    """Read ``HKLM\\<key>\\<value>``; only usable on a Windows interpreter."""
    import winreg  # type: ignore[import-not-found]  # Windows-only stdlib module

    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key) as handle:  # type: ignore[attr-defined]
        data, _kind = winreg.QueryValueEx(handle, value)  # type: ignore[attr-defined]
    return str(data) if data else None


def find_vmrun(
    configured: str | None = "auto",
    *,
    system: str | None = None,
    env: Mapping[str, str] | None = None,
    which: Which = shutil.which,
    exists: Callable[[str], bool] = os.path.exists,
    registry_reader: RegistryReader | None = None,
) -> str:
    """Locate the vmrun executable.

    Order: an explicit ``configured`` path (must exist, no fallback) >
    Linux: ``PATH`` then ``/usr/bin/vmrun`` >
    Windows: registry ``InstallPath`` + ``vmrun.exe``, the default install
    directory, then ``PATH`` >
    macOS: the Fusion bundle path, then ``PATH``.

    Raises VmrunNotFound whose ``details["tried"]`` lists every location checked.
    """
    sysname = host_system(system)
    environ = os.environ if env is None else env
    tried: list[str] = []

    if configured and configured.strip().lower() != "auto":
        path = os.path.expanduser(configured.strip())
        if exists(path):
            return path
        raise VmrunNotFound(
            f"configured vmrun path does not exist: {path}",
            stage="platform",
            hint="fix profiles.<name>.vmrun or set it to \"auto\"",
            details={"tried": [path], "system": sysname},
        )

    def try_path(candidate: str) -> str | None:
        if candidate in tried:
            return None
        tried.append(candidate)
        return candidate if exists(candidate) else None

    def try_which(name: str) -> str | None:
        search = environ.get("PATH")
        tried.append(f"PATH ({name})")
        found = which(name, path=search)
        return found if found and exists(found) else None

    found: str | None = None
    if sysname == "Windows":
        reader = registry_reader
        if reader is None and _stdlib_platform.system() == "Windows":
            reader = _windows_registry_reader
        if reader is not None:
            for key in WINDOWS_REGISTRY_KEYS:
                try:
                    install = reader(key, WINDOWS_REGISTRY_VALUE)
                except OSError:
                    install = None
                if install:
                    found = try_path(ntpath.join(install, "vmrun.exe"))
                    if found:
                        return found
        for var in ("ProgramFiles(x86)", "ProgramFiles"):
            base = environ.get(var)
            if base:
                found = try_path(ntpath.join(base, "VMware", "VMware Workstation", "vmrun.exe"))
                if found:
                    return found
        found = try_path(WINDOWS_VMRUN_DEFAULT) or try_which("vmrun.exe")
    elif sysname == "Darwin":
        found = try_path(MACOS_VMRUN) or try_which("vmrun")
    else:
        found = try_which("vmrun") or try_path(LINUX_VMRUN)

    if found:
        return found
    raise VmrunNotFound(
        f"vmrun not found on this {sysname} host; tried: {', '.join(tried)}",
        stage="platform",
        hint="install VMware Workstation/Fusion or set profiles.<name>.vmrun to the full vmrun path",
        details={"tried": tried, "system": sysname},
    )


def vmrun_type(configured: str | None, system: str | None = None) -> str:
    """Resolve the ``-T`` host type: "ws" or "fusion" ("auto" -> fusion on macOS)."""
    value = (configured or "auto").strip().lower()
    if value == "auto":
        return "fusion" if host_system(system) == "Darwin" else "ws"
    if value in VMRUN_TYPES:
        return value
    raise ConfigError(f"invalid vmrun_type (expected ws, fusion or auto): {value!r}")


# ── output decoding / subprocess options ───────────────────────────
def _windows_codec(lookup: Callable[[str], codecs.CodecInfo]) -> str:
    # vmrun is a console program: on Windows it writes in the OEM code page.
    for name in ("oem", "mbcs", "cp437"):
        try:
            lookup(name)
        except LookupError:
            continue
        return name
    return "cp437"  # pragma: no cover - cp437 always exists


def decode_output(data: bytes, system: str | None = None, *,
                  lookup: Callable[[str], codecs.CodecInfo] = codecs.lookup) -> str:
    """Decode vmrun output; never raises (undecodable bytes become U+FFFD)."""
    if host_system(system) == "Windows":
        info = lookup(_windows_codec(lookup))
        text, _consumed = info.decode(data, "replace")
        return text
    return data.decode("utf-8", errors="replace")


def subprocess_kwargs(system: str | None = None) -> dict[str, Any]:
    """Extra ``subprocess.Popen`` kwargs: hide the console window on Windows hosts."""
    if host_system(system) == "Windows":
        return {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", CREATE_NO_WINDOW)}
    return {}


# ── permissions ─────────────────────────────────────────────────────
def _secure(path: Path | str, mode: int, system: str | None,
            chmod: Callable[[Any, int], None]) -> bool:
    if host_system(system) == "Windows":
        # NTFS ACLs are not modelled; job dirs live under the user profile.
        return False
    chmod(path, mode)
    return True


def secure_dir(path: Path | str, *, system: str | None = None,
               chmod: Callable[[Any, int], None] = os.chmod) -> bool:
    """chmod 0700 on POSIX hosts. Returns False (no-op) on Windows."""
    return _secure(path, 0o700, system, chmod)


def secure_file(path: Path | str, *, system: str | None = None,
                chmod: Callable[[Any, int], None] = os.chmod) -> bool:
    """chmod 0600 (no exec bit) on POSIX hosts. Returns False (no-op) on Windows."""
    return _secure(path, 0o600, system, chmod)
