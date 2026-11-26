"""The VMs a first ``setup`` offers to choose from (``.vmx`` files VMware knows on this host).

Two sources, both best effort (one that cannot be read adds nothing):

- ``vmrun list``: the VMs running now (``Total running VMs: N`` and one ``.vmx`` path per line);
- the VMware inventory, the list Workstation / Fusion show in their library:
  Linux ``~/.vmware/inventory.vmls``, Windows ``%APPDATA%\\VMware\\inventory.vmls``, macOS
  ``~/Library/Application Support/VMware Fusion/vmInventory``. All three use the vmx syntax
  (``vmlistN.config = "<path>"``, ``vmlistN.DisplayName = "<name>"``; folders are entries
  whose config is not a ``.vmx``).

Running VMs come first, then the inventory entries whose ``.vmx`` file still exists.
Nothing here touches a VM: ``vmrun list`` only asks VMware which VMs run.

Thread-safety: pure functions apart from the file reads and the injected runner.
"""

from __future__ import annotations

import os
import posixpath
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath

from .contracts import VmrunRunner
from .errors import GatewayError
from .platform import host_system
from .vmrun import parse_vmx

__all__ = ["VmCandidate", "candidates", "find_vms", "inventory_files", "parse_inventory", "parse_vmrun_list",
           "running_vms"]

_ENTRY_RE = re.compile(r"^vmlist(\d+)\.(config|displayname)$")
_RUNNING_HEADER_RE = re.compile(r"^Total running VMs:\s*\d+\s*$", re.IGNORECASE)
_LIST_TIMEOUT_S = 30.0


@dataclass(frozen=True)
class VmCandidate:
    vmx: str
    name: str | None  # the inventory's display name
    running: bool  # listed by ``vmrun list``


def inventory_files(*, system: str | None = None, environ: Mapping[str, str] | None = None) -> list[Path]:
    """Where this host's VMware keeps its VM library (none when the base folder is unknown)."""
    env = os.environ if environ is None else environ
    sysname = host_system(system)
    if sysname == "Windows":
        appdata = env.get("APPDATA")
        return [Path(str(PureWindowsPath(appdata, "VMware", "inventory.vmls")))] if appdata else []
    home = env.get("HOME") or str(Path.home())
    if sysname == "Darwin":
        return [Path(posixpath.join(home, "Library", "Application Support", "VMware Fusion", "vmInventory"))]
    return [Path(posixpath.join(home, ".vmware", "inventory.vmls"))]


def parse_inventory(text: str) -> list[tuple[str, str | None]]:
    """``(vmx path, display name)`` of every VM entry, in the inventory's order."""
    entries: dict[int, dict[str, str]] = {}
    for key, value in parse_vmx(text).items():
        m = _ENTRY_RE.match(key)
        if m:
            entries.setdefault(int(m.group(1)), {})[m.group(2)] = value
    out: list[tuple[str, str | None]] = []
    for _index, entry in sorted(entries.items()):
        config = entry.get("config", "").strip()
        if config.lower().endswith(".vmx"):
            out.append((config, entry.get("displayname") or None))
    return out


def parse_vmrun_list(text: str) -> list[str]:
    """The ``.vmx`` paths of ``vmrun list`` output."""
    lines = (line.strip() for line in text.splitlines())
    return [line for line in lines if line and not _RUNNING_HEADER_RE.match(line)]


def running_vms(runner: VmrunRunner) -> list[str]:
    """``vmrun list`` through ``runner`` (no vmx, no guest credentials); [] when it fails."""
    try:
        res = runner.run("list", vmx=False, timeout_s=_LIST_TIMEOUT_S)
    except GatewayError:
        return []
    return parse_vmrun_list(res.stdout)


def _key(path: str) -> str:
    return os.path.normcase(os.path.abspath(os.path.expanduser(path)))


def candidates(*, running: Sequence[str], inventory: Sequence[tuple[str, str | None]],
               exists: Callable[[str], bool] = os.path.isfile) -> list[VmCandidate]:
    """Running VMs first (named from the inventory when it lists them), then the inventory
    entries that are not running and whose ``.vmx`` exists; each path once."""
    names: dict[str, str | None] = {}
    for vmx, name in inventory:
        names.setdefault(_key(vmx), name)
    out: list[VmCandidate] = []
    seen: set[str] = set()
    for vmx in running:
        key = _key(vmx)
        if key not in seen:
            seen.add(key)
            out.append(VmCandidate(vmx, names.get(key), True))
    for vmx, name in inventory:
        key = _key(vmx)
        if key not in seen and exists(os.path.expanduser(vmx)):
            seen.add(key)
            out.append(VmCandidate(vmx, name, False))
    return out


def find_vms(runner: VmrunRunner | None, *, files: Sequence[Path] | None = None,
             system: str | None = None, environ: Mapping[str, str] | None = None) -> list[VmCandidate]:
    """The candidates from ``vmrun list`` (when a runner is given) and the inventory ``files``
    (default: :func:`inventory_files`)."""
    running = running_vms(runner) if runner is not None else []
    inventory: list[tuple[str, str | None]] = []
    for path in inventory_files(system=system, environ=environ) if files is None else files:
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        inventory.extend(parse_inventory(text))
    return candidates(running=running, inventory=inventory)
