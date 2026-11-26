"""Host-OS abstraction layer (plan 5.2 "vmrun discovery", 6.3 "host OS handling").

Everything that differs between Linux, Windows and macOS hosts lives here so the
rest of the gateway stays OS-agnostic. Every function takes the OS name
(``platform.system()`` spelling: "Linux", "Windows", "Darwin") and its I/O
primitives as injectable parameters, so all three OSes are testable on any host.

Thread-safety: all functions are pure apart from the injected I/O callables and
are safe to call concurrently.
"""

from __future__ import annotations

import base64
import codecs
import json
import ntpath
import os
import platform as _stdlib_platform
import posixpath
import re
import shutil
import subprocess
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from .errors import ConfigError, GatewayError, VmrunNotFound

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
#: ``subprocess.run``-compatible callable (argv, capture_output=, timeout=, check=, ...).
Runner = Callable[..., Any]

#: Image names of the VMware hypervisor process that runs one VM (``-debug`` / ``-stats``
#: are the diagnostic builds Workstation ships next to it; they run a VM just the same).
VMX_PROCESS_NAMES = frozenset({"vmware-vmx", "vmware-vmx-debug", "vmware-vmx-stats"})
#: Seconds a host process listing (``ps`` / PowerShell) may take.
PROCESS_SCAN_TIMEOUT_S = 20.0
_PROC_MARKER = "MCPPROC:"
_MAC_PS = "/bin/ps"
_PS_LINE_RE = re.compile(r"^\s*(\d+)\s+(.*)$")


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
        # Always pass an explicit search path: with path=None shutil.which would read
        # os.environ, bypassing an injected env. No PATH means the OS default path.
        search = environ.get("PATH", os.defpath)
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


ICACLS_TIMEOUT_S = 30.0


def restrict_to_owner(path: Path | str, *, system: str | None = None,
                      environ: Mapping[str, str] | None = None, run: Runner = subprocess.run,
                      chmod: Callable[[Any, int], None] = os.chmod) -> bool:
    """Make a secret file readable by its owner only: chmod 0600 on POSIX hosts; on Windows
    ``icacls <path> /inheritance:r /grant:r <DOMAIN>\\<user>:F`` (the inherited entries, such as
    the Users group of a folder outside the profile, are dropped; only the current user keeps
    access). Returns False when that could not be done (chmod refused, e.g. on a FAT/exFAT
    volume; no user name; icacls failed); never raises for it."""
    if host_system(system) != "Windows":
        try:
            chmod(path, 0o600)
        except OSError:
            return False
        return True
    env = os.environ if environ is None else environ
    user = env.get("USERNAME")
    if not user:
        return False
    account = f"{env['USERDOMAIN']}\\{user}" if env.get("USERDOMAIN") else user
    icacls = ntpath.join(env.get("SystemRoot") or "C:\\Windows", "System32", "icacls.exe")
    try:
        res = run([icacls, str(path), "/inheritance:r", "/grant:r", f"{account}:F"], capture_output=True,
                  timeout=ICACLS_TIMEOUT_S, check=False, **subprocess_kwargs(system))
    except (OSError, subprocess.SubprocessError):
        return False
    return getattr(res, "returncode", 1) == 0


# ── hypervisor processes of one VM (E1: duplicate VM instances) ─────
def _scan_failed(message: str, **details: Any) -> GatewayError:
    return GatewayError(
        message, stage="platform", details=details,
        hint="the host process table could not be read, so it is unknown whether the VM already "
             "runs; do not start it until this works (check the VM with the hypervisor's own tools)",
    )


def split_windows_command_line(cmdline: str) -> list[str]:
    """Split a Windows command line into argv (MSVCRT / ``CommandLineToArgvW`` rules).

    argv[0] ends at its closing quote (no escapes) or at the first blank. Later
    arguments: blanks outside quotes separate; 2n backslashes before a quote give
    n backslashes and the quote toggles quoting, 2n+1 give n backslashes and a
    literal quote; other backslashes are literal; ``""`` inside quotes is a quote.
    """
    argv: list[str] = []
    n = len(cmdline)
    i = 0
    while i < n and cmdline[i] in " \t":
        i += 1
    if i >= n:
        return argv
    if cmdline[i] == '"':
        end = cmdline.find('"', i + 1)
        end = n if end < 0 else end
        argv.append(cmdline[i + 1:end])
        i = end + 1
    else:
        start = i
        while i < n and cmdline[i] not in " \t":
            i += 1
        argv.append(cmdline[start:i])
    while True:
        while i < n and cmdline[i] in " \t":
            i += 1
        if i >= n:
            return argv
        arg: list[str] = []
        quoted = False
        while i < n:
            ch = cmdline[i]
            if ch == "\\":
                j = i
                while j < n and cmdline[j] == "\\":
                    j += 1
                if j < n and cmdline[j] == '"':
                    arg.append("\\" * ((j - i) // 2))
                    if (j - i) % 2:
                        arg.append('"')
                        j += 1
                else:
                    arg.append("\\" * (j - i))
                i = j
            elif ch == '"':
                if quoted and i + 1 < n and cmdline[i + 1] == '"':
                    arg.append('"')
                    i += 2
                else:
                    quoted = not quoted
                    i += 1
            elif ch in " \t" and not quoted:
                break
            else:
                arg.append(ch)
                i += 1
        argv.append("".join(arg))


def _norm_posix(path: str) -> str:
    return os.path.normcase(os.path.realpath(path))


def _norm_windows(path: str, *, resolve: bool) -> str:
    return ntpath.normcase(ntpath.normpath(os.path.realpath(path) if resolve else path))


def _is_vmx_image(arg0: str, *, windows: bool) -> bool:
    if windows:
        base = ntpath.basename(arg0).lower()
        base = base[:-4] if base.endswith(".exe") else base
    else:
        base = posixpath.basename(arg0)
    return base in VMX_PROCESS_NAMES


def _linux_cmdline(entry: str) -> list[str] | None:
    try:
        with open(os.path.join(entry, "cmdline"), "rb") as f:
            raw = f.read(1 << 20)
    except OSError:  # vanished, permission denied, not a regular file ...
        return None
    if not raw:
        return None  # kernel thread or zombie
    return [part.decode("utf-8", errors="surrogateescape") for part in raw.rstrip(b"\0").split(b"\0")]


def _scan_linux(vmx_path: str, proc_root: str) -> list[int]:
    try:
        names = os.listdir(proc_root)
    except OSError as e:
        raise _scan_failed(f"cannot list {proc_root}: {e.strerror or type(e).__name__}",
                           proc_root=proc_root) from None
    target = _norm_posix(vmx_path)
    found: list[int] = []
    for name in names:
        if not name.isdigit():
            continue
        entry = os.path.join(proc_root, name)
        argv = _linux_cmdline(entry)
        if not argv or not _is_vmx_image(argv[0], windows=False):
            continue
        for arg in argv[1:]:
            if not arg.lower().endswith(".vmx"):
                continue
            if not os.path.isabs(arg):
                try:
                    cwd = os.readlink(os.path.join(entry, "cwd"))
                except OSError:
                    continue  # cannot tell what a relative path meant
                arg = os.path.join(cwd, arg)
            if _norm_posix(arg) == target:
                found.append(int(name))
                break
    return sorted(found)


def _run_scan(run: Runner, argv: list[str], what: str, sysname: str) -> bytes:
    try:
        res = run(argv, capture_output=True, timeout=PROCESS_SCAN_TIMEOUT_S, check=False,
                  **subprocess_kwargs(sysname))
    except subprocess.TimeoutExpired:
        raise _scan_failed(f"{what} did not finish within {PROCESS_SCAN_TIMEOUT_S:g}s",
                           command=what) from None
    except OSError as e:
        raise _scan_failed(f"cannot run {what}: {e.strerror or type(e).__name__}", command=what) from None
    if res.returncode != 0:
        raise _scan_failed(f"{what} exited with code {res.returncode}", command=what,
                           returncode=res.returncode)
    out = res.stdout
    return out if isinstance(out, bytes) else str(out or "").encode("utf-8")


# The image path at the start of a ps command: no " -" / " /" (the start of an argument)
# before the image name, so ".../VMware Fusion.app/.../vmware-vmx" matches and
# "vim /x/vmware-vmx" does not.
_MAC_IMAGE_RE = re.compile(r"^(?:(?:(?!\s[-/]).)*/)?(vmware-vmx(?:-debug|-stats)?)(?=\s|$)")


def _scan_macos(vmx_path: str, run: Runner) -> list[int]:
    # ps joins argv with spaces (no quoting), so the .vmx path is matched as a whole
    # token (start or blank before it, blank or end after it), not split out of argv.
    out = _run_scan(run, [_MAC_PS, "-axww", "-o", "pid=,command="], "ps", "Darwin")
    paths = {vmx_path, os.path.realpath(vmx_path)}
    patterns = [re.compile(r"(?:^|\s)" + re.escape(p) + r"(?:\s|$)") for p in paths]
    found: list[int] = []
    for line in out.decode("utf-8", errors="replace").splitlines():
        m = _PS_LINE_RE.match(line)
        if not m:
            continue
        command = m.group(2)
        if _MAC_IMAGE_RE.match(command) and any(p.search(command) for p in patterns):
            found.append(int(m.group(1)))
    return sorted(found)


_WINDOWS_SCAN_SCRIPT = (
    "$ErrorActionPreference = 'Stop'\n"
    "[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)\n"
    "$names = @(" + ", ".join(f"'{n}.exe'" for n in sorted(VMX_PROCESS_NAMES)) + ")\n"
    "$rows = @(Get-CimInstance -ClassName Win32_Process | Where-Object { $names -contains $_.Name } |\n"
    "    ForEach-Object {\n"
    "        [pscustomobject]@{ ProcessId = [int]$_.ProcessId; CommandLine = $_.CommandLine }\n"
    "    })\n"
    f"'{_PROC_MARKER}' + (ConvertTo-Json -InputObject $rows -Compress)\n"
)


def _windows_powershell(env: Mapping[str, str]) -> str:
    root = env.get("SystemRoot") or env.get("SYSTEMROOT") or "C:\\Windows"
    return ntpath.join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")


def _scan_windows(vmx_path: str, run: Runner, env: Mapping[str, str]) -> list[int]:
    encoded = base64.b64encode(_WINDOWS_SCAN_SCRIPT.encode("utf-16-le")).decode("ascii")
    argv = [_windows_powershell(env), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-EncodedCommand", encoded]
    text = _run_scan(run, argv, "powershell", "Windows").decode("utf-8", errors="replace")
    lines = [ln.strip() for ln in text.splitlines() if ln.strip().startswith(_PROC_MARKER)]
    if not lines:
        raise _scan_failed("the Windows process query printed no result", command="powershell")
    payload = lines[-1][len(_PROC_MARKER):].strip()
    try:
        rows = json.loads(payload) if payload else []
    except ValueError:
        raise _scan_failed("the Windows process query printed unreadable JSON",
                           command="powershell") from None
    if isinstance(rows, dict):
        rows = [rows]  # Windows PowerShell may unwrap a one-element array
    if not isinstance(rows, list):
        raise _scan_failed("the Windows process query printed an unexpected result", command="powershell")
    resolve = _stdlib_platform.system() == "Windows"  # realpath only means something on Windows
    target = _norm_windows(vmx_path, resolve=resolve)
    found: list[int] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        pid, cmdline = row.get("ProcessId"), row.get("CommandLine")
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0 or not isinstance(cmdline, str):
            continue  # another user's process: CommandLine is null without the rights to read it
        argv = split_windows_command_line(cmdline)
        if not argv or not _is_vmx_image(argv[0], windows=True):
            continue
        if any(a.lower().endswith(".vmx") and _norm_windows(a, resolve=resolve) == target for a in argv[1:]):
            found.append(pid)
    return sorted(found)


def find_vmx_processes(
    vmx_path: str,
    *,
    system: str | None = None,
    proc_root: str = "/proc",
    run: Runner = subprocess.run,
    env: Mapping[str, str] | None = None,
) -> list[int]:
    """PIDs of the hypervisor processes (``vmware-vmx``) that run exactly ``vmx_path``.

    ``vmrun list`` only shows the VMs VMware knows about. After a revert an older
    ``vmware-vmx`` of the same .vmx can survive unlisted (E1: the duplicate-instance
    incident in docs/PHASE0_RESULTS.md, section "E2E 중 추가로 확인한 사실"), and
    ``vmrun start`` then runs a second instance with the same MAC and IP. This
    scan asks the host's process table instead:

    - Linux (and any host that is neither Windows nor macOS):
      ``<proc_root>/<pid>/cmdline`` whose argv[0] is a ``vmware-vmx`` image and
      one of whose ``*.vmx`` arguments resolves (realpath, normcase) to
      ``vmx_path``; a relative argument is resolved against
      ``<proc_root>/<pid>/cwd``. Entries that cannot be read are skipped, never
      raised.
    - macOS (Fusion): ``ps -axww -o pid=,command=``; the image must be
      ``vmware-vmx`` and the .vmx path (as given or resolved) a whole token of
      the command (ps does not quote, so argv cannot be split exactly).
    - Windows: Windows PowerShell + CIM ``Win32_Process`` for the ``vmware-vmx``
      images, ``CommandLine`` split with the MSVCRT rules and the .vmx argument
      compared case-insensitively after ``os.path.realpath`` on both sides
      (on a Windows host that is ``GetFinalPathNameByHandleW``, which also maps
      8.3 short names, ``subst`` and mapped drives to one form; a path that
      cannot be opened is resolved only as far as it can be). Processes whose
      command line this user may not read are skipped.

    Subprocesses run with a timeout (:data:`PROCESS_SCAN_TIMEOUT_S`). Returns the
    PIDs sorted. Raises GatewayError (stage ``platform``) when the process table
    itself cannot be read (no ``proc_root``, ``ps`` / PowerShell failed or timed
    out, unreadable output): the answer is then unknown, not "none". On Linux a
    ``/proc`` mounted with ``hidepid`` hides other users' processes, which this
    scan cannot detect.
    """
    sysname = host_system(system)
    if sysname == "Windows":
        return _scan_windows(vmx_path, run, os.environ if env is None else env)
    if sysname == "Darwin":
        return _scan_macos(vmx_path, run)
    return _scan_linux(vmx_path, proc_root)
