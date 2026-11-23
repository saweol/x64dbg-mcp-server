"""Guest path validation and the vmrun-backed guest channel (plan 3.2 D5, 5.3).

Guest paths are Windows paths and are handled as strings / ``PureWindowsPath``.
Every guest path that reaches vmrun goes through :func:`validate_guest_path`
first, so a hostile or malformed path (UNC, device namespace, ADS, ``..``,
reserved device names, quotes that would break a PowerShell literal, ...)
never reaches the guest.

Thread-safety: :func:`validate_guest_path` is pure. :class:`VixChannel` holds
only immutable configuration plus the runner, so it is as thread-safe as the
runner (the ``VmrunRunner`` contract requires thread safety). Compound guest
operations such as :meth:`VixChannel.mkdir` are not atomic with respect to
other guest actors; ``mkdir`` tolerates a directory appearing concurrently.
"""

from __future__ import annotations

import re
import string
import subprocess
from collections.abc import Iterable, Sequence
from pathlib import Path, PureWindowsPath

from .contracts import GuestProcess, VmrunResult, VmrunRunner
from .errors import (
    GuestAuthFailed,
    GuestOperationError,
    PathNotAllowed,
    SnapshotNotFound,
    ToolsNotRunning,
    TransferError,
    VmLocked,
    VmNotRunning,
    VmrunError,
    VmrunTimeout,
)

__all__ = [
    "GUEST_ENV_ERRORS",
    "MAX_GUEST_PATH",
    "POWERSHELL_EXE",
    "VixChannel",
    "is_reserved_name",
    "parse_dir_list",
    "parse_process_list",
    "validate_guest_path",
]

#: Absolute path of Windows PowerShell 5.1 in the guest (runProgramInGuest needs a full path).
POWERSHELL_EXE = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

#: Classic MAX_PATH minus the terminating NUL. VIX guest operations are not long-path aware.
MAX_GUEST_PATH = 259

#: vmrun errors that describe the VM / Tools / credentials rather than the guest object an
#: operation targeted. They must never be reinterpreted as "file missing" or "exit code".
GUEST_ENV_ERRORS: tuple[type[VmrunError], ...] = (
    VmNotRunning,
    ToolsNotRunning,
    GuestAuthFailed,
    VmrunTimeout,
    VmLocked,
    SnapshotNotFound,
)

_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {f"{dev}{n}" for dev in ("COM", "LPT") for n in "123456789\u00b9\u00b2\u00b3"}
)
# Characters Windows forbids in names, plus every character PowerShell treats as a quote
# (ASCII and the typographic variants), so validated paths are safe inside '...' literals.
_FORBIDDEN_CHARS = frozenset('<>|?*"\'\u2018\u2019\u201a\u201b\u201c\u201d\u201e')
_DRIVE_LETTERS = frozenset(string.ascii_letters)

_EXIT_CODE_RE = re.compile(r"Guest program exited with non-zero exit code:\s*(-?\d+)")
_PROC_RE = re.compile(r"^pid=(\d+), owner=(.*?), cmd=(.*)$")
_NOT_FOUND_RE = re.compile(
    r"\bThe (?:file|directory) does not exist\b"
    r"|\bA file was not found\b"
    r"|\bThe system cannot find the (?:file|path) specified\b",
    re.IGNORECASE,
)
_DETAIL_LIMIT = 500


# ── path validation ─────────────────────────────────────────────────
def is_reserved_name(component: str) -> bool:
    """True if ``component`` is a Windows device name (``CON``, ``nul.txt``, ``COM1.log``, ...).

    Windows ignores the extension and trailing spaces of the base name when it
    resolves device names, so ``"CON .txt"`` is reserved too.
    """
    stem = component.split(".", 1)[0].rstrip(" ")
    return stem.upper() in _RESERVED_NAMES


def _shown(p: object) -> str:
    # repr() escapes control characters, so a hostile path cannot forge log lines.
    text = repr(p)
    return text if len(text) <= 120 else text[:117] + "..."


def _reject(reason: str, p: object) -> PathNotAllowed:
    return PathNotAllowed(
        f"guest path not allowed ({reason}): {_shown(p)}",
        stage="validate",
        details={"reason": reason, "path": _shown(p)},
    )


def _fold(s: str) -> str:
    """Case-fold for Windows-style comparisons: per-character simple lower-casing.

    ``str.casefold``/``str.upper`` apply multi-character mappings (``ß`` -> ``ss``)
    that NTFS does not, which would let distinct directories compare equal.
    """
    out = []
    for ch in s:
        low = ch.lower()
        out.append(low if len(low) == 1 else ch)
    return "".join(out)


def _validate(p: object) -> str:
    if not isinstance(p, str):
        raise _reject("not-a-string", type(p).__name__)
    if not p:
        raise _reject("empty", p)
    if len(p) > MAX_GUEST_PATH:
        raise _reject("too-long", p)
    s = p.replace("/", "\\")
    if s.startswith("\\\\"):
        raise _reject("unc-or-device", p)
    for ch in s:
        o = ord(ch)
        if o < 0x20 or 0x7F <= o <= 0x9F:
            raise _reject("control-char", p)
        if ch in _FORBIDDEN_CHARS:
            raise _reject("forbidden-char", p)
    if len(s) < 3 or s[0] not in _DRIVE_LETTERS or s[1] != ":" or s[2] != "\\":
        raise _reject("not-absolute", p)
    if ":" in s[2:]:
        raise _reject("ads", p)
    components = [c for c in s[3:].split("\\") if c]
    for comp in components:
        if comp in (".", ".."):
            raise _reject("traversal", p)
        if comp[-1] in ". ":
            raise _reject("trailing-dot-space", p)
        if is_reserved_name(comp):
            raise _reject("reserved-name", p)
    return str(PureWindowsPath(s[0].upper() + ":\\" + "\\".join(components)))


def validate_guest_path(p: str, *, must_be_under: str | Iterable[str] | None = None) -> str:
    """Validate a guest path and return its normalized form (``C:\\a\\b``).

    Requires an absolute drive path. Rejects control characters, quotes (including
    the typographic quotes PowerShell honours), wildcard/redirection characters,
    ``.``/``..`` components, UNC and device prefixes (``\\\\``, ``\\\\?\\``, ``\\\\.\\``),
    alternate data streams, reserved device names and components that end in a
    dot or space. With ``must_be_under`` (one root or several) the path must be
    equal to or inside one of the roots, compared case-insensitively.

    The root check is lexical only: it cannot see junctions, symbolic links or
    mount points that the guest created under an allowed root, so a path that
    passes may still resolve to a file elsewhere in the guest. 8.3 short names
    only alias names within the same directory and cannot escape a root, but a
    root spelled in long form does not match the same directory spelled short
    (that fails closed). Treat ``must_be_under`` as a policy filter for
    guest-to-host reads, not as a guarantee against a hostile guest.

    Raises errors.PathNotAllowed for every violation (``details["reason"]``).
    """
    normalized = _validate(p)
    if must_be_under is None:
        return normalized
    roots = [must_be_under] if isinstance(must_be_under, str) else list(must_be_under)
    folded = _fold(normalized)
    for root in roots:
        r = _fold(_validate(root)).rstrip("\\")
        if folded == r or folded.startswith(r + "\\"):
            return normalized
    raise _reject("outside-allowed-roots", p)


# ── vmrun output parsing ────────────────────────────────────────────
def _lines(text: str) -> list[str]:
    return text.replace("\r\n", "\n").replace("\r", "\n").split("\n")


def _clip(text: str) -> str:
    return text if len(text) <= _DETAIL_LIMIT else text[:_DETAIL_LIMIT] + "..."


def _error_texts(exc: VmrunError) -> list[str]:
    texts = [exc.message]
    for key in ("stdout", "stderr"):
        val = exc.details.get(key)
        if isinstance(val, str):
            texts.append(val)
    return texts


def _exit_code_in(texts: Iterable[str]) -> int | None:
    for text in texts:
        m = _EXIT_CODE_RE.search(text)
        if m:
            return int(m.group(1))
    return None


def _split_listing(text: str, header: str, command: str) -> tuple[int, list[str]]:
    """Split vmrun list output into the declared count ``N`` and the lines after the header.

    Trailing blank lines are dropped. Raises GuestOperationError when the header is
    missing or ``N`` is not a non-negative integer.
    """
    lines = _lines(text)
    for i, line in enumerate(lines):
        if line.startswith(header):
            count = line[len(header):].strip()
            if not count.isascii() or not count.isdigit():
                break
            body = lines[i + 1:]
            while body and not body[-1].strip():
                body.pop()
            return int(count), body
    raise GuestOperationError(f"unexpected {command} output", details={"stdout": _clip(text)})


def _count_mismatch(command: str, declared: int, parsed: int, text: str) -> GuestOperationError:
    return GuestOperationError(
        f"{command} output lists {parsed} entries but declares {declared}",
        details={"declared": declared, "parsed": parsed, "stdout": _clip(text)},
    )


def parse_process_list(text: str) -> list[GuestProcess]:
    """Parse ``listProcessesInGuest`` output (``Process list: N`` + ``pid=.., owner=.., cmd=..``).

    ``owner`` and ``cmd`` are guest-controlled and untrusted: a guest process can put
    any text, newlines included, into its command line. Lines that do not start a
    ``pid=`` entry are therefore continuation lines of the previous ``cmd``. Because
    a command line could also contain a complete fake ``pid=`` line, the number of
    entries must equal the declared ``N``; any difference raises GuestOperationError
    instead of returning a list that could hide or invent a process. Callers must
    not decide what to kill from ``cmd``/``owner`` text alone.
    """
    declared, body = _split_listing(text, "Process list:", "listProcessesInGuest")
    procs: list[tuple[int, str, list[str]]] = []
    for line in body:
        m = _PROC_RE.match(line)
        if m:
            procs.append((int(m.group(1)), m.group(2), [m.group(3)]))
        elif procs:
            procs[-1][2].append(line)
        elif line.strip():
            raise GuestOperationError("unexpected listProcessesInGuest output",
                                      details={"stdout": _clip(text)})
    if len(procs) != declared:
        raise _count_mismatch("listProcessesInGuest", declared, len(procs), text)
    return [GuestProcess(pid=pid, owner=owner, cmd="\n".join(cmd)) for pid, owner, cmd in procs]


def parse_dir_list(text: str) -> list[str]:
    """Parse ``listDirectoryInGuest`` output (``Directory list: N`` + one name per line).

    The number of names must equal the declared ``N``; otherwise GuestOperationError.
    """
    declared, body = _split_listing(text, "Directory list:", "listDirectoryInGuest")
    names = [name for name in body if name]
    if len(names) != declared:
        raise _count_mismatch("listDirectoryInGuest", declared, len(names), text)
    return names


# ── VixChannel ──────────────────────────────────────────────────────
class VixChannel:
    """``contracts.GuestChannel`` implemented with vmrun guest operations (VIX).

    Program arguments are quoted with the MSVCRT rules (``subprocess.list2cmdline``)
    before they are handed to vmrun, because vmrun joins the trailing argv
    elements into one guest command line with plain spaces. That joining
    behaviour is inferred, not yet verified against a real guest (Phase 0);
    pass ``quote_args=False`` to hand arguments through verbatim.

    Errors: besides the ``VmrunError`` subclasses listed in the ``GuestChannel``
    contract, every method raises ``PathNotAllowed`` for a guest path that fails
    :func:`validate_guest_path` (before vmrun runs), ``copy_to_guest`` /
    ``copy_from_guest`` raise ``TransferError`` for an unusable host path, and
    ``run_program`` / ``kill_process`` raise ``TypeError`` / ``ValueError`` for
    wrongly typed arguments (caller bugs). All but the last two are
    ``GatewayError`` subclasses.
    """

    def __init__(
        self,
        runner: VmrunRunner,
        *,
        timeout_s: float = 60.0,
        run_timeout_s: float = 300.0,
        copy_timeout_s: float = 1800.0,
        quote_args: bool = True,
    ) -> None:
        for name, val in (("timeout_s", timeout_s), ("run_timeout_s", run_timeout_s),
                          ("copy_timeout_s", copy_timeout_s)):
            if not val > 0:
                raise ValueError(f"{name} must be positive")
        self._runner = runner
        self._timeout_s = float(timeout_s)
        self._run_timeout_s = float(run_timeout_s)
        self._copy_timeout_s = float(copy_timeout_s)
        self._quote_args = quote_args

    def _run(self, command: str, *params: str, timeout_s: float) -> VmrunResult:
        return self._runner.run(command, *params, guest=True, timeout_s=timeout_s, vmx=True)

    # ── programs ────────────────────────────────────────────────────
    def run_program(
        self,
        exe: str,
        args: Sequence[str] = (),
        *,
        wait: bool = True,
        interactive: bool = False,
        active_window: bool = False,
        timeout_s: float | None = None,
    ) -> int | None:
        """Run ``exe`` in the guest. Returns the exit code when ``wait`` (0 on success), else None.

        A non-zero guest exit code is returned, not raised.
        """
        program = validate_guest_path(exe)
        argv = list(args)
        if not all(isinstance(a, str) for a in argv):
            raise TypeError("program arguments must be str")
        if self._quote_args:
            argv = [subprocess.list2cmdline([a]) for a in argv]
        flags: list[str] = []
        if not wait:
            flags.append("-noWait")
        if active_window:
            flags.append("-activeWindow")
        if interactive:
            flags.append("-interactive")
        if timeout_s is None:
            timeout_s = self._run_timeout_s if wait else self._timeout_s
        try:
            res = self._run("runProgramInGuest", *flags, program, *argv, timeout_s=timeout_s)
        except VmrunError as exc:
            code = None if isinstance(exc, GUEST_ENV_ERRORS) else _exit_code_in(_error_texts(exc))
            if code is None:
                raise
            return code
        code = _exit_code_in((res.stdout, res.stderr))
        if code is not None:
            return code
        return 0 if wait else None

    def run_script(self, interpreter: str, script: str, *, wait: bool = True,
                   timeout_s: float | None = None) -> None:
        """Run ``script`` (text) with ``interpreter`` in the guest. vmrun returns no output."""
        interp = validate_guest_path(interpreter)
        flags = [] if wait else ["-noWait"]
        if timeout_s is None:
            timeout_s = self._run_timeout_s if wait else self._timeout_s
        self._run("runScriptInGuest", *flags, interp, script, timeout_s=timeout_s)

    # ── files ───────────────────────────────────────────────────────
    def copy_to_guest(self, host_path: Path, guest_path: str) -> None:
        """Copy a host file into the guest. Raises TransferError if the host file is missing."""
        dst = validate_guest_path(guest_path)
        src = Path(host_path)
        if not src.is_file():
            raise TransferError("host source is not a regular file", stage="copy_to_guest",
                                details={"host_path": str(src)})
        self._run("CopyFileFromHostToGuest", str(src.resolve()), dst, timeout_s=self._copy_timeout_s)

    def copy_from_guest(self, guest_path: str, host_path: Path) -> None:
        """Copy a guest file to the host. The host parent directory must already exist."""
        src = validate_guest_path(guest_path)
        dst = Path(host_path)
        if dst.is_symlink() or dst.is_dir():
            raise TransferError("host destination is a symlink or a directory", stage="copy_from_guest",
                                details={"host_path": str(dst)})
        dst = dst.resolve()
        if not dst.parent.is_dir():
            raise TransferError("host destination directory does not exist", stage="copy_from_guest",
                                details={"host_path": str(dst)})
        self._run("CopyFileFromGuestToHost", src, str(dst), timeout_s=self._copy_timeout_s)

    def delete_file(self, guest_path: str) -> None:
        self._run("deleteFileInGuest", validate_guest_path(guest_path), timeout_s=self._timeout_s)

    def rename(self, src: str, dst: str) -> None:
        a = validate_guest_path(src)
        b = validate_guest_path(dst)
        self._run("renameFileInGuest", a, b, timeout_s=self._timeout_s)

    def list_dir(self, guest_path: str) -> list[str]:
        res = self._run("listDirectoryInGuest", validate_guest_path(guest_path), timeout_s=self._timeout_s)
        return parse_dir_list(res.stdout)

    # ── existence / directories ─────────────────────────────────────
    def _exists(self, command: str, path: str, noun: str) -> bool:
        try:
            res = self._run(command, path, timeout_s=self._timeout_s)
        except VmrunError as exc:
            if isinstance(exc, GUEST_ENV_ERRORS):
                raise
            if any(_NOT_FOUND_RE.search(t) for t in _error_texts(exc)):
                return False
            raise
        text = f"{res.stdout}\n{res.stderr}"
        if re.search(rf"\bThe {noun} does not exist\b", text, re.IGNORECASE):
            return False
        if re.search(rf"\bThe {noun} exists\b", text, re.IGNORECASE):
            return True
        raise GuestOperationError(f"unexpected {command} output", details={"stdout": _clip(res.stdout)})

    def file_exists(self, guest_path: str) -> bool:
        return self._exists("fileExistsInGuest", validate_guest_path(guest_path), "file")

    def dir_exists(self, guest_path: str) -> bool:
        return self._exists("directoryExistsInGuest", validate_guest_path(guest_path), "directory")

    def _create_dir(self, path: str) -> None:
        try:
            self._run("createDirectoryInGuest", path, timeout_s=self._timeout_s)
        except VmrunError as exc:
            # Someone else may have created it between our check and our create.
            if isinstance(exc, GUEST_ENV_ERRORS) or not self._exists("directoryExistsInGuest", path,
                                                                     "directory"):
                raise

    def mkdir(self, guest_path: str) -> None:
        """Create ``guest_path`` and any missing ancestors (no-op if it exists)."""
        target = validate_guest_path(guest_path)
        pw = PureWindowsPath(target)
        if len(pw.parts) <= 1:  # drive root
            return
        if self._exists("directoryExistsInGuest", target, "directory"):
            return
        missing = [target]
        for parent in pw.parents:  # deepest first
            if len(parent.parts) <= 1:
                break
            if self._exists("directoryExistsInGuest", str(parent), "directory"):
                break
            missing.append(str(parent))
        for path in reversed(missing):
            self._create_dir(path)

    # ── processes ───────────────────────────────────────────────────
    def list_processes(self) -> list[GuestProcess]:
        res = self._run("listProcessesInGuest", timeout_s=self._timeout_s)
        return parse_process_list(res.stdout)

    def kill_process(self, pid: int) -> None:
        if isinstance(pid, bool) or not isinstance(pid, int):
            raise TypeError("pid must be an int")
        if pid <= 0:
            raise ValueError("pid must be positive")
        self._run("killProcessInGuest", str(pid), timeout_s=self._timeout_s)
