"""Run PowerShell in the guest through any ``contracts.GuestChannel``.

Phase 0 findings (spike VM, vmrun 1.17.0) this module is built around:

- vmrun joins ``runProgramInGuest`` arguments into one Windows command line and
  inner double quotes are lost, so ``-Command "<script>"`` breaks on any script
  containing ``"``. Scripts are therefore sent as ``-EncodedCommand`` (base64 of
  UTF-16LE), whose alphabet needs no quoting at all.
- ``runProgramInGuest`` returns no program output. The script is wrapped so that
  every output stream (``*>&1``) is written as UTF-8 to a unique guest temp file,
  which is copied back to the host and deleted.
- A long script would exceed the Windows command-line limit (32767 characters,
  minus vmrun's own quoting), so above :data:`MAX_ENCODED_CHARS` the wrapper is
  copied to a guest temp ``.ps1`` (UTF-8 with BOM, which Windows PowerShell 5.1
  needs to read non-ASCII text) and run with ``-File``.

Wrapper semantics (Windows PowerShell 5.1):

- the caller's script runs inside ``& { ... }``, so it must be a plain statement
  list (no ``param()`` block; use :func:`run_powershell_file` for such scripts);
- the exit code is the script's own ``exit N``; otherwise 1 when a terminating
  error escaped the script (its text is appended to the output) and 0 when it
  completed. Non-terminating errors and native exit codes do not change it;
- the script runs inside the wrapper's ``try`` block, and PowerShell lets a
  statement-terminating error (e.g. a .NET method exception) inside a ``try``
  stop the whole block instead of only that statement: such an error ends the
  script with exit code 1. Wrap calls that may fail harmlessly in the script's
  own ``try``/``catch``;
- output lines are flushed as they are produced (``AutoFlush``), so output
  written before an ``exit`` or a crash is still captured;
- its first line is a comment carrying the call's unique tag, so the process
  can be told apart from other PowerShell instances by its command line.

Timeouts: when ``run_program`` times out, vmrun gives up but the guest process
keeps running (and keeps its output file open). The helper then kills the
``powershell.exe`` whose command line carries this call's tag (best effort)
before deleting its temp files; a temp file that still cannot be deleted is
logged as a warning with its path.

These semantics follow PowerShell's documented behaviour and have NOT been run
on a real PowerShell: the unit tests emulate the guest and only check what is
sent to it. Verify them on the spike VM (tests/vm) before relying on details
such as the exit code of an escaped error.

Secrets: script text is never logged. Callers must not embed secrets in scripts
(they would sit in the guest command line / temp file); pass them in a file that
the script deletes, as provision.ps1 does.

Thread-safety: functions are stateless; guest and host temp names are unique per
call, so concurrent calls on a thread-safe channel do not interfere.
"""

from __future__ import annotations

import base64
import codecs
import logging
import re
import secrets
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath

from .contracts import GuestChannel
from .errors import GatewayError, PathNotAllowed, TransferError, VmrunTimeout
from .guest import GUEST_ENV_ERRORS, POWERSHELL_EXE, validate_guest_path

__all__ = [
    "DEFAULT_GUEST_TMP_DIR",
    "DEFAULT_MAX_OUTPUT_BYTES",
    "MAX_ENCODED_CHARS",
    "POWERSHELL_EXE",
    "PS_BASE_ARGS",
    "PsResult",
    "build_wrapper",
    "decode_command",
    "encode_command",
    "fetch_guest_text",
    "ps_quote",
    "run_powershell",
    "run_powershell_file",
]

log = logging.getLogger(__name__)

PS_BASE_ARGS: tuple[str, ...] = ("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass")
DEFAULT_GUEST_TMP_DIR = "C:\\mcp\\tmp"
#: Above this many base64 characters the script goes through a temp ``.ps1`` and ``-File``.
MAX_ENCODED_CHARS = 8000
DEFAULT_MAX_OUTPUT_BYTES = 4 * 1024 * 1024
DEFAULT_TIMEOUT_S = 300.0

# Every character PowerShell treats as a single quote inside a '...' literal.
_SINGLE_QUOTES = "'\u2018\u2019\u201a\u201b"
_PARAM_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# What PowerShell would read as a parameter name if it appeared unquoted.
_PARAM_LIKE_RE = re.compile(r"-[A-Za-z_][A-Za-z0-9_]*:?")
_POWERSHELL_IMAGE = "powershell.exe"
_TRUNCATED = "\n[output truncated]"


@dataclass(frozen=True)
class PsResult:
    exit_code: int
    output: str  # every stream, UTF-8 decoded, CRLF normalised to LF; "" when not captured

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


# ── encoding / quoting ──────────────────────────────────────────────
def encode_command(script: str) -> str:
    """``-EncodedCommand`` form of ``script``: base64 of its UTF-16LE bytes."""
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


def decode_command(encoded: str) -> str:
    """Inverse of :func:`encode_command` (for diagnostics and tests)."""
    return base64.b64decode(encoded.encode("ascii"), validate=True).decode("utf-16-le")


def ps_quote(value: str) -> str:
    """Return ``value`` as a PowerShell single-quoted (verbatim) string literal.

    Every single-quote variant PowerShell honours (ASCII and typographic) is
    doubled, so no ``$``, backtick or double quote inside is interpreted.
    """
    if not isinstance(value, str):
        raise TypeError("ps_quote expects a str")
    if "\x00" in value:
        raise ValueError("PowerShell literals cannot contain NUL")
    return "'" + "".join(ch + ch if ch in _SINGLE_QUOTES else ch for ch in value) + "'"


def _ps_invocation_args(args: Sequence[str], params: Mapping[str, str | int | bool] | None) -> list[str]:
    """PowerShell tokens for ``params`` (named) followed by ``args`` (positional).

    Every value becomes a quoted literal, so no value can turn into a parameter
    name. ``True`` passes a switch, ``False`` passes ``-Name:$false``.
    """
    tokens: list[str] = []
    for name, value in (params or {}).items():
        if not isinstance(name, str) or not _PARAM_NAME_RE.fullmatch(name):
            raise ValueError(f"invalid PowerShell parameter name: {name!r} (give it without the dash)")
        if isinstance(value, bool):
            tokens.append(f"-{name}" if value else f"-{name}:$false")
        elif isinstance(value, str | int):
            tokens += [f"-{name}", ps_quote(str(value))]
        else:
            raise TypeError(f"value of parameter {name!r} must be str, int or bool")
    for arg in args:
        if not isinstance(arg, str):
            raise TypeError("script arguments must be str")
        if _PARAM_LIKE_RE.fullmatch(arg):
            # A -File style "-Name" token: refuse it instead of guessing whether it is a
            # parameter name or a value that happens to start with a dash.
            raise ValueError(f"positional argument {arg!r} looks like a parameter name; "
                             "pass named parameters through params={...}")
        tokens.append(ps_quote(arg))
    return tokens


# ── wrapper ─────────────────────────────────────────────────────────
# Line formatter used by the capturing wrapper: strings verbatim, stream records
# with a prefix, other objects through Out-String (wide, so tables are not cut).
_LINE_FN = """\
function __McpLine($o) {
    if ($o -is [string]) { return $o }
    if ($o -is [System.Management.Automation.ErrorRecord]) { return 'ERROR: ' + $o }
    if ($o -is [System.Management.Automation.InformationalRecord]) {
        return ($o.GetType().Name -replace 'Record$', '').ToUpper() + ': ' + $o.Message
    }
    if ($o -is [System.Management.Automation.InformationRecord]) { return [string]$o.MessageData }
    return ($o | Out-String -Width 4096).TrimEnd()
}"""


def _tag_line(tag: str) -> str:
    return f"# mcp-ps {tag}\n"


def build_wrapper(script: str, *, out_path: str | None, tmp_dir: str, tag: str | None = None) -> str:
    """Wrap ``script`` so its streams land in ``out_path`` (UTF-8) and its exit code is defined.

    With ``out_path=None`` all output is discarded. ``script`` is inserted
    verbatim on its own lines, so here-strings keep their column-0 terminators.
    ``tag`` (hex) becomes a leading comment that identifies this call's process.
    """
    if tag is not None and not re.fullmatch(r"[0-9a-f]{1,32}", tag):
        raise ValueError("tag must be 1-32 lower-case hex digits")
    head = (_tag_line(tag) if tag else "") + "$ProgressPreference = 'SilentlyContinue'\n$__mcpRc = 0\n"
    body = f"\n& {{\n{script}\n}} *>&1"
    if out_path is None:
        return (f"{head}try {{{body} | Out-Null\n}} catch {{\n    $__mcpRc = 1\n}}\nexit $__mcpRc\n")
    return (
        f"{head}{_LINE_FN}\n"
        f"[System.IO.Directory]::CreateDirectory({ps_quote(tmp_dir)}) | Out-Null\n"
        f"$__mcpOut = New-Object System.IO.StreamWriter({ps_quote(out_path)}, $false, "
        "(New-Object System.Text.UTF8Encoding($false)))\n"
        "$__mcpOut.AutoFlush = $true\n"
        f"try {{{body} | ForEach-Object {{ $__mcpOut.WriteLine((__McpLine $_)) }}\n"
        "} catch {\n"
        "    $__mcpRc = 1\n"
        "    $__mcpOut.WriteLine('ERROR: ' + $_)\n"
        "} finally {\n"
        "    $__mcpOut.Dispose()\n"
        "}\n"
        "exit $__mcpRc\n"
    )


# ── helpers ─────────────────────────────────────────────────────────
def _check_tmp_dir(path: str) -> str:
    """Validate the guest temp directory; it must also be safe on a vmrun command line."""
    norm = validate_guest_path(path)
    if any(ch.isspace() for ch in norm):
        # A -File path with spaces would need double quotes, which vmrun drops.
        raise PathNotAllowed(f"guest temp directory must not contain whitespace: {norm!r}",
                             stage="validate", details={"reason": "whitespace", "path": norm})
    return norm


def _gjoin(directory: str, name: str) -> str:
    return str(PureWindowsPath(directory) / name)


def _check_script(script: object) -> str:
    if not isinstance(script, str):
        raise TypeError("script must be a str")
    if "\x00" in script:
        raise ValueError("script must not contain NUL characters")
    return script


def _delete_quiet(channel: GuestChannel, guest_path: str) -> None:
    """Best-effort removal of a guest temp file; never masks the caller's outcome.

    A file that is still there afterwards (locked by a process that outlived a
    timeout, Tools gone, ...) is logged as a warning with its path; a file that
    never existed is not.
    """
    try:
        channel.delete_file(guest_path)
        return
    except GatewayError as exc:
        code = exc.code
    try:
        leaked = channel.file_exists(guest_path)
    except GatewayError:
        leaked = True  # cannot tell: report it rather than hide a leak
    if leaked:
        log.warning("guest temp file %s could not be deleted (%s); remove it by hand", guest_path, code)
    else:
        log.debug("guest temp file %s was not there to delete (%s)", guest_path, code)


def _kill_tagged(channel: GuestChannel, marker: str) -> None:
    """Best effort: kill guest ``powershell.exe`` processes whose command line contains ``marker``."""
    try:
        procs = channel.list_processes()
    except GatewayError as exc:
        log.warning("could not list guest processes to stop a timed-out PowerShell (%s)", exc.code)
        return
    for p in procs:
        if p.image_name != _POWERSHELL_IMAGE or marker not in p.cmd:
            continue
        try:
            channel.kill_process(p.pid)
            log.warning("killed timed-out guest PowerShell (pid %d)", p.pid)
        except GatewayError as exc:
            log.warning("could not kill timed-out guest PowerShell pid %d (%s)", p.pid, exc.code)


def _encoded_marker(encoded: str, tag: str) -> str:
    """The prefix of ``encoded`` fixed by the wrapper's tag line alone (whole base64 groups)."""
    nbytes = len(_tag_line(tag).encode("utf-16-le"))
    return encoded[: (nbytes // 3) * 4]


def _normalise(text: str) -> str:
    return text.lstrip("\ufeff").replace("\r\n", "\n")


def _decode_output(data: bytes) -> str:
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        text = data.decode("utf-16", errors="replace")
    else:
        if data.startswith(codecs.BOM_UTF8):
            data = data[len(codecs.BOM_UTF8):]
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            try:
                text = data.decode("cp949")  # Korean guests: OEM/ANSI code page 949
            except UnicodeDecodeError:
                text = data.decode("utf-8", errors="replace")
    return _normalise(text)


def _decode_head(data: bytes) -> str:
    """Decode the first bytes of a longer file without splitting the last character.

    A cut inside a multi-byte character would make strict UTF-8 decoding fail
    and send the whole text to the cp949 fallback, garbling it. So: UTF-8 with
    up to 3 trailing bytes dropped, then cp949 with up to 1 dropped.
    """
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return _decode_output(data[: len(data) - len(data) % 2])
    if data.startswith(codecs.BOM_UTF8):
        data = data[len(codecs.BOM_UTF8):]
    for encoding, max_cut in (("utf-8", 3), ("cp949", 1)):
        for cut in range(max_cut + 1):
            try:
                return _normalise(data[: len(data) - cut].decode(encoding))
            except UnicodeDecodeError:
                continue
    return _normalise(data.decode("utf-8", errors="replace"))


def fetch_guest_text(channel: GuestChannel, guest_path: str, *,
                     max_bytes: int = DEFAULT_MAX_OUTPUT_BYTES, tail: bool = False) -> str | None:
    """Copy a guest text file into a private host temp dir and decode it.

    Decoding: UTF-16 / UTF-8 BOMs honoured, UTF-8 first, then cp949, then UTF-8
    with replacement characters; CRLF becomes LF. At most ``max_bytes`` are
    decoded: the head (followed by an ``[output truncated]`` marker) or, with
    ``tail=True``, the end of the file starting at a line boundary.

    Returns None when the file cannot be copied for a reason other than the
    guest environment (normally: it does not exist). Guest-environment errors
    (Tools down, timeout, credentials) propagate. The host copy is always removed.
    """
    with tempfile.TemporaryDirectory(prefix="x64dbg-gw-ps-") as tmp:
        local = Path(tmp) / "guest.txt"
        try:
            channel.copy_from_guest(guest_path, local)
        except GatewayError as exc:
            if isinstance(exc, GUEST_ENV_ERRORS):
                raise
            log.debug("guest file %s not copied (%s)", guest_path, exc.code)
            return None
        size = local.stat().st_size
        with local.open("rb") as f:
            if tail and size > max_bytes:
                f.seek(size - max_bytes)
                data = f.read(max_bytes)
                cut = data.find(b"\n")
                return _decode_output(data[cut + 1:] if cut >= 0 else data)
            data = f.read(max_bytes + 1)
    if len(data) > max_bytes:
        return _decode_head(data[:max_bytes]) + _TRUNCATED
    return _decode_output(data)


def _copy_text(channel: GuestChannel, text: str, guest_path: str) -> None:
    """Copy ``text`` to the guest as UTF-8 with BOM (what Windows PowerShell 5.1 expects)."""
    with tempfile.TemporaryDirectory(prefix="x64dbg-gw-ps-") as tmp:
        local = Path(tmp) / "script.ps1"
        local.write_bytes(codecs.BOM_UTF8 + text.encode("utf-8"))
        channel.copy_to_guest(local, guest_path)


def _copy_script_file(channel: GuestChannel, src: Path, guest_path: str) -> None:
    """Copy a local .ps1; a BOM-less non-ASCII UTF-8 file gets a BOM so 5.1 decodes it right."""
    data = src.read_bytes()
    if data.startswith((codecs.BOM_UTF8, codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)) or data.isascii():
        channel.copy_to_guest(src, guest_path)
        return
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        channel.copy_to_guest(src, guest_path)  # some legacy code page: leave it alone
        return
    _copy_text(channel, text, guest_path)


# ── public API ──────────────────────────────────────────────────────
def run_powershell(
    channel: GuestChannel,
    script: str,
    *,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    guest_tmp_dir: str = DEFAULT_GUEST_TMP_DIR,
    capture: bool = True,
    max_encoded_chars: int = MAX_ENCODED_CHARS,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
) -> PsResult:
    """Run ``script`` with Windows PowerShell in the guest and wait for it.

    Returns the exit code (non-zero codes are returned, not raised) and, with
    ``capture``, the combined output of every stream (at most
    ``max_output_bytes`` bytes are read; longer output ends with a
    ``[output truncated]`` marker). A missing output file yields ``""``.

    Raises the channel's errors for guest-environment failures (Tools down,
    timeout, credentials) and PathNotAllowed for an unusable ``guest_tmp_dir``
    (it must be a valid absolute guest path without whitespace). On a timeout
    the guest PowerShell of this call is killed (best effort) before the
    VmrunTimeout propagates.
    """
    _check_script(script)
    tmp_dir = _check_tmp_dir(guest_tmp_dir)
    token = secrets.token_hex(8)
    out_path = _gjoin(tmp_dir, f"ps-{token}.out") if capture else None
    wrapper = build_wrapper(script, out_path=out_path, tmp_dir=tmp_dir, tag=token)
    encoded = encode_command(wrapper)
    guest_ps1: str | None = None
    try:
        if len(encoded) <= max_encoded_chars:
            args = [*PS_BASE_ARGS, "-EncodedCommand", encoded]
            mode, marker = "encoded", _encoded_marker(encoded, token)
        else:
            guest_ps1 = _gjoin(tmp_dir, f"ps-{token}.ps1")
            channel.mkdir(tmp_dir)
            _copy_text(channel, wrapper, guest_ps1)
            args = [*PS_BASE_ARGS, "-File", guest_ps1]
            mode, marker = "file", guest_ps1
        try:
            rc = channel.run_program(POWERSHELL_EXE, args, wait=True, timeout_s=timeout_s)
        except VmrunTimeout:
            _kill_tagged(channel, marker)
            raise
        exit_code = -1 if rc is None else int(rc)
        log.debug("powershell (%s, %d encoded chars) exited with %d", mode, len(encoded), exit_code)
        output = ""
        if out_path is not None:
            output = fetch_guest_text(channel, out_path, max_bytes=max_output_bytes) or ""
    finally:
        for path in (out_path, guest_ps1):
            if path is not None:
                _delete_quiet(channel, path)
    return PsResult(exit_code=exit_code, output=output)


def run_powershell_file(
    channel: GuestChannel,
    local_ps1: Path | str,
    args: Sequence[str] = (),
    *,
    params: Mapping[str, str | int | bool] | None = None,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    guest_tmp_dir: str = DEFAULT_GUEST_TMP_DIR,
    capture: bool = True,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
) -> PsResult:
    """Copy a host ``.ps1`` (which may declare ``param()``) to the guest and run it as a file.

    The script is invoked as ``& '<guest copy>' <params> <args>`` from a small
    wrapper sent with ``-EncodedCommand`` (deliberately not ``powershell -File``,
    whose arguments would be command-line text that vmrun's quoting can break):
    every value becomes a single-quoted PowerShell literal.

    ``params`` maps parameter names (without the dash) to values: a str/int
    gives ``-Name 'value'`` (a value starting with ``-`` stays a value), True a
    switch ``-Name``, False ``-Name:$false``. ``args`` are positional values; one
    that looks like a parameter name (``-Name``) is refused with ValueError
    rather than guessed, so pass named parameters through ``params``.

    The exit code is the script's ``exit N`` (as with ``powershell -File``), 1
    for an escaped terminating error, otherwise the last ``$LASTEXITCODE`` it
    left behind (0 when it ran no failing native command). The guest copy is
    deleted afterwards.
    """
    src = Path(local_ps1)
    if not src.is_file():
        raise TransferError("PowerShell script not found on the host", stage="powershell",
                            details={"host_path": str(src)})
    quoted = _ps_invocation_args(list(args), params)  # validated before touching the guest
    tmp_dir = _check_tmp_dir(guest_tmp_dir)
    guest_ps1 = _gjoin(tmp_dir, f"psf-{secrets.token_hex(8)}.ps1")
    channel.mkdir(tmp_dir)
    try:
        _copy_script_file(channel, src, guest_ps1)
        invocation = " ".join(["&", ps_quote(guest_ps1), *quoted])
        script = f"$global:LASTEXITCODE = 0\n{invocation}\nexit $LASTEXITCODE"
        return run_powershell(channel, script, timeout_s=timeout_s, guest_tmp_dir=tmp_dir,
                              capture=capture, max_output_bytes=max_output_bytes)
    finally:
        _delete_quiet(channel, guest_ps1)
