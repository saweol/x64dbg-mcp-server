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
  written before an ``exit`` or a crash is still captured.

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
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath

from .contracts import GuestChannel
from .errors import GatewayError, PathNotAllowed, TransferError
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
_PARAM_NAME_RE = re.compile(r"-[A-Za-z_][A-Za-z0-9_]*:?")
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


def _ps_arg(arg: str) -> str:
    """A ``-Name`` token stays a parameter name; anything else becomes a literal."""
    return arg if _PARAM_NAME_RE.fullmatch(arg) else ps_quote(arg)


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


def build_wrapper(script: str, *, out_path: str | None, tmp_dir: str) -> str:
    """Wrap ``script`` so its streams land in ``out_path`` (UTF-8) and its exit code is defined.

    With ``out_path=None`` all output is discarded. ``script`` is inserted
    verbatim on its own lines, so here-strings keep their column-0 terminators.
    """
    head = "$ProgressPreference = 'SilentlyContinue'\n$__mcpRc = 0\n"
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
    """Best-effort removal of a guest temp file; never masks the caller's outcome."""
    try:
        channel.delete_file(guest_path)
    except GatewayError as exc:
        log.debug("could not delete guest temp file %s (%s)", guest_path, exc.code)


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
    return text.lstrip("\ufeff").replace("\r\n", "\n")


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
        return _decode_output(data[:max_bytes]) + _TRUNCATED
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
    (it must be a valid absolute guest path without whitespace).
    """
    _check_script(script)
    tmp_dir = _check_tmp_dir(guest_tmp_dir)
    token = secrets.token_hex(8)
    out_path = _gjoin(tmp_dir, f"ps-{token}.out") if capture else None
    wrapper = build_wrapper(script, out_path=out_path, tmp_dir=tmp_dir)
    encoded = encode_command(wrapper)
    guest_ps1: str | None = None
    try:
        if len(encoded) <= max_encoded_chars:
            args = [*PS_BASE_ARGS, "-EncodedCommand", encoded]
            mode = "encoded"
        else:
            guest_ps1 = _gjoin(tmp_dir, f"ps-{token}.ps1")
            channel.mkdir(tmp_dir)
            _copy_text(channel, wrapper, guest_ps1)
            args = [*PS_BASE_ARGS, "-File", guest_ps1]
            mode = "file"
        rc = channel.run_program(POWERSHELL_EXE, args, wait=True, timeout_s=timeout_s)
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
    timeout_s: float = DEFAULT_TIMEOUT_S,
    guest_tmp_dir: str = DEFAULT_GUEST_TMP_DIR,
    capture: bool = True,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
) -> PsResult:
    """Copy a host ``.ps1`` (which may declare ``param()``) to the guest and run it as a file.

    The script is invoked as ``& '<guest copy>' <args>`` from a small wrapper sent
    with ``-EncodedCommand``: arguments become PowerShell literals instead of
    command-line text, so no vmrun quoting can break them. An argument that looks
    like ``-Name`` (or ``-Name:``) is passed as a parameter name, everything else
    as a single-quoted string. The exit code is the script's ``exit N`` (as with
    ``powershell -File``), 1 for an escaped terminating error, otherwise the last
    ``$LASTEXITCODE`` it left behind (0 when it ran no failing native command).
    The guest copy is deleted afterwards.
    """
    src = Path(local_ps1)
    if not src.is_file():
        raise TransferError("PowerShell script not found on the host", stage="powershell",
                            details={"host_path": str(src)})
    argv = list(args)
    if not all(isinstance(a, str) for a in argv):
        raise TypeError("script arguments must be str")
    quoted = [_ps_arg(a) for a in argv]  # validates every argument before touching the guest
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
