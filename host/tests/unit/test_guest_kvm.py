"""E3: vmrun program-argument escaping (VixChannel + every caller that builds guest argv).

Real-VM evidence (spike VM, vmrun 1.17.0, PowerShell -File script logging
``[Environment]::CommandLine``): vmrun builds the guest command line by wrapping
EVERY program argument in double quotes without escaping anything, e.g. the
arguments ``a b``, ``c"d``, ``plain``, ``e\\f`` arrived as
``"a b" "c"d" "plain" "e\\f"`` and the script received ``a b`` and ``cd plain e\\f``.

The tests model exactly that: :func:`vmrun_command_line` wraps each argument in
quotes like vmrun, and :func:`command_line_to_argv` is an independent reference
implementation of the Windows (CommandLineToArgvW / MSVCRT 2008+) parsing rules.
"""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest

from tests.fakes.fake_guest import FakeGuest
from tests.fakes.fake_powershell import GuestPowerShell as TransferPowerShell
from tests.fakes.fake_vmrun import FakeVmrunRunner
from tests.unit.test_ps import GuestPowerShell
from x64dbg_vm_gateway import provision, ps, transfer
from x64dbg_vm_gateway.contracts import VmrunResult
from x64dbg_vm_gateway.errors import GuestOperationError
from x64dbg_vm_gateway.guest import POWERSHELL_EXE, VixChannel, escape_for_vmrun

PROGRAM = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"


# ── reference model of vmrun + Windows argument parsing ─────────────
def vmrun_command_line(program: str, args: list[str]) -> str:
    """The guest command line vmrun 1.17.0 builds: every element wrapped in quotes, nothing escaped."""
    return " ".join(f'"{a}"' for a in [program, *args])


def command_line_to_argv(cmdline: str) -> list[str]:
    """Reference CommandLineToArgvW / MSVCRT (2008+) parser.

    argv[0]: up to the closing quote when it starts with one (no escapes), else up
    to the first blank. Later arguments: blanks outside quotes separate; 2n
    backslashes + quote -> n backslashes and the quote toggles quoting; 2n+1
    backslashes + quote -> n backslashes and a literal quote; backslashes not
    followed by a quote are literal; inside quotes ``""`` is a literal quote.
    """
    argv: list[str] = []
    i, n = 0, len(cmdline)
    if cmdline.startswith('"'):
        end = cmdline.find('"', 1)
        end = n if end < 0 else end
        argv.append(cmdline[1:end])
        i = end + 1
    else:
        while i < n and cmdline[i] not in " \t":
            i += 1
        argv.append(cmdline[:i])
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
                count = j - i
                if j < n and cmdline[j] == '"':
                    arg.append("\\" * (count // 2))
                    if count % 2:
                        arg.append('"')
                        j += 1
                    i = j
                else:
                    arg.append("\\" * count)
                    i = j
                continue
            if ch == '"':
                if quoted and i + 1 < n and cmdline[i + 1] == '"':
                    arg.append('"')
                    i += 2
                    continue
                quoted = not quoted
                i += 1
                continue
            if ch in " \t" and not quoted:
                break
            arg.append(ch)
            i += 1
        argv.append("".join(arg))


def round_trip(args: list[str]) -> list[str]:
    """What a guest program receives for ``args`` escaped by VixChannel and quoted by vmrun."""
    return command_line_to_argv(vmrun_command_line(PROGRAM, [escape_for_vmrun(a) for a in args]))[1:]


CASES = [
    "a b",
    'c"d',
    "e\\",
    'x\\"y',
    "",
    "plain",
    "e\\f",
    "  leading and trailing  ",
    "\t",
    "한글 경로\\파일.exe",
    "\u00e9\u00e8 \u2019quote\u2019 \U0001f600",
    'C:\\a b\\',
    'C:\\path with space\\',
    '\\\\server\\share',
    '"',
    '""',
    '\\"',
    '\\\\"',
    'a\\\\\\b',
    'say "hi" to \\"them\\"',
    "-Command",
    "(Get-Item -LiteralPath 'C:\\a [1]\\b c').Length | Out-File -FilePath 'C:\\o.txt'",
]


# Microsoft's documented examples ("Parsing C command-line arguments", Microsoft C/C++
# docs): raw command-line text -> argv[1:]. Hand-written, so they anchor both the
# reference parser above and platform.split_windows_command_line, which share an algorithm.
MS_DOC_EXAMPLES = [
    ('"a b c" d e', ["a b c", "d", "e"]),
    ('"ab\\"c" "\\\\" d', ['ab"c', "\\", "d"]),
    ('a\\\\\\b d"e f"g h', ["a\\\\\\b", "de fg", "h"]),
    ('a\\\\\\"b c d', ['a\\"b', "c", "d"]),
    ('a\\\\\\\\"b c" d e', ["a\\\\b c", "d", "e"]),
    ('a"b"" c d', ['ab" c d']),
]


def _splitters():
    from x64dbg_vm_gateway.platform import split_windows_command_line

    return [command_line_to_argv, split_windows_command_line]


@pytest.mark.parametrize(("cmdline", "expected"), MS_DOC_EXAMPLES)
@pytest.mark.parametrize("split", _splitters(), ids=["reference", "platform"])
def test_parsers_agree_with_microsofts_documented_examples(split, cmdline, expected):
    assert split("prog.exe " + cmdline)[1:] == expected
    assert split('"C:\\Program Files\\p.exe" ' + cmdline)[1:] == expected


@pytest.mark.parametrize("split", _splitters(), ids=["reference", "platform"])
def test_both_parsers_round_trip_every_case(split):
    cmdline = vmrun_command_line(PROGRAM, [escape_for_vmrun(a) for a in CASES])
    argv = split(cmdline)
    assert argv[0] == PROGRAM and argv[1:] == CASES


def test_argv0_takes_no_escapes():
    from x64dbg_vm_gateway.platform import split_windows_command_line

    for split in (command_line_to_argv, split_windows_command_line):
        assert split('"C:\\a\\" b') == ["C:\\a\\", "b"]  # a backslash before argv[0]'s quote is literal
        assert split("C:\\x.exe\t\"q r\"") == ["C:\\x.exe", "q r"]


# ── the reference model reproduces the E3 measurement ──────────────
def test_reference_parser_reproduces_the_e3_measurement():
    # vmrun's raw wrapping of unescaped arguments, as measured in the guest.
    cmdline = vmrun_command_line("C:\\x\\powershell.exe", ["-File", "C:\\mcp\\tmp\\cl.ps1",
                                                          "a b", 'c"d', "plain", "e\\f"])
    assert cmdline.endswith('"a b" "c"d" "plain" "e\\f"')
    argv = command_line_to_argv(cmdline)
    assert argv[3:] == ["a b", "cd plain e\\f"]


def test_old_list2cmdline_prequoting_breaks_under_vmrun_wrapping():
    # Control: the previous behaviour (MSVCRT pre-quoting) is what E3 caught failing.
    pre = [subprocess.list2cmdline([a]) for a in ["a b", "e\\"]]
    argv = command_line_to_argv(vmrun_command_line(PROGRAM, pre))[1:]
    assert argv != ["a b", "e\\"]


# ── escape_for_vmrun ────────────────────────────────────────────────
@pytest.mark.parametrize("arg", CASES)
def test_escape_for_vmrun_round_trips_through_vmrun_quoting(arg):
    assert round_trip([arg]) == [arg]


def test_all_cases_round_trip_together():
    assert round_trip(CASES) == CASES


def test_escape_rules():
    assert escape_for_vmrun("plain") == "plain"
    assert escape_for_vmrun("a b") == "a b"  # never adds outer quotes: vmrun does that
    assert escape_for_vmrun("") == ""
    assert escape_for_vmrun('c"d') == 'c\\"d'
    assert escape_for_vmrun('x\\"y') == 'x\\\\\\"y'
    assert escape_for_vmrun("e\\") == "e\\\\"
    assert escape_for_vmrun("e\\f") == "e\\f"  # backslashes not before a quote stay as they are
    assert escape_for_vmrun("a\\\\") == "a\\\\\\\\"


@pytest.mark.parametrize("bad", ["a\x00b", "line\nbreak", "car\rriage", "\n"])
def test_escape_rejects_nul_and_line_breaks(bad):
    with pytest.raises(ValueError):
        escape_for_vmrun(bad)


def test_escape_rejects_non_str():
    with pytest.raises(TypeError):
        escape_for_vmrun(b"bytes")  # type: ignore[arg-type]


# ── VixChannel uses it ──────────────────────────────────────────────
class VmrunWrapEmulator:
    """FakeVmrunRunner handler: models vmrun's quoting and the guest's argv parsing.

    runProgramInGuest arguments are joined the way vmrun joins them and parsed back
    with the reference parser; the resulting argv is handed to a FakeGuest. Other
    guest commands go straight to the FakeGuest.
    """

    _FLAGS = frozenset({"-noWait", "-activeWindow", "-interactive"})

    def __init__(self, guest: FakeGuest) -> None:
        self.guest = guest
        self.command_lines: list[str] = []
        self.received: list[tuple[str, ...]] = []

    def __call__(self, command: str, params: tuple[str, ...], guest: bool) -> VmrunResult:
        g = self.guest
        if command == "runProgramInGuest":
            rest = [p for p in params if p not in self._FLAGS]
            wait = "-noWait" not in params
            cmdline = vmrun_command_line(rest[0], rest[1:])
            self.command_lines.append(cmdline)
            argv = command_line_to_argv(cmdline)
            self.received.append(tuple(argv[1:]))
            code = g.run_program(argv[0], tuple(argv[1:]), wait=wait)
            if code:
                raise GuestOperationError(
                    f"Error: Guest program exited with non-zero exit code: {code}")
            return VmrunResult(0, "", "")
        if command == "fileExistsInGuest":
            ok = g.file_exists(params[0])
            return VmrunResult(0, "The file exists." if ok else "The file does not exist.", "")
        if command == "directoryExistsInGuest":
            ok = g.dir_exists(params[0])
            return VmrunResult(0, "The directory exists." if ok else "The directory does not exist.", "")
        if command == "createDirectoryInGuest":
            g.mkdir(params[0])
        elif command == "CopyFileFromHostToGuest":
            g.copy_to_guest(Path(params[0]), params[1])
        elif command == "CopyFileFromGuestToHost":
            try:
                g.copy_from_guest(params[0], Path(params[1]))
            except GuestOperationError:
                raise GuestOperationError("Error: A file was not found") from None
        elif command == "deleteFileInGuest":
            try:
                g.delete_file(params[0])
            except GuestOperationError:
                raise GuestOperationError("Error: A file was not found") from None
        elif command == "renameFileInGuest":
            g.rename(params[0], params[1])
        elif command == "listProcessesInGuest":
            return VmrunResult(0, f"Process list: {len(g.processes)}\n"
                               + "".join(f"pid={p.pid}, owner={p.owner}, cmd={p.cmd}\n"
                                         for p in g.processes), "")
        else:
            raise AssertionError(f"unexpected vmrun command {command}")
        return VmrunResult(0, "", "")


@pytest.fixture
def wired(fake_guest: FakeGuest) -> tuple[VixChannel, VmrunWrapEmulator, FakeVmrunRunner]:
    runner = FakeVmrunRunner()
    emu = VmrunWrapEmulator(fake_guest)
    runner.handler = emu
    return VixChannel(runner), emu, runner


def test_vix_channel_escapes_by_default_and_never_adds_outer_quotes(wired):
    chan, emu, runner = wired
    chan.run_program("C:\\p.exe", ["a b", 'c"d', "e\\", ""])
    (call,) = runner.calls
    assert call["params"] == ("C:\\p.exe", "a b", 'c\\"d', "e\\\\", "")
    assert emu.received == [("a b", 'c"d', "e\\", "")]


def test_vix_channel_round_trips_every_case(wired):
    chan, emu, _ = wired
    chan.run_program("C:\\p.exe", CASES)
    assert emu.received == [tuple(CASES)]


def test_vix_channel_rejects_unsendable_arguments_before_vmrun(wired):
    chan, _, runner = wired
    with pytest.raises(ValueError):
        chan.run_program("C:\\p.exe", ["ok", "two\nlines"])
    assert runner.calls == []


def test_quote_args_false_passes_arguments_verbatim():
    runner = FakeVmrunRunner()
    chan = VixChannel(runner, quote_args=False)
    chan.run_program("C:\\p.exe", ['"pre quoted"', "e\\"])
    assert runner.calls[0]["params"] == ("C:\\p.exe", '"pre quoted"', "e\\")


def test_vix_channel_documents_e3():
    doc = " ".join((VixChannel.__doc__ or "").split())
    assert "E3" in doc
    assert "wraps every program argument in double quotes" in doc
    assert "escape_for_vmrun" in doc
    assert "quote_args=False" in doc
    assert "list2cmdline" in doc  # says why the old pre-quoting was wrong


# ── callers build argv that survives the wrapping ───────────────────
def test_run_powershell_argv_round_trips(wired, fake_guest, tmp_path, monkeypatch):
    monkeypatch.setattr("tempfile.tempdir", str(tmp_path))
    chan, emu, _ = wired
    GuestPowerShell(fake_guest, lambda body: (0, "ok"))
    res = ps.run_powershell(chan, "Write-Output \"a b\" 'c' \\\\x\\")
    assert res.ok and res.output == "ok"
    (received,) = emu.received
    assert received[:4] == ps.PS_BASE_ARGS and received[4] == "-EncodedCommand"


def test_run_powershell_file_mode_argv_round_trips(wired, fake_guest, tmp_path, monkeypatch):
    monkeypatch.setattr("tempfile.tempdir", str(tmp_path))
    chan, emu, _ = wired
    GuestPowerShell(fake_guest, lambda body: (0, ""))
    ps.run_powershell(chan, "Write-Output 1", max_encoded_chars=10)
    (received,) = emu.received
    assert received[4] == "-File" and received[5].startswith(ps.DEFAULT_GUEST_TMP_DIR + "\\")


def test_schtasks_and_shutdown_argv_round_trip(wired, fake_guest):
    chan, emu, _ = wired
    chan.run_program(provision.SHUTDOWN_EXE, list(provision.REBOOT_ARGS), wait=False)
    chan.run_program(provision.SCHTASKS_EXE, ["/run", "/tn", "MCP x64dbg task"])  # a name with spaces
    assert emu.received == [provision.REBOOT_ARGS, ("/run", "/tn", "MCP x64dbg task")]


def test_transfer_powershell_commands_round_trip(wired, fake_guest, tmp_path, fake_clock):
    # transfer.py sends its PowerShell one-liners as -EncodedCommand (spec item 3: prefer
    # -EncodedCommand for scripts): base64 needs no quoting under any rule, and PowerShell
    # does not re-parse the text as it does a -Command argument.
    chan, emu, _ = wired
    tps = TransferPowerShell(fake_guest)
    fake_guest.on_run_program = tps
    in_dir = "C:\\mcp\\jobs\\job 1\\in"
    fake_guest.mkdir(in_dir)
    data = b"MZ" + bytes(range(256))
    src = tmp_path / "s.bin"
    src.write_bytes(data)
    sha = hashlib.sha256(data).hexdigest()
    final = transfer.upload_sample(chan, src, in_dir, sha256=sha, kind="exe", clock=fake_clock)
    assert fake_guest.read(final) == data
    assert emu.received == [(*ps.PS_BASE_ARGS, "-EncodedCommand", ps.encode_command(tps.commands[0]))]
    assert "'" in tps.commands[0] and " " in tps.commands[0]
    (call,) = [c for c in emu.command_lines if "powershell.exe" in c]
    assert "Get-FileHash" not in call  # the script text is not on the command line


def test_tar_arguments_with_a_drive_root_round_trip(wired, fake_guest):
    # A trailing backslash ("C:\\") used to escape vmrun's closing quote.
    chan, emu, _ = wired
    args = ["-a", "-c", "-f", "C:\\mcp\\jobs\\j\\out.zip", "-C", "C:\\", "."]
    chan.run_program(transfer.TAR_EXE, args)
    assert emu.received == [tuple(args)]


def test_powershell_exe_constant_unchanged():
    assert POWERSHELL_EXE == PROGRAM
