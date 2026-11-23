"""Tests for guest path validation and the vmrun-backed VixChannel.

Output-format fixtures under tests/fixtures/transfer/:
- ``*_synth.txt`` are synthesized from the format strings embedded in the
  vmrun 1.17.0 binary (``Process list``, ``pid=%ld, owner=%s, cmd=%s``,
  ``Directory list``, ``The %s %s.``). Guest operations were NOT run against a
  real VM to produce them (safety rule), so they are format-accurate but not
  recorded output.
- ``*_real.txt`` were captured from the real vmrun on this host.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.fakes.fake_vmrun import FakeVmrunRunner
from x64dbg_vm_gateway import contracts
from x64dbg_vm_gateway.contracts import VmrunResult
from x64dbg_vm_gateway.errors import (
    GuestAuthFailed,
    GuestOperationError,
    PathNotAllowed,
    ToolsNotRunning,
    TransferError,
    VmNotRunning,
    VmrunError,
    VmrunTimeout,
)
from x64dbg_vm_gateway.guest import VixChannel, validate_guest_path

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "transfer"


def _fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


# ── validate_guest_path ─────────────────────────────────────────────
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("C:\\mcp\\jobs\\j1\\in", "C:\\mcp\\jobs\\j1\\in"),
        ("c:/mcp/jobs", "C:\\mcp\\jobs"),
        ("C:\\mcp\\jobs\\", "C:\\mcp\\jobs"),
        ("C:\\", "C:\\"),
        ("D:\\a\\console.txt", "D:\\a\\console.txt"),
        ("C:\\a\\COM10", "C:\\a\\COM10"),
        ("C:\\a\\nul_x", "C:\\a\\nul_x"),
        ("C:\\a\\.hidden", "C:\\a\\.hidden"),
        ("C:\\a\\b.c.d", "C:\\a\\b.c.d"),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
        ("C:\\a\\x [1].txt", "C:\\a\\x [1].txt"),
    ],
)
def test_validate_guest_path_accepts_and_normalizes(raw, expected):
    assert validate_guest_path(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "mcp\\jobs",  # relative
        "\\mcp\\jobs",  # rooted, no drive
        "C:mcp\\jobs",  # drive-relative
        "\\\\server\\share\\x",  # UNC
        "//server/share/x",  # UNC with forward slashes
        "\\\\?\\C:\\x",  # Win32 device namespace
        "\\\\.\\PhysicalDrive0",  # device
        "\\??\\C:\\x",  # NT object namespace
        "C:\\a\\..\\b",
        "C:\\a\\..",
        "C:/a/../b",
        "C:\\a\\.\\b",
        "C:\\a\\file.txt:stream",  # ADS
        "C:\\a\\file.txt::$DATA",
        "C:\\a:b\\c",
        "C:\\a\\CON",
        "C:\\a\\con",
        "C:\\a\\con.txt",
        "C:\\a\\NUL.tar.gz",
        "C:\\PRN\\x",
        "C:\\a\\AUX",
        "C:\\COM1\\x",
        "C:\\a\\com9.log",
        "C:\\a\\LPT1",
        "C:\\a\\lpt9.txt",
        "C:\\a\\CON .txt",  # Windows trims spaces before the extension
        "C:\\a\\CONIN$",
        "C:\\a\\b.",  # trailing dot
        "C:\\a\\b ",  # trailing space
        "C:\\a. \\b",
        "C:\\a\\b\nc",
        "C:\\a\\b\rc",
        "C:\\a\\b\tc",
        "C:\\a\\b\x00c",
        "C:\\a\\b\x7fc",
        'C:\\a\\"b',
        "C:\\a\\'b",
        "C:\\a\\b\u2019c",  # PowerShell treats smart quotes as quotes
        "C:\\a\\b\u201cc",
        "C:\\a\\*",
        "C:\\a\\b?c",
        "C:\\a|b",
        "C:\\a<b",
        "C:\\a>b",
        "C:\\" + "a" * 300,  # longer than MAX_PATH
    ],
)
def test_validate_guest_path_rejects(raw):
    with pytest.raises(PathNotAllowed) as ei:
        validate_guest_path(raw)
    assert ei.value.code == "PATH_NOT_ALLOWED"
    assert "reason" in ei.value.details


@pytest.mark.parametrize("raw", [None, 5, b"C:\\a", Path("/tmp/x")])
def test_validate_guest_path_rejects_non_str(raw):
    with pytest.raises(PathNotAllowed):
        validate_guest_path(raw)  # type: ignore[arg-type]


def test_validate_guest_path_message_does_not_echo_control_chars():
    with pytest.raises(PathNotAllowed) as ei:
        validate_guest_path("C:\\a\nINJECTED")
    assert "\n" not in ei.value.message


def test_validate_guest_path_must_be_under_single_root():
    root = "C:\\mcp\\jobs\\j1"
    assert validate_guest_path("C:\\mcp\\jobs\\j1\\out\\x.bin", must_be_under=root) == \
        "C:\\mcp\\jobs\\j1\\out\\x.bin"
    assert validate_guest_path("c:\\MCP\\Jobs\\J1\\x", must_be_under=root) == "C:\\MCP\\Jobs\\J1\\x"
    assert validate_guest_path("C:\\mcp\\jobs\\j1", must_be_under=root) == "C:\\mcp\\jobs\\j1"
    with pytest.raises(PathNotAllowed):
        validate_guest_path("C:\\mcp\\jobs\\j10\\x", must_be_under=root)  # sibling prefix trick
    with pytest.raises(PathNotAllowed):
        validate_guest_path("C:\\mcp\\jobs\\x", must_be_under=root)
    with pytest.raises(PathNotAllowed):
        validate_guest_path("D:\\mcp\\jobs\\j1\\x", must_be_under=root)


def test_validate_guest_path_must_be_under_list_and_drive_root():
    roots = ["C:\\mcp\\jobs\\j1", "D:\\dumps\\"]
    assert validate_guest_path("D:\\dumps\\a.bin", must_be_under=roots) == "D:\\dumps\\a.bin"
    assert validate_guest_path("C:\\mcp\\jobs\\j1\\a", must_be_under=roots) == "C:\\mcp\\jobs\\j1\\a"
    with pytest.raises(PathNotAllowed):
        validate_guest_path("D:\\dumpsX\\a.bin", must_be_under=roots)
    assert validate_guest_path("C:\\anything\\x", must_be_under="C:\\") == "C:\\anything\\x"
    with pytest.raises(PathNotAllowed):
        validate_guest_path("C:\\x", must_be_under=[])


def test_validate_guest_path_rejects_invalid_root():
    with pytest.raises(PathNotAllowed):
        validate_guest_path("C:\\a\\b", must_be_under="\\\\srv\\share")


# ── VixChannel ──────────────────────────────────────────────────────
@pytest.fixture
def runner() -> FakeVmrunRunner:
    return FakeVmrunRunner()


@pytest.fixture
def chan(runner) -> VixChannel:
    return VixChannel(runner)


def test_vix_channel_satisfies_protocol(chan):
    assert isinstance(chan, contracts.GuestChannel)


def test_every_call_is_a_guest_call_with_timeout(runner, chan):
    runner.handler = lambda cmd, params, guest: VmrunResult(0, "The file exists.", "")
    chan.file_exists("C:\\a.txt")
    chan.delete_file("C:\\a.txt")
    chan.kill_process(42)
    for c in runner.calls:
        assert c["guest"] is True
        assert c["vmx"] is True
        assert c["timeout_s"] > 0


def test_run_program_wait_returns_zero(runner, chan):
    rc = chan.run_program("C:\\Windows\\System32\\cmd.exe", ["/c", "exit"])
    assert rc == 0
    (c,) = runner.calls
    assert c["command"] == "runProgramInGuest"
    assert c["params"] == ("C:\\Windows\\System32\\cmd.exe", "/c", "exit")
    assert c["guest"] is True


def test_run_program_flags_precede_program(runner, chan):
    rc = chan.run_program("C:\\x64dbg\\x64dbg.exe", ["a"], wait=False, interactive=True,
                          active_window=True)
    assert rc is None
    (c,) = runner.calls
    assert c["params"] == ("-noWait", "-activeWindow", "-interactive", "C:\\x64dbg\\x64dbg.exe", "a")


def test_run_program_quotes_args_for_the_guest_command_line(runner, chan):
    chan.run_program("C:\\ps.exe", ["-Command", "(Get-Item 'C:\\a b').Length", "", 'say "hi"'])
    (c,) = runner.calls
    assert c["params"] == ("C:\\ps.exe", "-Command", "\"(Get-Item 'C:\\a b').Length\"", '""',
                           '"say \\"hi\\""')


def test_run_program_quoting_can_be_disabled(runner):
    ch = VixChannel(runner, quote_args=False)
    ch.run_program("C:\\ps.exe", ["a b"])
    assert runner.calls[0]["params"] == ("C:\\ps.exe", "a b")


def test_run_program_timeout_passthrough_and_defaults(runner, chan):
    chan.run_program("C:\\a.exe", timeout_s=12.5)
    chan.run_program("C:\\a.exe")
    chan.run_program("C:\\a.exe", wait=False)
    assert runner.calls[0]["timeout_s"] == 12.5
    assert runner.calls[1]["timeout_s"] >= 60
    assert runner.calls[2]["timeout_s"] > 0


@pytest.mark.parametrize(
    "exc",
    [
        GuestOperationError("Error: Guest program exited with non-zero exit code: 3"),
        VmrunError("vmrun failed", details={"stdout": "Guest program exited with non-zero exit code: 3",
                                            "stderr": ""}),
        GuestOperationError("vmrun failed",
                            details={"stderr": "Error: Guest program exited with non-zero exit code: 3"}),
    ],
)
def test_run_program_nonzero_exit_returns_code(runner, chan, exc):
    runner.queue("runProgramInGuest", exc)
    assert chan.run_program("C:\\a.exe") == 3


def test_run_program_nonzero_exit_in_stdout_returns_code(runner, chan):
    runner.queue("runProgramInGuest", "Guest program exited with non-zero exit code: 255")
    assert chan.run_program("C:\\a.exe") == 255


@pytest.mark.parametrize(
    "exc",
    [
        GuestAuthFailed("Error: Invalid user name or password for the guest OS"),
        ToolsNotRunning("Error: The VMware Tools are not running in the virtual machine"),
        VmrunTimeout("vmrun timed out"),
        GuestOperationError("Error: A file was not found"),
    ],
)
def test_run_program_other_errors_propagate(runner, chan, exc):
    runner.queue("runProgramInGuest", exc)
    with pytest.raises(type(exc)):
        chan.run_program("C:\\a.exe")


def test_run_program_rejects_bad_exe_without_calling_vmrun(runner, chan):
    with pytest.raises(PathNotAllowed):
        chan.run_program("powershell.exe")
    assert runner.calls == []


def test_run_script(runner, chan):
    assert chan.run_script("C:\\Windows\\System32\\cmd.exe", "echo hi > C:\\o.txt") is None
    assert chan.run_script("C:\\Windows\\System32\\cmd.exe", "x", wait=False, timeout_s=5) is None
    c0, c1 = runner.calls
    assert c0["command"] == "runScriptInGuest"
    assert c0["params"] == ("C:\\Windows\\System32\\cmd.exe", "echo hi > C:\\o.txt")
    assert c1["params"] == ("-noWait", "C:\\Windows\\System32\\cmd.exe", "x")
    assert c1["timeout_s"] == 5


def test_copy_to_guest(tmp_path, runner, chan):
    src = tmp_path / "s.bin"
    src.write_bytes(b"x")
    chan.copy_to_guest(src, "C:\\mcp\\in\\s.bin")
    (c,) = runner.calls
    assert c["command"] == "CopyFileFromHostToGuest"
    assert c["params"] == (str(src.resolve()), "C:\\mcp\\in\\s.bin")
    assert c["timeout_s"] >= 300


def test_copy_to_guest_relative_host_path_is_made_absolute(tmp_path, runner, chan, monkeypatch):
    (tmp_path / "-rf").write_bytes(b"x")
    monkeypatch.chdir(tmp_path)
    chan.copy_to_guest(Path("-rf"), "C:\\a")
    host_arg = runner.calls[0]["params"][0]
    assert Path(host_arg).is_absolute() and not host_arg.startswith("-")


def test_copy_to_guest_missing_host_file(tmp_path, runner, chan):
    with pytest.raises(TransferError):
        chan.copy_to_guest(tmp_path / "missing.bin", "C:\\a")
    with pytest.raises(TransferError):
        chan.copy_to_guest(tmp_path, "C:\\a")  # a directory is not a file
    assert runner.calls == []


def test_copy_from_guest(tmp_path, runner, chan):
    dst = tmp_path / "out.zip"
    chan.copy_from_guest("C:\\mcp\\out.zip", dst)
    (c,) = runner.calls
    assert c["command"] == "CopyFileFromGuestToHost"
    assert c["params"] == ("C:\\mcp\\out.zip", str(dst.resolve()))
    assert c["timeout_s"] >= 300


def test_copy_from_guest_host_parent_must_exist(tmp_path, runner, chan):
    with pytest.raises(TransferError):
        chan.copy_from_guest("C:\\mcp\\out.zip", tmp_path / "nope" / "out.zip")
    assert runner.calls == []


def test_list_processes_parses_fixture(runner, chan):
    runner.queue("listProcessesInGuest", _fixture("list_processes_synth.txt"))
    procs = chan.list_processes()
    assert [p.pid for p in procs] == [0, 4, 612, 1234, 2048, 4096]
    assert procs[0].owner == "" and procs[0].cmd == "[System Process]"
    assert procs[1].owner == "NT AUTHORITY\\SYSTEM" and procs[1].cmd == ""
    assert procs[3].owner == "DESKTOP-ABC\\mcp"
    assert procs[3].cmd == '"C:\\tools\\x64dbg\\release\\x64\\x64dbg.exe" a b'
    assert procs[3].image_name == "x64dbg.exe"
    assert procs[4].cmd == '"C:\\mcp\\jobs\\j1\\in\\0123456789ab.exe" --opt=a,b,c "x, y"'
    assert procs[5].cmd == "C:\\Windows\\System32\\notepad.exe C:\\a, b.txt"
    assert runner.calls[0]["command"] == "listProcessesInGuest"
    assert runner.calls[0]["params"] == ()


def test_list_processes_tolerates_crlf_and_count_mismatch(runner, chan):
    runner.queue("listProcessesInGuest",
                 "Process list: 9\r\npid=8, owner=u, cmd=C:\\a.exe\r\n\r\n")
    procs = chan.list_processes()
    assert len(procs) == 1 and procs[0].cmd == "C:\\a.exe"


def test_list_processes_without_header_is_an_error(runner, chan):
    runner.queue("listProcessesInGuest", "something unexpected")
    with pytest.raises(GuestOperationError):
        chan.list_processes()


def test_kill_process(runner, chan):
    chan.kill_process(1234)
    assert runner.calls[0]["command"] == "killProcessInGuest"
    assert runner.calls[0]["params"] == ("1234",)


@pytest.mark.parametrize("pid", [0, -1, True, "12"])
def test_kill_process_rejects_bad_pid(runner, chan, pid):
    with pytest.raises((ValueError, TypeError)):
        chan.kill_process(pid)  # type: ignore[arg-type]
    assert runner.calls == []


def _dir_handler(existing: set[str]):
    def handler(cmd, params, guest):
        if cmd == "directoryExistsInGuest":
            key = params[0].lower()
            return VmrunResult(0, "The directory exists." if key in existing
                               else "The directory does not exist.", "")
        if cmd == "createDirectoryInGuest":
            existing.add(params[0].lower())
        return None
    return handler


def test_mkdir_creates_missing_ancestors_top_down(runner, chan):
    existing = {"c:\\mcp"}
    runner.handler = _dir_handler(existing)
    chan.mkdir("C:\\mcp\\jobs\\j1\\in")
    created = [c["params"][0] for c in runner.calls if c["command"] == "createDirectoryInGuest"]
    assert created == ["C:\\mcp\\jobs", "C:\\mcp\\jobs\\j1", "C:\\mcp\\jobs\\j1\\in"]


def test_mkdir_existing_dir_is_a_single_check(runner, chan):
    runner.handler = _dir_handler({"c:\\mcp\\jobs"})
    chan.mkdir("C:\\mcp\\jobs")
    assert runner.commands() == ["directoryExistsInGuest"]


def test_mkdir_drive_root_is_noop(runner, chan):
    chan.mkdir("C:\\")
    assert "createDirectoryInGuest" not in runner.commands()


class _RacingRunner(FakeVmrunRunner):
    """Another guest actor creates the directory between our check and our create."""

    def __init__(self) -> None:
        super().__init__()
        self.created = False

    def run(self, command, *params, **kw):
        if command == "createDirectoryInGuest":
            self.calls.append({"command": command, "params": params, **kw})
            self.created = True
            raise GuestOperationError("Error: The file already exists")
        if command == "directoryExistsInGuest":
            self.calls.append({"command": command, "params": params, **kw})
            return VmrunResult(0, "The directory exists." if self.created
                               else "The directory does not exist.", "")
        return super().run(command, *params, **kw)


def test_mkdir_tolerates_concurrent_creation():
    r = _RacingRunner()
    VixChannel(r).mkdir("C:\\a")
    assert r.commands() == ["directoryExistsInGuest", "createDirectoryInGuest", "directoryExistsInGuest"]


def test_mkdir_checks_ancestors_bottom_up(runner, chan):
    existing = {"c:\\mcp\\jobs"}
    runner.handler = _dir_handler(existing)
    chan.mkdir("C:\\mcp\\jobs\\j1\\in")
    checked = [c["params"][0] for c in runner.calls if c["command"] == "directoryExistsInGuest"]
    assert checked == ["C:\\mcp\\jobs\\j1\\in", "C:\\mcp\\jobs\\j1", "C:\\mcp\\jobs"]


def test_mkdir_create_failure_propagates(runner, chan):
    runner.handler = _dir_handler(set())
    runner.queue("createDirectoryInGuest", GuestOperationError("Error: Access is denied"))
    with pytest.raises(GuestOperationError):
        chan.mkdir("C:\\a")


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        ("The file exists.", True),
        ("The file does not exist.", False),
        (GuestOperationError("The file does not exist."), False),
        (VmrunError("Error: The file does not exist."), False),
    ],
)
def test_file_exists(runner, chan, response, expected):
    runner.queue("fileExistsInGuest", response)
    assert chan.file_exists("C:\\a.txt") is expected
    assert runner.calls[0]["params"] == ("C:\\a.txt",)


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        ("The directory exists.", True),
        ("The directory does not exist.", False),
        (GuestOperationError("Error: The directory does not exist."), False),
    ],
)
def test_dir_exists(runner, chan, response, expected):
    runner.queue("directoryExistsInGuest", response)
    assert chan.dir_exists("C:\\a") is expected
    assert runner.calls[0]["command"] == "directoryExistsInGuest"


@pytest.mark.parametrize(
    "exc",
    [
        GuestAuthFailed("Error: Invalid user name or password for the guest OS"),
        ToolsNotRunning("Error: The VMware Tools are not running in the virtual machine"),
        VmNotRunning("Error: The virtual machine is not powered on"),
        VmrunTimeout("timed out"),
        VmrunError(_fixture("vmrun_cannot_open_vm_real.txt").strip()),
    ],
)
def test_exists_environment_errors_propagate(runner, chan, exc):
    runner.queue("fileExistsInGuest", exc)
    with pytest.raises(type(exc)):
        chan.file_exists("C:\\a.txt")


def test_exists_unexpected_output_is_an_error(runner, chan):
    runner.queue("fileExistsInGuest", "hmm?")
    with pytest.raises(GuestOperationError):
        chan.file_exists("C:\\a.txt")


def test_list_dir_parses_fixture(runner, chan):
    runner.queue("listDirectoryInGuest", _fixture("list_dir_synth.txt"))
    assert chan.list_dir("C:\\mcp\\jobs\\j1\\in") == ["0123456789ab.exe", "dump 1.bin", "notes,v2.txt", "sub"]
    assert runner.calls[0]["params"] == ("C:\\mcp\\jobs\\j1\\in",)


def test_list_dir_empty(runner, chan):
    runner.queue("listDirectoryInGuest", "Directory list: 0\n")
    assert chan.list_dir("C:\\a") == []


def test_list_dir_without_header_is_an_error(runner, chan):
    runner.queue("listDirectoryInGuest", "garbage")
    with pytest.raises(GuestOperationError):
        chan.list_dir("C:\\a")


def test_delete_and_rename(runner, chan):
    chan.delete_file("C:\\a\\x.part")
    chan.rename("C:\\a\\x.part", "C:\\a\\x.exe")
    assert runner.calls[0]["command"] == "deleteFileInGuest"
    assert runner.calls[0]["params"] == ("C:\\a\\x.part",)
    assert runner.calls[1]["command"] == "renameFileInGuest"
    assert runner.calls[1]["params"] == ("C:\\a\\x.part", "C:\\a\\x.exe")


BAD = "C:\\a\\..\\b"


@pytest.mark.parametrize(
    "call",
    [
        lambda ch, tmp: ch.run_program(BAD),
        lambda ch, tmp: ch.run_script(BAD, "x"),
        lambda ch, tmp: ch.copy_to_guest(tmp / "f", BAD),
        lambda ch, tmp: ch.copy_from_guest(BAD, tmp / "o"),
        lambda ch, tmp: ch.mkdir(BAD),
        lambda ch, tmp: ch.file_exists(BAD),
        lambda ch, tmp: ch.dir_exists(BAD),
        lambda ch, tmp: ch.list_dir(BAD),
        lambda ch, tmp: ch.delete_file(BAD),
        lambda ch, tmp: ch.rename(BAD, "C:\\ok"),
        lambda ch, tmp: ch.rename("C:\\ok", BAD),
    ],
)
def test_every_guest_path_is_validated(tmp_path, runner, chan, call):
    (tmp_path / "f").write_bytes(b"x")
    with pytest.raises(PathNotAllowed):
        call(chan, tmp_path)
    assert runner.calls == []


def test_must_be_under_does_not_apply_multichar_case_mappings():
    # 'ß'.upper() == 'SS' and 'ß'.casefold() == 'ss', but NTFS keeps them distinct directories.
    with pytest.raises(PathNotAllowed):
        validate_guest_path("C:\\mass\\x", must_be_under="C:\\ma\u00df")
    assert validate_guest_path("C:\\MA\u1e9e\\x", must_be_under="C:\\ma\u00df") == "C:\\MA\u1e9e\\x"


def test_copy_from_guest_refuses_symlink_or_directory_destination(tmp_path, runner, chan):
    target = tmp_path / "victim.txt"
    target.write_bytes(b"keep")
    link = tmp_path / "link"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlinks not available")
    with pytest.raises(TransferError):
        chan.copy_from_guest("C:\\a.bin", link)
    with pytest.raises(TransferError):
        chan.copy_from_guest("C:\\a.bin", tmp_path)
    assert runner.calls == []


def test_run_program_rejects_non_str_args(runner, chan):
    with pytest.raises(TypeError):
        chan.run_program("C:\\a.exe", ["ok", 5])  # type: ignore[list-item]
    assert runner.calls == []


@pytest.mark.parametrize("kw", [{"timeout_s": 0}, {"run_timeout_s": -1}, {"copy_timeout_s": 0}])
def test_vix_channel_rejects_non_positive_timeouts(runner, kw):
    with pytest.raises(ValueError):
        VixChannel(runner, **kw)


def test_parsers_are_exported():
    from x64dbg_vm_gateway.guest import parse_dir_list, parse_process_list

    assert parse_dir_list("Directory list: 1\nx\n") == ["x"]
    assert parse_process_list("Process list: 1\npid=7, owner=a, cmd=b\n")[0].pid == 7
