"""Tests for vmrun.VmrunCli, vmrun.VmrunProvider and vmrun.NullProvider (plan 5.2, 5.7).

Real vmrun output captured on the dev host lives in tests/fixtures/vmrun/ (see
captures.json for provenance); error texts that could not be captured safely are
marked 'vix-unverified' in error_messages.json.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

from tests.fakes.fake_vm import FakeClock
from tests.fakes.fake_vmrun import FakeVmrunRunner
from x64dbg_vm_gateway import errors
from x64dbg_vm_gateway.contracts import (
    GuestCredentials,
    IsolationReport,
    PowerState,
    Secret,
    Snapshot,
    ToolsState,
    VmProvider,
    VmrunResult,
    VmrunRunner,
)
from x64dbg_vm_gateway.errors import (
    ConfigError,
    GuestAuthFailed,
    GuestOperationError,
    SnapshotNotFound,
    ToolsNotRunning,
    VmLocked,
    VmNotRunning,
    VmrunError,
    VmrunTimeout,
)
from x64dbg_vm_gateway.vmrun import NullProvider, VmrunCli, VmrunProvider

FIX = Path(__file__).resolve().parent.parent / "fixtures" / "vmrun"
RAW = FIX / "raw"
REAL_VMX = "/vms/analysis_vm/analysis_vm.vmx"
PASSWORD = "Pa55-w0rd!unique"
NOISE_OUT = (
    "[AppLoader] Use shipped Linux kernel AIO access library.\n"
    'An up-to-date "libaio" or "libaio1" package from your system is preferred.\n'
)
NOISE_ERR = "Warning: program compiled against libxml 212 using older 209\n"


def raw(name: str) -> tuple[bytes, bytes, int]:
    meta = json.loads((FIX / "captures.json").read_text())["captures"][name]
    return (RAW / f"{name}.stdout").read_bytes(), (RAW / f"{name}.stderr").read_bytes(), meta["returncode"]


# ── fake subprocess.Popen ───────────────────────────────────────────
@dataclass
class Script:
    stdout: bytes = b""
    stderr: bytes = b""
    rc: int = 0
    hang: bool = False  # wait() times out until kill()


class FakeProc:
    def __init__(self, script: Script, argv: list[str], kwargs: dict) -> None:
        self.script = script
        self.argv = argv
        self.kwargs = kwargs
        self.killed = False
        self.returncode: int | None = None
        self.wait_timeouts: list[float | None] = []
        for key, data in (("stdout", script.stdout), ("stderr", script.stderr)):
            sink = kwargs.get(key)
            if data and sink is not None and hasattr(sink, "write"):
                sink.write(data)
                sink.flush()

    def wait(self, timeout: float | None = None) -> int:
        self.wait_timeouts.append(timeout)
        if self.script.hang and not self.killed:
            raise subprocess.TimeoutExpired(self.argv, timeout)
        self.returncode = -9 if self.killed else self.script.rc
        return self.returncode

    def poll(self) -> int | None:
        return self.returncode

    def kill(self) -> None:
        self.killed = True

    def terminate(self) -> None:
        self.killed = True

    def communicate(self, input=None, timeout=None):  # pragma: no cover - not used by temp-file design
        raise AssertionError("VmrunCli must not read output through pipes")


class FakePopen:
    def __init__(self, *scripts: Script, exc: Exception | None = None) -> None:
        self.scripts = list(scripts)
        self.procs: list[FakeProc] = []
        self.exc = exc

    def __call__(self, argv, **kwargs):
        if self.exc is not None:
            raise self.exc
        script = self.scripts.pop(0) if self.scripts else Script()
        proc = FakeProc(script, list(argv), kwargs)
        self.procs.append(proc)
        return proc

    @property
    def last(self) -> FakeProc:
        return self.procs[-1]


def make_cli(popen: FakePopen, *, creds: GuestCredentials | None = None, vmx: str | None = "/vm/x.vmx",
             system: str = "Linux", host_type: str = "ws") -> VmrunCli:
    return VmrunCli("/usr/bin/vmrun", vmx, host_type, creds, system=system, popen=popen, clock=FakeClock())


CREDS = GuestCredentials("mcp", Secret(PASSWORD))


def assert_no_password(exc: BaseException) -> None:
    blob = " ".join([str(exc), repr(exc), repr(exc.args)])
    if isinstance(exc, errors.GatewayError):
        blob += json.dumps(exc.to_dict(), default=str) + repr(exc.details) + str(exc.hint)
    assert PASSWORD not in blob


# ── VmrunCli: argv construction ─────────────────────────────────────
def test_cli_satisfies_runner_protocol():
    assert isinstance(make_cli(FakePopen()), VmrunRunner)


def test_argv_plain_command_with_vmx_and_params():
    p = FakePopen(Script(b"ok\n"))
    res = make_cli(p).run("listSnapshots", "showTree")
    assert p.last.argv == ["/usr/bin/vmrun", "-T", "ws", "listSnapshots", "/vm/x.vmx", "showTree"]
    assert res == VmrunResult(0, "ok", "")


def test_argv_without_vmx():
    p = FakePopen(Script(b"Total running VMs: 0\n"))
    make_cli(p).run("list", vmx=False)
    assert p.last.argv == ["/usr/bin/vmrun", "-T", "ws", "list"]


def test_argv_guest_adds_credentials_before_command():
    p = FakePopen()
    make_cli(p, creds=CREDS).run("listProcessesInGuest", guest=True)
    assert p.last.argv == ["/usr/bin/vmrun", "-T", "ws", "-gu", "mcp", "-gp", PASSWORD,
                           "listProcessesInGuest", "/vm/x.vmx"]


def test_argv_non_guest_never_passes_credentials():
    p = FakePopen()
    make_cli(p, creds=CREDS).run("checkToolsState")
    assert "-gp" not in p.last.argv and PASSWORD not in p.last.argv


def test_host_type_fusion():
    p = FakePopen()
    make_cli(p, host_type="fusion").run("list", vmx=False)
    assert p.last.argv[1:3] == ["-T", "fusion"]


def test_runs_without_shell_and_without_pipes():
    p = FakePopen()
    make_cli(p).run("list", vmx=False)
    kw = p.last.kwargs
    assert not kw.get("shell")
    assert kw.get("stdin") == subprocess.DEVNULL
    # output goes to temporary files, not pipes: a daemon child (vmware-vmx after `start`)
    # that inherits the handles must not be able to block output collection.
    assert kw.get("stdout") not in (None, subprocess.PIPE)
    assert kw.get("stderr") not in (None, subprocess.PIPE)
    assert "creationflags" not in kw


def test_windows_hides_console_and_decodes_oem_fallback():
    p = FakePopen(Script(b"caf\x82\r\n"))
    res = make_cli(p, system="Windows").run("list", vmx=False)
    assert p.last.kwargs["creationflags"] == 0x08000000
    assert res.stdout == "café"


def test_guest_without_credentials_fails_before_spawning():
    p = FakePopen()
    with pytest.raises(GuestAuthFailed) as ei:
        make_cli(p, creds=None).run("listProcessesInGuest", guest=True)
    assert p.procs == []
    assert ei.value.hint


def test_exec_failure_maps_to_vmrun_error():
    p = FakePopen(exc=FileNotFoundError(2, "No such file or directory"))
    with pytest.raises(VmrunError) as ei:
        make_cli(p).run("list", vmx=False)
    assert "/usr/bin/vmrun" in ei.value.message


# ── VmrunCli: output handling ───────────────────────────────────────
def test_noise_lines_filtered_from_real_capture():
    out, err, rc = raw("listSnapshots_showTree")
    p = FakePopen(Script(NOISE_OUT.encode() + out, err, rc))
    res = make_cli(p).run("listSnapshots", "showTree")
    assert res.stderr == ""
    assert res.stdout.splitlines()[0] == "Total snapshots: 33"
    assert "AppLoader" not in res.stdout and "libaio" not in res.stdout
    assert res.stdout.splitlines()[1:3] == ["vbsedit_install", "\tbefore_analysis"]


def test_noise_on_both_streams_is_removed():
    p = FakePopen(Script((NOISE_OUT + "running\n").encode(), (NOISE_OUT + NOISE_ERR).encode()))
    res = make_cli(p).run("checkToolsState")
    assert res == VmrunResult(0, "running", "")


# ── VmrunCli: error mapping ─────────────────────────────────────────
ERROR_CASES = json.loads((FIX / "error_messages.json").read_text())["cases"]
CODE_TO_CLASS = {c.code: c for c in (VmrunError, VmNotRunning, ToolsNotRunning, GuestAuthFailed,
                                     SnapshotNotFound, VmLocked, GuestOperationError)}


@pytest.mark.parametrize("case", ERROR_CASES, ids=lambda c: f"{c['command']}:{c['text'][7:40]}")
def test_error_text_mapping(case):
    text = (case["text"] + "\n").encode()
    if case["stream"] == "stdout":
        script = Script(stdout=text, rc=255)
    else:
        script = Script(stderr=NOISE_ERR.encode() + text, rc=255)
    creds = CREDS if case["guest"] else None
    with pytest.raises(VmrunError) as ei:
        make_cli(FakePopen(script), creds=creds).run(case["command"], guest=case["guest"])
    exc = ei.value
    assert type(exc) is CODE_TO_CLASS[case["code"]], (case, type(exc))
    assert exc.code == case["code"]
    assert case["text"][len("Error: "):] in exc.message
    assert exc.details["returncode"] == 255
    assert_no_password(exc)


@pytest.mark.parametrize("name", ["err_checkToolsState_nonexistent", "err_revertToSnapshot_nonexistent",
                                  "err_unknown_command", "err_start_nonexistent"])
def test_real_captured_errors_are_generic_vmrun_errors(name):
    out, err, rc = raw(name)
    with pytest.raises(VmrunError) as ei:
        make_cli(FakePopen(Script(out, err, rc))).run("x")
    assert type(ei.value) is VmrunError
    assert ei.value.details["stdout"] == out.decode().strip()


def test_words_inside_the_vmx_path_do_not_steer_classification():
    # control: the same text with a neutral path is a generic error; a path containing
    # "snapshot not found"/"not powered on" must not turn it into a specific class.
    for vmx in ("/vm/x.vmx", "/vm/snapshot not found/not powered on/x.vmx"):
        text = f"Error: Cannot open VM: {vmx}, The virtual machine cannot be found\n".encode()
        with pytest.raises(VmrunError) as ei:
            make_cli(FakePopen(Script(text, rc=255)), vmx=vmx).run("revertToSnapshot", "s")
        assert type(ei.value) is VmrunError, vmx


def test_error_line_with_zero_exit_code_is_still_an_error():
    p = FakePopen(Script(b"Error: Failed to lock the file\n", rc=0))
    with pytest.raises(VmLocked):
        make_cli(p).run("snapshot", "s1")


def test_nonzero_exit_without_error_text():
    p = FakePopen(Script(b"something odd\n", NOISE_ERR.encode(), rc=3))
    with pytest.raises(VmrunError) as ei:
        make_cli(p).run("start", "nogui")
    assert type(ei.value) is VmrunError
    assert "3" in ei.value.message
    assert ei.value.details["returncode"] == 3
    assert ei.value.details["stderr"] == ""  # noise filtered from details too


def test_retryable_flags():
    with pytest.raises(VmLocked) as ei:
        make_cli(FakePopen(Script(b"Error: Failed to lock the file\n", rc=255))).run("start")
    assert ei.value.retryable is True
    with pytest.raises(GuestAuthFailed) as ei2:
        make_cli(FakePopen(Script(b"Error: Invalid user name or password for the guest OS\n", rc=255)),
                 creds=CREDS).run("listProcessesInGuest", guest=True)
    assert ei2.value.retryable is False


# ── VmrunCli: masking, truncation, timeout ──────────────────────────
def test_password_masked_in_details_argv():
    p = FakePopen(Script(b"Error: Invalid user name or password for the guest OS\n", rc=255))
    with pytest.raises(GuestAuthFailed) as ei:
        make_cli(p, creds=CREDS).run("listProcessesInGuest", guest=True)
    argv = ei.value.details["argv"]
    assert argv[argv.index("-gp") + 1] == "***"
    assert p.last.argv[p.last.argv.index("-gp") + 1] == PASSWORD  # the real process still gets it
    assert_no_password(ei.value)


def test_password_echoed_by_vmrun_is_scrubbed():
    text = f"Error: login failure for mcp/{PASSWORD} (bad)\n".encode()
    p = FakePopen(Script(text, text, rc=255))
    with pytest.raises(GuestAuthFailed) as ei:
        make_cli(p, creds=CREDS).run("runProgramInGuest", "C:\\x.exe", guest=True)
    assert_no_password(ei.value)
    assert "***" in ei.value.details["stdout"]


def test_details_truncated_to_4kib():
    big = ("Error: Failed to lock the file\n" + "é" * 9000 + "\n").encode()
    p = FakePopen(Script(big, big, rc=255))
    with pytest.raises(VmLocked) as ei:
        make_cli(p).run("start", "x" * 9000)
    d = ei.value.details
    assert len(d["stdout"].encode()) <= 4096
    assert len(d["stderr"].encode()) <= 4096
    assert all(len(a.encode()) <= 4096 for a in d["argv"])
    assert len(ei.value.message.encode()) <= 4096


def test_timeout_kills_process_and_raises():
    p = FakePopen(Script(b"partial\n", hang=True))
    with pytest.raises(VmrunTimeout) as ei:
        make_cli(p, creds=CREDS).run("runProgramInGuest", "C:\\a.exe", guest=True, timeout_s=0.5)
    proc = p.last
    assert proc.killed
    assert proc.wait_timeouts[0] == 0.5
    assert proc.wait_timeouts[1] is not None  # reaping after kill is bounded too
    exc = ei.value
    assert exc.retryable is True
    assert exc.details["argv"][exc.details["argv"].index("-gp") + 1] == "***"
    assert exc.details["stdout"] == "partial"
    assert_no_password(exc)


def test_timeout_is_a_vmrun_error_subclass():
    assert issubclass(VmrunTimeout, VmrunError)


# ── VmrunProvider ───────────────────────────────────────────────────
def provider(tmp_path: Path, runner: FakeVmrunRunner | None = None, vmx_text: str | None = "",
             **kw) -> tuple[VmrunProvider, FakeVmrunRunner, Path]:
    vmdir = tmp_path / "vm"
    vmdir.mkdir(exist_ok=True)
    vmx = vmdir / "x.vmx"
    if vmx_text is not None:
        vmx.write_text(vmx_text)
    r = runner or FakeVmrunRunner()
    return VmrunProvider(r, str(vmx), clock=FakeClock(), **kw), r, vmx


def test_provider_satisfies_protocol(tmp_path):
    prov, _, _ = provider(tmp_path)
    assert isinstance(prov, VmProvider)


def test_power_state_running_when_listed(tmp_path):
    prov, r, vmx = provider(tmp_path)
    r.queue("list", f"Total running VMs: 2\n/other/y.vmx\n{vmx}")
    assert prov.power_state() is PowerState.RUNNING
    assert r.calls[-1]["command"] == "list" and r.calls[-1]["vmx"] is False


def test_power_state_matches_through_symlink(tmp_path):
    prov, r, vmx = provider(tmp_path)
    link = tmp_path / "link"
    link.symlink_to(vmx.parent, target_is_directory=True)
    r.queue("list", f"Total running VMs: 1\n{link / 'x.vmx'}")
    assert prov.power_state() is PowerState.RUNNING


def test_power_state_real_list_fixture_other_vm_is_off(tmp_path):
    out, _, _ = raw("list")
    prov, r, _ = provider(tmp_path)
    r.queue("list", out.decode())
    assert prov.power_state() is PowerState.OFF


def test_power_state_suspended_by_vmss_next_to_vmx(tmp_path):
    prov, r, vmx = provider(tmp_path)
    (vmx.parent / "x.vmss").write_bytes(b"")
    r.queue("list", "Total running VMs: 0")
    assert prov.power_state() is PowerState.SUSPENDED


def test_power_state_suspended_by_checkpoint_vmstate(tmp_path):
    prov, r, vmx = provider(tmp_path, vmx_text='checkpoint.vmState.readOnly = "FALSE"\n'
                                                'checkpoint.vmState = "x-1a2b.vmss"\n')
    (vmx.parent / "x-1a2b.vmss").write_bytes(b"")
    r.queue("list", "Total running VMs: 0")
    assert prov.power_state() is PowerState.SUSPENDED


def test_power_state_off_when_vmstate_file_missing(tmp_path):
    prov, r, _ = provider(tmp_path, vmx_text='checkpoint.vmState = "gone.vmss"\n')
    r.queue("list", "Total running VMs: 0")
    assert prov.power_state() is PowerState.OFF


def test_power_state_off_with_real_vmx_keys(tmp_path):
    prov, r, _ = provider(tmp_path, vmx_text=(FIX / "vmx" / "real_analysis_vm.vmx").read_text())
    r.queue("list", "Total running VMs: 0")
    assert prov.power_state() is PowerState.OFF


def test_power_state_propagates_vmrun_errors(tmp_path):
    prov, r, _ = provider(tmp_path)
    r.queue("list", VmrunTimeout("t"))
    with pytest.raises(VmrunTimeout):
        prov.power_state()


@pytest.mark.parametrize(
    ("out", "state"),
    [("running", ToolsState.RUNNING), ("installed", ToolsState.INSTALLED),
     ("not installed", ToolsState.NOT_INSTALLED), ("unknown", ToolsState.UNKNOWN),
     ("", ToolsState.UNKNOWN), ("Running\n", ToolsState.RUNNING)],
)
def test_tools_state_mapping(tmp_path, out, state):
    prov, r, _ = provider(tmp_path)
    r.queue("checkToolsState", out)
    assert prov.tools_state() is state


def test_tools_state_real_fixture(tmp_path):
    out, _, _ = raw("checkToolsState")
    prov, r, _ = provider(tmp_path)
    r.queue("checkToolsState", out.decode())
    assert prov.tools_state() is ToolsState.RUNNING


def test_tools_state_vm_not_running_is_unknown(tmp_path):
    prov, r, _ = provider(tmp_path)
    r.queue("checkToolsState", VmNotRunning("off"))
    assert prov.tools_state() is ToolsState.UNKNOWN


def test_tools_state_other_errors_propagate(tmp_path):
    prov, r, _ = provider(tmp_path)
    r.queue("checkToolsState", VmLocked("busy"))
    with pytest.raises(VmLocked):
        prov.tools_state()


def test_guest_ip_real_fixture(tmp_path):
    out, _, _ = raw("getGuestIPAddress")
    prov, r, _ = provider(tmp_path)
    r.queue("getGuestIPAddress", out.decode())
    assert prov.guest_ip() == "192.168.10.15"
    assert r.calls[-1]["params"] == ()


def test_guest_ip_wait_passes_flag_and_timeout(tmp_path):
    prov, r, _ = provider(tmp_path)
    r.queue("getGuestIPAddress", "192.168.56.10\n")
    assert prov.guest_ip(wait=True, timeout_s=42.0) == "192.168.56.10"
    assert r.calls[-1]["params"] == ("-wait",)
    assert r.calls[-1]["timeout_s"] == 42.0


@pytest.mark.parametrize(
    "out", ["unknown", "", "999.1.1.1", "fe80::1", "0.0.0.0", "not-an-ip", "1.2.3"]  # noqa: S104 - data
)
def test_guest_ip_invalid_values_are_none(tmp_path, out):
    prov, r, _ = provider(tmp_path)
    r.queue("getGuestIPAddress", out)
    assert prov.guest_ip() is None


@pytest.mark.parametrize("exc", [VmrunError("Error: Unable to get the IP address"), VmNotRunning("off"),
                                 VmrunTimeout("t")])
def test_guest_ip_errors_are_none(tmp_path, exc):
    prov, r, _ = provider(tmp_path)
    r.queue("getGuestIPAddress", exc)
    assert prov.guest_ip(wait=True, timeout_s=1.0) is None


def test_list_snapshots_parses_real_show_tree(tmp_path):
    out, _, _ = raw("listSnapshots_showTree")
    prov, r, _ = provider(tmp_path)
    r.queue("listSnapshots", out.decode())
    snaps = prov.list_snapshots()
    assert r.calls[-1]["params"] == ("showTree",)
    assert len(snaps) == 33
    by_name = {s.name: s for s in snaps}
    assert snaps[0] == Snapshot("vbsedit_install", 0, None)
    assert snaps[1] == Snapshot("before_analysis", 1, "vbsedit_install")
    assert by_name["agent_omega"] == Snapshot("agent_omega", 9, "agent_base")
    assert by_name["MCP_BASE"] == Snapshot("MCP_BASE", 12, "themida_base")
    assert by_name["remote_base"] == Snapshot("remote_base", 11, "4g_analysis_base_20260205_1")
    assert by_name["argonwiper_base"] == Snapshot("argonwiper_base", 8, "4G_Analaysis_base")
    # every parent is an earlier snapshot exactly one level up
    seen: dict[str, Snapshot] = {}
    for s in snaps:
        if s.parent is not None:
            assert seen[s.parent].depth == s.depth - 1
        seen[s.name] = s


def test_list_snapshots_flat_names_match_tree(tmp_path):
    flat, _, _ = raw("listSnapshots_flat")
    tree, _, _ = raw("listSnapshots_showTree")
    prov, r, _ = provider(tmp_path)
    r.queue("listSnapshots", tree.decode())
    names = [s.name for s in prov.list_snapshots()]
    assert names == flat.decode().splitlines()[1:]


def test_list_snapshots_empty(tmp_path):
    prov, r, _ = provider(tmp_path)
    r.queue("listSnapshots", "Total snapshots: 0\n")
    assert prov.list_snapshots() == []


def test_list_snapshots_names_with_spaces_and_crlf(tmp_path):
    prov, r, _ = provider(tmp_path)
    r.queue("listSnapshots", "Total snapshots: 2\r\nmy base \r\n\tchild one\r\n")
    assert prov.list_snapshots() == [Snapshot("my base", 0, None), Snapshot("child one", 1, "my base")]


def test_snapshot_operations_commands(tmp_path):
    prov, r, _ = provider(tmp_path)
    prov.take_snapshot("gw-job-1")
    prov.revert_snapshot("MCP_CLEAN")
    prov.delete_snapshot("gw-job-1")
    assert [(c["command"], c["params"], c["guest"]) for c in r.calls] == [
        ("snapshot", ("gw-job-1",), False),
        ("revertToSnapshot", ("MCP_CLEAN",), False),
        ("deleteSnapshot", ("gw-job-1",), False),
    ]
    assert all("andDeleteChildren" not in c["params"] for c in r.calls)


@pytest.mark.parametrize("bad", ["", "a\nb", "a\x00b", "\tindented"])
def test_snapshot_names_validated(tmp_path, bad):
    prov, r, _ = provider(tmp_path)
    for op in (prov.take_snapshot, prov.revert_snapshot, prov.delete_snapshot):
        with pytest.raises(VmrunError):
            op(bad)
    assert r.calls == []


def test_snapshot_not_found_propagates(tmp_path):
    prov, r, _ = provider(tmp_path)
    r.queue("revertToSnapshot", SnapshotNotFound("nope"))
    with pytest.raises(SnapshotNotFound):
        prov.revert_snapshot("nope")


def test_power_operations_commands(tmp_path):
    prov, r, _ = provider(tmp_path)
    prov.start()
    prov.start(gui=True)
    prov.stop()
    prov.stop(hard=True)
    prov.suspend()
    assert [(c["command"], c["params"]) for c in r.calls] == [
        ("start", ("nogui",)), ("start", ("gui",)), ("stop", ("soft",)), ("stop", ("hard",)),
        ("suspend", ("soft",)),
    ]
    assert all(c["vmx"] for c in r.calls)


def test_screenshot_uses_guest_credentials(tmp_path):
    prov, r, _ = provider(tmp_path)
    target = tmp_path / "shot.png"
    prov.screenshot(target)
    assert r.calls[-1]["command"] == "captureScreen"
    assert r.calls[-1]["params"] == (str(target),)
    assert r.calls[-1]["guest"] is True


def test_long_operations_get_generous_timeouts(tmp_path):
    prov, r, _ = provider(tmp_path)
    prov.revert_snapshot("MCP_CLEAN")
    prov.delete_snapshot("gw-x")
    prov.start()
    assert all(c["timeout_s"] >= 120 for c in r.calls)


def test_timeouts_overridable(tmp_path):
    prov, r, _ = provider(tmp_path, timeouts={"revertToSnapshot": 7.0})
    prov.revert_snapshot("MCP_CLEAN")
    assert r.calls[-1]["timeout_s"] == 7.0


# ── isolation_report ────────────────────────────────────────────────
def test_isolation_real_vmx_keys_not_isolated(tmp_path):
    prov, _, _ = provider(tmp_path, vmx_text=(FIX / "vmx" / "real_analysis_vm.vmx").read_text())
    rep = prov.isolation_report()
    assert rep == IsolationReport(True, True, ("bridged",))
    assert rep.isolated is False


def test_isolation_hgfs_disabled_hostonly_is_isolated(tmp_path):
    prov, _, _ = provider(tmp_path, vmx_text=(FIX / "vmx" / "isolated.vmx").read_text())
    rep = prov.isolation_report()
    assert rep == IsolationReport(False, False, ("hostonly",))
    assert rep.isolated is True


def test_isolation_mixed_case_keys_and_multiple_nics(tmp_path):
    prov, _, _ = provider(tmp_path, vmx_text=(FIX / "vmx" / "mixed.vmx").read_text())
    rep = prov.isolation_report()
    # share 0 is disabled, share 1 is enabled read-only
    assert rep.shared_folders_enabled is True
    assert rep.shared_folders_writable is False
    assert rep.network_types == ("disconnected", "custom", "hostonly")
    assert rep.isolated is False


def test_isolation_no_nics_no_shares(tmp_path):
    prov, _, _ = provider(tmp_path, vmx_text='.encoding = "UTF-8"\n')
    assert prov.isolation_report() == IsolationReport(False, False, ())


def test_isolation_unknown_connection_type_kept_and_not_isolated(tmp_path):
    prov, _, _ = provider(tmp_path, vmx_text='ethernet0.present = "TRUE"\nethernet0.connectionType = "pvn"\n')
    rep = prov.isolation_report()
    assert rep.network_types == ("pvn",)
    assert rep.isolated is False


def test_isolation_uses_injected_reader(tmp_path):
    seen = []

    def reader(path: str) -> str:
        seen.append(path)
        return 'ethernet0.present = "TRUE"\nethernet0.connectionType = "nat"\n'

    prov, _, vmx = provider(tmp_path, vmx_text=None, vmx_reader=reader)
    assert prov.isolation_report().network_types == ("nat",)
    assert seen == [str(vmx)]


def test_isolation_unreadable_vmx_is_config_error(tmp_path):
    prov, _, _ = provider(tmp_path, vmx_text=None)
    with pytest.raises(ConfigError):
        prov.isolation_report()


# ── NullProvider ────────────────────────────────────────────────────
def test_null_provider_read_methods():
    n = NullProvider()
    assert isinstance(n, VmProvider)
    assert n.power_state() is PowerState.UNKNOWN
    assert n.tools_state() is ToolsState.UNKNOWN
    assert n.guest_ip() is None and n.guest_ip(wait=True, timeout_s=1) is None
    assert n.isolation_report() == IsolationReport(None, None, ())


@pytest.mark.parametrize(
    "call",
    [
        lambda n: n.list_snapshots(),
        lambda n: n.take_snapshot("a"),
        lambda n: n.revert_snapshot("a"),
        lambda n: n.delete_snapshot("a"),
        lambda n: n.start(),
        lambda n: n.stop(hard=True),
        lambda n: n.suspend(),
        lambda n: n.screenshot(Path("x.png")),
    ],
)
def test_null_provider_control_methods_raise(call):
    with pytest.raises(ConfigError) as ei:
        call(NullProvider())
    assert ei.value.message == "profile is in endpoint mode: VM control is unavailable"


# ── real vmrun (opt-in: -m vm). Read-only commands only. ─────────────
@pytest.mark.vm
def test_real_vmrun_read_only_roundtrip():
    from x64dbg_vm_gateway.platform import find_vmrun

    vmx = os.environ.get("X64DBG_GW_TEST_VMX", REAL_VMX)
    if not os.path.exists(vmx):
        pytest.skip(f"vmx not present: {vmx}")
    path = find_vmrun()
    prov = VmrunProvider(VmrunCli(path, vmx, "ws", None), vmx)
    assert prov.power_state() in (PowerState.RUNNING, PowerState.OFF, PowerState.SUSPENDED)
    assert prov.list_snapshots()
    assert isinstance(prov.tools_state(), ToolsState)
    ip = prov.guest_ip()
    assert ip is None or ip.count(".") == 3
    assert isinstance(prov.isolation_report(), IsolationReport)  # reads the vmx file only

    bad = VmrunCli(path, "/nonexistent/x.vmx", "ws", None)
    with pytest.raises(VmrunError) as ei:
        bad.run("checkToolsState")
    assert type(ei.value) is VmrunError
    assert ei.value.details["returncode"] == 255
