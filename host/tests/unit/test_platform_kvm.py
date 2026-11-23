"""E1: host-side detection of hypervisor processes running one .vmx (duplicate instances).

Real-VM evidence: after ``vmrun revertToSnapshot`` an older ``vmware-vmx`` for the
same .vmx survived, invisible to ``vmrun list``; ``vmrun start`` then created a
second instance with the same MAC/IP. ``find_vmx_processes`` lists every
hypervisor process of one .vmx, so callers can refuse to start a duplicate.
All three host OSes are exercised here with injected /proc trees and runners.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
from pathlib import Path

import pytest

from x64dbg_vm_gateway import platform as plat
from x64dbg_vm_gateway.errors import GatewayError

VMX_ARGS = ["-s", "vmx.stdio.keep=TRUE", "-#",
            "product=1;name=VMware Workstation;version=17.6.3;buildnumber=24583834;licensename=VMware "
            "Workstation;licenseversion=17.0+;", "-@", "duplex=3;msgs=ui"]


def _proc(root: Path, pid: int | str, argv: list[str] | None, *, raw: bytes | None = None,
          cwd: Path | None = None) -> Path:
    d = root / str(pid)
    d.mkdir(parents=True)
    if raw is not None:
        (d / "cmdline").write_bytes(raw)
    elif argv is not None:
        (d / "cmdline").write_bytes(b"\0".join(a.encode() for a in argv) + b"\0")
    if cwd is not None:
        (d / "cwd").symlink_to(cwd, target_is_directory=True)
    return d


@pytest.fixture
def vmx(tmp_path: Path) -> Path:
    d = tmp_path / "vms" / "analysis_clone"
    d.mkdir(parents=True)
    f = d / "analysis_clone.vmx"
    f.write_text('.encoding = "UTF-8"\n')
    return f


@pytest.fixture
def proc(tmp_path: Path) -> Path:
    root = tmp_path / "proc"
    root.mkdir()
    return root


def _no_run(*_a, **_k):
    raise AssertionError("no subprocess expected on Linux")


# ── Linux: /proc/<pid>/cmdline ──────────────────────────────────────
def test_linux_finds_every_vmware_vmx_of_this_vmx(vmx: Path, proc: Path) -> None:
    exe = "/usr/lib/vmware/bin/vmware-vmx"
    _proc(proc, 4242, [exe, *VMX_ARGS, str(vmx)])  # registered instance
    _proc(proc, 1717, [exe, *VMX_ARGS, str(vmx)])  # the E1 orphan
    _proc(proc, 3000, [exe, *VMX_ARGS, str(vmx.parent / "other.vmx")])
    _proc(proc, 3001, ["/usr/bin/vim", str(vmx)])  # mentions the vmx, but is no hypervisor
    _proc(proc, 3002, ["/usr/bin/vmrun", "-T", "ws", "start", str(vmx), "nogui"])
    assert plat.find_vmx_processes(str(vmx), system="Linux", proc_root=str(proc), run=_no_run) == [1717, 4242]


def test_linux_matches_through_symlinks_and_any_argument_position(vmx: Path, proc: Path,
                                                                  tmp_path: Path) -> None:
    link = tmp_path / "vm-link"
    try:
        link.symlink_to(vmx.parent, target_is_directory=True)
    except OSError as e:  # pragma: no cover - platforms without symlinks
        pytest.skip(f"cannot create symlinks: {e}")
    _proc(proc, 10, ["/usr/lib/vmware/bin/vmware-vmx", "-x", str(link / vmx.name), "-s", "a=b"])
    assert plat.find_vmx_processes(str(vmx), system="Linux", proc_root=str(proc), run=_no_run) == [10]
    assert plat.find_vmx_processes(str(link / vmx.name), system="Linux", proc_root=str(proc),
                                   run=_no_run) == [10]


def test_linux_accepts_hypervisor_variants_and_bare_names(vmx: Path, proc: Path) -> None:
    _proc(proc, 11, ["vmware-vmx", str(vmx)])
    _proc(proc, 12, ["/usr/lib/vmware/bin/vmware-vmx-debug", str(vmx)])
    _proc(proc, 13, ["/usr/lib/vmware/bin/vmware-vmx-stats", str(vmx)])
    _proc(proc, 14, ["/usr/lib/vmware/bin/vmware-vmxfoo", str(vmx)])
    assert plat.find_vmx_processes(str(vmx), system="Linux", proc_root=str(proc), run=_no_run) == [11, 12, 13]


def test_linux_resolves_a_relative_vmx_argument_against_the_process_cwd(vmx: Path, proc: Path) -> None:
    _proc(proc, 20, ["/usr/lib/vmware/bin/vmware-vmx", vmx.name], cwd=vmx.parent)
    _proc(proc, 21, ["/usr/lib/vmware/bin/vmware-vmx", vmx.name])  # cwd unknown: cannot be resolved
    assert plat.find_vmx_processes(str(vmx), system="Linux", proc_root=str(proc), run=_no_run) == [20]


def test_linux_never_raises_for_unreadable_or_odd_entries(vmx: Path, proc: Path) -> None:
    _proc(proc, 30, ["/usr/lib/vmware/bin/vmware-vmx", str(vmx)])
    _proc(proc, 31, None)  # vanished between listdir and open: no cmdline file
    (_proc(proc, 32, None) / "cmdline").mkdir()  # unreadable (EISDIR)
    _proc(proc, 33, None, raw=b"")  # kernel thread
    _proc(proc, 34, None, raw=b"\xff\xfe\0\0")  # undecodable bytes
    _proc(proc, "self", ["/usr/lib/vmware/bin/vmware-vmx", str(vmx)])  # not a pid directory
    (proc / "uptime").write_text("1 2\n")
    assert plat.find_vmx_processes(str(vmx), system="Linux", proc_root=str(proc), run=_no_run) == [30]


def test_linux_without_a_readable_proc_raises(vmx: Path, tmp_path: Path) -> None:
    with pytest.raises(GatewayError) as ei:
        plat.find_vmx_processes(str(vmx), system="Linux", proc_root=str(tmp_path / "nope"), run=_no_run)
    assert ei.value.stage == "platform"
    assert "nope" in str(ei.value.details)


def test_linux_default_proc_root_is_proc() -> None:
    import inspect

    assert inspect.signature(plat.find_vmx_processes).parameters["proc_root"].default == "/proc"


# ── macOS (Fusion): ps -axo pid=,command= ───────────────────────────
class FakeRun:
    def __init__(self, stdout: bytes = b"", returncode: int = 0, exc: BaseException | None = None) -> None:
        self.stdout = stdout
        self.returncode = returncode
        self.exc = exc
        self.calls: list[tuple[list[str], dict]] = []

    def __call__(self, argv, **kw):
        self.calls.append((list(argv), kw))
        if self.exc is not None:
            raise self.exc
        return subprocess.CompletedProcess(argv, self.returncode, self.stdout, b"")


FUSION = "/Applications/VMware Fusion.app/Contents/Library/vmware-vmx"


def test_macos_parses_ps_output() -> None:
    vmx = "/Users/u/Virtual Machines.localized/Win 10.vmwarevm/Win 10.vmx"
    out = (f"  501 {FUSION} -s vmx.stdio.keep=TRUE -# product=64;name=VMware Fusion; -@ duplex=3 {vmx}\n"
           f"  777 {FUSION} -s vmx.stdio.keep=TRUE {vmx}.bak\n"
           f"  502 /usr/bin/vim {vmx}\n"
           f"  503 {FUSION} -@ duplex=3 /Users/u/Other.vmwarevm/Other.vmx\n"
           "garbage line\n").encode()
    run = FakeRun(out)
    assert plat.find_vmx_processes(vmx, system="Darwin", run=run) == [501]
    (argv, kw), = run.calls
    assert argv[0].endswith("ps") and "pid=,command=" in argv
    assert kw["timeout"] > 0 and kw.get("check") in (None, False)


@pytest.mark.parametrize("run", [FakeRun(returncode=1), FakeRun(exc=subprocess.TimeoutExpired("ps", 10)),
                                 FakeRun(exc=FileNotFoundError("ps"))])
def test_macos_ps_failure_raises(run: FakeRun) -> None:
    with pytest.raises(GatewayError) as ei:
        plat.find_vmx_processes("/Users/u/w.vmx", system="Darwin", run=run)
    assert ei.value.stage == "platform"


# ── Windows: PowerShell / CIM Win32_Process ─────────────────────────
WIN_VMX = "D:\\VMs\\Win 10\\win10.vmx"
WIN_EXE = "C:\\Program Files (x86)\\VMware\\VMware Workstation\\x64\\vmware-vmx.exe"


def _cim(rows) -> bytes:
    return ("noise\r\nMCPPROC:" + json.dumps(rows) + "\r\n").encode("utf-8")


def test_windows_matches_command_lines_case_insensitively() -> None:
    rows = [
        {"ProcessId": 4242, "CommandLine": f'"{WIN_EXE}" -T querytoken -s vmx.stdio.keep=TRUE "{WIN_VMX}"'},
        {"ProcessId": 1717, "CommandLine": f'"{WIN_EXE}" -s a=b "d:\\vms\\WIN 10\\WIN10.VMX"'},
        {"ProcessId": 5000, "CommandLine": f'"{WIN_EXE}" "D:\\VMs\\Other\\other.vmx"'},
        {"ProcessId": 5001, "CommandLine": None},  # another user's process: no access
        {"ProcessId": 5002, "CommandLine": f'"{WIN_EXE}" "{WIN_VMX}.bak"'},
    ]
    run = FakeRun(_cim(rows))
    assert plat.find_vmx_processes(WIN_VMX, system="Windows", run=run, env={"SystemRoot": "C:\\Windows"}) \
        == [1717, 4242]
    (argv, kw), = run.calls
    assert argv[0] == "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    assert "-EncodedCommand" in argv
    script = base64.b64decode(argv[argv.index("-EncodedCommand") + 1]).decode("utf-16-le")
    assert "Win32_Process" in script and "vmware-vmx.exe" in script and "MCPPROC:" in script
    assert kw["timeout"] > 0


def test_windows_accepts_a_single_unwrapped_object() -> None:
    row = {"ProcessId": 9, "CommandLine": f'"{WIN_EXE}" "{WIN_VMX}"'}
    assert plat.find_vmx_processes(WIN_VMX, system="Windows", run=FakeRun(_cim(row)), env={}) == [9]


def test_windows_empty_result() -> None:
    assert plat.find_vmx_processes(WIN_VMX, system="Windows", run=FakeRun(b"MCPPROC:\r\n"), env={}) == []
    assert plat.find_vmx_processes(WIN_VMX, system="Windows", run=FakeRun(b"MCPPROC:[]"), env={}) == []


@pytest.mark.parametrize("run", [FakeRun(returncode=1), FakeRun(b"no marker"), FakeRun(b"MCPPROC:{bad"),
                                 FakeRun(exc=subprocess.TimeoutExpired("powershell", 20)),
                                 FakeRun(exc=OSError("no powershell"))])
def test_windows_failures_raise(run: FakeRun) -> None:
    with pytest.raises(GatewayError) as ei:
        plat.find_vmx_processes(WIN_VMX, system="Windows", run=run, env={})
    assert ei.value.stage == "platform"


def test_split_windows_command_line() -> None:
    assert plat.split_windows_command_line('"C:\\a b\\x.exe" -s "D:\\v m\\w.vmx" plain "q\\"x"') == \
        ["C:\\a b\\x.exe", "-s", "D:\\v m\\w.vmx", "plain", 'q"x']
    assert plat.split_windows_command_line("") == []


def test_real_host_scan_does_not_raise() -> None:
    # Read-only scan of this host's process table (no vmrun, no VM change).
    if not os.path.isdir("/proc") or os.name != "posix" or plat.host_system() != "Linux":
        pytest.skip("Linux /proc only")
    assert plat.find_vmx_processes("/nonexistent/k-vm-test.vmx") == []
