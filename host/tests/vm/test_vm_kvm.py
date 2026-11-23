"""Real-VM checks for the K-vm fixes (opt-in: ``-m vm`` and X64DBG_VM_E2E_CONFIG).

Run with ``uv run pytest -m vm tests/vm/test_vm_kvm.py`` (the default
``addopts`` deselect the ``vm`` marker). Set
``X64DBG_VM_E2E_CONFIG`` to a gateway config file whose default profile is
the spike VM (vmware mode, guest credentials resolvable). These tests are
written to be run by the main session on the spike VM; they do not change the
VM's power state or snapshots:

- E3: a PowerShell ``-File`` script receives the arguments VixChannel sends,
  exactly (it writes ``[Environment]::GetCommandLineArgs()``, ``$args`` and the raw
  command line as JSON to a guest file that is copied back). Guest side effects:
  the script and its output file under ``C:\\mcp\\tmp`` (both deleted).
- E3: transfer.py's PowerShell one-liners (``-Command <one argument>``, now
  escaped by ``escape_for_vmrun`` instead of list2cmdline) run and write what
  they should: text with single and double quotes, ``&``, a backslash and
  blanks, to a guest file under ``C:\\mcp\\tmp`` with a blank in its name
  (deleted afterwards).
- E1: ``instance_report()`` (``vmrun list`` + host process scan, read-only).
- E2: ``guest_boot_time()`` returns an ISO-8601 UTC time, and the boot query's
  uptime grows while the boot time stays (two PowerShell runs each).
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import secrets
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

import pytest

from x64dbg_vm_gateway.guest import POWERSHELL_EXE
from x64dbg_vm_gateway.ps import ps_quote

pytestmark = pytest.mark.vm

ENV = "X64DBG_VM_E2E_CONFIG"
TMP_DIR = "C:\\mcp\\tmp"

ARG_CASES = [
    "a b",
    'c"d',
    "e\\",
    'x\\"y',
    "",
    "plain",
    "e\\f",
    "\ud55c\uae00 \uacbd\ub85c\\\ud30c\uc77c.exe",
    "caf\u00e9 \u2019q\u2019",
    "  two  spaces  ",
    "C:\\path with space\\",
    'say "hi" to \\"them\\"',
]

# ASCII only, so Windows PowerShell 5.1 reads it without a BOM.
ECHO_SCRIPT = r"""
$out = '__OUT__'
$doc = [ordered]@{
    command_line = [Environment]::CommandLine
    argv = @([Environment]::GetCommandLineArgs())
    args = @($args)
}
$json = ConvertTo-Json -InputObject $doc -Depth 4 -Compress
[System.IO.File]::WriteAllText($out, $json, (New-Object System.Text.UTF8Encoding($false)))
exit 0
"""


@pytest.fixture(scope="module")
def runtime() -> Iterator[object]:
    path = os.environ.get(ENV)
    if not path:
        pytest.skip(f"set {ENV} to a gateway config whose default profile is the spike VM")
    if not Path(path).is_file():
        pytest.skip(f"{ENV} does not point to a file: {path}")
    from x64dbg_vm_gateway.config import load_config
    from x64dbg_vm_gateway.wiring import build_runtime

    rt = build_runtime(load_config(Path(path)))
    if getattr(rt, "channel", None) is None:
        pytest.skip("the default profile is not in vmware mode")
    yield rt


def test_e3_program_arguments_round_trip_through_vmrun(runtime, tmp_path: Path) -> None:
    channel = runtime.channel  # type: ignore[attr-defined]
    token = secrets.token_hex(6)
    script_guest = f"{TMP_DIR}\\kvm-args-{token}.ps1"
    out_guest = f"{TMP_DIR}\\kvm-args-{token}.json"
    local = tmp_path / "echo.ps1"
    local.write_text(ECHO_SCRIPT.replace("__OUT__", out_guest), encoding="ascii")
    channel.mkdir(TMP_DIR)
    channel.copy_to_guest(local, script_guest)
    try:
        args = ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script_guest,
                *ARG_CASES]
        rc = channel.run_program(POWERSHELL_EXE, args, wait=True, timeout_s=120)
        assert rc == 0
        back = tmp_path / "out.json"
        channel.copy_from_guest(out_guest, back)
        doc = json.loads(back.read_bytes().decode("utf-8-sig"))
    finally:
        for p in (script_guest, out_guest):
            with contextlib.suppress(Exception):  # best-effort cleanup in a VM test
                channel.delete_file(p)
    received = doc["argv"][-len(ARG_CASES):]
    # OS-level argument splitting (CommandLineToArgvW rules) gives back every case exactly.
    assert received == ARG_CASES, doc["command_line"]
    # What the script itself sees: Windows PowerShell 5.1 may drop empty -File arguments,
    # so compare without them (recorded, not assumed).
    assert [a for a in doc["args"] if a] == [a for a in ARG_CASES if a], doc["command_line"]


def test_e3_transfer_powershell_one_liner_runs_through_vmrun(runtime, tmp_path: Path) -> None:
    # transfer._ps: the exact path upload hashing / fetch size probes / Compress-Archive use.
    from x64dbg_vm_gateway import transfer

    channel = runtime.channel  # type: ignore[attr-defined]
    token = secrets.token_hex(6)
    out_guest = f"{TMP_DIR}\\kvm ps {token}.txt"
    text = 'it\'s "quoted" & spaced \\ ; $notavar'
    command = (f"{ps_quote(text)} | Out-File -Encoding ascii -FilePath {ps_quote(out_guest)}")
    channel.mkdir(TMP_DIR)
    try:
        assert transfer._ps(channel, POWERSHELL_EXE, command, 120.0) == 0
        back = tmp_path / "ps.txt"
        channel.copy_from_guest(out_guest, back)
    finally:
        with contextlib.suppress(Exception):  # best-effort cleanup in a VM test
            channel.delete_file(out_guest)
    assert back.read_bytes().decode("ascii").rstrip("\r\n") == text
    # Control: a failing one-liner gives a non-zero exit code (VixChannel returns it), so the
    # 0 above is the command's own success, not a run that never parsed the script.
    rc = transfer._ps(channel, POWERSHELL_EXE, "Get-Item -LiteralPath 'C:\\no\\such\\file' -ErrorAction Stop",
                      120.0)
    assert rc not in (0, None)


def test_e1_instance_report_is_consistent(runtime) -> None:
    vm = runtime.vm  # type: ignore[attr-defined]
    if not hasattr(vm, "instance_report"):
        pytest.skip("VM provider without instance_report")
    report = vm.instance_report()
    assert set(report) >= {"listed", "pids", "orphans"}
    assert all(isinstance(p, int) and p > 0 for p in report["pids"])
    # A healthy spike VM: running and listed with exactly one hypervisor process,
    # or powered off with none. Anything else is the E1 duplicate/orphan state.
    assert report["orphans"] == [], report
    assert len(report["pids"]) == (1 if report["listed"] else 0), report


def test_e2_guest_boot_time_is_an_iso_utc_time(runtime) -> None:
    from x64dbg_vm_gateway.provision import guest_boot_time

    value = guest_boot_time(runtime.channel)  # type: ignore[attr-defined]
    assert value is not None
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,7})?Z", value), value
    again = guest_boot_time(runtime.channel)  # type: ignore[attr-defined]
    assert again is not None
    # Without a reboot the value must stay within the 1 s tolerance the reboot
    # detection allows (provision._BOOT_TIME_TOLERANCE_S); exact equality is expected.
    first, second = (datetime.fromisoformat(v.replace("Z", "+00:00")) for v in (value, again))
    assert abs((second - first).total_seconds()) <= 1.0, (value, again)


def test_e2_uptime_grows_while_the_boot_time_stays(runtime) -> None:
    # The reboot detection needs both values of one query (provision._is_new_boot).
    from x64dbg_vm_gateway import provision

    first = provision._read_boot(runtime.channel)  # type: ignore[attr-defined]
    second = provision._read_boot(runtime.channel)  # type: ignore[attr-defined]
    assert first is not None and second is not None
    assert first.uptime_s is not None and second.uptime_s is not None
    assert first.uptime_s > 60  # a running guest
    assert second.uptime_s >= first.uptime_s - provision._BOOT_TIME_TOLERANCE_S, (first, second)
    assert abs((second.at - first.at).total_seconds()) <= provision._BOOT_TIME_TOLERANCE_S, (first, second)
    assert not provision._is_new_boot(first, second)
