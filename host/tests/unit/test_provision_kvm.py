"""E2 (reboot detection by guest boot time) and E7 (plugin backups outside plugins\\).

E2 real-VM evidence: provision_guest(reboot=True) raised VmNotReady "the guest
did not go down within 300s" although LastBootUpTime moved from 22:16:44 to
22:22:29: the guest was down (no Tools, no port) for less than the 5 s poll
interval, so the down/up observation never saw it.

E7 real-VM evidence: install_plugin left ``x64dbg-MCP-Server.dp64.bak`` inside
the plugins folder that x64dbg scans for plugins.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from tests.fakes.fake_guest import FakeGuest
from tests.fakes.fake_vm import FakeClock
from tests.unit.test_provision import (
    HOST_IP,
    PASSWORD,
    ROOT,
    SCHTASKS,
    SHUTDOWN,
    X32_PLUGIN,
    X64_PLUGIN,
    FakeRuntime,
    Probe,
    ProvisionScript,
    Timeline,
    TimelineVm,
    _dist,
    _install,
    _plugins_leftovers,
    _profile,
    _seed_install,
)
from tests.unit.test_ps import GuestPowerShell
from x64dbg_vm_gateway import provision
from x64dbg_vm_gateway.contracts import Secret
from x64dbg_vm_gateway.errors import GuestOperationError, ToolsNotRunning, VmNotReady, VmrunTimeout
from x64dbg_vm_gateway.provision import guest_boot_time, provision_guest
from x64dbg_vm_gateway.ps import decode_command

BOOT0 = datetime(2026, 11, 23, 13, 16, 44, 500000, tzinfo=UTC)


def _iso(dt: datetime) -> str:
    """.NET ``ToString('o')`` of a UTC DateTime: 7 fractional digits and ``Z``."""
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"


# ── guest emulation ─────────────────────────────────────────────────
class GuestBoot:
    """``LastBootUpTime`` and uptime of the emulated guest: a new boot at the end of every
    reboot window.

    ``fail_at``: exceptions raised by given reads (1 = first); ``shift_s``: offsets added
    to the reported boot time only (jitter, or a wall-clock step in the expected Windows
    behaviour: the boot time moves with the clock, so ``now - boot`` stays the uptime);
    ``uptime_shift_s``: offsets added to the reported uptime only (a clock step if the
    boot time does NOT move with the clock); ``uptime=False`` leaves the uptime line out;
    ``output``: replaces the whole output (malformed answers). Reads are logged in ``reads``.
    """

    def __init__(self, timeline: Timeline) -> None:
        self.timeline = timeline
        self.base_t = timeline.clock.t - 3600.0  # the guest has been up for an hour
        self.fail_at: dict[int, Exception] = {}  # read number (1 = first) -> exception
        self.shift_s: list[float] = []
        self.uptime_shift_s: list[float] = []
        self.uptime = True
        self.output: str | None = None
        self.reads: list[tuple[float, str | None]] = []

    def boot_t(self) -> float:
        t = self.timeline.clock.t
        ends = [e for s, e in self.timeline.windows if e <= t]
        return max(ends) if ends else self.base_t

    def boot_dt(self) -> datetime:
        return BOOT0 + timedelta(seconds=self.boot_t() - self.base_t)

    def __call__(self, body: str) -> tuple[int, str]:
        t = self.timeline.clock.t
        self.reads.append((t, None))
        if self.timeline.down():
            raise ToolsNotRunning("Error: The VMware Tools are not running in the virtual machine")
        exc = self.fail_at.get(len(self.reads))
        if exc is not None:
            raise exc
        if self.output is not None:
            return 0, self.output
        shift = self.shift_s.pop(0) if self.shift_s else 0.0
        ushift = self.uptime_shift_s.pop(0) if self.uptime_shift_s else 0.0
        value = _iso(self.boot_dt() + timedelta(seconds=shift))
        self.reads[-1] = (t, value)
        out = f"MCPBOOT:{value}\r\n"
        if self.uptime:
            out += f"MCPUPTIME:{t - self.boot_t() + ushift:.3f}\r\n"
        return 0, out


class RebootProbe(Probe):
    """Plugin ports: the old debuggers answer until the reboot starts, the new ones
    ``delay_s`` after the guest is back (auto-logon + logon task)."""

    def __init__(self, timeline: Timeline, *, delay_s: float = 0.0, **kw) -> None:
        super().__init__(timeline, **kw)
        self.delay_s = delay_s

    def _status(self, port: int) -> int | None:
        t = self.timeline.clock.t
        if any(s <= t < e + self.delay_s for s, e in self.timeline.windows):
            return None
        return super()._status(port)


def is_boot_query(body: str) -> bool:
    return "LastBootUpTime" in body and "Win32_OperatingSystem" in body


def _setup(rt: FakeRuntime, timeline: Timeline, *, reboot_s: float, stale_s: float = 1.0,
           reboots: bool = True, boot: bool = True,
           **script_kw) -> tuple[ProvisionScript, GuestBoot, GuestPowerShell]:
    script = ProvisionScript(rt.channel, **script_kw)
    gboot = GuestBoot(timeline)

    def handler(body: str):
        if is_boot_query(body):
            return gboot(body) if boot else (0, "")
        return script(body)

    def other(exe: str, args: tuple, **kw):
        if exe == SHUTDOWN:
            if reboots:
                timeline.reboot(stale_s=stale_s, reboot_s=reboot_s)
            return None
        return 0 if kw.get("wait", True) else None

    emu = GuestPowerShell(rt.channel, handler, other)
    return script, gboot, emu


def _provision(rt: FakeRuntime, probe: Probe, **kw):
    args = {"x64dbg_root": ROOT, "user": "analyst", "password": Secret(PASSWORD), "reboot": True,
            "http_probe": probe, "local_ip_for": lambda ip: HOST_IP, "poll_s": 5.0}
    args.update(kw)
    return provision_guest(rt, **args)


@pytest.fixture
def host_tmp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    d = tmp_path / "hosttmp"
    d.mkdir()
    monkeypatch.setattr("tempfile.tempdir", str(d))
    return d


@pytest.fixture
def timeline(fake_clock: FakeClock) -> Timeline:
    return Timeline(fake_clock)


@pytest.fixture
def vm(timeline: Timeline) -> TimelineVm:
    return TimelineVm(timeline)


@pytest.fixture
def rt(vm: TimelineVm, fake_guest: FakeGuest, fake_clock: FakeClock) -> FakeRuntime:
    return FakeRuntime(vm=vm, channel=fake_guest, profile=_profile(), clock=fake_clock)


# ── guest_boot_time ─────────────────────────────────────────────────
def test_guest_boot_time_reads_last_boot_up_time_through_powershell(fake_guest, host_tmp) -> None:
    answer = "WARNING: x\r\nMCPBOOT:2026-11-23T13:16:44.5000000Z\r\n"
    emu = GuestPowerShell(fake_guest, lambda body: (0, answer))
    assert guest_boot_time(fake_guest) == "2026-11-23T13:16:44.5000000Z"
    (run,) = emu.runs
    assert run["mode"] == "encoded"
    assert "Win32_OperatingSystem" in run["body"] and "LastBootUpTime" in run["body"]
    assert "ToUniversalTime()" in run["body"]


def test_boot_query_also_reports_the_uptime(fake_guest, host_tmp) -> None:
    # The uptime (now - LastBootUpTime, both UTC) does not move when the guest clock is
    # stepped; the reboot detection needs it besides the boot time (review of E2).
    answer = "MCPBOOT:2026-11-23T13:16:44.5000000Z\r\nMCPUPTIME:3600.250\r\n"
    emu = GuestPowerShell(fake_guest, lambda body: (0, answer))
    reading = provision._read_boot(fake_guest)
    assert reading is not None
    assert reading.iso == "2026-11-23T13:16:44.5000000Z" and reading.uptime_s == 3600.25
    body = emu.runs[0]["body"]
    assert "MCPUPTIME:" in body and "(Get-Date).ToUniversalTime()" in body
    assert "InvariantCulture" in body  # no locale decimal comma (Korean guest, any other)


@pytest.mark.parametrize("answer", ["MCPBOOT:2026-11-23T13:16:44Z\r\n",
                                    "MCPBOOT:2026-11-23T13:16:44Z\r\nMCPUPTIME:\r\n",
                                    "MCPBOOT:2026-11-23T13:16:44Z\r\nMCPUPTIME:-3.5\r\n",
                                    "MCPBOOT:2026-11-23T13:16:44Z\r\nMCPUPTIME:1,5\r\n",
                                    "MCPUPTIME:12.0\r\n"])
def test_boot_reading_needs_both_values(fake_guest, host_tmp, answer) -> None:
    GuestPowerShell(fake_guest, lambda body: (0, answer))
    assert provision._read_boot(fake_guest) is None


def test_guest_boot_time_does_not_need_the_uptime(fake_guest, host_tmp) -> None:
    GuestPowerShell(fake_guest, lambda body: (0, "MCPBOOT:2026-11-23T13:16:44Z\r\n"))
    assert guest_boot_time(fake_guest) == "2026-11-23T13:16:44Z"


@pytest.mark.parametrize("answer", [(0, ""), (0, "MCPBOOT:yesterday"), (1, "MCPBOOT:2026-11-23T13:16:44Z"),
                                    (0, "MCPBOOT:2026-13-45T99:00:00Z")])
def test_guest_boot_time_none_for_unusable_answers(fake_guest, host_tmp, answer) -> None:
    GuestPowerShell(fake_guest, lambda body: answer)
    assert guest_boot_time(fake_guest) is None


def test_guest_boot_time_propagates_guest_environment_errors(fake_guest, host_tmp) -> None:
    def down(body):
        raise ToolsNotRunning("Error: The VMware Tools are not running")

    GuestPowerShell(fake_guest, down)
    with pytest.raises(ToolsNotRunning):
        guest_boot_time(fake_guest)


# ── E2 regression: a reboot faster than the poll interval ──────────
# The E2 mechanism: the old debuggers keep answering for the first polls (each port
# is asked at most three times while waiting for the reboot, to stay clear of the
# plugin's auth lockout, and then its last answer is reused), and VMware reports
# Tools as not running only for a window shorter than the 5 s poll interval.
E2_STALE_S = 12.0  # shutdown /t 2 plus Windows shutting down: three polls see the old debuggers
E2_DOWN_S = 3.0  # no Tools, no ports: shorter than one poll interval, between two polls


def test_fast_reboot_between_two_polls_is_detected_by_boot_time(rt, timeline, fake_clock, host_tmp) -> None:
    probe = RebootProbe(timeline, delay_s=20)
    _setup(rt, timeline, stale_s=E2_STALE_S, reboot_s=E2_DOWN_S)
    t0 = fake_clock.t
    summary = _provision(rt, probe, wait_ready_s=300)
    start, end = timeline.windows[0]
    assert end - start < 5
    assert summary["rebooted"] is True
    assert summary["reboot_signal"] == "boot_time"
    before, after = summary["boot_time"]["before"], summary["boot_time"]["after"]
    assert before == _iso(BOOT0) and after is not None and after != before
    assert fake_clock.t >= end + 20  # waited for the new debuggers, not the old ones
    assert summary["ready_s"] <= E2_STALE_S + E2_DOWN_S + 20 + 2 * 5
    assert summary["readiness"] == {"x64": 401, "x32": 401}
    assert fake_clock.t - t0 < 300


def test_control_without_boot_time_the_fast_reboot_is_missed(rt, timeline, fake_clock, host_tmp) -> None:
    # Same timeline, boot time unavailable: only the old down/up observation remains,
    # and it misses the reboot (the E2 failure). Shows that the boot time detects it.
    probe = RebootProbe(timeline, delay_s=20)
    _setup(rt, timeline, stale_s=E2_STALE_S, reboot_s=E2_DOWN_S, boot=False)
    with pytest.raises(VmNotReady) as ei:
        _provision(rt, probe, wait_ready_s=120)
    assert ei.value.details["phase"] == "down"
    assert ei.value.details.get("boot_time") is None


def test_boot_time_is_read_before_the_reboot_is_requested(rt, timeline, host_tmp) -> None:
    probe = RebootProbe(timeline)
    _, gboot, emu = _setup(rt, timeline, stale_s=1, reboot_s=3)
    _provision(rt, probe)
    calls = [(a[0], a[1]) for a, _ in rt.channel.calls_of("run_program")]
    shut = next(i for i, (exe, _) in enumerate(calls) if exe == SHUTDOWN)
    ps_before = [i for i, (exe, _) in enumerate(calls[:shut]) if exe.endswith("powershell.exe")]
    assert len(ps_before) >= 2  # provision.ps1, then the boot-time read
    assert gboot.reads[0] == (gboot.reads[0][0], _iso(BOOT0))
    assert gboot.reads[0][0] <= timeline.windows[0][0]


def test_reboot_that_never_happens_reports_the_unchanged_boot_time(rt, timeline, fake_clock,
                                                                   host_tmp) -> None:
    probe = RebootProbe(timeline)
    _, gboot, _ = _setup(rt, timeline, reboot_s=0, reboots=False)
    t0 = fake_clock.t
    with pytest.raises(VmNotReady) as ei:
        _provision(rt, probe, wait_ready_s=60)
    before = _iso(BOOT0)
    assert before in ei.value.message
    assert "did not reboot" in ei.value.message
    d = ei.value.details
    assert d["phase"] == "down" and d["boot_time"] == before and d["timeout_s"] == 60
    assert d["last_boot_time"] == before
    assert 60 <= fake_clock.t - t0 <= 60 + 5
    assert len([r for r in gboot.reads if r[1] is not None]) >= 3  # it kept polling


@pytest.mark.parametrize("shift", [0.4, -0.4, 1.0, -30.0, -3600.0, 5.0, 3600.0, 3 * 86400.0])
def test_jitter_or_a_clock_step_is_not_a_reboot(rt, timeline, host_tmp, shift) -> None:
    # A forward step (VMware Tools time sync after a revert, w32time) moves LastBootUpTime
    # forward with the clock; without a reboot the uptime does not drop (review of E2).
    probe = RebootProbe(timeline)
    _, gboot, _ = _setup(rt, timeline, reboot_s=0, reboots=False)
    gboot.shift_s = [0.0] + [shift] * 50  # first read (before) exact, later ones shifted
    with pytest.raises(VmNotReady) as ei:
        _provision(rt, probe, wait_ready_s=30)
    assert ei.value.details["phase"] == "down"


@pytest.mark.parametrize("step", [-5.0, -3600.0, 5.0, 3600.0])
def test_clock_step_that_leaves_the_boot_time_alone_is_not_a_reboot(rt, timeline, host_tmp, step) -> None:
    # The other model of a clock step: the boot time stays, so now - boot (the uptime as
    # computed in the guest) jumps. The boot time not moving forward rules the reboot out.
    probe = RebootProbe(timeline)
    _, gboot, _ = _setup(rt, timeline, reboot_s=0, reboots=False)
    gboot.uptime_shift_s = [0.0] + [step] * 50
    with pytest.raises(VmNotReady) as ei:
        _provision(rt, probe, wait_ready_s=30)
    assert ei.value.details["phase"] == "down"


def test_reboot_is_recognised_by_the_uptime_drop_with_a_clock_step(rt, timeline, fake_clock,
                                                                   host_tmp) -> None:
    # Control for the uptime rule: a real (fast) reboot plus a forward clock step after it
    # is still recognised (boot time later, uptime far below the hour before).
    probe = RebootProbe(timeline, delay_s=20)
    _, gboot, _ = _setup(rt, timeline, stale_s=E2_STALE_S, reboot_s=E2_DOWN_S)
    gboot.shift_s = [0.0] + [7200.0] * 50
    summary = _provision(rt, probe, wait_ready_s=300)
    assert summary["reboot_signal"] == "boot_time"
    assert fake_clock.t >= timeline.windows[0][1] + 20


def test_boot_time_without_uptime_is_not_used(rt, timeline, host_tmp,
                                              caplog: pytest.LogCaptureFixture) -> None:
    # A guest that reports no uptime: the boot time alone cannot tell a reboot from a
    # clock step, so only the secondary (down) signal is used, and the E2 fast reboot is
    # missed again (same timeline as the E2 regression test).
    probe = RebootProbe(timeline, delay_s=20)
    _, gboot, _ = _setup(rt, timeline, stale_s=E2_STALE_S, reboot_s=E2_DOWN_S)
    gboot.uptime = False
    with pytest.raises(VmNotReady) as ei:
        _provision(rt, probe, wait_ready_s=120)
    assert ei.value.details["phase"] == "down"
    assert any("uptime" in r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING)


def test_boot_time_without_uptime_still_sees_a_long_reboot(rt, timeline, host_tmp) -> None:
    probe = RebootProbe(timeline)
    _, gboot, _ = _setup(rt, timeline, stale_s=2, reboot_s=60)
    gboot.uptime = False
    summary = _provision(rt, probe)
    assert summary["rebooted"] is True and summary["reboot_signal"] == "down"


def test_failed_boot_time_reads_during_the_reboot_are_tolerated(fake_guest, fake_clock, timeline,
                                                                host_tmp) -> None:
    vm = TimelineVm(timeline, tools_follow=False)  # Tools never report the reboot
    rt = FakeRuntime(vm=vm, channel=fake_guest, profile=_profile(), clock=fake_clock)
    probe = RebootProbe(timeline, delay_s=10)
    _, gboot, _ = _setup(rt, timeline, stale_s=1, reboot_s=3)
    gboot.fail_at = {2: VmrunTimeout("vmrun runProgramInGuest timed out"),
                     3: GuestOperationError("Error: Guest program exited with non-zero exit code: 1")}
    summary = _provision(rt, probe, wait_ready_s=120)
    assert summary["rebooted"] is True and summary["reboot_signal"] == "boot_time"
    assert [v is None for _, v in gboot.reads[:3]] == [False, True, True]


def test_boot_time_reads_are_bounded_by_the_remaining_budget(rt, timeline, host_tmp) -> None:
    probe = RebootProbe(timeline)
    _, _, emu = _setup(rt, timeline, reboot_s=0, reboots=False)
    with pytest.raises(VmNotReady):
        _provision(rt, probe, wait_ready_s=20)
    timeouts = [kw["timeout_s"] for (exe, args), kw in rt.channel.calls_of("run_program")
                if exe.endswith("powershell.exe") and args[4] == "-EncodedCommand"
                and is_boot_query(decode_command(args[5]))]
    assert len(timeouts) >= 2  # before the request, then while waiting
    assert all(0 < t <= 60 for t in timeouts)
    assert timeouts[-1] <= 20  # never more than what is left of wait_ready_s


def test_slow_debuggers_after_a_detected_reboot_still_time_out_as_up_phase(rt, timeline, fake_clock,
                                                                           host_tmp) -> None:
    probe = RebootProbe(timeline, delay_s=10_000)
    _setup(rt, timeline, stale_s=1, reboot_s=3)
    t0 = fake_clock.t
    with pytest.raises(VmNotReady) as ei:
        _provision(rt, probe, wait_ready_s=90)
    assert ei.value.details["phase"] == "up"
    assert fake_clock.t - t0 <= 90 + 5


def test_down_observation_remains_a_secondary_signal(rt, timeline, host_tmp) -> None:
    # Boot time unreadable, a long reboot: Tools going down still proves the reboot.
    probe = RebootProbe(timeline)
    _setup(rt, timeline, stale_s=2, reboot_s=60, boot=False)
    summary = _provision(rt, probe)
    assert summary["rebooted"] is True
    assert summary["reboot_signal"] == "down"
    assert summary["boot_time"] == {"before": None, "after": None}


def test_no_reboot_summary_has_no_boot_time(rt, timeline, host_tmp) -> None:
    probe = RebootProbe(timeline)
    _setup(rt, timeline, reboot_s=3)
    summary = _provision(rt, probe, reboot=False)
    assert summary["reboot_signal"] is None and summary["boot_time"] is None


# ── E7: plugin backups live in <root>\<arch>\plugins_backup ─────────
X64_BACKUPS = f"{ROOT}\\x64\\plugins_backup"
X32_BACKUPS = f"{ROOT}\\x32\\plugins_backup"
X64_PLUGINS = f"{ROOT}\\x64\\plugins"
# FakeGuest keeps names lower-cased (Windows paths are case-insensitive).
_STAMP_RE = re.compile(r"^x64dbg-mcp-server\.dp(64|32)\.(\d{8}T\d{6}Z)\.bak$", re.IGNORECASE)


class BackupHashes:
    """Emulates the guest-side SHA-256 listing of the plugins_backup folders."""

    def __init__(self, guest: FakeGuest) -> None:
        self.guest = guest
        self.queries = 0
        self.answer: tuple[int, str] | None = None  # override (exit code, output)

    @staticmethod
    def matches(body: str) -> bool:
        return "plugins_backup" in body and "Get-FileHash" in body

    def __call__(self, body: str) -> tuple[int, str]:
        self.queries += 1
        if self.answer is not None:
            return self.answer
        rows = []
        for d in re.findall(r"'([^']*plugins_backup)'", body):
            prefix = d.lower() + "\\"
            for key, data in sorted(self.guest.files.items()):
                rest = key[len(prefix):] if key.startswith(prefix) else None
                if rest and "\\" not in rest and rest.endswith(".bak"):
                    rows.append({"dir": d, "name": rest, "sha256": hashlib.sha256(data).hexdigest()})
        return 0, "MCPJSON:" + json.dumps(rows)


def _files_in(guest: FakeGuest, directory: str) -> dict[str, bytes]:
    prefix = directory.lower() + "\\"
    return {k[len(prefix):]: v for k, v in guest.files.items()
            if k.startswith(prefix) and "\\" not in k[len(prefix):]}


def _emu(guest: FakeGuest) -> BackupHashes:
    hashes = BackupHashes(guest)
    GuestPowerShell(guest, lambda body: hashes(body) if hashes.matches(body) else (0, ""))
    return hashes


def _stamp(clock: FakeClock, plus_s: int = 0) -> str:
    dt = datetime.fromisoformat(clock.now_iso()) + timedelta(seconds=plus_s)
    return dt.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")


def test_backup_goes_to_plugins_backup_with_a_utc_stamp(rt, timeline, fake_clock, tmp_path) -> None:
    _seed_install(rt.channel)
    _emu(rt.channel)
    stamp = _stamp(fake_clock)
    summary = _install(rt, Probe(timeline), _dist(tmp_path))
    x64 = summary["installed"]["x64"]
    assert x64["backup"] == "created"
    assert x64["backup_path"] == f"{X64_BACKUPS}\\x64dbg-MCP-Server.dp64.{stamp}.bak"
    assert rt.channel.read(x64["backup_path"]) == b"old64"
    assert rt.channel.read(f"{X32_BACKUPS}\\x64dbg-MCP-Server.dp32.{stamp}.bak") == b"old32"
    # nothing but the plugin itself is left in the plugins folders
    assert _files_in(rt.channel, X64_PLUGINS) == {"x64dbg-mcp-server.dp64": b"new64"}
    assert _files_in(rt.channel, f"{ROOT}\\x32\\plugins") == {"x64dbg-mcp-server.dp32": b"new32"}


def test_every_distinct_replaced_build_is_backed_up(rt, timeline, fake_clock, tmp_path) -> None:
    _seed_install(rt.channel)
    _emu(rt.channel)
    _install(rt, Probe(timeline), _dist(tmp_path, b"v1"))
    fake_clock.advance(61)
    rt.channel.add_process(f"{ROOT}\\x64\\x64dbg.exe")
    summary = _install(rt, Probe(timeline), _dist(tmp_path, b"v2"))
    assert summary["installed"]["x64"]["backup"] == "created"
    backups = _files_in(rt.channel, X64_BACKUPS)
    assert sorted(backups.values()) == [b"old64", b"v164"]
    assert all(_STAMP_RE.match(n) for n in backups)
    assert rt.channel.read(X64_PLUGIN) == b"v264"


def test_backup_is_skipped_when_an_identical_one_exists(rt, timeline, fake_clock, tmp_path) -> None:
    _seed_install(rt.channel)
    hashes = _emu(rt.channel)
    existing = f"{X64_BACKUPS}\\x64dbg-MCP-Server.dp64.20260101T000000Z.bak"
    rt.channel.mkdir(X64_BACKUPS)
    rt.channel.write(existing, b"old64")
    summary = _install(rt, Probe(timeline), _dist(tmp_path))
    x64 = summary["installed"]["x64"]
    assert x64["backup"] == "kept"
    assert x64["backup_path"].lower() == existing.lower()
    assert list(_files_in(rt.channel, X64_BACKUPS).values()) == [b"old64"]  # no duplicate
    assert summary["installed"]["x32"]["backup"] == "created"
    assert hashes.queries == 1  # one guest-side query for both architectures


def test_reinstalling_the_same_build_keeps_a_single_backup_of_it(rt, timeline, fake_clock, tmp_path) -> None:
    _seed_install(rt.channel)
    _emu(rt.channel)
    for _ in range(3):
        _install(rt, Probe(timeline), _dist(tmp_path, b"v1"))
        fake_clock.advance(61)
        rt.channel.add_process(f"{ROOT}\\x64\\x64dbg.exe")
    assert sorted(_files_in(rt.channel, X64_BACKUPS).values()) == [b"old64", b"v164"]


def test_legacy_bak_in_plugins_is_moved_to_plugins_backup(rt, timeline, fake_clock, tmp_path) -> None:
    _seed_install(rt.channel)
    rt.channel.write(X64_PLUGIN + ".bak", b"orig64")
    _emu(rt.channel)
    summary = _install(rt, Probe(timeline), _dist(tmp_path))
    assert not rt.channel.file_exists(X64_PLUGIN + ".bak")
    backups = _files_in(rt.channel, X64_BACKUPS)
    assert sorted(backups.values()) == [b"old64", b"orig64"]
    assert len(set(backups)) == 2  # same second, still two names
    assert all(_STAMP_RE.match(n) for n in backups)
    legacy = summary["installed"]["x64"]["legacy_backup"]
    assert legacy is not None and rt.channel.read(legacy) == b"orig64"
    assert summary["installed"]["x32"]["legacy_backup"] is None
    assert _files_in(rt.channel, X64_PLUGINS) == {"x64dbg-mcp-server.dp64": b"new64"}


def test_legacy_bak_identical_to_an_existing_backup_is_not_duplicated(rt, timeline, tmp_path) -> None:
    _seed_install(rt.channel)
    rt.channel.write(X64_PLUGIN + ".bak", b"old64")  # the same build as the current plugin
    _emu(rt.channel)
    summary = _install(rt, Probe(timeline), _dist(tmp_path))
    assert not rt.channel.file_exists(X64_PLUGIN + ".bak")
    assert list(_files_in(rt.channel, X64_BACKUPS).values()) == [b"old64"]
    assert summary["installed"]["x64"]["backup"] == "kept"


def test_stale_old_file_is_backed_up_before_it_leaves_plugins(rt, timeline, tmp_path) -> None:
    # A <plugin>.old from an interrupted install of an earlier version may be the only
    # copy of that build: it is kept in plugins_backup, not just deleted.
    _seed_install(rt.channel)
    rt.channel.write(X64_PLUGIN + ".old", b"interrupted64")
    _emu(rt.channel)
    _install(rt, Probe(timeline), _dist(tmp_path))
    assert not rt.channel.file_exists(X64_PLUGIN + ".old")
    assert sorted(_files_in(rt.channel, X64_BACKUPS).values()) == [b"interrupted64", b"old64"]
    assert _files_in(rt.channel, X64_PLUGINS) == {"x64dbg-mcp-server.dp64": b"new64"}


def test_stale_old_file_identical_to_a_backup_is_just_removed(rt, timeline, tmp_path) -> None:
    _seed_install(rt.channel)
    rt.channel.write(X64_PLUGIN + ".old", b"old64")
    _emu(rt.channel)
    _install(rt, Probe(timeline), _dist(tmp_path))
    assert not rt.channel.file_exists(X64_PLUGIN + ".old")
    assert list(_files_in(rt.channel, X64_BACKUPS).values()) == [b"old64"]


def test_unknown_backup_hashes_fail_open_to_a_new_backup(rt, timeline, fake_clock, tmp_path,
                                                         caplog: pytest.LogCaptureFixture) -> None:
    _seed_install(rt.channel)
    hashes = _emu(rt.channel)
    hashes.answer = (1, "ERROR: access denied")
    rt.channel.mkdir(X64_BACKUPS)
    rt.channel.write(f"{X64_BACKUPS}\\x64dbg-MCP-Server.dp64.20260101T000000Z.bak", b"old64")
    summary = _install(rt, Probe(timeline), _dist(tmp_path))
    assert summary["installed"]["x64"]["backup"] == "created"
    assert len(_files_in(rt.channel, X64_BACKUPS)) == 2
    assert any("backup" in r.getMessage() and r.levelno >= logging.WARNING for r in caplog.records)


def test_stamp_collision_picks_the_next_free_second(rt, timeline, fake_clock, tmp_path) -> None:
    _seed_install(rt.channel)
    _emu(rt.channel)
    taken = f"{X64_BACKUPS}\\x64dbg-MCP-Server.dp64.{_stamp(fake_clock)}.bak"
    rt.channel.mkdir(X64_BACKUPS)
    rt.channel.write(taken, b"something else")
    summary = _install(rt, Probe(timeline), _dist(tmp_path))
    assert summary["installed"]["x64"]["backup_path"] == \
        f"{X64_BACKUPS}\\x64dbg-MCP-Server.dp64.{_stamp(fake_clock, 1)}.bak"
    assert rt.channel.read(taken) == b"something else"


def test_failed_backup_leaves_the_plugin_untouched(rt, timeline, tmp_path) -> None:
    _seed_install(rt.channel)
    _emu(rt.channel)
    orig = rt.channel.copy_to_guest

    def copy(host_path: Path, guest_path: str) -> None:
        if "plugins_backup" in guest_path:
            raise GuestOperationError("Error: disk full")
        orig(host_path, guest_path)

    rt.channel.copy_to_guest = copy  # type: ignore[method-assign]
    with pytest.raises(GuestOperationError) as ei:
        _install(rt, Probe(timeline), _dist(tmp_path))
    assert rt.channel.read(X64_PLUGIN) == b"old64" and rt.channel.read(X32_PLUGIN) == b"old32"
    assert ei.value.details["failed_arch"] == "x64"
    assert ei.value.details["relaunched"] == ["MCP-x64dbg", "MCP-x32dbg"]
    # nothing but the plugins stays in plugins\, not even the uploaded .new (review of E7)
    assert _plugins_leftovers(rt.channel) == []
    runs = [a for a, _ in rt.channel.calls_of("run_program") if a[0] == SCHTASKS]
    assert len(runs) == 2


def test_failed_upload_leaves_no_partial_new_file(rt, timeline, tmp_path) -> None:
    _seed_install(rt.channel)
    _emu(rt.channel)
    orig = rt.channel.copy_to_guest

    def copy(host_path: Path, guest_path: str) -> None:
        if guest_path.lower().endswith(".dp64.new"):
            rt.channel.write(guest_path, b"partial")  # vmrun died half way through the copy
            raise GuestOperationError("Error: disk full")
        orig(host_path, guest_path)

    rt.channel.copy_to_guest = copy  # type: ignore[method-assign]
    with pytest.raises(GuestOperationError):
        _install(rt, Probe(timeline), _dist(tmp_path))
    assert rt.channel.read(X64_PLUGIN) == b"old64"
    assert _plugins_leftovers(rt.channel) == []


def _interrupted_swap(guest: FakeGuest) -> None:
    """What a run that died between rename(plugin, .old) and rename(.new, plugin) leaves."""
    guest.write(X64_PLUGIN + ".old", guest.read(X64_PLUGIN))
    guest.delete_file(X64_PLUGIN)
    guest.write(X64_PLUGIN + ".new", b"half-installed")
    guest.calls.clear()


def test_interrupted_swap_puts_the_previous_plugin_back_and_backs_it_up(rt, timeline, tmp_path) -> None:
    # The .old is then the only copy of the previous build: it becomes the plugin again
    # and goes through the normal backup, before the new build replaces it.
    _seed_install(rt.channel)
    _interrupted_swap(rt.channel)
    _emu(rt.channel)
    summary = _install(rt, Probe(timeline), _dist(tmp_path))
    x64 = summary["installed"]["x64"]
    assert x64["backup"] == "created"
    assert rt.channel.read(x64["backup_path"]) == b"old64"
    assert rt.channel.read(X64_PLUGIN) == b"new64"
    assert _plugins_leftovers(rt.channel) == []


def test_interrupted_swap_with_a_failing_backup_keeps_the_previous_plugin(rt, timeline, tmp_path) -> None:
    # Review of E7: the stale .old was deleted when moving it to plugins_backup failed,
    # although no plugin file existed, i.e. it was the only copy of the previous build.
    _seed_install(rt.channel)
    _interrupted_swap(rt.channel)
    _emu(rt.channel)
    orig = rt.channel.copy_to_guest

    def copy(host_path: Path, guest_path: str) -> None:
        if "plugins_backup" in guest_path:
            raise GuestOperationError("Error: disk full")
        orig(host_path, guest_path)

    rt.channel.copy_to_guest = copy  # type: ignore[method-assign]
    with pytest.raises(GuestOperationError) as ei:
        _install(rt, Probe(timeline), _dist(tmp_path))
    assert rt.channel.read(X64_PLUGIN) == b"old64"  # back in place, not lost
    assert _plugins_leftovers(rt.channel) == []
    assert ei.value.details["failed_arch"] == "x64"


def test_interrupted_swap_whose_old_cannot_be_put_back_is_kept(rt, timeline, tmp_path) -> None:
    _seed_install(rt.channel)
    _interrupted_swap(rt.channel)
    _emu(rt.channel)
    orig = rt.channel.rename

    def rename(src: str, dst: str) -> None:
        if src.lower().endswith(".old"):
            raise GuestOperationError("Error: Access is denied")
        orig(src, dst)

    rt.channel.rename = rename  # type: ignore[method-assign]
    with pytest.raises(GuestOperationError) as ei:
        _install(rt, Probe(timeline), _dist(tmp_path))
    assert rt.channel.read(X64_PLUGIN + ".old") == b"old64"
    assert not rt.channel.file_exists(X64_PLUGIN)
    assert not rt.channel.file_exists(X64_PLUGIN + ".new")
    assert ei.value.details["previous_plugin"].lower() == (X64_PLUGIN + ".old").lower()


def test_backup_name_exhaustion_is_an_error_before_the_swap(rt, timeline, fake_clock, tmp_path,
                                                            monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(provision, "_BACKUP_NAME_TRIES", 2)
    _seed_install(rt.channel)
    _emu(rt.channel)
    rt.channel.mkdir(X64_BACKUPS)
    for i in range(2):
        rt.channel.write(f"{X64_BACKUPS}\\x64dbg-MCP-Server.dp64.{_stamp(fake_clock, i)}.bak", b"other%d" % i)
    with pytest.raises(GuestOperationError) as ei:
        _install(rt, Probe(timeline), _dist(tmp_path))
    assert "no free backup name" in ei.value.message
    assert ei.value.details["backup_dir"] == X64_BACKUPS
    assert rt.channel.read(X64_PLUGIN) == b"old64"
    assert _plugins_leftovers(rt.channel) == []


def test_utc_now_converts_the_clock_to_whole_utc_seconds() -> None:
    class Clock:
        def now_iso(self) -> str:
            return "2026-11-23T09:00:05.750000+09:00"

    assert provision._utc_now(Clock()) == datetime(2026, 11, 23, 0, 0, 5, tzinfo=UTC)  # type: ignore[arg-type]


@pytest.mark.parametrize("value", ["not a time", None, ""])
def test_utc_now_falls_back_to_the_host_clock(value) -> None:
    class Clock:
        def now_iso(self):
            return value

    before = datetime.now(UTC).replace(microsecond=0)
    got = provision._utc_now(Clock())  # type: ignore[arg-type]
    assert before <= got <= datetime.now(UTC)
    assert got.tzinfo is not None and got.utcoffset() == timedelta(0) and got.microsecond == 0


def test_utc_now_reads_a_naive_clock_as_utc() -> None:
    class Clock:
        def now_iso(self) -> str:
            return "2026-11-23T01:02:03"

    assert provision._utc_now(Clock()) == datetime(2026, 11, 23, 1, 2, 3, tzinfo=UTC)  # type: ignore[arg-type]


def test_backup_happens_before_the_swap(rt, timeline, tmp_path) -> None:
    _seed_install(rt.channel)
    _emu(rt.channel)
    _install(rt, Probe(timeline), _dist(tmp_path))
    calls = rt.channel.calls
    backup = min(i for i, c in enumerate(calls) if c[0] == "copy_to_guest" and "plugins_backup" in c[1][1])
    swap = min(i for i, c in enumerate(calls) if c[0] == "rename" and c[1][0].lower() == X64_PLUGIN.lower())
    assert backup < swap


# ── the new PowerShell parses (only where PowerShell 7 is installed) ─
@pytest.mark.skipif(shutil.which("pwsh") is None, reason="pwsh (PowerShell 7) is not installed")
def test_kvm_powershell_parses(tmp_path: Path) -> None:
    # Syntax only (PowerShell 7 parser); behaviour on 5.1 needs the spike VM (tests/vm/test_vm_kvm.py).
    from x64dbg_vm_gateway import platform as plat
    from x64dbg_vm_gateway import provision as prov
    from x64dbg_vm_gateway.ps import ps_quote

    scripts = {
        "boot.ps1": prov._BOOT_SCRIPT,
        "backups.ps1": prov._BACKUP_HASH_SCRIPT.replace(
            "__DIRS__", ", ".join(ps_quote(d) for d in (X64_BACKUPS, X32_BACKUPS))),
        "vmx_scan.ps1": plat._WINDOWS_SCAN_SCRIPT,
    }
    paths = []
    for name, text in scripts.items():
        p = tmp_path / name
        p.write_text(text, encoding="utf-8")
        paths.append(str(p))
    checker = tmp_path / "check.ps1"
    checker.write_text(
        "$failed = 0\n"
        "foreach ($path in $args) {\n"
        "    $tokens = $null; $errors = $null\n"
        "    [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)"
        " | Out-Null\n"
        "    foreach ($e in $errors) {\n"
        "        Write-Output ('{0}:{1}: {2}' -f $path, $e.Extent.StartLineNumber, $e.Message)\n"
        "        $failed = 1\n"
        "    }\n"
        "}\n"
        "exit $failed\n", encoding="utf-8")
    res = subprocess.run(["pwsh", "-NoProfile", "-NonInteractive", "-File", str(checker), *paths],
                         capture_output=True, text=True, timeout=50, check=False)
    assert res.returncode == 0, res.stdout + res.stderr
