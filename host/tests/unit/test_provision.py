"""Tests for guest provisioning, plugin deployment and x64dbg discovery.

The guest side is emulated: ``GuestPowerShell`` (see test_ps) decodes what the
provisioning code hands to powershell.exe, and ``ProvisionScript`` plays the
part of guest/provision.ps1 (reads and deletes the params file, writes
provision.result.json / provision.log). Reboots are a timeline on a FakeClock
shared by a VM whose Tools go down and an HTTP probe whose ports go dark.
"""

from __future__ import annotations

import json
import logging
import math
import os
import re
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from tests.fakes.fake_guest import FakeGuest
from tests.fakes.fake_plugin_server import FakePluginServer
from tests.fakes.fake_vm import FakeClock, FakeVm
from tests.unit.test_ps import GuestPowerShell
from x64dbg_vm_gateway.config import BackendConfig, ProfileConfig
from x64dbg_vm_gateway.contracts import GuestProcess, Secret, Snapshot, ToolsState
from x64dbg_vm_gateway.errors import (
    BackendUnavailable,
    ConfigError,
    GuestOperationError,
    PathNotAllowed,
    ProtectedSnapshotError,
    StateViolation,
    TransferError,
    VmNotReady,
    VmrunTimeout,
)
from x64dbg_vm_gateway.provision import (
    _DISCOVER_SCRIPT,
    RuntimeLike,
    default_http_probe,
    default_info_probe,
    default_local_ip_for,
    discover_x64dbg,
    install_plugin,
    packaged_provision_script,
    provision_guest,
)
from x64dbg_vm_gateway.ps import build_wrapper

REPO = Path(__file__).resolve().parents[3]
GUEST_SCRIPT = REPO / "guest" / "provision.ps1"
ROOT = "C:\\Users\\analyst\\Desktop\\x64dbg\\release"
PASSWORD = "pw-SECRET-4711"
IP = "192.168.56.10"
HOST_IP = "192.168.56.1"  # host-only adapter of the host, as seen from the guest
RESULT = "C:\\mcp\\provision.result.json"
LOG = "C:\\mcp\\provision.log"
SHUTDOWN = "C:\\Windows\\System32\\shutdown.exe"
SCHTASKS = "C:\\Windows\\System32\\schtasks.exe"
INF = math.inf
ANY_ADDR = "0.0.0.0"  # noqa: S104 - plugin bind address inside the guest


def _profile(**kw) -> ProfileConfig:
    base = {
        "name": "win10",
        "vmx": "/vm/win10.vmx",
        "clean_snapshot": "MCP_CLEAN",
        "protected_snapshots": ("MCP_CLEAN", "MCP_BASE"),
        "job_root_guest": "C:\\mcp\\jobs",
        "backends": (BackendConfig(id="x64", arch="x64", port=9094, launch_task="MCP-x64dbg"),
                     BackendConfig(id="x32", arch="x32", port=9095)),
    }
    base.update(kw)
    return ProfileConfig(**base)


# ── timeline-driven fakes ───────────────────────────────────────────
class Timeline:
    """Windows of absolute FakeClock time during which the guest is down."""

    def __init__(self, clock: FakeClock) -> None:
        self.clock = clock
        self.windows: list[tuple[float, float]] = []

    def down(self) -> bool:
        return any(s <= self.clock.t < e for s, e in self.windows)

    def reboot(self, *, stale_s: float = 2.0, reboot_s: float = 60.0) -> None:
        start = self.clock.t + stale_s
        self.windows.append((start, start + reboot_s))


class TimelineVm(FakeVm):
    """Tools stop while the timeline says the guest is down.

    ``tools_errors`` / ``tools_unknown`` / ``missing_ip``: the first N queries fail
    with a vmrun timeout / report an unknown Tools state / return no IP, as a
    loaded host or vmrun hiccup does. ``tools_follow=False`` keeps Tools RUNNING
    through a reboot, so only the dark ports show it.
    """

    def __init__(self, timeline: Timeline, *, tools_errors: int = 0, tools_unknown: int = 0,
                 missing_ip: int = 0, tools_follow: bool = True) -> None:
        super().__init__()
        self.timeline = timeline
        self.ip = IP
        self.tools_errors = tools_errors
        self.tools_unknown = tools_unknown
        self.missing_ip = missing_ip
        self.tools_follow = tools_follow

    def tools_state(self) -> ToolsState:
        self._rec("tools_state")
        if self.tools_errors > 0:
            self.tools_errors -= 1
            raise VmrunTimeout("vmrun checkToolsState timed out")
        if self.tools_unknown > 0:
            self.tools_unknown -= 1
            return ToolsState.UNKNOWN
        if self.tools_follow and self.timeline.down():
            return ToolsState.INSTALLED
        return ToolsState.RUNNING

    def guest_ip(self, *, wait: bool = False, timeout_s: float = 60.0) -> str | None:
        if self.missing_ip > 0:
            self._rec("guest_ip", wait)
            self.missing_ip -= 1
            return None
        return super().guest_ip(wait=wait, timeout_s=timeout_s)


class Probe:
    """``GET /`` of the plugin ports: dark while the guest is down.

    ``up_at`` maps a port to the clock time it starts answering; ``dark_calls``
    makes the first N probes fail (a transient network hiccup). Every answer is
    recorded with its time in ``answers``.
    """

    def __init__(self, timeline: Timeline, *, status: int = 401, dead_ports: tuple[int, ...] = (),
                 dark_calls: int = 0) -> None:
        self.timeline = timeline
        self.status = status
        self.dead_ports = set(dead_ports)
        self.up_at: dict[int, float] = {}
        self.dark_calls = dark_calls
        self.calls: list[tuple[str, int, float]] = []
        self.answers: list[tuple[float, int, int | None]] = []

    def _status(self, port: int) -> int | None:
        if self.dark_calls > 0:
            self.dark_calls -= 1
            return None
        if port in self.dead_ports or self.timeline.down():
            return None
        if self.timeline.clock.t < self.up_at.get(port, -INF):
            return None
        return self.status

    def __call__(self, ip: str, port: int, timeout: float) -> int | None:
        self.calls.append((ip, port, timeout))
        status = self._status(port)
        self.answers.append((self.timeline.clock.t, port, status))
        return status

    def max_rejections_per_minute(self, port: int) -> int:
        """Most 401 answers ``port`` gave within any 60 s (the plugin locks out at 5)."""
        times = [t for t, p, s in self.answers if p == port and s == 401]
        return max((sum(1 for u in times if t <= u < t + 60) for t in times), default=0)


@dataclass
class FakeRuntime:
    vm: FakeVm
    channel: FakeGuest
    profile: ProfileConfig
    clock: FakeClock
    backends: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.backends:
            self.backends = {b.id: b for b in self.profile.backends}

    def guest_ip(self) -> str | None:
        return self.vm.guest_ip()


class ProvisionScript:
    """Plays guest/provision.ps1 for ``GuestPowerShell``."""

    INVOKE_RE = re.compile(r"^& '([^']+\.ps1)' -ParamsFile '([^']+)'$", re.MULTILINE)

    def __init__(self, guest: FakeGuest, *, status: str = "ok", exit_code: int | None = None,
                 error: str = "", archs: tuple[str, ...] = ("x64", "x32"), write_result: bool = True,
                 output: str = "", log_lines: tuple[str, ...] = ()) -> None:
        self.guest = guest
        self.status = status
        self.exit_code = exit_code if exit_code is not None else (0 if status == "ok" else 1)
        self.error = error
        self.archs = archs
        self.write_result = write_result
        self.output = output
        self.log_lines = log_lines
        self.params: dict | None = None
        self.script_bytes: bytes | None = None
        self.runs = 0

    def __call__(self, body: str):
        m = self.INVOKE_RE.search(body)
        if m is None:
            return 0, ""
        self.runs += 1
        ps1, params_path = m.groups()
        self.script_bytes = self.guest.read(ps1)
        self.params = json.loads(self.guest.read(params_path))
        del self.guest.files[params_path.lower()]  # the real script deletes it on read
        p = self.params
        extra = "".join(f"[2026-11-23T10:00:00] {line}\r\n" for line in self.log_lines).encode()
        self.guest.write(LOG, b"[2026-11-23T10:00:00] provision start\r\n" + extra
                              + b"[2026-11-23T10:00:01] provision done\r\n")
        if self.write_result:
            if self.status == "ok":
                exes = {"x64": "x64dbg.exe", "x32": "x32dbg.exe"}
                doc = {
                    "x64dbg_root": p["x64dbg_root"], "user": p["user"], "bind": p["bind"],
                    "job_root": p["job_root"], "status": "ok", "dry_run": bool(p.get("dry_run")),
                    "autologon": bool(p.get("autologon")),
                    "backends": {
                        a: {"exe": f"{p['x64dbg_root']}\\{a}\\{exes[a]}",
                            "config": f"{p['x64dbg_root']}\\{a}\\mcp_config.json",
                            "port": p["ports"][a], "task": f"MCP-{a}dbg", "token_length": 32,
                            "token_generated": False,
                            "plugin": {"present": True, "file_version": None, "size": 123456,
                                       "mtime": "2026-11-20T10:00:00Z", "sha256": "ab" * 32}}
                        for a in self.archs
                    },
                }
                if p.get("dry_run"):
                    doc["actions"] = ["create job root C:\\mcp\\jobs", "register scheduled task MCP-x64dbg"]
            else:
                doc = {"status": self.status, "error": self.error}
            self.guest.write(RESULT, json.dumps(doc).encode())
        return self.exit_code, self.output


@pytest.fixture
def host_tmp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    d = tmp_path / "hosttmp"
    d.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(d))
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


def _setup(rt: FakeRuntime, timeline: Timeline, *, reboot_s: float = 60.0, stale_s: float = 2.0,
           **script_kw) -> tuple[ProvisionScript, GuestPowerShell]:
    script = ProvisionScript(rt.channel, **script_kw)

    def other(exe: str, args: tuple, **kw):
        if exe == SHUTDOWN:
            timeline.reboot(stale_s=stale_s, reboot_s=reboot_s)
            return None
        return 0 if kw.get("wait", True) else None

    emu = GuestPowerShell(rt.channel, script, other)
    return script, emu


def _provision(rt: FakeRuntime, probe: Probe, **kw):
    args = {"x64dbg_root": ROOT, "user": "analyst", "password": Secret(PASSWORD), "reboot": False,
            "http_probe": probe, "local_ip_for": lambda ip: HOST_IP}
    args.update(kw)
    return provision_guest(rt, **args)


# ── packaging / script content ──────────────────────────────────────
def test_packaged_script_is_byte_identical_to_guest_script() -> None:
    packaged = packaged_provision_script()
    assert packaged.read_bytes() == GUEST_SCRIPT.read_bytes()
    src = REPO / "host" / "src" / "x64dbg_vm_gateway" / "data" / "guest" / "provision.ps1"
    assert src.read_bytes() == GUEST_SCRIPT.read_bytes()


def test_guest_script_is_ascii_so_powershell_51_reads_it_without_a_bom() -> None:
    GUEST_SCRIPT.read_bytes().decode("ascii")


def test_guest_script_keeps_secret_handling_and_has_new_features() -> None:
    text = GUEST_SCRIPT.read_text()
    # params file deleted right after it is read
    read_at = text.index("ConvertFrom-Json", text.index("Get-Content -Raw -LiteralPath $ParamsFile"))
    assert "Remove-Item -Force -LiteralPath $ParamsFile" in text[read_at:read_at + 200]
    assert "dry_run" in text and "[switch]$DryRun" in text
    assert "FileSystemAccessRule" in text and "'Modify'" in text
    assert "VersionInfo" in text and "LastWriteTimeUtc" in text
    assert "DefaultPassword" in text
    # the password must never reach the log
    for line in text.splitlines():
        if "Write-Log" in line:
            assert "password" not in line.lower() or "no password" in line.lower(), line


def test_runtime_protocol_is_satisfied_by_the_fake(rt: FakeRuntime) -> None:
    assert isinstance(rt, RuntimeLike)


# ── provision_guest: happy path / params / secrets ─────────────────
def test_provision_copies_script_and_params_and_returns_summary(rt: FakeRuntime, timeline: Timeline,
                                                               host_tmp: Path) -> None:
    script, emu = _setup(rt, timeline)
    probe = Probe(timeline)
    summary = _provision(rt, probe)

    assert ("C:\\mcp",) in [a for a, _ in rt.channel.calls_of("mkdir")]
    assert script.script_bytes == GUEST_SCRIPT.read_bytes()
    assert script.params == {
        "x64dbg_root": ROOT, "user": "analyst", "password": PASSWORD, "autologon": True, "bind": ANY_ADDR,
        "ports": {"x64": 9094, "x32": 9095}, "job_root": "C:\\mcp\\jobs", "no_sleep": True,
        "dry_run": False, "allowed_clients": [HOST_IP],
    }
    params_copies = [a for a, _ in rt.channel.calls_of("copy_to_guest") if str(a[1]).endswith(".json")]
    assert len(params_copies) == 1
    host_params, guest_params = params_copies[0]
    assert re.fullmatch(r"C:\\mcp\\provision-[0-9a-f]{16}\.json", guest_params)
    assert not Path(host_params).exists()
    assert not rt.channel.file_exists(guest_params)
    assert list(host_tmp.iterdir()) == []

    assert summary["status"] == "ok"
    assert summary["x64dbg_root"] == ROOT and summary["job_root"] == "C:\\mcp\\jobs"
    assert summary["backends"]["x64"]["port"] == 9094
    assert summary["backends"]["x32"]["task"] == "MCP-x32dbg"
    assert summary["backends"]["x64"]["plugin"]["sha256"] == "ab" * 32
    assert summary["rebooted"] is False and summary["snapshot"] is None
    assert summary["log_tail"][-1].endswith("provision done")
    assert PASSWORD not in json.dumps(summary)
    assert rt.channel.calls_of("run_program") and not any(
        a[0] == SHUTDOWN for a, _ in rt.channel.calls_of("run_program"))


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_params_host_file_is_private(rt: FakeRuntime, timeline: Timeline, host_tmp: Path) -> None:
    _setup(rt, timeline)
    modes: list[int] = []
    orig = rt.channel.copy_to_guest

    def spy(host_path: Path, guest_path: str) -> None:
        if str(guest_path).endswith(".json"):
            modes.append(stat.S_IMODE(os.stat(host_path).st_mode))
        orig(host_path, guest_path)

    rt.channel.copy_to_guest = spy  # type: ignore[method-assign]
    _provision(rt, Probe(timeline))
    assert modes == [0o600]


def test_ports_and_job_root_come_from_runtime(vm: TimelineVm, fake_guest: FakeGuest, fake_clock: FakeClock,
                                              timeline: Timeline, host_tmp: Path) -> None:
    profile = _profile(job_root_guest="D:\\jobs",
                       backends=(BackendConfig(id="main", arch="x64", port=9100),))
    rt = FakeRuntime(vm=vm, channel=fake_guest, profile=profile, clock=fake_clock)
    script, _ = _setup(rt, timeline, archs=("x64",))
    _provision(rt, Probe(timeline), autologon=False, password=None, bind="192.168.56.10", no_sleep=False)
    assert script.params["ports"] == {"x64": 9100}
    assert script.params["job_root"] == "D:\\jobs"
    assert script.params["autologon"] is False and "password" not in script.params
    assert script.params["bind"] == "192.168.56.10" and script.params["no_sleep"] is False
    _provision(rt, Probe(timeline), job_root="E:\\other")
    assert script.params["job_root"] == "E:\\other"


def test_duplicate_arch_ports_are_a_config_error(rt: FakeRuntime, timeline: Timeline) -> None:
    _setup(rt, timeline)
    rt.backends = {"a": BackendConfig(id="a", arch="x64", port=1),
                   "b": BackendConfig(id="b", arch="x64", port=2)}
    with pytest.raises(ConfigError):
        _provision(rt, Probe(timeline))
    assert rt.channel.calls == []


def test_autologon_requires_password_before_touching_the_guest(rt: FakeRuntime, timeline: Timeline) -> None:
    _setup(rt, timeline)
    with pytest.raises(ConfigError):
        _provision(rt, Probe(timeline), password=None)
    assert rt.channel.calls == []


@pytest.mark.parametrize("kw", [{"x64dbg_root": "relative\\x64dbg"}, {"bind": "not-an-ip"},
                                {"bind": "::"}, {"bind": "::1"},
                                {"user": ""}, {"user": 'a"b'}, {"job_root": "\\\\srv\\jobs"},
                                {"wait_ready_s": 0}])
def test_invalid_arguments_are_rejected_up_front(rt: FakeRuntime, timeline: Timeline, kw: dict) -> None:
    _setup(rt, timeline)
    with pytest.raises((ConfigError, PathNotAllowed, ValueError)):
        _provision(rt, Probe(timeline), **kw)
    assert rt.channel.calls == []


@pytest.mark.parametrize("bind", ["::", "::1", "fe80::1"])
def test_ipv6_bind_is_a_config_error(rt: FakeRuntime, timeline: Timeline, bind: str) -> None:
    # The plugin binds IPv4 only and refuses to start otherwise.
    _setup(rt, timeline)
    with pytest.raises(ConfigError) as ei:
        _provision(rt, Probe(timeline), bind=bind, allowed_clients=[HOST_IP])
    assert "IPv4" in ei.value.message
    assert rt.channel.calls == []


def test_password_is_never_logged_returned_or_raised(rt: FakeRuntime, timeline: Timeline, host_tmp: Path,
                                                    caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    _setup(rt, timeline)
    summary = _provision(rt, Probe(timeline))
    assert PASSWORD not in json.dumps(summary)

    # A failing guest that echoes the password in its error text and output.
    _setup(rt, timeline, status="failed", error=f"Set-ItemProperty rejected value {PASSWORD}",
           output=f"ERROR: {PASSWORD}")
    with pytest.raises(GuestOperationError) as ei:
        _provision(rt, Probe(timeline))
    exc = ei.value
    assert PASSWORD not in str(exc)
    assert PASSWORD not in json.dumps(exc.to_dict(), default=str)
    assert "***" in exc.message
    assert PASSWORD not in caplog.text


def test_failed_status_raises_guest_operation_error(rt: FakeRuntime, timeline: Timeline,
                                                    host_tmp: Path) -> None:
    _setup(rt, timeline, status="failed", error="x64dbg_root not found: C:\\nope")
    with pytest.raises(GuestOperationError) as ei:
        _provision(rt, Probe(timeline), reboot=True, clean_snapshot="NEW_CLEAN")
    exc = ei.value
    assert "x64dbg_root not found" in exc.message
    assert exc.stage == "provision"
    assert exc.details["exit_code"] == 1
    assert exc.details["log_tail"]
    assert "provision.log" in (exc.hint or "")
    # no reboot and no snapshot after a failure
    assert not any(a[0] == SHUTDOWN for a, _ in rt.channel.calls_of("run_program"))
    assert not [c for c in rt.vm.calls if c[0] == "take_snapshot"]
    assert list(host_tmp.iterdir()) == []


def test_ok_result_with_nonzero_exit_is_a_failure(rt: FakeRuntime, timeline: Timeline,
                                                  host_tmp: Path) -> None:
    _setup(rt, timeline, status="ok", exit_code=1)
    with pytest.raises(GuestOperationError):
        _provision(rt, Probe(timeline))


def test_stale_result_from_an_earlier_run_is_removed_first(rt: FakeRuntime, timeline: Timeline,
                                                          host_tmp: Path) -> None:
    rt.channel.write(RESULT, json.dumps({"status": "ok", "backends": {}}).encode())
    _setup(rt, timeline, write_result=False, exit_code=1, output="ParserError: unexpected token")
    with pytest.raises(GuestOperationError) as ei:
        _provision(rt, Probe(timeline))
    assert "ParserError" in json.dumps(ei.value.details)
    deletes = [a[0] for a, _ in rt.channel.calls_of("delete_file")]
    assert RESULT in deletes


def test_guest_params_file_is_removed_when_the_script_never_ran(rt: FakeRuntime, timeline: Timeline,
                                                               host_tmp: Path) -> None:
    _setup(rt, timeline)
    rt.channel.fail_next("run_program", VmrunTimeout("vmrun runProgramInGuest timed out"))
    with pytest.raises(VmrunTimeout):
        _provision(rt, Probe(timeline))
    assert not any(k.startswith("c:\\mcp\\provision-") for k in rt.channel.files)
    assert list(host_tmp.iterdir()) == []


# ── reboot wait loop ────────────────────────────────────────────────
def test_reboot_issues_shutdown_and_waits_until_every_port_answers(rt: FakeRuntime, timeline: Timeline,
                                                                  fake_clock: FakeClock,
                                                                  host_tmp: Path) -> None:
    _setup(rt, timeline, reboot_s=60)
    probe = Probe(timeline)
    t0 = fake_clock.t
    summary = _provision(rt, probe, reboot=True)
    shut = [(a, k) for a, k in rt.channel.calls_of("run_program") if a[0] == SHUTDOWN]
    assert shut == [((SHUTDOWN, ("/r", "/t", "2", "/f")), shut[0][1])]
    assert shut[0][1]["wait"] is False
    assert summary["rebooted"] is True
    assert 60 <= summary["ready_s"] <= 60 + 2 + 5
    assert fake_clock.t - t0 < 80
    assert summary["readiness"] == {"x64": 401, "x32": 401}
    assert {p for _, p, _ in probe.calls} == {9094, 9095}
    assert {ip for ip, _, _ in probe.calls} == {IP}
    assert all(s <= 5 for s in fake_clock.sleeps)


def test_reboot_does_not_trust_the_old_instance_before_it_goes_down(rt: FakeRuntime, timeline: Timeline,
                                                                   host_tmp: Path) -> None:
    _setup(rt, timeline, stale_s=10, reboot_s=30)
    summary = _provision(rt, Probe(timeline), reboot=True)
    assert summary["ready_s"] >= 40


def test_reboot_timeout_raises_vm_not_ready(rt: FakeRuntime, timeline: Timeline, fake_clock: FakeClock,
                                            host_tmp: Path) -> None:
    _setup(rt, timeline, reboot_s=INF)
    t0 = fake_clock.t
    with pytest.raises(VmNotReady) as ei:
        _provision(rt, Probe(timeline), reboot=True, wait_ready_s=120, clean_snapshot="NEW_CLEAN")
    assert 120 <= fake_clock.t - t0 <= 120 + 5
    assert ei.value.details["phase"] == "up"
    assert sorted(ei.value.details["pending"]) == ["x32", "x64"]
    assert not [c for c in rt.vm.calls if c[0] == "take_snapshot"]


def test_reboot_that_never_goes_down_raises(rt: FakeRuntime, timeline: Timeline, host_tmp: Path) -> None:
    script = ProvisionScript(rt.channel)
    GuestPowerShell(rt.channel, script)  # shutdown.exe does nothing
    probe = Probe(timeline)
    with pytest.raises(VmNotReady) as ei:
        _provision(rt, probe, reboot=True, wait_ready_s=60)
    assert ei.value.details["phase"] == "down"
    # The old instances were asked only a few times: five 401s within 60 s lock the host out.
    assert probe.max_rejections_per_minute(9094) == 3
    assert probe.max_rejections_per_minute(9095) == 3


def test_ready_requires_every_provisioned_backend(rt: FakeRuntime, timeline: Timeline,
                                                  host_tmp: Path) -> None:
    _setup(rt, timeline)
    with pytest.raises(VmNotReady) as ei:
        _provision(rt, Probe(timeline, dead_ports=(9095,)), reboot=True, wait_ready_s=200)
    assert ei.value.details["pending"] == ["x32"]


def test_only_backends_the_script_configured_are_awaited(rt: FakeRuntime, timeline: Timeline,
                                                        host_tmp: Path) -> None:
    _setup(rt, timeline, archs=("x64",))
    probe = Probe(timeline, dead_ports=(9095,))
    summary = _provision(rt, probe, reboot=True)
    assert {p for _, p, _ in probe.calls} == {9094}
    assert summary["readiness"] == {"x64": 401}


def test_probe_status_200_counts_as_ready(rt: FakeRuntime, timeline: Timeline, host_tmp: Path) -> None:
    _setup(rt, timeline)
    summary = _provision(rt, Probe(timeline, status=200), reboot=True)
    assert summary["readiness"] == {"x64": 200, "x32": 200}


def test_probe_status_other_than_200_or_401_is_not_ready(rt: FakeRuntime, timeline: Timeline,
                                                        host_tmp: Path) -> None:
    _setup(rt, timeline)
    with pytest.raises(VmNotReady):
        _provision(rt, Probe(timeline, status=500), reboot=True, wait_ready_s=100)


@pytest.mark.parametrize("flaky", [{"tools_errors": 1}, {"tools_unknown": 1}, {"missing_ip": 1},
                                   {"tools_errors": 3, "missing_ip": 2}])
def test_unobservable_guest_is_not_taken_for_the_reboot(fake_guest: FakeGuest, fake_clock: FakeClock,
                                                        timeline: Timeline, host_tmp: Path,
                                                        flaky: dict) -> None:
    # A vmrun hiccup right after shutdown.exe was started says nothing about the reboot:
    # the old debuggers still answer, and a snapshot taken now would precede the reboot.
    vm = TimelineVm(timeline, **flaky)
    rt = FakeRuntime(vm=vm, channel=fake_guest, profile=_profile(), clock=fake_clock)
    _setup(rt, timeline, stale_s=10, reboot_s=30)
    t0 = fake_clock.t
    # An explicit allowlist: no guest_ip() query before the reboot uses up the hiccups.
    summary = _provision(rt, Probe(timeline), reboot=True, clean_snapshot="MCP_CLEAN_V2",
                         allowed_clients=[HOST_IP])
    window_end = timeline.windows[0][1]
    assert summary["ready_s"] >= 40
    take = [i for i, c in enumerate(vm.calls) if c[0] == "take_snapshot"]
    assert take and fake_clock.t >= window_end
    assert summary["snapshot"] == {"name": "MCP_CLEAN_V2", "replaced": False}
    assert fake_clock.t - t0 < 40 + 2 * 5 + 1


def test_one_dark_probe_round_is_not_a_reboot(rt: FakeRuntime, timeline: Timeline, host_tmp: Path) -> None:
    _setup(rt, timeline, stale_s=10, reboot_s=30)
    summary = _provision(rt, Probe(timeline, dark_calls=2), reboot=True)  # both ports, first poll
    assert summary["ready_s"] >= 40


def test_reboot_seen_only_through_dark_ports(fake_guest: FakeGuest, fake_clock: FakeClock,
                                             timeline: Timeline, host_tmp: Path) -> None:
    vm = TimelineVm(timeline, tools_follow=False)  # Tools never report the reboot
    rt = FakeRuntime(vm=vm, channel=fake_guest, profile=_profile(), clock=fake_clock)
    _setup(rt, timeline, stale_s=2, reboot_s=60)
    summary = _provision(rt, Probe(timeline), reboot=True)
    assert summary["rebooted"] is True and summary["ready_s"] >= 60


def test_answered_ports_are_not_probed_again(rt: FakeRuntime, timeline: Timeline, fake_clock: FakeClock,
                                             host_tmp: Path) -> None:
    # Every unauthenticated GET / is a failed login for the v1.10 plugin; five within
    # 60 s lock the host out (HTTP 429). x64 is up long before x32 here.
    _setup(rt, timeline, reboot_s=30)
    probe = Probe(timeline)
    probe.up_at[9095] = fake_clock.t + 150
    summary = _provision(rt, probe, reboot=True)
    assert summary["readiness"] == {"x64": 401, "x32": 401}
    assert summary["ready_s"] >= 150
    assert probe.max_rejections_per_minute(9094) <= 2
    assert probe.max_rejections_per_minute(9095) <= 2


def test_install_wait_does_not_trip_the_auth_lockout(rt: FakeRuntime, timeline: Timeline,
                                                     fake_clock: FakeClock, tmp_path: Path) -> None:
    _seed_install(rt.channel)
    GuestPowerShell(rt.channel)
    probe = Probe(timeline)
    probe.up_at[9095] = fake_clock.t + 60
    summary = _install(rt, probe, _dist(tmp_path))
    assert summary["backends"]["x32"]["status"] == 401
    assert probe.max_rejections_per_minute(9094) == 1


def test_locked_out_port_counts_as_up_and_is_reported(rt: FakeRuntime, timeline: Timeline, host_tmp: Path,
                                                      caplog: pytest.LogCaptureFixture) -> None:
    _setup(rt, timeline)
    summary = _provision(rt, Probe(timeline, status=429), reboot=True)
    assert summary["readiness"] == {"x64": 429, "x32": 429}
    warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("429" in m for m in warnings)


def test_ip_change_after_reboot_reprobes(fake_guest: FakeGuest, fake_clock: FakeClock, timeline: Timeline,
                                         host_tmp: Path) -> None:
    vm = TimelineVm(timeline)
    rt = FakeRuntime(vm=vm, channel=fake_guest, profile=_profile(), clock=fake_clock)
    _setup(rt, timeline, reboot_s=30)
    probe = Probe(timeline)
    probe.up_at[9095] = fake_clock.t + 100
    real_ip = vm.guest_ip

    def ip_after_reboot(*, wait: bool = False, timeout_s: float = 60.0) -> str | None:
        ip = real_ip(wait=wait, timeout_s=timeout_s)
        renewed = bool(timeline.windows) and fake_clock.t > timeline.windows[0][1] + 20
        return "192.168.56.20" if ip and renewed else ip

    vm.guest_ip = ip_after_reboot  # type: ignore[method-assign]
    _provision(rt, probe, reboot=True)
    late = {(ip, port) for ip, port, _ in probe.calls}
    assert ("192.168.56.20", 9094) in late and ("192.168.56.20", 9095) in late


# ── plugin allowlist (v1.10 refuses a non-loopback bind without it) ─
def test_non_loopback_bind_allows_the_hosts_address_by_default(rt: FakeRuntime, timeline: Timeline,
                                                               host_tmp: Path) -> None:
    script, _ = _setup(rt, timeline)
    asked: list[str] = []
    summary = _provision(rt, Probe(timeline), local_ip_for=lambda ip: asked.append(ip) or HOST_IP)
    assert asked == [IP]
    assert script.params["allowed_clients"] == [HOST_IP]
    assert summary["allowed_clients"] == [HOST_IP]


def test_explicit_allowed_clients_are_normalised(rt: FakeRuntime, timeline: Timeline, host_tmp: Path) -> None:
    script, _ = _setup(rt, timeline)

    def never(ip: str) -> str:
        raise AssertionError("must not be derived when given")

    _provision(rt, Probe(timeline), allowed_clients=[" 192.168.56.7/24", "10.0.0.5", "10.0.0.5"],
               local_ip_for=never)
    assert script.params["allowed_clients"] == ["192.168.56.0/24", "10.0.0.5"]


@pytest.mark.parametrize("bad", [[], ["not-an-ip"], ["::1"], ["10.0.0.0/33"], "10.0.0.1",
                                 [f"10.0.{i // 250}.{i % 250}" for i in range(65)], [None]])
def test_bad_allowed_clients_are_rejected_before_touching_the_guest(rt: FakeRuntime, timeline: Timeline,
                                                                    bad) -> None:
    _setup(rt, timeline)
    with pytest.raises(ConfigError):
        _provision(rt, Probe(timeline), allowed_clients=bad)
    assert rt.channel.calls == []


def test_non_loopback_bind_without_a_host_address_is_refused(rt: FakeRuntime, timeline: Timeline) -> None:
    _setup(rt, timeline)
    with pytest.raises(ConfigError) as ei:
        _provision(rt, Probe(timeline), local_ip_for=lambda ip: None)
    assert "allowed_clients" in (ei.value.hint or "")
    assert rt.channel.calls == []


def test_loopback_bind_needs_no_allowlist(rt: FakeRuntime, timeline: Timeline, host_tmp: Path) -> None:
    script, _ = _setup(rt, timeline)

    def never(ip: str) -> str:
        raise AssertionError("loopback needs no allowlist")

    summary = _provision(rt, Probe(timeline), bind="127.0.0.1", local_ip_for=never)
    assert script.params["allowed_clients"] == []
    assert summary["allowed_clients"] == []


def test_guest_script_merges_the_plugin_config_and_allows_external_clients() -> None:
    text = GUEST_SCRIPT.read_text()
    assert "allowed_clients" in text
    assert "AllowExternal" in text and "AllowedClients" in text
    assert "NoteProperty" in text  # keys of an existing config the script does not manage are kept
    # The four keys every plugin version reads come first (v1.3 reads only 512 bytes).
    order = [text.index(k) for k in ("IpAddress = $bind", "Port = $port", "AutoStart = $true",
                                     "AuthToken = $token")]
    assert order == sorted(order)


# ── default probes (real I/O, loopback only) ───────────────────────
def test_default_probes_against_a_plugin_server() -> None:
    token = "T" * 32
    srv = FakePluginServer(token=token, version="1.10").start()
    try:
        assert default_http_probe("127.0.0.1", srv.port, 3.0) == 401
        info = default_info_probe("127.0.0.1", srv.port, 3.0, Secret(token))
        assert info is not None and info["version"] == "1.10"
        assert default_info_probe("127.0.0.1", srv.port, 3.0, Secret("wrong")) is None
        assert [r.authorization for r in srv.requests if r.authorized] == [f"Bearer {token}"]
        srv.set_raw_response("GET", 200, b"not json")
        assert default_info_probe("127.0.0.1", srv.port, 3.0, Secret(token)) is None
        srv.set_raw_response("GET", 200, b"[1, 2]")
        assert default_info_probe("127.0.0.1", srv.port, 3.0, Secret(token)) is None
        srv.set_raw_response("GET", 200, b'{"version": "' + b"x" * (70 * 1024) + b'"}')
        assert default_info_probe("127.0.0.1", srv.port, 3.0, Secret(token)) is None  # over 64 KiB
    finally:
        srv.stop()
    assert default_http_probe("127.0.0.1", srv.port, 1.0) is None  # refused


def test_default_local_ip_for_loopback() -> None:
    assert default_local_ip_for("127.0.0.1") == "127.0.0.1"
    assert default_local_ip_for("not-an-ip") is None


# ── guest-side PowerShell parses (only where PowerShell 7 is installed) ─
@pytest.mark.skipif(shutil.which("pwsh") is None, reason="pwsh (PowerShell 7) is not installed")
def test_guest_powershell_parses(tmp_path: Path) -> None:
    # A syntax check only, with the PowerShell 7 parser (a superset of 5.1's syntax);
    # behaviour on Windows PowerShell 5.1 still needs the spike VM (tests/vm).
    scripts = {
        "provision.ps1": GUEST_SCRIPT.read_text(),
        "discover.ps1": _DISCOVER_SCRIPT.replace("__MAX_DEPTH__", "4").replace("__EXTRA_ROOTS__", "'D:\\x'"),
        "wrapper.ps1": build_wrapper("Get-Date\nexit 3", out_path="C:\\mcp\\tmp\\ps-1.out",
                                     tmp_dir="C:\\mcp\\tmp", tag="0123456789abcdef"),
        "quiet.ps1": build_wrapper("Get-Date", out_path=None, tmp_dir="C:\\mcp\\tmp"),
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


# ── clean snapshot ──────────────────────────────────────────────────
def test_existing_snapshot_is_refused_before_any_guest_change(rt: FakeRuntime, timeline: Timeline) -> None:
    _setup(rt, timeline)
    with pytest.raises(StateViolation) as ei:
        _provision(rt, Probe(timeline), clean_snapshot="MCP_CLEAN")
    assert "overwrite_snapshot" not in (ei.value.hint or "")  # it is protected: overwrite would not help
    assert rt.channel.calls == []
    assert not [c for c in rt.vm.calls if c[0] in ("take_snapshot", "delete_snapshot")]


def test_overwrite_deletes_then_takes_after_ready(rt: FakeRuntime, timeline: Timeline,
                                                  host_tmp: Path) -> None:
    rt.vm.snapshots.append(Snapshot("MCP_CLEAN_TRY"))
    _setup(rt, timeline)
    summary = _provision(rt, Probe(timeline), reboot=True, clean_snapshot="MCP_CLEAN_TRY",
                         overwrite_snapshot=True)
    ops = [c for c in rt.vm.calls if c[0] in ("take_snapshot", "delete_snapshot")]
    assert ops == [("delete_snapshot", ("MCP_CLEAN_TRY",)), ("take_snapshot", ("MCP_CLEAN_TRY",))]
    last_tools = max(i for i, c in enumerate(rt.vm.calls) if c[0] == "tools_state")
    first_snap = min(i for i, c in enumerate(rt.vm.calls) if c[0] == "delete_snapshot")
    assert last_tools < first_snap
    assert summary["snapshot"] == {"name": "MCP_CLEAN_TRY", "replaced": True}


@pytest.mark.parametrize("protected", [("MCP_CLEAN", "MCP_BASE"), ()])
@pytest.mark.parametrize("name", ["MCP_CLEAN", "mcp_clean"])
def test_overwrite_never_deletes_the_profiles_clean_snapshot(vm: TimelineVm, fake_guest: FakeGuest,
                                                             fake_clock: FakeClock, timeline: Timeline,
                                                             protected: tuple, name: str) -> None:
    # Plan 5.7: protected snapshots are never deleted, and the profile's clean snapshot
    # is always protected (as in policy.check_snapshot_delete).
    rt = FakeRuntime(vm=vm, channel=fake_guest, profile=_profile(protected_snapshots=protected),
                     clock=fake_clock)
    _setup(rt, timeline)
    with pytest.raises(ProtectedSnapshotError) as ei:
        _provision(rt, Probe(timeline), reboot=True, clean_snapshot=name, overwrite_snapshot=True)
    assert "clean_snapshot" in (ei.value.hint or "")
    assert rt.channel.calls == []
    assert not [c for c in rt.vm.calls if c[0] in ("take_snapshot", "delete_snapshot")]


def test_failed_take_after_delete_says_the_old_snapshot_is_gone(rt: FakeRuntime, timeline: Timeline,
                                                               host_tmp: Path,
                                                               caplog: pytest.LogCaptureFixture) -> None:
    rt.vm.snapshots.append(Snapshot("MCP_CLEAN_TRY"))
    _setup(rt, timeline)

    def failing_take(name: str) -> None:
        rt.vm.calls.append(("take_snapshot", (name,)))
        raise VmrunTimeout("vmrun snapshot timed out")

    rt.vm.take_snapshot = failing_take  # type: ignore[method-assign]
    with pytest.raises(VmrunTimeout) as ei:
        _provision(rt, Probe(timeline), clean_snapshot="MCP_CLEAN_TRY", overwrite_snapshot=True)
    d = ei.value.details
    assert d["snapshot"] == "MCP_CLEAN_TRY"
    assert d["step"] == "take_snapshot"
    assert d["old_snapshot_deleted"] is True
    assert "MCP_CLEAN_TRY" in (ei.value.hint or "")
    assert "MCP_CLEAN_TRY" not in [s.name for s in rt.vm.snapshots]
    assert any(r.levelno >= logging.ERROR and "MCP_CLEAN_TRY" in r.getMessage() for r in caplog.records)


def test_failed_take_of_a_new_snapshot_reports_the_step(rt: FakeRuntime, timeline: Timeline,
                                                       host_tmp: Path) -> None:
    _setup(rt, timeline)
    rt.vm.take_snapshot = lambda name: (_ for _ in ()).throw(  # type: ignore[method-assign]
        VmrunTimeout("vmrun snapshot timed out"))
    with pytest.raises(VmrunTimeout) as ei:
        _provision(rt, Probe(timeline), clean_snapshot="MCP_CLEAN_V2")
    assert ei.value.details["step"] == "take_snapshot"
    assert ei.value.details["old_snapshot_deleted"] is False


def test_absent_snapshot_is_taken(rt: FakeRuntime, timeline: Timeline, host_tmp: Path) -> None:
    _setup(rt, timeline)
    summary = _provision(rt, Probe(timeline), reboot=True, clean_snapshot="MCP_CLEAN_V2")
    ops = [c for c in rt.vm.calls if c[0] in ("take_snapshot", "delete_snapshot")]
    assert ops == [("take_snapshot", ("MCP_CLEAN_V2",))]
    assert summary["snapshot"] == {"name": "MCP_CLEAN_V2", "replaced": False}


def test_snapshot_without_reboot_still_waits_for_ready(rt: FakeRuntime, timeline: Timeline,
                                                      host_tmp: Path) -> None:
    _setup(rt, timeline)
    probe = Probe(timeline, dead_ports=(9094, 9095))
    with pytest.raises(VmNotReady):
        _provision(rt, probe, reboot=False, clean_snapshot="MCP_CLEAN_V2", wait_ready_s=30)
    assert not [c for c in rt.vm.calls if c[0] == "take_snapshot"]


def test_overwrite_never_touches_other_protected_snapshots(rt: FakeRuntime, timeline: Timeline) -> None:
    rt.vm.snapshots.append(Snapshot("MCP_BASE"))
    _setup(rt, timeline)
    with pytest.raises(ProtectedSnapshotError):
        _provision(rt, Probe(timeline), clean_snapshot="mcp_base", overwrite_snapshot=True)
    assert rt.channel.calls == []


def test_ambiguous_snapshot_name_is_refused(rt: FakeRuntime, timeline: Timeline) -> None:
    rt.vm.snapshots += [Snapshot("MCP_TRY"), Snapshot("mcp_try")]
    _setup(rt, timeline)
    with pytest.raises(StateViolation):
        _provision(rt, Probe(timeline), clean_snapshot="MCP_TRY", overwrite_snapshot=True)
    assert rt.channel.calls == []


# ── dry run ─────────────────────────────────────────────────────────
def test_dry_run_reports_plan_without_reboot_or_snapshot(rt: FakeRuntime, timeline: Timeline,
                                                        host_tmp: Path) -> None:
    script, _ = _setup(rt, timeline)
    summary = _provision(rt, Probe(timeline), reboot=True, clean_snapshot="MCP_CLEAN", dry_run=True)
    assert script.params["dry_run"] is True
    assert summary["dry_run"] is True
    assert summary["actions"] == ["create job root C:\\mcp\\jobs", "register scheduled task MCP-x64dbg"]
    assert summary["plan"] == {"reboot": True, "snapshot": {"name": "MCP_CLEAN", "exists": True,
                                                            "action": "refuse"}}
    assert summary["rebooted"] is False and summary["snapshot"] is None
    assert not any(a[0] == SHUTDOWN for a, _ in rt.channel.calls_of("run_program"))
    assert not [c for c in rt.vm.calls if c[0] in ("take_snapshot", "delete_snapshot")]


def test_dry_run_never_sends_the_password(rt: FakeRuntime, timeline: Timeline, host_tmp: Path) -> None:
    script, _ = _setup(rt, timeline)
    _provision(rt, Probe(timeline), dry_run=True)
    assert script.params["autologon"] is True and script.params["dry_run"] is True
    assert "password" not in script.params
    # ... and the guest script does not insist on one when it only plans.
    text = GUEST_SCRIPT.read_text()
    check = next(line for line in text.splitlines() if "autologon requested but no password" in line)
    assert "-not $dry" in check


def test_scrubbing_only_touches_guest_text(rt: FakeRuntime, timeline: Timeline, host_tmp: Path) -> None:
    # A password equal to the account name (common on analysis VMs) must not mangle
    # host-supplied paths, while guest-written text is still scrubbed.
    _setup(rt, timeline, log_lines=("auto-logon configured for analyst",))
    summary = provision_guest(rt, x64dbg_root=ROOT, user="analyst", password=Secret("analyst"), reboot=False,
                              http_probe=Probe(timeline), local_ip_for=lambda ip: HOST_IP)
    assert summary["x64dbg_root"] == ROOT
    assert summary["user"] == "analyst"
    assert summary["backends"]["x64"]["exe"] == f"{ROOT}\\x64\\x64dbg.exe"
    assert summary["backends"]["x64"]["config"] == f"{ROOT}\\x64\\mcp_config.json"
    assert any(line.endswith("auto-logon configured for ***") for line in summary["log_tail"])


# ── install_plugin ──────────────────────────────────────────────────
X64_PLUGIN = f"{ROOT}\\x64\\plugins\\x64dbg-MCP-Server.dp64"
X32_PLUGIN = f"{ROOT}\\x32\\plugins\\x64dbg-MCP-Server.dp32"


def _seed_install(guest: FakeGuest, *, plugins: bool = True) -> None:
    guest.write(f"{ROOT}\\x64\\x64dbg.exe", b"MZ64")
    guest.write(f"{ROOT}\\x32\\x32dbg.exe", b"MZ32")
    guest.mkdir(f"{ROOT}\\x64\\plugins")
    guest.mkdir(f"{ROOT}\\x32\\plugins")
    if plugins:
        guest.write(X64_PLUGIN, b"old64")
        guest.write(X32_PLUGIN, b"old32")
    guest.add_process(f'"{ROOT}\\x64\\x64dbg.exe" ')
    guest.add_process(f"{ROOT}\\x32\\x32dbg.exe")
    guest.add_process("C:\\Windows\\notepad.exe")
    guest.calls.clear()


def _dist(tmp_path: Path, tag: bytes = b"new", *, x32: bool = True) -> Path:
    d = tmp_path / f"dist-{tag.decode()}"
    (d / "x64" / "plugins").mkdir(parents=True, exist_ok=True)
    (d / "x64" / "plugins" / "x64dbg-MCP-Server.dp64").write_bytes(tag + b"64")
    if x32:
        (d / "x32" / "plugins").mkdir(parents=True, exist_ok=True)
        (d / "x32" / "plugins" / "x64dbg-MCP-Server.dp32").write_bytes(tag + b"32")
    return d


def _install(rt: FakeRuntime, probe: Probe, dist: Path, **kw):
    return install_plugin(rt, dist_dir=dist, x64dbg_root=ROOT, http_probe=probe, **kw)


def test_install_requires_both_dist_plugins(rt: FakeRuntime, timeline: Timeline, tmp_path: Path) -> None:
    _seed_install(rt.channel)
    with pytest.raises(TransferError) as ei:
        _install(rt, Probe(timeline), _dist(tmp_path, x32=False))
    assert "x64dbg-MCP-Server.dp32" in json.dumps(ei.value.details)
    assert rt.channel.calls == []


def test_install_kills_debuggers_backs_up_once_and_relaunches(rt: FakeRuntime, timeline: Timeline,
                                                             tmp_path: Path) -> None:
    _seed_install(rt.channel)
    GuestPowerShell(rt.channel)
    summary = _install(rt, Probe(timeline), _dist(tmp_path))

    assert [p.image_name for p in rt.channel.processes] == ["notepad.exe"]
    assert rt.channel.read(X64_PLUGIN) == b"new64" and rt.channel.read(X32_PLUGIN) == b"new32"
    assert rt.channel.read(X64_PLUGIN + ".bak") == b"old64"
    assert rt.channel.read(X32_PLUGIN + ".bak") == b"old32"
    assert not any(k.endswith(".new") for k in rt.channel.files)
    runs = [a for a, _ in rt.channel.calls_of("run_program") if a[0] == SCHTASKS]
    assert runs == [(SCHTASKS, ("/run", "/tn", "MCP-x64dbg")), (SCHTASKS, ("/run", "/tn", "MCP-x32dbg"))]
    kill_idx = max(i for i, c in enumerate(rt.channel.calls) if c[0] == "kill_process")
    copy_idx = min(i for i, c in enumerate(rt.channel.calls) if c[0] == "copy_to_guest")
    assert kill_idx < copy_idx
    assert summary["installed"]["x64"]["backup"] == "created"
    assert summary["installed"]["x64"]["guest_path"] == X64_PLUGIN
    assert len(summary["installed"]["x64"]["sha256"]) == 64
    assert len(summary["killed"]) == 2
    assert summary["relaunched"] is True
    assert summary["backends"]["x64"] == {"port": 9094, "status": 401, "version": None}
    assert summary["backends"]["x32"]["status"] == 401


def test_second_install_keeps_the_original_backup(rt: FakeRuntime, timeline: Timeline,
                                                  tmp_path: Path) -> None:
    _seed_install(rt.channel)
    GuestPowerShell(rt.channel)
    _install(rt, Probe(timeline), _dist(tmp_path, b"v1"))
    rt.channel.add_process(f"{ROOT}\\x64\\x64dbg.exe")
    summary = _install(rt, Probe(timeline), _dist(tmp_path, b"v2"))
    assert rt.channel.read(X64_PLUGIN + ".bak") == b"old64"
    assert rt.channel.read(X64_PLUGIN) == b"v264"
    assert rt.channel.read(X32_PLUGIN) == b"v232"
    assert summary["installed"]["x64"]["backup"] == "kept"


def test_install_without_existing_plugin_makes_no_backup(rt: FakeRuntime, timeline: Timeline,
                                                         tmp_path: Path) -> None:
    _seed_install(rt.channel, plugins=False)
    GuestPowerShell(rt.channel)
    summary = _install(rt, Probe(timeline), _dist(tmp_path))
    assert summary["installed"]["x64"]["backup"] == "none"
    assert not rt.channel.file_exists(X64_PLUGIN + ".bak")
    assert rt.channel.read(X64_PLUGIN) == b"new64"


def test_install_replaces_a_stale_new_file(rt: FakeRuntime, timeline: Timeline, tmp_path: Path) -> None:
    _seed_install(rt.channel)
    rt.channel.write(X64_PLUGIN + ".new", b"partial")
    GuestPowerShell(rt.channel)
    _install(rt, Probe(timeline), _dist(tmp_path))
    assert rt.channel.read(X64_PLUGIN) == b"new64"
    assert not rt.channel.file_exists(X64_PLUGIN + ".new")


def test_install_reports_versions_only_with_a_token(rt: FakeRuntime, timeline: Timeline,
                                                    tmp_path: Path) -> None:
    _seed_install(rt.channel)
    GuestPowerShell(rt.channel)
    seen: list = []

    def info_probe(ip: str, port: int, timeout: float, token: Secret):
        seen.append((ip, port, token.reveal()))
        return {"name": "x64dbg-MCP Server", "version": "1.10"}

    token = "T" * 40
    summary = _install(rt, Probe(timeline), _dist(tmp_path),
                       token_for=lambda bid: Secret(token) if bid == "x64" else None,
                       info_probe=info_probe)
    assert seen == [(IP, 9094, token)]
    assert summary["backends"]["x64"]["version"] == "1.10"
    assert summary["backends"]["x32"]["version"] is None
    assert token not in json.dumps(summary)


def test_install_without_relaunch_does_not_wait(rt: FakeRuntime, timeline: Timeline, tmp_path: Path) -> None:
    _seed_install(rt.channel)
    GuestPowerShell(rt.channel)
    probe = Probe(timeline)
    summary = _install(rt, probe, _dist(tmp_path), relaunch=False)
    assert not [a for a, _ in rt.channel.calls_of("run_program") if a[0] == SCHTASKS]
    assert probe.calls == []
    assert summary["relaunched"] is False
    assert rt.channel.read(X64_PLUGIN) == b"new64"


def test_install_not_ready_raises_with_install_details(rt: FakeRuntime, timeline: Timeline,
                                                       fake_clock: FakeClock, tmp_path: Path) -> None:
    _seed_install(rt.channel)
    GuestPowerShell(rt.channel)
    t0 = fake_clock.t
    with pytest.raises(VmNotReady) as ei:
        _install(rt, Probe(timeline, dead_ports=(9095,)), _dist(tmp_path), wait_ready_s=30)
    assert ei.value.details["pending"] == ["x32"]
    assert ei.value.details["installed"]["x32"]["guest_path"] == X32_PLUGIN
    assert fake_clock.t - t0 <= 30 + 2


def test_install_schtasks_failure_raises(rt: FakeRuntime, timeline: Timeline, tmp_path: Path) -> None:
    _seed_install(rt.channel)
    GuestPowerShell(rt.channel, other=lambda exe, args, **kw: 1 if exe == SCHTASKS else 0)
    with pytest.raises(GuestOperationError) as ei:
        _install(rt, Probe(timeline), _dist(tmp_path))
    assert ei.value.details["tasks"] == {"MCP-x64dbg": 1, "MCP-x32dbg": 1}
    assert rt.channel.read(X64_PLUGIN) == b"new64"  # the copy itself completed


class LingeringGuest(FakeGuest):
    """Killed processes disappear only after ``linger`` further listings."""

    def __init__(self, linger: int) -> None:
        super().__init__()
        self.linger = linger
        self.dying: dict[int, int] = {}

    def kill_process(self, pid: int) -> None:
        self._record("kill_process", pid)
        self.dying[pid] = self.linger

    def list_processes(self) -> list[GuestProcess]:
        self._record("list_processes")
        for pid in list(self.dying):
            if self.dying[pid] <= 0:
                self.processes = [p for p in self.processes if p.pid != pid]
                del self.dying[pid]
            else:
                self.dying[pid] -= 1
        return list(self.processes)


def test_install_waits_for_killed_debuggers_to_exit(vm: TimelineVm, fake_clock: FakeClock,
                                                    timeline: Timeline, tmp_path: Path) -> None:
    guest = LingeringGuest(linger=3)
    rt = FakeRuntime(vm=vm, channel=guest, profile=_profile(), clock=fake_clock)
    _seed_install(guest)
    GuestPowerShell(guest)
    _install(rt, Probe(timeline), _dist(tmp_path))
    assert len(guest.calls_of("list_processes")) >= 4
    assert guest.read(X64_PLUGIN) == b"new64"


class SwapFailGuest(FakeGuest):
    """Renaming ``<plugin>.new`` into place fails ``swap_failures`` times (AV lock)."""

    def __init__(self) -> None:
        super().__init__()
        self.swap_failures = 0

    def rename(self, src: str, dst: str) -> None:
        if src.lower().endswith(".new") and self.swap_failures > 0:
            self.swap_failures -= 1
            self._record("rename", src, dst)
            raise GuestOperationError("Error: Access is denied")
        super().rename(src, dst)


@pytest.fixture
def swap_rt(vm: TimelineVm, fake_clock: FakeClock) -> FakeRuntime:
    return FakeRuntime(vm=vm, channel=SwapFailGuest(), profile=_profile(), clock=fake_clock)


def test_failed_swap_with_an_existing_backup_restores_the_previous_plugin(swap_rt: FakeRuntime,
                                                                          timeline: Timeline,
                                                                          tmp_path: Path) -> None:
    guest = swap_rt.channel
    _seed_install(guest)
    GuestPowerShell(guest)
    _install(swap_rt, Probe(timeline), _dist(tmp_path, b"v1"))  # creates the .bak backups
    guest.swap_failures = 1
    with pytest.raises(GuestOperationError) as ei:
        _install(swap_rt, Probe(timeline), _dist(tmp_path, b"v2"))
    assert guest.read(X64_PLUGIN) == b"v164"  # the previous build is back in place
    assert guest.read(X64_PLUGIN + ".bak") == b"old64"
    assert not guest.file_exists(X64_PLUGIN + ".old")
    d = ei.value.details
    assert d["failed_arch"] == "x64" and d["target"] == X64_PLUGIN and d["restored"] is True
    assert d["installed"] == {}


def test_failed_swap_without_a_backup_restores_the_original(swap_rt: FakeRuntime, timeline: Timeline,
                                                            tmp_path: Path) -> None:
    guest = swap_rt.channel
    _seed_install(guest)
    GuestPowerShell(guest)
    guest.swap_failures = 1
    with pytest.raises(GuestOperationError) as ei:
        _install(swap_rt, Probe(timeline), _dist(tmp_path))
    assert guest.read(X64_PLUGIN) == b"old64"
    assert not guest.file_exists(X64_PLUGIN + ".bak")
    assert ei.value.details["restored"] is True


def test_upload_failure_reports_progress_and_relaunches_the_old_plugin(rt: FakeRuntime, timeline: Timeline,
                                                                       tmp_path: Path) -> None:
    _seed_install(rt.channel)
    GuestPowerShell(rt.channel)
    rt.channel.fail_next("copy_to_guest", GuestOperationError("Error: disk full"))
    with pytest.raises(GuestOperationError) as ei:
        _install(rt, Probe(timeline), _dist(tmp_path))
    d = ei.value.details
    assert d["failed_arch"] == "x64" and d["installed"] == {}
    assert len(d["killed"]) == 2
    assert d["relaunched"] == ["MCP-x64dbg", "MCP-x32dbg"]
    assert rt.channel.read(X64_PLUGIN) == b"old64" and rt.channel.read(X32_PLUGIN) == b"old32"
    runs = [a for a, _ in rt.channel.calls_of("run_program") if a[0] == SCHTASKS]
    assert runs == [(SCHTASKS, ("/run", "/tn", "MCP-x64dbg")), (SCHTASKS, ("/run", "/tn", "MCP-x32dbg"))]


def test_failure_on_the_second_arch_reports_the_first(rt: FakeRuntime, timeline: Timeline,
                                                      tmp_path: Path) -> None:
    _seed_install(rt.channel)
    GuestPowerShell(rt.channel)
    orig = rt.channel.copy_to_guest

    def copy(host_path: Path, guest_path: str) -> None:
        if guest_path.endswith(".dp32.new"):
            raise GuestOperationError("Error: disk full")
        orig(host_path, guest_path)

    rt.channel.copy_to_guest = copy  # type: ignore[method-assign]
    with pytest.raises(GuestOperationError) as ei:
        _install(rt, Probe(timeline), _dist(tmp_path), relaunch=False)
    d = ei.value.details
    assert d["failed_arch"] == "x32"
    assert d["installed"]["x64"]["guest_path"] == X64_PLUGIN
    assert d["relaunched"] == []
    assert rt.channel.read(X64_PLUGIN) == b"new64" and rt.channel.read(X32_PLUGIN) == b"old32"
    assert not [a for a, _ in rt.channel.calls_of("run_program") if a[0] == SCHTASKS]


def test_install_gives_up_when_a_debugger_will_not_exit(vm: TimelineVm, fake_clock: FakeClock,
                                                        timeline: Timeline, tmp_path: Path) -> None:
    guest = LingeringGuest(linger=10**9)
    rt = FakeRuntime(vm=vm, channel=guest, profile=_profile(), clock=fake_clock)
    _seed_install(guest)
    GuestPowerShell(guest)
    with pytest.raises(BackendUnavailable):
        _install(rt, Probe(timeline), _dist(tmp_path), kill_wait_s=10)
    assert guest.read(X64_PLUGIN) == b"old64"  # nothing replaced next to a live debugger


# ── discover_x64dbg ─────────────────────────────────────────────────
def _entry(root: str, **extra) -> dict:
    arch = {"exe": True, "plugin": {"present": True, "size": 10, "mtime": "2026-11-20T10:00:00Z",
                                    "file_version": None},
            "config": {"state": "valid", "port": 9094, "bind": ANY_ADDR}}
    empty = {"state": "empty", "port": None, "bind": None}
    doc = {"root": root, "x64": arch, "x32": {**arch, "config": empty}}
    doc.update(extra)
    return doc


def test_discover_parses_the_marked_json_line(fake_guest: FakeGuest, host_tmp: Path) -> None:
    payload = [_entry(ROOT, token="LEAK" * 10), _entry("\\\\evil\\share\\release")]
    emu = GuestPowerShell(fake_guest, lambda body: (0, "WARNING: noise\r\nMCPJSON:" + json.dumps(payload)))
    found = discover_x64dbg(fake_guest)
    assert [e["root"] for e in found] == [ROOT]
    e = found[0]
    assert e["x64"]["exe"] is True and e["x64"]["plugin"]["present"] is True
    assert e["x64"]["config"]["state"] == "valid" and e["x64"]["ready"] is True
    assert e["x32"]["config"]["state"] == "empty" and e["x32"]["ready"] is False
    assert "provision" in e["x32"]["hint"]
    assert "LEAK" not in json.dumps(found)
    body = emu.runs[0]["body"]
    for needle in ("Desktop", "Downloads", "'C:\\'", "-Depth", "x64dbg.exe", "x32dbg.exe",
                   "mcp_config.json", "x64dbg-MCP-Server.dp64", "x64dbg-MCP-Server.dp32", "ReparsePoint"):
        assert needle in body, needle


def test_discover_accepts_a_single_unwrapped_object(fake_guest: FakeGuest, host_tmp: Path) -> None:
    GuestPowerShell(fake_guest, lambda body: (0, "MCPJSON:" + json.dumps(_entry(ROOT))))
    assert [e["root"] for e in discover_x64dbg(fake_guest)] == [ROOT]


def test_discover_includes_extra_roots_as_literals(fake_guest: FakeGuest, host_tmp: Path) -> None:
    emu = GuestPowerShell(fake_guest, lambda body: (0, "MCPJSON:[]"))
    assert discover_x64dbg(fake_guest, extra_roots=["D:\\tools", "E:\\x64 dbg"], max_depth=2) == []
    body = emu.runs[0]["body"]
    assert "'D:\\tools'" in body and "'E:\\x64 dbg'" in body
    assert "$maxDepth = 2" in body
    with pytest.raises(PathNotAllowed):
        discover_x64dbg(fake_guest, extra_roots=["E:\\it's"])


@pytest.mark.parametrize("handler", [lambda body: (1, "ERROR: boom"), lambda body: (0, "no marker"),
                                     lambda body: (0, "MCPJSON:{not json")])
def test_discover_failures_raise(fake_guest: FakeGuest, host_tmp: Path, handler) -> None:
    GuestPowerShell(fake_guest, handler)
    with pytest.raises(GuestOperationError):
        discover_x64dbg(fake_guest)
