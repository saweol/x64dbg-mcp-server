"""Runtime fixes from the spike-VM E2E run (E4, E6).

- ``Runtime.connect(timeout_s=...)`` retries the guest token read while VMware Tools
  are not running (right after a revert) instead of failing once;
- the supervisor resolves clients through ``Runtime.connect`` (it never probes the
  ``UnresolvedClient`` placeholder);
- ``Runtime.vm_state`` caches power / Tools observations for status polling for a
  short TTL; any VM operation (a write hold of the VM lock) invalidates it.
"""

from __future__ import annotations

import threading

import pytest

from tests.fakes.fake_runtime import CFG, make_lab
from x64dbg_vm_gateway.backend import HttpBackendClient
from x64dbg_vm_gateway.contracts import PowerState, ToolsState
from x64dbg_vm_gateway.errors import ToolsNotRunning, VmNotReady
from x64dbg_vm_gateway.locks import VmOpLock
from x64dbg_vm_gateway.supervisor import HealthState
from x64dbg_vm_gateway.wiring import SUPERVISOR_RESOLVE_TIMEOUT_S, VM_STATE_TTL_S, UnresolvedClient

TOOLS_DOWN = "Error: The VMware Tools are not running in the virtual machine"


@pytest.fixture
def lab(tmp_path):
    lab = make_lab(tmp_path)
    yield lab
    lab.close()


def token_copies(lab) -> int:
    return len([a for a, _ in lab.guest.calls_of("copy_from_guest") if a[0].lower() == CFG["x64"].lower()])


# ── token re-read while Tools start ─────────────────────────────────
def test_connect_retries_the_token_read_while_tools_are_not_running(lab):
    rt = lab.runtime()
    lab.guest.fail_next("copy_from_guest", ToolsNotRunning(TOOLS_DOWN), times=3)
    t0 = lab.clock.monotonic()
    client = rt.connect("x64", timeout_s=60)
    assert isinstance(client, HttpBackendClient) and client.health_l1() is True
    assert token_copies(lab) == 4
    assert 0 < lab.clock.monotonic() - t0 < 60


def test_connect_gives_up_at_its_timeout(lab):
    rt = lab.runtime()
    lab.guest.fail_next("copy_from_guest", ToolsNotRunning(TOOLS_DOWN), times=10_000)
    t0 = lab.clock.monotonic()
    with pytest.raises(ToolsNotRunning):
        rt.connect("x64", timeout_s=20)
    waited = lab.clock.monotonic() - t0
    assert 20 <= waited <= 25
    assert isinstance(rt.clients["x64"], UnresolvedClient)


def test_connect_without_a_timeout_reads_once(lab):
    # control: callers that must not wait (status polling, mirrored calls) still fail fast
    rt = lab.runtime()
    lab.guest.fail_next("copy_from_guest", ToolsNotRunning(TOOLS_DOWN), times=3)
    with pytest.raises(ToolsNotRunning):
        rt.connect("x64")
    assert token_copies(lab) == 1
    with pytest.raises(ToolsNotRunning):
        rt.connect("x64", wait=False, timeout_s=60)  # wait=False never retries either
    assert token_copies(lab) == 2


# ── the supervisor resolves through the runtime ─────────────────────
def test_the_supervisor_resolves_the_placeholder_through_connect(lab):
    rt = lab.runtime()
    assert isinstance(rt.clients["x64"], UnresolvedClient)
    report = rt.supervisor.check("x64")
    assert report.state is HealthState.HEALTHY, report
    assert isinstance(rt.clients["x64"], HttpBackendClient)


def test_e4_a_revert_with_tools_still_starting_never_kills_x64dbg(lab):
    """The spike-VM probe: placeholder client, health_l1 False, check -> LOADING, then HUNG."""
    rt = lab.runtime()
    rt.connect("x64")
    rt.invalidate_clients(drop_tokens=True, reason="VM reverted")
    lab.guest.fail_next("copy_from_guest", ToolsNotRunning(TOOLS_DOWN), times=100_000)
    for _ in range(4):
        report = rt.supervisor.check("x64")
        assert report.state is HealthState.UNRESOLVED, report
        assert report.details["error"] == "TOOLS_NOT_RUNNING"
        lab.clock.advance(60)  # far beyond boot_grace_s
    with pytest.raises(VmNotReady):
        rt.supervisor.ensure_alive("x64", reason="analysis_start")
    assert lab.guest.calls_of("kill_process") == [] and lab.launches == []
    assert rt.supervisor.epoch("x64") == 0
    assert lab.servers["x64"].running  # the plugin was healthy all along


def test_the_supervisor_resolution_is_bounded_by_the_callers_budget(lab):
    """Review: the resolve hook must not block a check for its own 20 s when the caller (the
    proxy's call budget, ensure_alive's max_wait_s) has less left."""
    rt = lab.runtime()
    rt.connect("x64")
    rt.invalidate_clients(drop_tokens=True, reason="VM reverted")
    lab.guest.fail_next("copy_from_guest", ToolsNotRunning(TOOLS_DOWN), times=100_000)
    t0 = lab.clock.monotonic()
    assert rt.supervisor.check("x64", max_wait_s=3).state is HealthState.UNRESOLVED
    assert lab.clock.monotonic() - t0 <= 3
    t0 = lab.clock.monotonic()
    assert rt.supervisor.check("x64", max_wait_s=0).state is HealthState.UNRESOLVED
    assert lab.clock.monotonic() - t0 == 0  # one read, no waiting
    t0 = lab.clock.monotonic()
    assert rt.supervisor.check("x64").state is HealthState.UNRESOLVED  # no budget: the runtime's bound
    assert lab.clock.monotonic() - t0 <= SUPERVISOR_RESOLVE_TIMEOUT_S


# ── VM state cache (session_status fast path) ───────────────────────
def vm_calls(lab, name: str) -> int:
    return sum(1 for c in lab.vm.calls if c[0] == name)


def test_vm_state_is_cached_for_a_short_ttl(lab):
    rt = lab.runtime()
    assert rt.vm_state.power_state() == PowerState.RUNNING
    assert rt.vm_state.tools_state() == ToolsState.RUNNING
    rt.vm_state.power_state()
    rt.vm_state.tools_state()
    assert vm_calls(lab, "power_state") == 1 and vm_calls(lab, "tools_state") == 1
    lab.clock.advance(VM_STATE_TTL_S + 0.1)
    lab.vm.power = PowerState.OFF
    assert rt.vm_state.power_state() == PowerState.OFF
    assert vm_calls(lab, "power_state") == 2


def test_a_vm_operation_invalidates_the_cache(lab):
    rt = lab.runtime()
    assert isinstance(rt.lock, VmOpLock)
    rt.vm_state.power_state()
    with rt.lock.write(timeout_s=5):
        lab.vm.power = PowerState.OFF
    assert rt.vm_state.power_state() == PowerState.OFF


def test_nothing_read_during_a_vm_operation_is_cached(lab):
    rt = lab.runtime()
    with rt.lock.write(timeout_s=5):
        lab.vm.power = PowerState.SUSPENDED
        seen = []
        t = threading.Thread(target=lambda: seen.append(rt.vm_state.power_state()))
        t.start()
        t.join(5)
        assert seen == [PowerState.SUSPENDED]
        lab.vm.power = PowerState.RUNNING
    assert rt.vm_state.power_state() == PowerState.RUNNING


def test_the_raw_provider_stays_the_runtime_vm(lab):
    rt = lab.runtime()
    assert rt.vm is lab.vm
    rt.vm.power_state()
    rt.vm.power_state()
    assert vm_calls(lab, "power_state") == 2  # VM operations always ask the VM itself
