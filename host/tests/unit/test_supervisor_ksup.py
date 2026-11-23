"""Supervisor never acts on an unresolved client (E4 on the spike VM).

After a revert the runtime drops its tokens and every ``Runtime.clients`` entry is a
``wiring.UnresolvedClient`` placeholder until ``Runtime.connect`` read the token from
the guest again (which fails while VMware Tools are still starting). Probing that
placeholder answered ``health_l1() == False``: the supervisor classified a healthy
plugin as refused -> LOADING -> HUNG after ``boot_grace_s`` and killed x64dbg.

The supervisor now resolves a client through ``resolve`` first; VmNotReady,
ToolsNotRunning and guest-channel errors become HealthState.UNRESOLVED (no kill, no
relaunch, no L2 failure counting), BackendAuthError becomes AUTH, and a placeholder
never reaches a health probe.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from tests.unit.test_supervisor import EXE, ScriptedClient, cfg, make_sup, relaunch_brings_up
from x64dbg_vm_gateway.config import BackendConfig
from x64dbg_vm_gateway.contracts import BackendEndpoint, PowerState, Secret, ToolsState
from x64dbg_vm_gateway.errors import (
    BackendAuthError,
    GuestOperationError,
    ToolsNotRunning,
    VmNotReady,
    VmrunTimeout,
)
from x64dbg_vm_gateway.supervisor import HealthState, Supervisor, is_unresolved_client
from x64dbg_vm_gateway.wiring import UnresolvedClient


@pytest.fixture
def client() -> ScriptedClient:
    return ScriptedClient()


class ProbedPlaceholder(UnresolvedClient):
    """A placeholder that fails the test if anything probes it."""

    def __init__(self) -> None:
        super().__init__(BackendEndpoint(id="x64", arch="x64", url="", token=Secret(""), exe=EXE,
                                         launch_task="x64dbg-mcp-x64"), "dropped after a revert")
        self.probed = 0

    def health_l1(self, timeout_s: float = 2.0) -> bool:
        self.probed += 1
        raise AssertionError("health_l1 ran against an unresolved placeholder")

    def health_l2(self, timeout_s: float = 5.0) -> bool:
        self.probed += 1
        raise AssertionError("health_l2 ran against an unresolved placeholder")


class Resolver:
    """Programmable ``resolve`` hook: each answer is a client or an exception to raise."""

    def __init__(self, *answers: Any) -> None:
        self.answers = list(answers)
        self.calls: list[str] = []

    def __call__(self, backend_id: str) -> Any:
        self.calls.append(backend_id)
        answer = self.answers[0] if len(self.answers) == 1 else self.answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return answer


def sup_with(vm, guest, clock, clients: dict[str, Any], *, resolve: Callable[[str], Any] | None = None,
             **kw: Any) -> Supervisor:
    return Supervisor(vm=vm, guest=guest, clients=clients, backends={"x64": cfg()}, relaunch_mode="task",
                      clock=clock, resolve=resolve, **kw)


def no_side_effects(guest) -> None:
    assert guest.calls_of("kill_process") == []
    assert guest.calls_of("run_program") == []


# ── the placeholder is never probed ─────────────────────────────────
def test_the_placeholder_marker(client):
    assert is_unresolved_client(ProbedPlaceholder()) is True
    assert is_unresolved_client(client) is False


def test_a_placeholder_in_the_clients_dict_is_unresolved_not_loading(fake_vm, fake_guest, fake_clock):
    fake_guest.add_process(f'"{EXE}"')  # x64dbg runs (E4: the plugin answered 401 to curl)
    ph = ProbedPlaceholder()
    sup = sup_with(fake_vm, fake_guest, fake_clock, {"x64": ph})
    report = sup.check("x64")
    assert report.state is HealthState.UNRESOLVED
    assert "dropped after a revert" in report.details["reason"]
    assert ph.probed == 0
    assert fake_guest.calls_of("list_processes") == []  # nothing classified: no process lookup


def test_a_resolver_that_hands_back_a_placeholder_is_unresolved(fake_vm, fake_guest, fake_clock):
    ph = ProbedPlaceholder()
    sup = sup_with(fake_vm, fake_guest, fake_clock, {"x64": ph}, resolve=Resolver(ph))
    assert sup.check("x64").state is HealthState.UNRESOLVED
    assert ph.probed == 0


def test_a_given_placeholder_client_is_never_probed(fake_vm, fake_guest, fake_clock, client):
    ph = ProbedPlaceholder()
    sup = sup_with(fake_vm, fake_guest, fake_clock, {"x64": client})
    assert sup.check("x64", client=ph).state is HealthState.UNRESOLVED
    assert ph.probed == 0 and client.l1_calls == 0


@pytest.mark.parametrize("error", [
    VmNotReady("backend x64: endpoint not resolved"),
    ToolsNotRunning("Error: The VMware Tools are not running in the virtual machine"),
    GuestOperationError("Error: A general system error occurred"),
    VmrunTimeout("vmrun CopyFileFromGuestToHost timed out"),
])
def test_resolution_failures_are_unresolved(fake_vm, fake_guest, fake_clock, client, error):
    fake_guest.add_process(f'"{EXE}"')
    resolver = Resolver(error)
    sup = sup_with(fake_vm, fake_guest, fake_clock, {"x64": client}, resolve=resolver)
    report = sup.check("x64")
    assert report.state is HealthState.UNRESOLVED
    assert report.details["error"] == error.code and error.code in report.details["reason"]
    assert resolver.calls == ["x64"]
    assert client.l1_calls == 0 and client.l2_calls == 0
    assert fake_guest.calls_of("list_processes") == []


def test_a_token_the_resolver_cannot_use_is_auth(fake_vm, fake_guest, fake_clock, client):
    resolver = Resolver(BackendAuthError("the guest mcp_config.json is unusable (empty or zero-filled)"))
    sup = sup_with(fake_vm, fake_guest, fake_clock, {"x64": client}, resolve=resolver)
    report = sup.check("x64")
    assert report.state is HealthState.AUTH
    assert client.l1_calls == 0
    with pytest.raises(BackendAuthError):
        sup.ensure_alive("x64", reason="probe")
    no_side_effects(fake_guest)


def test_unresolved_never_turns_hung_and_nothing_is_killed(fake_vm, fake_guest, fake_clock, client):
    """E4: Tools 'not running' for minutes while x64dbg runs; the old code killed it after 90 s."""
    fake_guest.add_process(f'"{EXE}"')
    resolver = Resolver(ToolsNotRunning("Error: The VMware Tools are not running in the virtual machine"))
    sup = sup_with(fake_vm, fake_guest, fake_clock, {"x64": client}, resolve=resolver, boot_grace_s=90)
    for _ in range(10):
        assert sup.check("x64").state is HealthState.UNRESOLVED
        fake_clock.advance(30)
    with pytest.raises(VmNotReady) as ei:
        sup.ensure_alive("x64", job_id="j1", reason="analysis_start j1")
    assert ei.value.retryable is True
    assert ei.value.details["state"] == "UNRESOLVED"
    no_side_effects(fake_guest)
    assert sup.epoch("x64") == 0 and sup.restarts("j1") == 0


def test_unresolved_checks_do_not_count_as_l2_failures(fake_vm, fake_guest, fake_clock, client):
    client.l2 = False
    resolver = Resolver(client)
    sup = sup_with(fake_vm, fake_guest, fake_clock, {"x64": client}, resolve=resolver,
                   l2_fail_threshold=3, l2_min_window_s=30)
    assert sup.check("x64").details["l2_failures"] == 1
    resolver.answers = [ToolsNotRunning("tools are not running")]
    for _ in range(5):
        fake_clock.advance(10)
        assert sup.check("x64").state is HealthState.UNRESOLVED
    resolver.answers = [client]
    report = sup.check("x64")
    assert report.details["l2_failures"] == 2  # not 7: the unresolved checks probed nothing


def test_check_probes_the_resolved_client_not_the_dict_entry(fake_vm, fake_guest, fake_clock, client):
    ph = ProbedPlaceholder()
    sup = sup_with(fake_vm, fake_guest, fake_clock, {"x64": ph}, resolve=Resolver(client))
    assert sup.check("x64").state is HealthState.HEALTHY
    assert client.l1_calls == 1 and client.l2_calls == 1 and ph.probed == 0


def test_ensure_alive_resolves_before_it_classifies(fake_vm, fake_guest, fake_clock, client):
    resolver = Resolver(client)
    sup = sup_with(fake_vm, fake_guest, fake_clock, {"x64": ProbedPlaceholder()}, resolve=resolver)
    assert sup.ensure_alive("x64", reason="analysis_start") == 0
    assert resolver.calls and client.l1_calls >= 1
    no_side_effects(fake_guest)


def test_the_readiness_wait_after_a_relaunch_resolves_too(fake_vm, fake_guest, fake_clock, client):
    # DEAD -> relaunched -> the token cannot be read for two polls -> then ready
    client.down()
    relaunch_brings_up(fake_guest, client)
    tools_down = ToolsNotRunning("tools are not running")
    resolver = Resolver(client, tools_down, tools_down, client)
    sup = sup_with(fake_vm, fake_guest, fake_clock, {"x64": ProbedPlaceholder()}, resolve=resolver)
    assert sup.ensure_alive("x64", reason="dead") == 1
    assert len(resolver.calls) == 4


def test_check_with_a_given_client_and_vm_state_asks_neither_vm_nor_resolver(
        fake_vm, fake_guest, fake_clock, client):
    resolver = Resolver(AssertionError("resolver must not run"))
    sup = sup_with(fake_vm, fake_guest, fake_clock, {"x64": client}, resolve=resolver)
    report = sup.check("x64", client=client, vm_state=(PowerState.RUNNING, ToolsState.RUNNING))
    assert report.state is HealthState.HEALTHY
    assert fake_vm.calls == [] and resolver.calls == []


def test_a_given_vm_state_still_classifies_vm_and_tools_down(fake_vm, fake_guest, fake_clock, client):
    sup = sup_with(fake_vm, fake_guest, fake_clock, {"x64": client})
    assert sup.check("x64", vm_state=(PowerState.OFF, ToolsState.UNKNOWN)).state is HealthState.VM_DOWN
    assert sup.check("x64", vm_state=(PowerState.RUNNING, ToolsState.INSTALLED)).state \
        is HealthState.TOOLS_DOWN
    assert fake_vm.calls == [] and client.l1_calls == 0


def test_status_checks_list_guest_processes_only_when_l1_fails(fake_vm, fake_guest, fake_clock, client):
    fake_guest.add_process(f'"{EXE}"')
    sup = make_sup(fake_vm, fake_guest, fake_clock, client)
    assert sup.check("x64", record_pids=False).state is HealthState.HEALTHY
    assert fake_guest.calls_of("list_processes") == []
    client.l1 = False
    assert sup.check("x64", record_pids=False).state is HealthState.LOADING
    assert len(fake_guest.calls_of("list_processes")) == 1


def test_default_checks_still_record_the_pids(fake_vm, fake_guest, fake_clock, client):
    # control: restart detection keeps its evidence when check() is called without the flag
    fake_guest.add_process(f'"{EXE}"')
    sup = make_sup(fake_vm, fake_guest, fake_clock, client)
    assert sup.check("x64").state is HealthState.HEALTHY
    assert len(fake_guest.calls_of("list_processes")) == 1


def test_endpoint_mode_without_resolver_still_works(client):
    sup = Supervisor(vm=None, guest=None, clients={"x64": client},
                     backends={"x64": BackendConfig(id="x64", arch="x64", url="http://h:1/")},
                     relaunch_mode="direct")
    assert sup.check("x64").state is HealthState.HEALTHY


def test_unresolved_is_reported_as_retryable_vm_not_ready_by_ensure_alive(fake_vm, fake_guest, fake_clock):
    sup = sup_with(fake_vm, fake_guest, fake_clock, {"x64": ProbedPlaceholder()})
    with pytest.raises(VmNotReady) as ei:
        sup.ensure_alive("x64", reason="x")
    assert ei.value.next_tool == "session_status"
    no_side_effects(fake_guest)


def test_scripted_client_is_not_a_placeholder():
    assert is_unresolved_client(ScriptedClient()) is False
