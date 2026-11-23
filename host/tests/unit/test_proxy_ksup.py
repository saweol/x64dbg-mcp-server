"""Proxy recovery hands the rest of the call budget to the supervisor's health check
(review of K-sup: the supervisor resolves a client itself, which may re-read the guest
token for a while; that must not outlast the client's call budget)."""

from __future__ import annotations

from typing import Any

import pytest

from tests.unit.test_proxy import FakeClient, endpoint_sup, make_proxy
from x64dbg_vm_gateway.catalog import ToolCatalog
from x64dbg_vm_gateway.errors import BackendUnavailable, GatewayError
from x64dbg_vm_gateway.supervisor import HealthReport, Supervisor


class RecordingSupervisor:
    """Wraps a Supervisor and records the keyword arguments of every ``check``."""

    def __init__(self, inner: Supervisor) -> None:
        self._inner = inner
        self.checks: list[dict[str, Any]] = []

    def check(self, backend_id: str, **kw: Any) -> HealthReport:
        self.checks.append(kw)
        return self._inner.check(backend_id, **kw)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def test_recovery_gives_the_health_check_the_rest_of_the_call_budget(tmp_path, fake_clock):
    client = FakeClient()
    rec = RecordingSupervisor(endpoint_sup(client, fake_clock))
    p = make_proxy(ToolCatalog(cache_dir=tmp_path / "cache"), client, rec,  # type: ignore[arg-type]
                   max_call_s=60, clock=fake_clock)

    def slow_failure() -> BackendUnavailable:
        fake_clock.advance(45)  # the failed HTTP call used most of the budget
        return BackendUnavailable("reset")

    client.queue("StepOver", slow_failure)
    with pytest.raises(GatewayError):
        p.call("x64", "StepOver", {}, job_id="j1")
    assert len(rec.checks) == 1
    left = rec.checks[0].get("max_wait_s")
    assert left is not None and 0 <= left <= 15, rec.checks
