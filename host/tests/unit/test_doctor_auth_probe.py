"""gateway_doctor must not lock the gateway out of its own plugin (real-VM finding).

Plugin v1.10 counts every request without a valid bearer token as a failed login
(AuthMaxFailures=5 per window, then HTTP 429 for AuthLockoutSeconds=300). The doctor's
reachability probe used to be sent without a token on purpose, so five doctor runs (or a
doctor run plus a few manual probes) locked the host out for five minutes.
"""

from __future__ import annotations

import pytest

from tests.fakes.fake_runtime import make_lab


@pytest.fixture
def lab(tmp_path):
    lab = make_lab(tmp_path)
    yield lab
    lab.close()


def _checks(report: dict) -> dict[str, dict]:
    return {c["name"]: c for c in report["checks"]}


def test_doctor_sends_no_unauthenticated_request_when_the_token_is_known(lab):
    gw = lab.gateway()
    srv = lab.servers["x64"]
    srv.clear_log()
    for _ in range(6):  # more runs than the plugin's AuthMaxFailures
        report = gw.doctor()
        c = _checks(report)
        assert c["backend:x64:reachable"]["ok"] and c["backend:x64:token"]["ok"], c
    unauthenticated = [r for r in srv.requests if not r.authorized]
    assert unauthenticated == [], [(r.method, r.path, r.authorization is not None) for r in unauthenticated]


def test_doctor_without_a_token_checks_the_port_without_a_failed_login(lab):
    # No usable token: an HTTP probe without one would still count as a failed login (review),
    # so reachability is a plain TCP connect and the token check reports the real problem.
    lab.write_guest_token_config("x64", b"\x00" * 101)  # corrupt guest config: no usable token
    srv = lab.servers["x64"]
    srv.clear_log()
    gw = lab.gateway()
    for _ in range(6):
        c = _checks(gw.doctor())
        reach = c["backend:x64:reachable"]
        assert reach["ok"] is True and "accepts connections" in reach["detail"], reach
        assert c["backend:x64:token"]["ok"] is False
    assert [r for r in srv.requests if not r.authorized] == []


def test_doctor_without_a_token_reports_a_closed_port(lab):
    lab.write_guest_token_config("x64", b"\x00" * 101)
    lab.servers["x64"].stop()
    reach = _checks(lab.gateway().doctor())["backend:x64:reachable"]
    assert reach["ok"] is False and "does not accept connections" in reach["detail"], reach


def test_doctor_reports_a_rejected_token_as_reachable_and_the_token_check_fails(lab):
    gw = lab.gateway()
    gw.doctor()
    srv = lab.servers["x64"]
    srv.token = "rotated-on-the-plugin"  # the plugin now expects another token
    srv.clear_log()
    c = _checks(gw.doctor())
    assert c["backend:x64:reachable"]["ok"] is True, c["backend:x64:reachable"]
    assert c["backend:x64:token"]["ok"] is False, c["backend:x64:token"]
    assert "rejects the token" in c["backend:x64:token"]["detail"]
    # one rejected request proves it: the token check does not spend a second failed login (review)
    assert len([r for r in srv.requests if not r.authorized]) == 1, [(r.method, r.path) for r in srv.requests]
