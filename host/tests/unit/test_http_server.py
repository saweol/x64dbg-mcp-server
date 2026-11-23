"""Remote streamable-HTTP front-end (plan 6.1 / M3): allowlist, scoped tokens,
rate limit, audit log, TLS/token start-up refusal. Driven through Starlette's
TestClient, so no port is opened."""

from __future__ import annotations

import inspect
import json
import os
import stat
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from starlette.testclient import TestClient

from tests.fakes.fake_app import FakeApp
from x64dbg_vm_gateway.config import HttpServerConfig
from x64dbg_vm_gateway.errors import ConfigError
from x64dbg_vm_gateway.frontends import http_server
from x64dbg_vm_gateway.frontends.tool_defs import GATEWAY_TOOL_NAMES, TOOLS_BY_NAME, RiskTier

READ_TOKEN = "r" * 24 + "-read-token"
ANALYZE_TOKEN = "z" * 24 + "-analyze-token"
ADMIN_TOKEN = "a" * 24 + "-admin-token"
ENV = {"GW_READ": READ_TOKEN, "GW_ANALYZE": ANALYZE_TOKEN, "GW_ADMIN": ADMIN_TOKEN}
TOKEN_ENVS = {"read": "GW_READ", "analyze": "GW_ANALYZE", "admin": "GW_ADMIN"}
BASE = "http://127.0.0.1:9100"
LOCAL = ("127.0.0.1", 50000)
PROTO = "2025-06-18"
FIXED_NOW = datetime(2026, 11, 23, 12, 0, 0, tzinfo=UTC)
ANY_ADDR = "0.0.0.0"  # noqa: S104 - a value under test, nothing binds


class FakeMonotonic:
    def __init__(self) -> None:
        self.t = 100.0

    def __call__(self) -> float:
        return self.t


def cfg(**kw: Any) -> HttpServerConfig:
    base: dict[str, Any] = {"enabled": True, "token_envs": dict(TOKEN_ENVS)}
    base.update(kw)
    return HttpServerConfig(**base)


def build(app: FakeApp, tmp_path: Path, http_cfg: HttpServerConfig | None = None, **kw: Any) -> Any:
    kw.setdefault("environ", ENV)
    kw.setdefault("now", lambda: FIXED_NOW)
    return http_server.build_asgi_app(app, http_cfg or cfg(), audit_dir=tmp_path / "_audit", **kw)


def headers(token: str | None, sid: str | None = None) -> dict[str, str]:
    h = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
    if token is not None:
        h["Authorization"] = f"Bearer {token}"
    if sid is not None:
        h["mcp-session-id"] = sid
        h["mcp-protocol-version"] = PROTO
    return h


def sse_json(text: str) -> dict[str, Any]:
    for line in text.splitlines():
        if line.startswith("data:"):
            return json.loads(line[5:].strip())
    return json.loads(text)


def open_session(client: TestClient, token: str) -> str:
    r = client.post("/mcp", headers=headers(token), json={
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": PROTO, "capabilities": {},
                   "clientInfo": {"name": "t", "version": "1"}}})
    assert r.status_code == 200, r.text
    sid = r.headers["mcp-session-id"]
    r = client.post("/mcp", headers=headers(token, sid),
                    json={"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert r.status_code == 202
    return sid


def rpc(client: TestClient, token: str, sid: str, method: str, params: dict[str, Any], rid: int = 7) -> Any:
    r = client.post("/mcp", headers=headers(token, sid),
                    json={"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
    assert r.status_code == 200, r.text
    return sse_json(r.text)


def audit_lines(tmp_path: Path) -> list[dict[str, Any]]:
    f = tmp_path / "_audit" / "http-20261123.jsonl"
    if not f.exists():
        return []
    return [json.loads(line) for line in f.read_text(encoding="utf-8").splitlines() if line.strip()]


def audit_text(tmp_path: Path) -> str:
    d = tmp_path / "_audit"
    return "".join(p.read_text(encoding="utf-8") for p in d.glob("*")) if d.exists() else ""


@pytest.fixture
def app() -> FakeApp:
    return FakeApp()


# ── authentication / allowlist / rate limit ─────────────────────────
def test_missing_token_is_401_and_audited(app, tmp_path):
    with TestClient(build(app, tmp_path), base_url=BASE, client=LOCAL) as c:
        r = c.post("/mcp", headers=headers(None), json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert r.status_code == 401
    assert r.headers["www-authenticate"].lower().startswith("bearer")
    assert r.json()["error"]["code"] == "UNAUTHORIZED"
    lines = audit_lines(tmp_path)
    assert lines and lines[-1]["outcome"] == "UNAUTHORIZED" and lines[-1]["client"] == "127.0.0.1"
    assert set(lines[-1]) >= {"time", "client", "scope", "tool", "outcome"}


@pytest.mark.parametrize("auth", ["Bearer wrong-token-but-long-enough", "Basic abc", "Bearer", "bearer  ",
                                  "Bearer " + READ_TOKEN + "x", "Bearer éé".encode()])
def test_bad_tokens_are_401(app, tmp_path, auth):
    with TestClient(build(app, tmp_path), base_url=BASE, client=LOCAL) as c:
        h: dict[str, Any] = headers(None)
        h["Authorization"] = auth  # bytes: a non-ASCII header value (httpx refuses non-ASCII str)
        r = c.post("/mcp", headers=h, json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert r.status_code == 401
    assert READ_TOKEN not in audit_text(tmp_path)


def test_non_loopback_client_is_403_with_empty_allowlist(app, tmp_path):
    with TestClient(build(app, tmp_path), base_url=BASE, client=("10.0.0.5", 4000)) as c:
        r = c.post("/mcp", headers=headers(ADMIN_TOKEN), json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "FORBIDDEN"
    line = audit_lines(tmp_path)[-1]
    assert line["client"] == "10.0.0.5" and line["outcome"] == "FORBIDDEN"
    assert ADMIN_TOKEN not in audit_text(tmp_path)


def test_allowlisted_cidr_is_accepted(app, tmp_path):
    asgi = build(app, tmp_path, cfg(allow_clients=("10.0.0.0/24",)))
    with TestClient(asgi, base_url=BASE, client=("10.0.0.5", 4000)) as c:
        sid = open_session(c, ADMIN_TOKEN)
        assert sid
    with TestClient(build(app, tmp_path, cfg(allow_clients=("10.0.0.0/24",))), base_url=BASE,
                    client=("127.0.0.1", 4000)) as c:
        # An explicit allowlist replaces the loopback default.
        r = c.post("/mcp", headers=headers(ADMIN_TOKEN), json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
        assert r.status_code == 403


def test_ipv4_mapped_loopback_is_loopback(app, tmp_path):
    with TestClient(build(app, tmp_path), base_url=BASE, client=("::ffff:127.0.0.1", 4000)) as c:
        assert open_session(c, READ_TOKEN)


def test_unparseable_client_address_is_refused(app, tmp_path):
    with TestClient(build(app, tmp_path), base_url=BASE, client=("testclient", 4000)) as c:
        r = c.post("/mcp", headers=headers(ADMIN_TOKEN), json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert r.status_code == 403


def test_rate_limit_returns_429_per_client(app, tmp_path):
    clock = FakeMonotonic()
    asgi = build(app, tmp_path, cfg(allow_clients=("127.0.0.0/8", "10.0.0.0/24")), clock=clock,
                 rate_per_s=1.0, burst=3)
    body = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
    with TestClient(asgi, base_url=BASE, client=LOCAL) as c:
        codes = [c.post("/mcp", headers=headers(None), json=body).status_code for _ in range(4)]
        assert codes == [401, 401, 401, 429]  # unauthenticated requests are throttled too
        r = c.post("/mcp", headers=headers(None), json=body)
        assert r.status_code == 429 and int(r.headers["retry-after"]) >= 1
        assert r.json()["error"]["code"] == "RATE_LIMITED"
        clock.t += 2.0  # two tokens refilled
        assert c.post("/mcp", headers=headers(None), json=body).status_code == 401
    with TestClient(asgi, base_url=BASE, client=("10.0.0.9", 1)) as c2:
        # Another client has its own bucket.
        assert c2.post("/mcp", headers=headers(None), json=body).status_code == 401
    outcomes = [line["outcome"] for line in audit_lines(tmp_path)]
    assert "RATE_LIMITED" in outcomes


def test_repeated_denials_are_not_written_one_line_each(app, tmp_path):
    body = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
    with TestClient(build(app, tmp_path, burst=1000), base_url=BASE, client=("10.1.1.1", 1)) as c:
        for _ in range(50):
            assert c.post("/mcp", headers=headers(None), json=body).status_code == 403
    assert 1 <= len(audit_lines(tmp_path)) <= 2


def test_ipv6_clients_share_a_rate_bucket_per_64(app, tmp_path):
    """Rotating addresses inside one /64 must not yield fresh buckets."""
    clock = FakeMonotonic()
    asgi = build(app, tmp_path, cfg(allow_clients=("2001:db8::/48",)), clock=clock, rate_per_s=1.0, burst=1)
    body = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
    with TestClient(asgi, base_url=BASE, client=("2001:db8:0:1::1", 1)) as c:
        assert c.post("/mcp", headers=headers(None), json=body).status_code == 401
    with TestClient(asgi, base_url=BASE, client=("2001:db8:0:1::2", 1)) as c:
        assert c.post("/mcp", headers=headers(None), json=body).status_code == 429
    with TestClient(asgi, base_url=BASE, client=("2001:db8:0:2::1", 1)) as c:
        assert c.post("/mcp", headers=headers(None), json=body).status_code == 401  # another /64


def test_ipv6_denials_are_collapsed_per_64(app, tmp_path):
    body = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
    asgi = build(app, tmp_path)
    for i in range(1, 31):
        with TestClient(asgi, base_url=BASE, client=(f"2001:db8::{i:x}", 1)) as c:
            assert c.post("/mcp", headers=headers(None), json=body).status_code == 403
    lines = audit_lines(tmp_path)
    assert 1 <= len(lines) <= 2
    assert lines[0]["client"] == "2001:db8::1"  # the real address is still recorded


def test_non_finite_numbers_from_the_wire_never_reach_the_app(app, tmp_path):
    with TestClient(build(app, tmp_path), base_url=BASE, client=LOCAL) as c:
        sid = open_session(c, ADMIN_TOKEN)
        for token in ("NaN", "Infinity", "1e18"):
            raw = ('{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"vm_power",'
                   '"arguments":{"action":"start","wait_s":' + token + '}}}')
            r = c.post("/mcp", headers=headers(ADMIN_TOKEN, sid), content=raw)
            assert r.status_code == 200, r.text
            res = sse_json(r.text)["result"]
            assert res["isError"] is True
            assert json.loads(res["content"][0]["text"])["code"] == "INVALID_ARGUMENTS"
    assert app.called("vm_power") == []


# ── host header checks (DNS rebinding) ──────────────────────────────
INIT_BODY = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": PROTO, "capabilities": {},
                        "clientInfo": {"name": "t", "version": "1"}}}


def test_loopback_bind_rejects_a_foreign_host_header(app, tmp_path):
    with TestClient(build(app, tmp_path), base_url="http://evil.example:9100", client=LOCAL) as c:
        r = c.post("/mcp", headers=headers(ADMIN_TOKEN), json=INIT_BODY)
    assert r.status_code in (400, 403, 421)
    assert "mcp-session-id" not in r.headers


def test_loopback_bind_rejects_a_foreign_origin(app, tmp_path):
    with TestClient(build(app, tmp_path), base_url=BASE, client=LOCAL) as c:
        h = headers(ADMIN_TOKEN)
        h["Origin"] = "http://evil.example"
        r = c.post("/mcp", headers=h, json=INIT_BODY)
    assert r.status_code in (400, 403, 421)
    assert "mcp-session-id" not in r.headers


def test_remote_bind_serves_clients_under_any_host_name(app, tmp_path):
    asgi = build(app, tmp_path, cfg(bind=ANY_ADDR, tls_cert="/c.pem", tls_key="/k.pem",
                                    allow_clients=("10.0.0.0/24",)))
    with TestClient(asgi, base_url="https://lab-host.example:9100", client=("10.0.0.7", 5000)) as c:
        sid = open_session(c, ANALYZE_TOKEN)
        res = rpc(c, ANALYZE_TOKEN, sid, "tools/call", {"name": "session_status", "arguments": {}})
        assert res["result"]["isError"] is False
    line = [ln for ln in audit_lines(tmp_path) if ln.get("tool")][-1]
    assert (line["tool"], line["outcome"], line["scope"], line["client"]) == (
        "session_status", "OK", "analyze", "10.0.0.7")


# ── scopes over HTTP ────────────────────────────────────────────────
def test_read_token_sees_only_read_tools_and_is_forbidden_to_mutate(app, tmp_path):
    with TestClient(build(app, tmp_path), base_url=BASE, client=LOCAL) as c:
        sid = open_session(c, READ_TOKEN)
        listed = rpc(c, READ_TOKEN, sid, "tools/list", {})
        names = {t["name"] for t in listed["result"]["tools"]}
        observe = {n for n in GATEWAY_TOOL_NAMES if TOOLS_BY_NAME[n].tier is RiskTier.OBSERVE}
        assert names == observe | {"GetDebugState", "ReadMemory"}

        res = rpc(c, READ_TOKEN, sid, "tools/call", {"name": "vm_power", "arguments": {"action": "stop"}})
        assert res["result"]["isError"] is True
        assert json.loads(res["result"]["content"][0]["text"])["code"] == "FORBIDDEN"
        res = rpc(c, READ_TOKEN, sid, "tools/call",
                  {"name": "file_upload", "arguments": {"host_path": "/home/u/SENSITIVE-ARG.bin"}})
        assert res["result"]["isError"] is True
    assert app.called("vm_power") == [] and app.called("file_upload") == []
    lines = [ln for ln in audit_lines(tmp_path) if ln.get("tool")]
    assert [(ln["tool"], ln["outcome"], ln["scope"], ln["client"]) for ln in lines] == [
        ("vm_power", "FORBIDDEN", "read", "127.0.0.1"),
        ("file_upload", "FORBIDDEN", "read", "127.0.0.1"),
    ]
    text = audit_text(tmp_path)
    assert "SENSITIVE-ARG" not in text and READ_TOKEN not in text


def test_admin_token_can_call_everything_and_success_is_audited(app, tmp_path):
    with TestClient(build(app, tmp_path), base_url=BASE, client=LOCAL) as c:
        sid = open_session(c, ADMIN_TOKEN)
        listed = rpc(c, ADMIN_TOKEN, sid, "tools/list", {})
        assert "vm_snapshot_revert" in {t["name"] for t in listed["result"]["tools"]}
        res = rpc(c, ADMIN_TOKEN, sid, "tools/call", {"name": "vm_power", "arguments": {"action": "start"}})
        assert res["result"]["isError"] is False
    assert app.called("vm_power") == [{"action": "start", "profile": None, "wait_s": None}]
    line = [ln for ln in audit_lines(tmp_path) if ln.get("tool")][-1]
    assert (line["tool"], line["outcome"], line["scope"]) == ("vm_power", "OK", "admin")


def test_analyze_token_scope(app, tmp_path):
    with TestClient(build(app, tmp_path), base_url=BASE, client=LOCAL) as c:
        sid = open_session(c, ANALYZE_TOKEN)
        res = rpc(c, ANALYZE_TOKEN, sid, "tools/call",
                  {"name": "SetBreakpoint", "arguments": {"address": "0x1"}})
        assert res["result"]["isError"] is False
        res = rpc(c, ANALYZE_TOKEN, sid, "tools/call", {"name": "analysis_finish", "arguments": {}})
        assert json.loads(res["result"]["content"][0]["text"])["code"] == "FORBIDDEN"


def test_session_cannot_be_reused_with_a_lower_scope_token(app, tmp_path):
    with TestClient(build(app, tmp_path), base_url=BASE, client=LOCAL) as c:
        sid = open_session(c, ADMIN_TOKEN)
        r = c.post("/mcp", headers=headers(READ_TOKEN, sid),
                   json={"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                         "params": {"name": "vm_power", "arguments": {"action": "stop"}}})
        assert r.status_code == 404
    assert app.called("vm_power") == []


def test_only_scopes_with_a_token_in_the_environment_are_served(app, tmp_path):
    env = {"GW_READ": READ_TOKEN}
    with TestClient(build(app, tmp_path, environ=env), base_url=BASE, client=LOCAL) as c:
        assert open_session(c, READ_TOKEN)
        r = c.post("/mcp", headers=headers(ADMIN_TOKEN), json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
        assert r.status_code == 401


# ── audit file ──────────────────────────────────────────────────────
@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_audit_file_location_and_permissions(app, tmp_path):
    with TestClient(build(app, tmp_path), base_url=BASE, client=LOCAL) as c:
        c.post("/mcp", headers=headers(None), json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
    f = tmp_path / "_audit" / "http-20261123.jsonl"
    assert f.exists()
    assert stat.S_IMODE(os.stat(f).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(tmp_path / "_audit").st_mode) == 0o700


def test_audit_log_never_raises(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    log = http_server.AuditLog(blocker / "_audit", now=lambda: FIXED_NOW)
    log.write({"client": "1.2.3.4", "scope": None, "tool": None, "outcome": "X"})  # must not raise


def test_audit_log_clips_and_cleans_tool_names(tmp_path):
    log = http_server.AuditLog(tmp_path, now=lambda: FIXED_NOW)
    log.write({"client": "1.2.3.4", "scope": "read", "tool": "A\x1b[31m" + "B" * 500,
               "outcome": "UNKNOWN_TOOL"})
    line = json.loads((tmp_path / "http-20261123.jsonl").read_text(encoding="utf-8"))
    assert "\x1b" not in line["tool"] and len(line["tool"]) <= 128
    assert line["time"].startswith("2026-11-23T12:00:00")


# ── start-up refusal ────────────────────────────────────────────────
def test_refuses_non_loopback_bind_without_tls(app, tmp_path):
    with pytest.raises(ConfigError) as ei:
        build(app, tmp_path, cfg(bind=ANY_ADDR))
    assert "tls" in ei.value.message.lower()


def test_non_loopback_bind_with_tls_is_accepted(app, tmp_path):
    assert build(app, tmp_path, cfg(bind=ANY_ADDR, tls_cert="/c.pem", tls_key="/k.pem")) is not None


def test_refuses_without_any_token(app, tmp_path):
    with pytest.raises(ConfigError) as ei:
        build(app, tmp_path, cfg(token_envs={}), environ={})
    assert ei.value.hint
    with pytest.raises(ConfigError):
        build(app, tmp_path, cfg(), environ={})  # env names configured but unset


def test_refuses_short_or_duplicate_tokens(app, tmp_path):
    with pytest.raises(ConfigError) as ei:
        build(app, tmp_path, environ={"GW_READ": "tiny-secret", "GW_ADMIN": ADMIN_TOKEN})
    assert "tiny-secret" not in ei.value.message  # never echo the secret
    with pytest.raises(ConfigError):
        build(app, tmp_path, environ={"GW_READ": ADMIN_TOKEN, "GW_ADMIN": ADMIN_TOKEN})


def test_resolve_tokens_returns_secrets(app):
    toks = http_server.resolve_tokens(cfg(), ENV)
    assert set(toks) == {"read", "analyze", "admin"}
    assert toks["admin"].reveal() == ADMIN_TOKEN and ADMIN_TOKEN not in repr(toks)


def test_serve_http_runs_uvicorn_with_tls_and_no_proxy_headers(app, tmp_path, monkeypatch):
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    cert.write_text("x")
    key.write_text("y")
    seen: dict[str, Any] = {}

    class FakeServer:
        def __init__(self, config: Any) -> None:
            seen["config"] = config

        def run(self) -> None:
            seen["ran"] = True

    class FakeConfig:
        def __init__(self, asgi: Any, **kw: Any) -> None:
            seen["kw"] = kw
            seen["asgi"] = asgi

    monkeypatch.setattr(http_server.uvicorn, "Server", FakeServer)
    monkeypatch.setattr(http_server.uvicorn, "Config", FakeConfig)
    http_server.serve_http(app, cfg(bind=ANY_ADDR, port=9443, tls_cert=str(cert), tls_key=str(key)),
                           environ=ENV, jobs_root=tmp_path)
    kw = seen["kw"]
    assert seen["ran"] is True
    assert kw["host"] == ANY_ADDR and kw["port"] == 9443
    assert kw["ssl_certfile"] == str(cert) and kw["ssl_keyfile"] == str(key)
    assert kw["proxy_headers"] is False


def test_serve_http_connection_limit_covers_every_session(app, tmp_path, monkeypatch):
    """Each session may hold a GET event stream plus a POST connection; uvicorn answers
    503 (unaudited) beyond limit_concurrency, so it must exceed sessions x 2."""
    seen: dict[str, Any] = {}

    class FakeServer:
        def __init__(self, config: Any) -> None:
            pass

        def run(self) -> None:
            pass

    def fake_config(asgi: Any, **kw: Any) -> None:
        seen.update(kw)

    monkeypatch.setattr(http_server.uvicorn, "Server", FakeServer)
    monkeypatch.setattr(http_server.uvicorn, "Config", fake_config)
    http_server.serve_http(app, cfg(), environ=ENV, jobs_root=tmp_path)
    sessions = http_server.MAX_SESSIONS_PER_SCOPE * len(TOKEN_ENVS)
    assert seen["limit_concurrency"] >= 2 * sessions


def test_audit_location_must_be_given_explicitly():
    """No silent fallback to the default jobs root: the caller passes the configured one."""
    serve = inspect.signature(http_server.serve_http).parameters["jobs_root"]
    build_app = inspect.signature(http_server.build_asgi_app).parameters["audit_dir"]
    assert serve.default is inspect.Parameter.empty and serve.kind is inspect.Parameter.KEYWORD_ONLY
    assert build_app.default is inspect.Parameter.empty and build_app.kind is inspect.Parameter.KEYWORD_ONLY


def test_serve_http_refuses_missing_tls_files(app, tmp_path):
    with pytest.raises(ConfigError):
        http_server.serve_http(app, cfg(bind=ANY_ADDR, tls_cert=str(tmp_path / "no.pem"),
                                        tls_key=str(tmp_path / "no.key")), environ=ENV, jobs_root=tmp_path)
