"""HttpBackendClient against the fake plugin server (real sockets on 127.0.0.1)."""

from __future__ import annotations

import json
import logging
import socket
import threading
import time

import pytest

from tests.fakes.fake_plugin_server import FakePluginServer, RpcError, ToolError
from x64dbg_vm_gateway import contracts
from x64dbg_vm_gateway.backend import HttpBackendClient
from x64dbg_vm_gateway.contracts import BackendEndpoint, Secret, ToolCallResult
from x64dbg_vm_gateway.errors import (
    BackendAuthError,
    BackendProtocolError,
    BackendTimeout,
    BackendUnavailable,
    CancelledByVmOp,
    ConfigError,
)

TOKEN = "s3cr3t-token-value-XYZ"


@pytest.fixture
def server():
    srv = FakePluginServer(token=TOKEN).start()
    yield srv
    srv.stop()


def make_client(url: str, token: str = TOKEN, **kw) -> HttpBackendClient:
    ep = BackendEndpoint(id="x64", arch="x64", url=url, token=Secret(token))
    return HttpBackendClient(ep, **kw)


@pytest.fixture
def client(server) -> HttpBackendClient:
    return make_client(server.url)


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def assert_no_token(exc: BaseException) -> None:
    blob = " ".join([str(exc), repr(exc), json.dumps(getattr(exc, "details", {}), default=str),
                     repr(getattr(exc, "__cause__", None)), repr(getattr(exc, "__context__", None))])
    assert TOKEN not in blob


# ── protocol / construction ─────────────────────────────────────────
def test_satisfies_backend_client_protocol(client):
    assert isinstance(client, contracts.BackendClient)
    assert client.endpoint.id == "x64"


def test_repr_does_not_leak_token(client):
    assert TOKEN not in repr(client) and TOKEN not in str(client)


def test_rejects_non_http_scheme():
    with pytest.raises(ConfigError):
        make_client("ftp://127.0.0.1:1/")


# ── health L1 ───────────────────────────────────────────────────────
def test_health_l1_ok_and_sends_bearer_and_closes(client, server):
    assert client.health_l1() is True
    req = server.requests[-1]
    assert req.method == "GET" and req.path == "/"
    assert req.authorization == f"Bearer {TOKEN}"
    assert (req.connection_header or "").lower() == "close"


def test_health_l1_false_when_refused():
    c = make_client(f"http://127.0.0.1:{_free_port()}/")
    assert c.health_l1(timeout_s=1.0) is False


def test_health_l1_false_without_name_field(client, server):
    server.set_raw_response("GET", 200, b'{"version":"1.9"}')
    assert client.health_l1() is False


def test_health_l1_false_on_non_200(client, server):
    server.set_raw_response("GET", 503, b"")
    assert client.health_l1() is False


def test_health_l1_raises_auth_error_on_401(server):
    c = make_client(server.url, token="wrong-token")
    with pytest.raises(BackendAuthError) as ei:
        c.health_l1()
    assert "wrong-token" not in str(ei.value) and "wrong-token" not in repr(ei.value.details)


def test_server_info(client):
    info = client.server_info()
    assert info["name"] == "x64dbg-MCP Server" and info["version"] == "1.9"


# ── health L2 ───────────────────────────────────────────────────────
def test_health_l2_true_on_any_result_including_is_error(client, server):
    assert client.health_l2() is True
    assert server.tool_calls("GetDebugState")
    server.on_tool("GetDebugState", ToolError("Tool requires an active debug session."))
    assert client.health_l2() is True


def test_health_l2_false_on_timeout(client, server):
    server.set_delay("GetDebugState", 2.0)
    t0 = time.monotonic()
    assert client.health_l2(timeout_s=0.3) is False
    assert time.monotonic() - t0 < 1.5


def test_health_l2_false_when_refused():
    c = make_client(f"http://127.0.0.1:{_free_port()}/")
    assert c.health_l2(timeout_s=1.0) is False


# ── initialize / tools/list ─────────────────────────────────────────
def test_initialize_returns_instructions(client, server):
    res = client.initialize()
    assert "x64dbg" in res["instructions"]
    req = server.requests[-1]
    assert req.rpc_method == "initialize" and req.body["jsonrpc"] == "2.0"
    assert "clientInfo" in req.body["params"]


def test_list_tools_maps_read_only_hint(client):
    tools = client.list_tools()
    assert len(tools) == 80
    by_name = {t.name: t for t in tools}
    assert by_name["GetDebugState"].read_only is True
    assert by_name["run"].read_only is False
    assert by_name["run"].input_schema["type"] == "object"
    assert sum(t.read_only for t in tools) == 36


def test_list_tools_rejects_non_list(client, server):
    server.set_raw_response("tools/list", 200, b'{"jsonrpc":"2.0","id":1,"result":{"tools":{}}}')
    with pytest.raises(BackendProtocolError):
        client.list_tools()


# ── tools/call ──────────────────────────────────────────────────────
def test_call_tool_success_collects_all_text_items(client, server):
    server.on_tool("GetAllRegisters", "rax=1")
    res = client.call_tool("GetAllRegisters", {"x": 1}, timeout_s=5)
    assert isinstance(res, ToolCallResult)
    assert res.is_error is False
    assert res.texts == ["rax=1", server.state_line]
    call = server.tool_calls("GetAllRegisters")[-1]
    assert call.arguments == {"x": 1}


def test_call_tool_none_arguments_sends_empty_object(client, server):
    client.call_tool("GetDebugState", None, timeout_s=5)
    assert server.tool_calls("GetDebugState")[-1].arguments == {}


def test_call_tool_is_error_flag(client, server):
    server.on_tool("SetBreakpoint", {"content": [{"type": "text", "text": "Error: bad"}], "isError": True})
    res = client.call_tool("SetBreakpoint", {"address": "0"}, timeout_s=5)
    assert res.is_error is True and res.texts == ["Error: bad"]
    assert res.raw["isError"] is True


def test_call_tool_non_text_items_are_placeholders(client, server):
    server.on_tool("Echo", {"content": [{"type": "image", "data": "AAAA"}, {"type": "text", "text": "x"}]})
    res = client.call_tool("Echo", {}, timeout_s=5)
    assert res.texts[1] == "x"
    assert "image" in res.texts[0]


def test_minus_32602_with_error_payload_becomes_error_result(client, server):
    server.debugging = False
    res = client.call_tool("StepInto", {}, timeout_s=5)
    assert res.is_error is True
    assert res.texts == ["Tool requires an active debug session."]


def test_tool_not_found_becomes_error_result(client):
    res = client.call_tool("NoSuchTool", {}, timeout_s=5)
    assert res.is_error is True and res.texts == ["Tool not found."]


def test_minus_32602_with_plain_message_is_protocol_error(client, server):
    server.on_tool("Echo", RpcError(-32602, "Invalid params"))
    with pytest.raises(BackendProtocolError) as ei:
        client.call_tool("Echo", {}, timeout_s=5)
    assert ei.value.details["code"] == -32602


def test_minus_32603_overflow_is_protocol_error(client, server):
    server.on_tool("DumpMemory", RpcError(-32603, "Result too large — response buffer overflow"))
    with pytest.raises(BackendProtocolError) as ei:
        client.call_tool("DumpMemory", {}, timeout_s=5)
    assert ei.value.details["code"] == -32603
    assert "overflow" in ei.value.details["message"]


def test_response_id_mismatch_is_protocol_error(client, server):
    server.set_raw_response("Echo", 200, b'{"jsonrpc":"2.0","id":999999,"result":{"content":[]}}')
    with pytest.raises(BackendProtocolError):
        client.call_tool("Echo", {}, timeout_s=5)


def test_non_serializable_arguments_rejected(client):
    with pytest.raises(BackendProtocolError):
        client.call_tool("Echo", {"x": object()}, timeout_s=5)


# ── error mapping ───────────────────────────────────────────────────
def test_refused_maps_to_unavailable():
    c = make_client(f"http://127.0.0.1:{_free_port()}/")
    with pytest.raises(BackendUnavailable) as ei:
        c.call_tool("GetDebugState", {}, timeout_s=2)
    assert_no_token(ei.value)
    assert ei.value.details["backend"] == "x64"


def test_close_without_response_maps_to_unavailable(client, server):
    server.close_without_response("run", times=1)
    with pytest.raises(BackendUnavailable) as ei:
        client.call_tool("run", {}, timeout_s=5)
    assert_no_token(ei.value)


def test_unauthorized_maps_to_auth_error_without_token(server):
    c = make_client(server.url, token="not-the-token-" + "Q" * 8)
    with pytest.raises(BackendAuthError) as ei:
        c.call_tool("GetDebugState", {}, timeout_s=5)
    assert "not-the-token-" not in str(ei.value) + repr(ei.value) + repr(ei.value.details)
    assert ei.value.details.get("status") == 401


def test_socket_timeout_maps_to_backend_timeout(client, server):
    server.set_delay("run", 3.0)
    t0 = time.monotonic()
    with pytest.raises(BackendTimeout) as ei:
        client.call_tool("run", {}, timeout_s=0.4)
    assert time.monotonic() - t0 < 2.0
    assert_no_token(ei.value)


def test_malformed_json_maps_to_protocol_error(client, server):
    server.set_raw_response("Echo", 200, b"{not json")
    with pytest.raises(BackendProtocolError):
        client.call_tool("Echo", {}, timeout_s=5)


def test_non_200_status_maps_to_protocol_error(client, server):
    server.set_raw_response("Echo", 500, b"oops")
    with pytest.raises(BackendProtocolError) as ei:
        client.call_tool("Echo", {}, timeout_s=5)
    assert ei.value.details["status"] == 500


def test_oversized_body_by_content_length(server):
    c = make_client(server.url, max_response_bytes=2000)
    server.on_tool("ReadMemory", "A" * 5000)
    with pytest.raises(BackendProtocolError) as ei:
        c.call_tool("ReadMemory", {}, timeout_s=5)
    assert_no_token(ei.value)
    assert ei.value.details["max_response_bytes"] == 2000


def test_oversized_body_without_content_length(server):
    c = make_client(server.url, max_response_bytes=2000)
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text",
                                                                         "text": "B" * 5000}]}})
    # close-delimited body (no Content-Length): the limit is enforced while reading
    server.set_raw_response("ReadMemory", 200, body.encode(), content_length=False)
    with pytest.raises(BackendProtocolError):
        c.call_tool("ReadMemory", {}, timeout_s=5)


def _nested(depth: int) -> object:
    obj: object = "leaf"
    for _ in range(depth):
        obj = {"a": obj}
    return obj


def test_json_nesting_limit(client, server):
    # envelope {jsonrpc,result:{content,raw}} adds two levels around the nested value
    server.on_tool("Echo", {"content": [{"type": "text", "text": "ok"}], "x": _nested(70)})
    with pytest.raises(BackendProtocolError):
        client.call_tool("Echo", {}, timeout_s=5)
    server.on_tool("Echo", {"content": [{"type": "text", "text": "ok"}], "x": _nested(40)})
    assert client.call_tool("Echo", {}, timeout_s=5).texts == ["ok"]


def test_pathological_nesting_does_not_crash(client, server):
    server.set_raw_response("Echo", 200, b"[" * 200_000)
    with pytest.raises(BackendProtocolError):
        client.call_tool("Echo", {}, timeout_s=5)


def test_invalid_utf8_in_text_is_tolerated(client, server):
    body = b'{"jsonrpc":"2.0","id":%d,"result":{"content":[{"type":"text","text":"a\xff\xfeb"}]}}'
    # id must match: find the next id by peeking at the client counter via a first call
    client.call_tool("GetDebugState", {}, timeout_s=5)
    next_id = server.tool_calls("GetDebugState")[-1].rpc_id + 1
    server.set_raw_response("Echo", 200, body % next_id)
    res = client.call_tool("Echo", {}, timeout_s=5)
    assert res.texts[0].startswith("a") and res.texts[0].endswith("b")


# ── token hygiene in logs ───────────────────────────────────────────
def test_token_never_logged(client, server, caplog):
    caplog.set_level(logging.DEBUG)
    client.health_l1()
    client.call_tool("GetDebugState", {}, timeout_s=5)
    server.close_without_response("run", times=1)
    with pytest.raises(BackendUnavailable):
        client.call_tool("run", {}, timeout_s=5)
    assert TOKEN not in caplog.text


# ── one connection per request ─────────────────────────────────────
def test_each_request_uses_its_own_connection(client, server):
    for _ in range(3):
        client.call_tool("GetDebugState", {}, timeout_s=5)
    threads = {r.thread for r in server.tool_calls("GetDebugState")}
    assert len(threads) == 3  # ThreadingHTTPServer spawns one thread per connection


def test_request_ids_increase(client, server):
    client.call_tool("Echo", {}, timeout_s=5)
    client.call_tool("Echo", {}, timeout_s=5)
    ids = [r.rpc_id for r in server.tool_calls("Echo")]
    assert ids[1] > ids[0]


# ── cancel_all ──────────────────────────────────────────────────────
def test_cancel_all_unblocks_in_flight_calls(client, server):
    server.set_delay("run", 10.0)
    server.set_delay("WaitForEvent", 10.0)
    errors: list[BaseException] = []

    def worker(tool: str) -> None:
        try:
            client.call_tool(tool, {}, timeout_s=30)
        except BaseException as e:  # noqa: BLE001 - collected for assertions
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(t,)) for t in ("run", "WaitForEvent")]
    for t in threads:
        t.start()
    deadline = time.monotonic() + 5
    while len(server.tool_calls()) < 2 and time.monotonic() < deadline:
        time.sleep(0.01)
    assert client.in_flight() == 2
    t0 = time.monotonic()
    client.cancel_all()
    for t in threads:
        t.join(timeout=3)
    assert time.monotonic() - t0 < 1.5
    assert len(errors) == 2 and all(isinstance(e, CancelledByVmOp) for e in errors)
    assert client.in_flight() == 0
    for e in errors:
        assert_no_token(e)


def test_cancel_all_does_not_affect_later_calls(client, server):
    client.cancel_all()
    assert client.call_tool("GetDebugState", {}, timeout_s=5).texts


def test_cancel_while_connect_is_pending():
    """A call whose TCP connect never completes (guest suspended, SYN unanswered) is cancellable.

    A listener with a full accept queue makes the kernel drop further SYNs, so the
    client's connect stays pending (or, if it completes, the request is never read).
    """
    lsock = socket.socket()
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(0)
    port = lsock.getsockname()[1]
    fillers = []
    for _ in range(4):
        f = socket.socket()
        f.setblocking(False)
        f.connect_ex(("127.0.0.1", port))
        fillers.append(f)
    c = make_client(f"http://127.0.0.1:{port}/")
    errors: list[BaseException] = []

    def worker() -> None:
        try:
            c.call_tool("GetDebugState", {}, timeout_s=30)
        except BaseException as e:  # noqa: BLE001
            errors.append(e)

    t = threading.Thread(target=worker)
    t.start()
    try:
        deadline = time.monotonic() + 5
        while c.in_flight() < 1 and time.monotonic() < deadline:
            time.sleep(0.01)
        time.sleep(0.2)
        assert t.is_alive()
        t0 = time.monotonic()
        c.cancel_all()
        t.join(timeout=3)
        assert time.monotonic() - t0 < 1.5
        assert errors and isinstance(errors[0], CancelledByVmOp)
    finally:
        for f in fillers:
            f.close()
        lsock.close()


def test_update_token(server):
    c = make_client(server.url, token="old-wrong")
    with pytest.raises(BackendAuthError):
        c.health_l1()
    c.update_token(Secret(TOKEN))
    assert c.health_l1() is True
    assert c.endpoint.token.reveal() == TOKEN
