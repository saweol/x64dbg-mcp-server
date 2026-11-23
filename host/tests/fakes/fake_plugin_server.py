"""Threaded HTTP server that emulates the x64dbg-MCP plugin (src/core/mcp_server.zig).

Protocol facts mirrored from the plugin:

- every request needs ``Authorization: Bearer <token>``; otherwise
  ``401 Unauthorized`` with body ``{"error":"Unauthorized"}``;
- ``GET /`` returns
  ``{"name":"x64dbg-MCP Server","version":...,"transport":"streamable-http","endpoint":"/"}``;
- ``POST /`` speaks JSON-RPC 2.0 (``initialize``, ``tools/list``, ``tools/call``, ``ping``);
- ``tools/call`` success: ``{"content":[{"type":"text","text":...}, "[state] ..."], "isError"?: true}``;
- tool-not-found / "Tool requires an active debug session." come back as JSON-RPC
  error ``-32602`` whose message is the JSON text ``{"error":"..."}``;
- the connection is closed after every response.

Programming the fake::

    srv = FakePluginServer(token="t").start()
    srv.on_tool("GetDebugState", "PAUSED at 0x401000")      # fixed text reply
    srv.on_tool("run", lambda args: ["a", "b"])             # handler; list -> exact text items
    srv.on_tool("Echo", {"content": [], "isError": True})    # raw tools/call result
    srv.on_tool("X", ToolError("Tool not found."))           # -> -32602 {"error": ...}
    srv.on_tool("Y", RpcError(-32603, "overflow"))           # -> JSON-RPC error
    srv.set_delay("run", 5.0)                                # sleep before answering
    srv.close_without_response("run", times=1)               # drop the connection
    srv.set_raw_response("tools/list", 200, b"not json")     # arbitrary bytes
    srv.lock_out(300)                                        # 429 + Retry-After (v1.10 lockout)
    srv.stop(); srv.restart()                                # refused while stopped

Keys accepted by ``set_delay`` / ``close_without_response`` / ``set_raw_response``:
a tool name (``tools/call``), a JSON-RPC method (``initialize``, ``tools/list``,
``ping``), ``"GET"`` for ``GET /``, or ``"*"`` for every request.

Thread-safety: all programming methods and the request log are guarded by one lock;
handlers run on the server's per-connection threads.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from typing import Any

SERVER_NAME = "x64dbg-MCP Server"

PLUGIN_INSTRUCTIONS = (
    "You are controlling x64dbg, a Windows debugger, via MCP tools.\n\nCRITICAL RULES:\n"
    "1. ALWAYS call GetDebugState first to understand the current state before doing anything."
)


class ToolError(Exception):
    """Raised/returned by a tool handler: becomes JSON-RPC -32602 with {"error": message}."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class RpcError(Exception):
    """Raised/returned by a handler: becomes a JSON-RPC error with this code and message."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


Reply = str | list[str] | dict[str, Any] | ToolError | RpcError
Handler = Callable[[dict[str, Any]], Reply]


@dataclass
class RecordedRequest:
    method: str  # HTTP method
    path: str
    authorized: bool
    authorization: str | None  # raw header value (tests assert the bearer token)
    connection_header: str | None
    body: Any = None  # parsed JSON body (POST) or None
    rpc_method: str | None = None
    rpc_id: Any = None
    tool: str | None = None
    arguments: dict[str, Any] | None = None
    thread: str = field(default_factory=lambda: threading.current_thread().name)


@dataclass
class _RawResponse:
    status: int
    body: bytes
    headers: dict[str, str]
    content_length: bool = True


def builtin_wire_tools() -> list[dict[str, Any]]:
    """The builtin v1.9 catalog in the plugin's ``tools/list`` wire format."""
    data = json.loads(
        resources.files("x64dbg_vm_gateway").joinpath("data/tools-v1.9.json").read_text(encoding="utf-8")
    )
    out = []
    for t in data["tools"]:
        out.append({
            "name": t["name"],
            "description": t["description"],
            "inputSchema": t["inputSchema"],
            "annotations": {"readOnlyHint": bool(t["read_only"]), "openWorldHint": False},
            "_debug_only": bool(t.get("debug_only", False)),
        })
    return out


class FakePluginServer:
    def __init__(
        self,
        token: str = "test-token",  # noqa: S107 - fake credential for tests
        *,
        version: str = "1.9",
        tools: list[dict[str, Any]] | None = None,
        instructions: str = PLUGIN_INSTRUCTIONS,
        debugging: bool = True,
        state_line: str = "[state] PAUSED at 0x401000 (sample.exe) | push rbp",
    ) -> None:
        self.token = token
        self.version = version
        self.instructions = instructions
        self.debugging = debugging
        self.state_line = state_line
        self._tools = tools if tools is not None else builtin_wire_tools()
        self._lock = threading.Lock()
        self._handlers: dict[str, Handler | Reply] = {}
        self._delays: dict[str, float] = {}
        self._drops: dict[str, int | None] = {}  # key -> remaining count (None = forever)
        self._raw: dict[str, _RawResponse] = {}
        self._log: list[RecordedRequest] = []
        self._release = threading.Event()  # set on stop(): delayed handlers return early
        self._lockout: tuple[int, bool, bool] | None = None  # (retry_after_s, header, body)
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._port = 0

    # ── lifecycle ────────────────────────────────────────────────────
    def start(self) -> FakePluginServer:
        if self._httpd is not None:
            return self
        self._release.clear()
        httpd = _Server(("127.0.0.1", self._port), _make_handler(self))
        self._port = httpd.server_address[1]
        self._httpd = httpd
        self._thread = threading.Thread(
            target=httpd.serve_forever, kwargs={"poll_interval": 0.05},
            name=f"fake-plugin-{self._port}", daemon=True,
        )
        self._thread.start()
        return self

    def stop(self) -> None:
        """Stop listening. New connections are refused until restart()."""
        httpd, self._httpd = self._httpd, None
        self._release.set()
        if httpd is not None:
            httpd.shutdown()
            httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def restart(self) -> FakePluginServer:
        self.stop()
        return self.start()

    @property
    def running(self) -> bool:
        return self._httpd is not None

    def __enter__(self) -> FakePluginServer:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    @property
    def port(self) -> int:
        return self._port

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._port}/"

    # ── programming ─────────────────────────────────────────────────
    def on_tool(self, name: str, reply: Handler | Reply) -> None:
        with self._lock:
            self._handlers[name] = reply

    def set_delay(self, key: str, seconds: float) -> None:
        with self._lock:
            if seconds <= 0:
                self._delays.pop(key, None)
            else:
                self._delays[key] = seconds

    def close_without_response(self, key: str = "*", times: int | None = None) -> None:
        with self._lock:
            self._drops[key] = times

    def clear_close_without_response(self) -> None:
        with self._lock:
            self._drops.clear()

    def set_raw_response(self, key: str, status: int, body: bytes,
                         headers: dict[str, str] | None = None, *, content_length: bool = True) -> None:
        """Answer ``key`` with these exact bytes. ``content_length=False`` sends a
        close-delimited body (no Content-Length header)."""
        with self._lock:
            self._raw[key] = _RawResponse(status, body, dict(headers or {}), content_length)

    def clear_raw_responses(self) -> None:
        with self._lock:
            self._raw.clear()

    def lock_out(self, retry_after_s: int = 300, *, header: bool = True, body: bool = True) -> None:
        """Answer every request with ``429 Too Many Requests`` before authentication, like the
        v1.10 plugin's auth-failure lockout (http.zig ``lockedOutResponse``): ``Retry-After``
        header (unless ``header=False``) and ``{"error", "retry_after_s"}`` body (unless
        ``body=False``)."""
        with self._lock:
            self._lockout = (retry_after_s, header, body)

    def unlock(self) -> None:
        with self._lock:
            self._lockout = None

    def _locked_out(self) -> tuple[int, bool, bool] | None:
        with self._lock:
            return self._lockout

    def set_tools(self, tools: list[dict[str, Any]]) -> None:
        with self._lock:
            self._tools = tools

    # ── request log ─────────────────────────────────────────────────
    @property
    def requests(self) -> list[RecordedRequest]:
        with self._lock:
            return list(self._log)

    def tool_calls(self, name: str | None = None) -> list[RecordedRequest]:
        return [r for r in self.requests
                if r.rpc_method == "tools/call" and (name is None or r.tool == name)]

    def clear_log(self) -> None:
        with self._lock:
            self._log.clear()

    # ── internals used by the request handler ───────────────────────
    def _record(self, req: RecordedRequest) -> None:
        with self._lock:
            self._log.append(req)

    def _lookup(self, keys: list[str]) -> tuple[float, bool, _RawResponse | None]:
        with self._lock:
            delay = 0.0
            for k in keys:
                if k in self._delays:
                    delay = self._delays[k]
                    break
            drop = False
            for k in keys:
                if k in self._drops:
                    remaining = self._drops[k]
                    if remaining is None:
                        drop = True
                    elif remaining > 0:
                        drop = True
                        self._drops[k] = remaining - 1
                    if drop:
                        break
            raw = None
            for k in keys:
                if k in self._raw:
                    raw = self._raw[k]
                    break
            return delay, drop, raw

    def _tool_meta(self, name: str) -> dict[str, Any] | None:
        with self._lock:
            for t in self._tools:
                if t["name"] == name:
                    return t
        return None

    def _handler_for(self, name: str) -> Handler | Reply | None:
        with self._lock:
            return self._handlers.get(name)

    def _wait(self, seconds: float) -> None:
        if seconds > 0:
            self._release.wait(seconds)

    def _tools_call_result(self, name: str, arguments: dict[str, Any]) -> tuple[str, Any]:
        """Return ("result", obj) or ("error", (code, message))."""
        h = self._handler_for(name)
        meta = self._tool_meta(name)
        if h is None and meta is None:
            return "error", (-32602, json.dumps({"error": "Tool not found."}))
        if meta is not None and meta.get("_debug_only") and not self.debugging and h is None:
            return "error", (-32602, json.dumps({"error": "Tool requires an active debug session."}))
        try:
            reply: Any = h(arguments) if callable(h) else h
        except (ToolError, RpcError) as e:
            reply = e
        if reply is None:
            reply = f"{name} ok"
        if isinstance(reply, ToolError):
            return "error", (-32602, json.dumps({"error": reply.message}))
        if isinstance(reply, RpcError):
            return "error", (reply.code, reply.message)
        if isinstance(reply, dict):
            return "result", reply
        if isinstance(reply, list):
            return "result", {"content": [{"type": "text", "text": t} for t in reply]}
        content = [{"type": "text", "text": str(reply)}]
        if name not in ("GetDebugState", "Echo") and self.state_line:
            content.append({"type": "text", "text": self.state_line})
        return "result", {"content": content}

    def _rpc(self, body: Any) -> tuple[str, Any]:
        method = body.get("method")
        if method == "initialize":
            return "result", {
                "protocolVersion": "2024-11-05",
                "serverInfo": {"name": SERVER_NAME, "version": self.version},
                "capabilities": {"tools": {"listChanged": True}},
                "instructions": self.instructions,
            }
        if method == "tools/list":
            with self._lock:
                tools = [{k: v for k, v in t.items() if not k.startswith("_")} for t in self._tools]
            return "result", {"tools": tools}
        if method == "ping":
            return "result", {}
        if method == "tools/call":
            params = body.get("params") or {}
            name = params.get("name")
            if not isinstance(name, str):
                return "error", (-32602, json.dumps({"error": "Missing params.name"}))
            args = params.get("arguments") or {}
            return self._tools_call_result(name, args)
        return "error", (-32601, "Method not found")


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False  # stop() must not wait for handlers that are still sleeping
    allow_reuse_address = True

    def handle_error(self, request: Any, client_address: Any) -> None:
        # Clients that were cancelled close their sockets; the resulting broken
        # pipes in handler threads are expected and must not spam test output.
        pass


def _make_handler(fake: FakePluginServer) -> type[BaseHTTPRequestHandler]:
    class _Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "fake-x64dbg-mcp"

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            pass

        # -- helpers ---------------------------------------------------
        def _authorized(self) -> tuple[bool, str | None]:
            value = self.headers.get("Authorization")
            return value == f"Bearer {fake.token}", value

        def _send(self, status: int, body: bytes, headers: dict[str, str] | None = None,
                  content_length: bool = True) -> None:
            try:
                self.send_response(status)
                hdrs = {"Content-Type": "application/json"}
                hdrs.update(headers or {})
                for k, v in hdrs.items():
                    self.send_header(k, v)
                if content_length and "Content-Length" not in hdrs:
                    self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                self.wfile.flush()
            except OSError:
                pass
            self.close_connection = True

        def _send_locked_out(self) -> bool:
            lock = fake._locked_out()
            if lock is None:
                return False
            retry_after_s, header, body = lock
            payload = (json.dumps({"error": "Too many failed authentication attempts",
                                   "retry_after_s": retry_after_s}).encode() if body
                       else b'{"error":"Too many failed authentication attempts"}')
            self._send(429, payload, {"Retry-After": str(retry_after_s)} if header else None)
            return True

        def _send_json(self, obj: Any) -> None:
            self._send(200, json.dumps(obj).encode("utf-8"))

        def _common(self, keys: list[str]) -> bool:
            """Apply delay / drop / raw programming. Return True if the request was handled."""
            delay, drop, raw = fake._lookup(keys + ["*"])
            fake._wait(delay)
            if drop:
                self.close_connection = True
                return True
            if raw is not None:
                self._send(raw.status, raw.body, raw.headers, raw.content_length)
                return True
            return False

        # -- verbs ------------------------------------------------------
        def do_GET(self) -> None:  # noqa: N802
            ok, auth = self._authorized()
            fake._record(RecordedRequest("GET", self.path, ok, auth, self.headers.get("Connection")))
            if self._send_locked_out():
                return
            if not ok:
                self._send(401, b'{"error":"Unauthorized"}')
                return
            if self._common(["GET"]):
                return
            self._send_json({"name": SERVER_NAME, "version": fake.version,
                             "transport": "streamable-http", "endpoint": "/"})

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length") or 0)
            raw_body = self.rfile.read(length) if length else b""
            ok, auth = self._authorized()
            rec = RecordedRequest("POST", self.path, ok, auth, self.headers.get("Connection"))
            try:
                body = json.loads(raw_body.decode("utf-8")) if raw_body else None
            except ValueError:
                body = None
            if isinstance(body, dict):
                rec.body = body
                rec.rpc_method = body.get("method")
                rec.rpc_id = body.get("id")
                if rec.rpc_method == "tools/call":
                    params = body.get("params") or {}
                    rec.tool = params.get("name")
                    rec.arguments = params.get("arguments")
            fake._record(rec)
            if self._send_locked_out():
                return
            if not ok:
                self._send(401, b'{"error":"Unauthorized"}')
                return
            keys = [k for k in (rec.tool, rec.rpc_method) if k]
            if self._common(keys):
                return
            if not isinstance(body, dict):
                self._send_json({"jsonrpc": "2.0", "id": None,
                                 "error": {"code": -32700, "message": "Parse error"}})
                return
            kind, payload = fake._rpc(body)
            if kind == "result":
                self._send_json({"jsonrpc": "2.0", "id": body.get("id"), "result": payload})
            else:
                code, message = payload
                self._send_json({"jsonrpc": "2.0", "id": body.get("id"),
                                 "error": {"code": code, "message": message}})

    return _Handler
