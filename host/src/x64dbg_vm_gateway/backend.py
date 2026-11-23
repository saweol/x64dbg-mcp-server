"""HTTP JSON-RPC client for one x64dbg-MCP plugin instance.

Protocol (src/core/mcp_server.zig): every request is answered and then the
connection is closed, so this client opens one TCP connection per request.
Every request carries ``Authorization: Bearer <token>``; a wrong token yields
``HTTP/1.1 401`` with ``{"error":"Unauthorized"}``. ``GET /`` returns server
info; ``POST /`` speaks JSON-RPC 2.0 (``initialize``, ``tools/list``,
``tools/call``, ``ping``).

Error mapping (never retries by itself):

========================================  ==========================================
transport / payload                       raised
========================================  ==========================================
refused, reset, EOF before/inside body    BackendUnavailable
HTTP 401                                  BackendAuthError
socket timeout / overall deadline         BackendTimeout
malformed JSON, oversized body, JSON      BackendProtocolError
nesting > 64, non-200 status, other
JSON-RPC errors
JSON-RPC -32602 with ``{"error": msg}``     ToolCallResult(is_error=True, texts=[msg])
call aborted by cancel_all()              CancelledByVmOp
========================================  ==========================================

Thread-safety: an instance may be used from many threads at once. The only
shared mutable state is the in-flight registry and the request-id counter, both
guarded by a lock. The bearer token is never written to logs, exception
messages, ``details`` or reprs.
"""

from __future__ import annotations

import dataclasses
import errno
import http.client
import itertools
import json
import logging
import selectors
import socket
import threading
import time
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

from . import __version__
from .contracts import BackendEndpoint, Clock, Secret, SystemClock, ToolCallResult, ToolInfo
from .errors import (
    BackendAuthError,
    BackendError,
    BackendProtocolError,
    BackendTimeout,
    BackendUnavailable,
    CancelledByVmOp,
    ConfigError,
)

log = logging.getLogger(__name__)

MAX_JSON_DEPTH = 64
MCP_PROTOCOL_VERSION = "2024-11-05"
_CONNECT_POLL_S = 0.1  # granularity at which a pending connect() notices cancel_all()
_READ_CHUNK = 65536
_MAX_ERROR_TEXT = 500  # untrusted text copied into exception details is truncated
# connect_ex() results that mean "in progress" (POSIX and Windows)
_CONNECT_PENDING = {0, errno.EINPROGRESS, errno.EALREADY, errno.EWOULDBLOCK, 10035}


class _Cancelled(Exception):
    """Internal: the call was aborted by cancel_all()."""


class _InFlight:
    """One in-flight request. ``cancel()`` may be called from any thread."""

    __slots__ = ("_lock", "cancelled", "sock")

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.cancelled = False
        self.sock: socket.socket | None = None

    def attach(self, sock: socket.socket) -> None:
        with self._lock:
            self.sock = sock
            if self.cancelled:
                raise _Cancelled()

    def cancel(self) -> None:
        with self._lock:
            self.cancelled = True
            sock = self.sock
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass  # not connected yet / already closed: the cancelled flag still aborts the call


def _wait_connected(sock: socket.socket, call: _InFlight, deadline: float) -> None:
    """Wait for a non-blocking connect() to finish, polling the cancel flag."""
    with selectors.DefaultSelector() as sel:
        sel.register(sock, selectors.EVENT_WRITE)
        while True:
            if call.cancelled:
                raise _Cancelled()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("connect timed out")
            if sel.select(min(_CONNECT_POLL_S, remaining)):
                break
    if call.cancelled:
        raise _Cancelled()
    err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
    if err:
        raise OSError(err, f"connect failed (errno {err})")


def _json_depth_exceeds(obj: Any, limit: int) -> bool:
    """True if containers in ``obj`` nest deeper than ``limit`` levels (iterative)."""
    stack: list[tuple[Any, int]] = [(obj, 1)]
    while stack:
        cur, depth = stack.pop()
        if isinstance(cur, dict):
            children: Any = cur.values()
        elif isinstance(cur, list):
            children = cur
        else:
            continue
        if depth > limit:
            return True
        for child in children:
            if isinstance(child, dict | list):
                stack.append((child, depth + 1))
    return False


def _clip(text: Any) -> str:
    s = str(text)
    return s if len(s) <= _MAX_ERROR_TEXT else s[:_MAX_ERROR_TEXT] + "...[clipped]"


class HttpBackendClient:
    """Synchronous BackendClient over stdlib sockets + http.client.

    ``clock`` is used only to measure call durations reported in log lines and
    ``ToolCallResult.raw['_gateway']``; socket deadlines always use real time.
    """

    def __init__(self, endpoint: BackendEndpoint, *, max_response_bytes: int = 1_048_576,
                 clock: Clock | None = None) -> None:
        parts = urlsplit(endpoint.url)
        if parts.scheme != "http":
            raise ConfigError(f"backend {endpoint.id!r}: only http:// endpoints are supported "
                              f"(got scheme {parts.scheme!r})")
        if not parts.hostname:
            raise ConfigError(f"backend {endpoint.id!r}: endpoint URL has no host")
        try:
            port = parts.port or 80
        except ValueError as e:
            raise ConfigError(f"backend {endpoint.id!r}: invalid port in endpoint URL") from e
        if max_response_bytes <= 0:
            raise ConfigError("max_response_bytes must be positive")
        self._endpoint = endpoint
        self._host = parts.hostname
        self._port = port
        self._path = parts.path or "/"
        self._display = f"http://{self._host}:{self._port}{self._path}"  # never includes userinfo
        self._max_bytes = max_response_bytes
        self._clock: Clock = clock if clock is not None else SystemClock()
        self._lock = threading.Lock()
        self._inflight: set[_InFlight] = set()
        self._ids = itertools.count(1)

    # ── identity ────────────────────────────────────────────────────
    @property
    def endpoint(self) -> BackendEndpoint:
        with self._lock:
            return self._endpoint

    def update_token(self, token: Secret | str) -> None:
        """Replace the bearer token (used by the supervisor's token refresher)."""
        value = token.reveal() if isinstance(token, Secret) else str(token)
        with self._lock:
            self._endpoint = dataclasses.replace(self._endpoint, token=Secret(value))

    def __repr__(self) -> str:
        return f"HttpBackendClient(id={self._endpoint.id!r}, url={self._display!r}, token='***')"

    __str__ = __repr__

    def in_flight(self) -> int:
        with self._lock:
            return len(self._inflight)

    def _details(self, **extra: Any) -> dict[str, Any]:
        d: dict[str, Any] = {"backend": self._endpoint.id, "endpoint": self._display}
        d.update(extra)
        return d

    # ── cancellation ────────────────────────────────────────────────
    def cancel_all(self) -> None:
        """Abort every in-flight request; each raises CancelledByVmOp promptly."""
        with self._lock:
            calls = list(self._inflight)
        for c in calls:
            c.cancel()
        if calls:
            log.info("backend %s: cancelled %d in-flight request(s)", self._endpoint.id, len(calls))

    # ── transport ───────────────────────────────────────────────────
    def _connect(self, call: _InFlight, deadline: float) -> socket.socket:
        infos = socket.getaddrinfo(self._host, self._port, type=socket.SOCK_STREAM)
        last: OSError | None = None
        for family, socktype, proto, _canon, addr in infos:
            sock = socket.socket(family, socktype, proto)
            try:
                call.attach(sock)
                sock.setblocking(False)
                rc = sock.connect_ex(addr)
                if rc not in _CONNECT_PENDING:
                    raise OSError(rc, f"connect failed (errno {rc})")
                if rc != 0:
                    _wait_connected(sock, call, deadline)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                return sock
            except (TimeoutError, _Cancelled):
                sock.close()
                raise
            except OSError as e:
                sock.close()
                last = e
        raise last if last is not None else OSError("no addresses for backend host")

    def _exchange(self, method: str, body: bytes | None, timeout_s: float) -> tuple[int, bytes]:
        """Send one HTTP request on a fresh connection; return (status, body)."""
        endpoint = self.endpoint
        call = _InFlight()
        with self._lock:
            self._inflight.add(call)
        deadline = time.monotonic() + max(0.001, timeout_s)
        conn = http.client.HTTPConnection(self._host, self._port, timeout=timeout_s)
        try:
            sock = self._connect(call, deadline)
            sock.settimeout(max(0.001, deadline - time.monotonic()))
            conn.sock = sock
            headers = {
                "Authorization": "Bearer " + endpoint.token.reveal(),
                "Accept": "application/json",
                "Connection": "close",
            }
            if body is not None:
                headers["Content-Type"] = "application/json"
            conn.request(method, self._path, body=body, headers=headers)
            sock.settimeout(max(0.001, deadline - time.monotonic()))
            resp = conn.getresponse()
            status = resp.status
            if resp.length is not None and resp.length > self._max_bytes:
                raise self._oversized(resp.length)
            chunks: list[bytes] = []
            total = 0
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("response deadline exceeded")
                sock.settimeout(remaining)
                chunk = resp.read(min(_READ_CHUNK, self._max_bytes + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > self._max_bytes:
                    raise self._oversized(total)
            return status, b"".join(chunks)
        except BackendError:
            raise
        except _Cancelled:
            raise self._cancelled() from None
        except TimeoutError:
            if call.cancelled:
                raise self._cancelled() from None
            raise BackendTimeout(
                f"backend {endpoint.id} did not answer within {timeout_s:g}s",
                stage="backend_call", details=self._details(timeout_s=timeout_s),
            ) from None
        except (ConnectionError, http.client.RemoteDisconnected, http.client.IncompleteRead) as e:
            if call.cancelled:
                raise self._cancelled() from None
            raise BackendUnavailable(
                f"backend {endpoint.id} at {self._display} is unavailable: {type(e).__name__}",
                stage="backend_call", details=self._details(error=type(e).__name__),
            ) from None
        except http.client.HTTPException as e:
            if call.cancelled:
                raise self._cancelled() from None
            raise BackendProtocolError(
                f"backend {endpoint.id} sent an invalid HTTP response: {type(e).__name__}",
                stage="backend_call", details=self._details(error=type(e).__name__),
            ) from None
        except OSError as e:
            if call.cancelled:
                raise self._cancelled() from None
            raise BackendUnavailable(
                f"backend {endpoint.id} at {self._display} is unavailable: "
                f"{type(e).__name__} (errno {e.errno})",
                stage="backend_call", details=self._details(error=type(e).__name__, errno=e.errno),
            ) from None
        finally:
            conn.close()
            with self._lock:
                self._inflight.discard(call)

    def _oversized(self, size: int) -> BackendProtocolError:
        return BackendProtocolError(
            f"backend {self._endpoint.id} response exceeds {self._max_bytes} bytes",
            stage="backend_call", details=self._details(size=size, max_response_bytes=self._max_bytes),
        )

    def _cancelled(self) -> CancelledByVmOp:
        return CancelledByVmOp(
            f"request to backend {self._endpoint.id} was cancelled by a VM operation",
            stage="backend_call", details=self._details(),
        )

    def _parse_json(self, data: bytes) -> Any:
        try:
            obj = json.loads(data.decode("utf-8", errors="replace"))
        except (ValueError, RecursionError):
            raise BackendProtocolError(
                f"backend {self._endpoint.id} returned malformed JSON",
                stage="backend_call", details=self._details(size=len(data)),
            ) from None
        if _json_depth_exceeds(obj, MAX_JSON_DEPTH):
            raise BackendProtocolError(
                f"backend {self._endpoint.id} returned JSON nested deeper than {MAX_JSON_DEPTH}",
                stage="backend_call", details=self._details(max_depth=MAX_JSON_DEPTH),
            )
        return obj

    def _check_status(self, status: int, what: str) -> None:
        if status == 401:
            raise BackendAuthError(
                f"backend {self._endpoint.id} rejected the bearer token (HTTP 401)",
                stage="backend_call", hint="check token_source / the token env var or mcp_config.json",
                details=self._details(status=401),
            )
        if status != 200:
            raise BackendProtocolError(
                f"backend {self._endpoint.id} answered {what} with HTTP {status}",
                stage="backend_call", details=self._details(status=status),
            )

    def _rpc(self, method: str, params: dict[str, Any] | None, timeout_s: float) -> tuple[Any, Any]:
        """Run one JSON-RPC call; return (result, None) or (None, error-object)."""
        with self._lock:
            rid = next(self._ids)
        payload: dict[str, Any] = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            payload["params"] = params
        try:
            body = json.dumps(payload).encode("utf-8")
        except (TypeError, ValueError):
            raise BackendProtocolError(
                f"arguments for {method} are not JSON-serialisable",
                stage="backend_call", details=self._details(method=method),
            ) from None
        t0 = self._clock.monotonic()
        try:
            status, data = self._exchange("POST", body, timeout_s)
        except BackendError as e:
            log.debug("backend %s %s failed after %.0f ms: %s", self._endpoint.id, method,
                      (self._clock.monotonic() - t0) * 1000, e.code)
            raise
        log.debug("backend %s %s -> HTTP %d, %d bytes in %.0f ms", self._endpoint.id, method, status,
                  len(data), (self._clock.monotonic() - t0) * 1000)
        self._check_status(status, method)
        msg = self._parse_json(data)
        if not isinstance(msg, dict):
            raise BackendProtocolError(f"backend {self._endpoint.id}: JSON-RPC response is not an object",
                                       stage="backend_call", details=self._details(method=method))
        if msg.get("id") != rid:
            raise BackendProtocolError(
                f"backend {self._endpoint.id}: JSON-RPC response id does not match the request",
                stage="backend_call", details=self._details(method=method, expected_id=rid,
                                                            got_id=_clip(msg.get("id"))),
            )
        if "error" in msg:
            err = msg["error"]
            if not isinstance(err, dict):
                raise BackendProtocolError(f"backend {self._endpoint.id}: malformed JSON-RPC error",
                                           stage="backend_call", details=self._details(method=method))
            return None, err
        if "result" not in msg:
            raise BackendProtocolError(f"backend {self._endpoint.id}: JSON-RPC response has no result",
                                       stage="backend_call", details=self._details(method=method))
        return msg["result"], None

    def _rpc_error(self, method: str, err: dict[str, Any]) -> BackendProtocolError:
        code = err.get("code")
        code = code if isinstance(code, int) else _clip(code)
        return BackendProtocolError(
            f"backend {self._endpoint.id}: {method} failed with JSON-RPC error {code}",
            stage="backend_call",
            details=self._details(method=method, code=code, message=_clip(err.get("message", ""))),
        )

    def _rpc_result(self, method: str, params: dict[str, Any] | None, timeout_s: float) -> Any:
        result, err = self._rpc(method, params, timeout_s)
        if err is not None:
            raise self._rpc_error(method, err)
        return result

    # ── BackendClient API ───────────────────────────────────────────
    def server_info(self, timeout_s: float = 2.0) -> dict[str, Any]:
        """``GET /`` -> ``{"name", "version", "transport", "endpoint"}``."""
        status, data = self._exchange("GET", None, timeout_s)
        self._check_status(status, "GET /")
        info = self._parse_json(data)
        if not isinstance(info, dict):
            raise BackendProtocolError(f"backend {self._endpoint.id}: server info is not an object",
                                       stage="backend_call", details=self._details())
        return info

    def health_l1(self, timeout_s: float = 2.0) -> bool:
        """True iff ``GET /`` answers 200 with a ``name`` field.

        Returns False when unreachable, slow or malformed. Raises
        BackendAuthError on 401 (the server is alive but the token is wrong).
        """
        try:
            info = self.server_info(timeout_s)
        except BackendAuthError:
            raise
        except (BackendError, CancelledByVmOp):
            return False
        return isinstance(info.get("name"), str)

    def health_l2(self, timeout_s: float = 5.0) -> bool:
        """True iff ``tools/call GetDebugState`` returns any result within ``timeout_s``.

        Raises BackendAuthError on 401; every other failure returns False.
        """
        try:
            self.call_tool("GetDebugState", {}, timeout_s)
        except BackendAuthError:
            raise
        except (BackendError, CancelledByVmOp):
            return False
        return True

    def initialize(self, timeout_s: float = 10.0) -> dict[str, Any]:
        result = self._rpc_result("initialize", {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "x64dbg-vm-gateway", "version": __version__},
        }, timeout_s)
        if not isinstance(result, dict):
            raise BackendProtocolError(f"backend {self._endpoint.id}: initialize result is not an object",
                                       stage="backend_call", details=self._details())
        return result

    def list_tools(self, timeout_s: float = 10.0) -> list[ToolInfo]:
        result = self._rpc_result("tools/list", None, timeout_s)
        tools = result.get("tools") if isinstance(result, dict) else None
        if not isinstance(tools, list):
            raise BackendProtocolError(f"backend {self._endpoint.id}: tools/list did not return a list",
                                       stage="backend_call", details=self._details())
        out: list[ToolInfo] = []
        for t in tools:
            if not isinstance(t, dict) or not isinstance(t.get("name"), str):
                raise BackendProtocolError(f"backend {self._endpoint.id}: malformed tool entry",
                                           stage="backend_call", details=self._details())
            ann = t.get("annotations")
            read_only = bool(ann.get("readOnlyHint")) if isinstance(ann, dict) else False
            desc = t.get("description")
            out.append(ToolInfo(name=t["name"], description=desc if isinstance(desc, str) else "",
                                input_schema=t.get("inputSchema"),  # type: ignore[arg-type]  # catalog sanitises
                                read_only=read_only))
        return out

    def call_tool(self, name: str, arguments: Mapping[str, Any] | None, timeout_s: float) -> ToolCallResult:
        params = {"name": name, "arguments": dict(arguments or {})}
        result, err = self._rpc("tools/call", params, timeout_s)
        if err is not None:
            if err.get("code") == -32602 and isinstance(err.get("message"), str):
                try:
                    payload = json.loads(err["message"])
                except ValueError:
                    payload = None
                if isinstance(payload, dict) and isinstance(payload.get("error"), str):
                    return ToolCallResult(texts=[payload["error"]], is_error=True,
                                          raw={"jsonrpc_error": {"code": -32602, "message": err["message"]}})
            raise self._rpc_error(f"tools/call {name}", err)
        if not isinstance(result, dict) or not isinstance(result.get("content"), list):
            raise BackendProtocolError(
                f"backend {self._endpoint.id}: tools/call {name} result has no content",
                stage="backend_call", details=self._details(tool=name))
        texts: list[str] = []
        for item in result["content"]:
            if isinstance(item, dict) and item.get("type") == "text" and isinstance(item.get("text"), str):
                texts.append(item["text"])
            else:
                kind = item.get("type") if isinstance(item, dict) else type(item).__name__
                texts.append(f"[non-text content omitted: {_clip(kind)}]")
        return ToolCallResult(texts=texts, is_error=bool(result.get("isError")), raw=result)
