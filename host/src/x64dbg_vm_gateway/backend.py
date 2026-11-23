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
HTTP 429 (v1.10 auth-failure lockout)     BackendThrottled (``details["retry_after_s"]``
                                          from ``Retry-After``, else the JSON body)
socket timeout / overall deadline         BackendTimeout
malformed JSON, oversized body, JSON      BackendProtocolError
nesting > 64, non-200 status, other
JSON-RPC errors, request body too large
JSON-RPC -32602 with ``{"error": msg}``     ToolCallResult(is_error=True, texts=[msg])
call aborted by cancel_all()              CancelledByVmOp
========================================  ==========================================

Request size: the plugin reads a request into one 64 KiB buffer (headers
included, ``mcp_server.zig`` ``wsRecv``) and silently truncates the rest, which
it then reports as a JSON parse error with ``id: null``. Bodies larger than
``max_request_bytes`` are therefore rejected before anything is sent.

Untrusted text: JSON-RPC error messages come from the guest; the copy placed in
exception ``details`` is stripped of control/bidi characters and clipped.

Server version: ``server_info`` (``GET /``) and ``initialize`` record the plugin
version they saw; ``on_server_version(callback)`` registers a callback that gets
each newly seen version (the runtime uses it to pick the tool catalog matching
the plugin, see ``catalog.ToolCatalog.set_server_version``).

Thread-safety: an instance may be used from many threads at once. The only
shared mutable state is the in-flight registry, the endpoint (replaced by
``update_token``) and the request-id counter, all guarded by a lock. The bearer
token is validated up front (printable ASCII, surrounding whitespace stripped)
so it can never reach an exception message via header encoding, and it is never
written to logs, exception messages, ``details`` or reprs.
"""

from __future__ import annotations

import dataclasses
import errno
import http.client
import itertools
import json
import logging
import re
import selectors
import socket
import threading
import time
from collections.abc import Callable, Mapping
from typing import Any
from urllib.parse import urlsplit

from . import __version__
from .contracts import BackendEndpoint, Clock, Secret, SystemClock, ToolCallResult, ToolInfo
from .errors import (
    BackendAuthError,
    BackendError,
    BackendProtocolError,
    BackendThrottled,
    BackendTimeout,
    BackendUnavailable,
    CancelledByVmOp,
    ConfigError,
)
from .proxy import sanitize_untrusted_text

log = logging.getLogger(__name__)

MAX_JSON_DEPTH = 64
MCP_PROTOCOL_VERSION = "2024-11-05"
PLUGIN_RECV_BUFFER = 65536  # mcp_server.zig RecvResult.buf: request line + headers + body
MAX_REQUEST_BYTES = PLUGIN_RECV_BUFFER - 2048  # leave room for the request line and headers
THROTTLED_STATUS = 429  # plugin v1.10: peer locked out after repeated authentication failures
#: Upper bound for a reported lockout (the plugin prints a u64; its own limit is far lower).
MAX_RETRY_AFTER_S = 86_400
_DELTA_SECONDS_RE = re.compile(r"[0-9]+")  # RFC 9110 delay-seconds: ASCII digits only
_MAX_VERSION_CHARS = 64
_CONNECT_POLL_S = 0.1  # granularity at which a pending connect() notices cancel_all()
_READ_CHUNK = 65536
_MAX_ERROR_TEXT = 500  # untrusted text copied into exception details is truncated
# connect_ex() results that mean "in progress" (POSIX and Windows)
_CONNECT_PENDING = {0, errno.EINPROGRESS, errno.EALREADY, errno.EWOULDBLOCK, 10035}
# Socket constructor used for backend connections (a seam for tests; never reassigned at runtime).
_socket_factory: Callable[..., socket.socket] = socket.socket


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
    """Untrusted (guest-provided) text for exception details: controls/bidi removed, clipped."""
    return sanitize_untrusted_text(str(text), _MAX_ERROR_TEXT)


def _retry_after_s(header: str | None, body: bytes) -> int | None:
    """Seconds of a 429 lockout: the ``Retry-After`` header (delta-seconds), else the
    ``retry_after_s`` field of the plugin's JSON body; clamped to ``MAX_RETRY_AFTER_S``.

    The guest controls both. Only ASCII digits count as a header value: ``str.isdigit``
    also accepts e.g. '\u00b2' (a latin-1 decoded byte 0xB2), which ``int()`` rejects, and
    ``int()`` parses digits of other scripts."""
    value: Any = None
    if header is not None and _DELTA_SECONDS_RE.fullmatch(header.strip()):
        value = int(header.strip())
    else:
        try:
            doc = json.loads(body[:4096].decode("utf-8", errors="replace"))
        except (ValueError, RecursionError):
            doc = None
        raw = doc.get("retry_after_s") if isinstance(doc, dict) else None
        if isinstance(raw, int) and not isinstance(raw, bool) and raw >= 0:
            value = raw
    return None if value is None else min(int(value), MAX_RETRY_AFTER_S)


def _validated_token(backend_id: str, token: Secret | str) -> Secret:
    """Return the token as a Secret, stripped of surrounding whitespace.

    Raises ConfigError (without echoing the value) when the token contains
    anything but printable ASCII: CR/LF would be rejected by http.client with a
    ValueError that quotes the whole header (token included), and non-latin-1
    characters cannot be encoded into a header at all.
    """
    value = token.reveal() if isinstance(token, Secret) else str(token)
    value = value.strip(" \t\r\n")
    if any(not (0x20 <= ord(ch) <= 0x7E) for ch in value):
        raise ConfigError(
            f"backend {backend_id!r}: the bearer token contains control or non-ASCII characters",
            hint="check token_source / the token env var or mcp_config.json (the value is not shown)",
        )
    return Secret(value)


class HttpBackendClient:
    """Synchronous BackendClient over stdlib sockets + http.client.

    ``clock`` is used only to measure call durations reported in log lines;
    socket deadlines always use real time.
    """

    def __init__(self, endpoint: BackendEndpoint, *, max_response_bytes: int = 1_048_576,
                 clock: Clock | None = None, max_request_bytes: int = MAX_REQUEST_BYTES) -> None:
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
        if max_response_bytes <= 0 or max_request_bytes <= 0:
            raise ConfigError("max_response_bytes and max_request_bytes must be positive")
        self._endpoint = dataclasses.replace(endpoint, token=_validated_token(endpoint.id, endpoint.token))
        self._host = parts.hostname
        self._port = port
        self._path = parts.path or "/"
        self._display = f"http://{self._host}:{self._port}{self._path}"  # never includes userinfo
        self._max_bytes = max_response_bytes
        self._max_request_bytes = max_request_bytes
        self._clock: Clock = clock if clock is not None else SystemClock()
        self._lock = threading.Lock()
        self._inflight: set[_InFlight] = set()
        self._ids = itertools.count(1)
        self._server_version: str | None = None
        self._version_listeners: list[Callable[[str], None]] = []

    # ── identity ────────────────────────────────────────────────────
    @property
    def endpoint(self) -> BackendEndpoint:
        with self._lock:
            return self._endpoint

    @property
    def server_version(self) -> str | None:
        """Plugin version from the last ``GET /`` or ``initialize`` answer (None until seen)."""
        with self._lock:
            return self._server_version

    def on_server_version(self, callback: Callable[[str], None]) -> None:
        """Call ``callback(version)`` whenever a different plugin version is seen (and now, if known).

        The callback runs on the calling thread after the answer was parsed; its
        exceptions are logged and ignored.
        """
        with self._lock:
            self._version_listeners.append(callback)
            known = self._server_version
        if known is not None:
            self._notify_version(callback, known)

    def _notify_version(self, callback: Callable[[str], None], version: str) -> None:
        try:
            callback(version)
        except Exception:  # noqa: BLE001 - a listener must never break a backend call
            log.warning("backend %s: server version listener failed", self._endpoint.id, exc_info=True)

    def _saw_version(self, raw: Any) -> None:
        if not isinstance(raw, str) or not raw.strip():
            return
        version = _clip(raw.strip())[:_MAX_VERSION_CHARS]
        with self._lock:
            if version == self._server_version:
                return
            self._server_version = version
            listeners = list(self._version_listeners)
        for callback in listeners:
            self._notify_version(callback, version)

    def update_token(self, token: Secret | str) -> None:
        """Replace the bearer token (used by the supervisor's token refresher).

        Raises ConfigError (and keeps the old token) if the new one is not printable ASCII.
        """
        value = _validated_token(self._endpoint.id, token)
        with self._lock:
            self._endpoint = dataclasses.replace(self._endpoint, token=value)

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
            sock = _socket_factory(family, socktype, proto)
            try:
                call.attach(sock)
                sock.setblocking(False)
                rc = sock.connect_ex(addr)
                if rc not in _CONNECT_PENDING:
                    raise OSError(rc, f"connect failed (errno {rc})")
                if rc != 0:
                    _wait_connected(sock, call, deadline)
                # A cancel that landed before the socket was connected could not shut it down
                # (ENOTCONN); only the flag recorded it. Once connected, shutdown() works.
                if call.cancelled:
                    raise _Cancelled()
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
        """Send one HTTP request on a fresh connection; return (status, body).

        HTTP 429 raises BackendThrottled here, so every request kind reports it alike.
        """
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
            try:
                conn.request(method, self._path, body=body, headers=headers)
                encode_failed = False
            except ValueError:  # header value rejected/unencodable; its message quotes the header
                encode_failed = True
            if encode_failed:
                # raised outside the handler so no __context__ links back to the ValueError
                raise BackendProtocolError(
                    f"backend {endpoint.id}: the HTTP request could not be encoded "
                    "(invalid characters in the bearer token or endpoint)",
                    stage="backend_call", details=self._details(),
                )
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
                    if resp.length:
                        # http.client returns b"" (no IncompleteRead) when the peer closes
                        # before Content-Length bytes arrived: the connection was lost.
                        raise http.client.IncompleteRead(b"".join(chunks), resp.length)
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > self._max_bytes:
                    raise self._oversized(total)
            data = b"".join(chunks)
            if status == THROTTLED_STATUS:
                raise self._throttled(_retry_after_s(resp.getheader("Retry-After"), data))
            return status, data
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

    def _throttled(self, retry_after_s: int | None) -> BackendThrottled:
        wait = f"retry after {retry_after_s} s" if retry_after_s is not None else "retry later"
        return BackendThrottled(
            f"backend {self._endpoint.id} has locked this host out after repeated authentication "
            f"failures (HTTP 429); {wait}",
            stage="backend_call", retry_after_s=retry_after_s,
            hint=f"the plugin is running; do not restart it. Wait ({wait}), then retry; if it keeps "
                 "happening the gateway's token is wrong (x64dbg-vm-gateway doctor)",
            details=self._details(status=THROTTLED_STATUS),
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
        if len(body) > self._max_request_bytes:
            raise BackendProtocolError(
                f"request for {method} is too large ({len(body)} bytes; the plugin accepts at most "
                f"{self._max_request_bytes}); it was not sent",
                stage="backend_call", hint="split the data into smaller chunks",
                details=self._details(method=method, size=len(body),
                                      max_request_bytes=self._max_request_bytes),
            )
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
        if msg.get("id") is None and isinstance(msg.get("error"), dict):
            # e.g. -32700 for a body the plugin could not parse: report the error itself
            raise self._rpc_error(method, msg["error"])
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
        self._saw_version(info.get("version"))
        return info

    def health_l1(self, timeout_s: float = 2.0) -> bool:
        """True iff ``GET /`` answers 200 with a ``name`` field.

        Returns False when unreachable, slow or malformed. Raises
        BackendAuthError on 401 (the server is alive but the token is wrong) and
        BackendThrottled on 429 (alive, but this host is locked out): neither may
        be mistaken for a dead backend.
        """
        try:
            info = self.server_info(timeout_s)
        except (BackendAuthError, BackendThrottled):
            raise
        except (BackendError, CancelledByVmOp):
            return False
        return isinstance(info.get("name"), str)

    def health_l2(self, timeout_s: float = 5.0) -> bool:
        """True iff ``tools/call GetDebugState`` returns any result within ``timeout_s``.

        Raises BackendAuthError on 401 and BackendThrottled on 429; every other
        failure returns False.
        """
        try:
            self.call_tool("GetDebugState", {}, timeout_s)
        except (BackendAuthError, BackendThrottled):
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
        server = result.get("serverInfo")
        if isinstance(server, dict):
            self._saw_version(server.get("version"))
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
            schema = t.get("inputSchema")
            if not isinstance(schema, dict):
                # keep the ToolInfo contract (dict); ToolCatalog applies the stricter checks
                log.warning("backend %s: tool %s has a non-object inputSchema; using {'type': 'object'}",
                            self._endpoint.id, _clip(t["name"]))
                schema = {"type": "object"}
            out.append(ToolInfo(name=t["name"], description=desc if isinstance(desc, str) else "",
                                input_schema=schema, read_only=read_only))
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
