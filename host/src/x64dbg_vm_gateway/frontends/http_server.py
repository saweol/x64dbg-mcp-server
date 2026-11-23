"""Remote MCP access over streamable HTTP (plan 6.1, milestone M3).

Request pipeline (pure ASGI, outermost first):

1. Client allowlist: the peer address must fall inside ``http.allow_clients``
   (CIDRs); an empty list means loopback only. ``X-Forwarded-For`` is never
   trusted (uvicorn runs with ``proxy_headers=False``). -> 403
2. Per-client token bucket (``rate_per_s`` refill, ``burst`` capacity), keyed
   by the peer address (IPv6: its /64, which one client usually controls). It
   runs before authentication so token guessing is throttled too; the price is
   that a process sending bad requests from the same address (or /64) also
   throttles a legitimate client there. -> 429
3. ``Authorization: Bearer <token>`` -> scope. Tokens come from the environment
   variables named in ``http.token_envs`` ({scope: ENV_NAME}); only SHA-256
   digests are kept and compared with ``hmac.compare_digest`` over every scope
   (no early exit). -> 401
4. The request goes to the scope's own ``StreamableHTTPSessionManager`` whose
   server was built with ``mcp_server.build_server(app, scope=...)``. A session
   therefore lives in exactly one scope: reusing its id with another token
   answers 404.

Start-up refusals (``ConfigError``): a non-loopback bind without
``tls_cert``/``tls_key``; no usable token (scopes whose variable is unset are
disabled); tokens shorter than ``MIN_TOKEN_CHARS``, not printable ASCII, or
shared between scopes. Unlike the config loader, a token is required even on a
loopback bind: any local process (or a browser via DNS rebinding) could
otherwise drive the VM.

Audit log: one JSON line per ``tools/call`` and per denied request in
``<jobs_root>/_audit/http-YYYYMMDD.jsonl`` (UTC date; dir 0700, file 0600):
``time, event, client, scope, tool, outcome``. Arguments, results and tokens
are never written. Repeated denials of one client (IPv6: one /64) are collapsed
to one line per minute with a ``suppressed`` count so a flood cannot fill the
disk. The caller must name the audit location (``jobs_root`` / ``audit_dir``):
there is no fallback that could silently write somewhere else.

State: everything lives in the objects built by ``build_asgi_app``; the ASGI
app can be started (lifespan) more than once because the session managers are
created per start.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import ipaddress
import json
import logging
import math
import os
import threading
import time
from collections.abc import AsyncIterator, Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import uvicorn
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

from ..app_api import GatewayApp
from ..config import HttpServerConfig, _is_loopback_host, resolve_secret
from ..contracts import Secret
from ..errors import ConfigError
from ..platform import secure_dir, secure_file
from ..proxy import sanitize_untrusted_text
from .mcp_server import SCOPES, ToolCallRecord, build_server

log = logging.getLogger(__name__)

__all__ = [
    "DEFAULT_BURST",
    "DEFAULT_RATE_PER_S",
    "LIMIT_CONCURRENCY",
    "MAX_SESSIONS_PER_SCOPE",
    "MCP_PATH",
    "MIN_TOKEN_CHARS",
    "AuditLog",
    "build_asgi_app",
    "check_http_config",
    "resolve_tokens",
    "serve_http",
]

MCP_PATH = "/mcp"
MIN_TOKEN_CHARS = 16
DEFAULT_RATE_PER_S = 10.0
DEFAULT_BURST = 40
MAX_SESSIONS_PER_SCOPE = 64
# uvicorn answers 503 (before the app, so unaudited) beyond this many connections or
# tasks. A session may hold a GET event stream and a POST connection at once.
LIMIT_CONCURRENCY = 2 * MAX_SESSIONS_PER_SCOPE * len(SCOPES) + 16
SCOPE_KEY = "x64dbg_vm_gateway.scope"  # ASGI scope entry set by the guard for the router

_DENIAL_LOG_INTERVAL_S = 60.0
_MAX_TRACKED_CLIENTS = 10_000
_MAX_AUDIT_FIELD = 128
_ACCESS_HINT = ("set http.token_envs.<read|analyze|admin> to environment variable NAMES and export each "
               "variable with a random token, e.g. "
               "`python -c \"import secrets; print(secrets.token_urlsafe(32))\"`")

IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


# ── configuration checks ────────────────────────────────────────────
def resolve_tokens(http_cfg: HttpServerConfig,
                   environ: Mapping[str, str] | None = None) -> dict[str, Secret]:
    """Read the bearer token of every configured scope from the environment.

    Scopes whose variable is unset are skipped (logged). Raises ConfigError when
    no token is left, a token is too short or unusable in a header, or two
    scopes share one token. Messages name variables, never values.
    """
    env = dict(os.environ if environ is None else environ)
    tokens: dict[str, Secret] = {}
    for scope, env_name in http_cfg.token_envs.items():
        key = f"http.token_envs.{scope}"
        if scope not in SCOPES:
            raise ConfigError(f"config key {key}: unknown scope (expected one of {', '.join(SCOPES)})",
                              stage="http", details={"key": key})
        secret = resolve_secret(env_name, env)
        if secret is None:
            log.warning("HTTP scope %r is disabled: environment variable %s is not set", scope, env_name)
            continue
        value = secret.reveal()
        if len(value) < MIN_TOKEN_CHARS:
            raise ConfigError(f"the token in {env_name} (scope {scope}) is shorter than {MIN_TOKEN_CHARS} "
                              "characters", stage="http", hint=_ACCESS_HINT, details={"key": key})
        if not (value.isascii() and value.isprintable()) or any(c.isspace() for c in value):
            raise ConfigError(f"the token in {env_name} (scope {scope}) must be printable ASCII without "
                              "spaces", stage="http", hint=_ACCESS_HINT, details={"key": key})
        tokens[scope] = secret
    if not tokens:
        raise ConfigError("no HTTP access token is available, refusing to serve without authentication",
                          stage="http", hint=_ACCESS_HINT, details={"key": "http.token_envs"})
    values = [t.reveal() for t in tokens.values()]
    if len(set(values)) != len(values):
        raise ConfigError("two HTTP scopes use the same token; every scope needs its own token",
                          stage="http", hint=_ACCESS_HINT, details={"key": "http.token_envs"})
    return tokens


def check_http_config(http_cfg: HttpServerConfig,
                      environ: Mapping[str, str] | None = None) -> dict[str, Secret]:
    """Start-up gate: TLS for non-loopback binds, then ``resolve_tokens``."""
    if not _is_loopback_host(http_cfg.bind) and not (http_cfg.tls_cert and http_cfg.tls_key):
        raise ConfigError(
            f"http.bind = {http_cfg.bind!r} is reachable from other machines but no TLS certificate is "
            "configured; refusing to send tokens in clear text",
            stage="http",
            hint="set http.tls_cert and http.tls_key, or bind to 127.0.0.1 and use an SSH tunnel",
            details={"key": "http.tls_cert"},
        )
    return resolve_tokens(http_cfg, environ)


# ── client addresses ────────────────────────────────────────────────
def parse_client_ip(host: Any) -> IpAddress | None:
    """The peer address as an IP (IPv4-mapped IPv6 folded to IPv4), or None if it is not an IP."""
    if not isinstance(host, str):
        return None
    try:
        ip = ipaddress.ip_address(host.strip())
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def client_key(ip: IpAddress) -> str:
    """Rate-limit / denial-collapsing key: the IPv4 address, or the IPv6 /64 it lies in."""
    if isinstance(ip, ipaddress.IPv6Address):
        return str(ipaddress.IPv6Network((int(ip) >> 64 << 64, 64)))
    return str(ip)


def _client_label(host: Any) -> str | None:
    ip = parse_client_ip(host)
    if ip is not None:
        return str(ip)
    return _clean_field(host) if isinstance(host, str) else None


class _ClientFilter:
    def __init__(self, cidrs: tuple[str, ...]) -> None:
        try:
            self.networks = [ipaddress.ip_network(c, strict=False) for c in cidrs]
        except ValueError as e:
            raise ConfigError(f"http.allow_clients contains an invalid CIDR: {e}", stage="http",
                              details={"key": "http.allow_clients"}) from None

    def allows(self, ip: IpAddress | None) -> bool:
        if ip is None:
            return False
        if not self.networks:
            return ip.is_loopback
        return any(ip.version == n.version and ip in n for n in self.networks)


class _RateLimiter:
    """Token bucket per client key. Called from the event loop only, guarded anyway."""

    def __init__(self, rate_per_s: float, burst: int, clock: Callable[[], float]) -> None:
        if not (math.isfinite(rate_per_s) and rate_per_s > 0) or burst < 1:
            raise ValueError("rate_per_s must be > 0 and burst >= 1")
        self.rate = float(rate_per_s)
        self.burst = float(burst)
        self.clock = clock
        self._buckets: dict[str, list[float]] = {}  # key -> [tokens, last refill time]
        self._lock = threading.Lock()

    def take(self, key: str) -> float:
        """0.0 if a request may proceed, else the seconds until the next token."""
        with self._lock:
            now = self.clock()
            bucket = self._buckets.get(key)
            if bucket is None:
                if len(self._buckets) >= _MAX_TRACKED_CLIENTS:
                    self._prune(now)
                bucket = self._buckets[key] = [self.burst, now]
            tokens = min(self.burst, bucket[0] + max(0.0, now - bucket[1]) * self.rate)
            bucket[1] = now
            if tokens >= 1.0:
                bucket[0] = tokens - 1.0
                return 0.0
            bucket[0] = tokens
            return (1.0 - tokens) / self.rate

    def _prune(self, now: float) -> None:
        full_after = self.burst / self.rate
        for key in [k for k, (_, last) in self._buckets.items() if now - last >= full_after]:
            del self._buckets[key]  # refilled completely: forgetting it changes nothing
        if len(self._buckets) >= _MAX_TRACKED_CLIENTS:
            self._buckets.clear()


class _DenialThrottle:
    """Collapse repeated denials of one client/outcome into one audit line per interval."""

    def __init__(self, clock: Callable[[], float], interval_s: float = _DENIAL_LOG_INTERVAL_S) -> None:
        self.clock = clock
        self.interval_s = interval_s
        self._seen: dict[tuple[str, str], list[float]] = {}  # -> [last logged time, suppressed count]
        self._lock = threading.Lock()

    def admit(self, client: str, outcome: str) -> int | None:
        """Number of suppressed denials since the last logged one, or None to suppress this one."""
        with self._lock:
            now = self.clock()
            key = (client, outcome)
            entry = self._seen.get(key)
            if entry is not None and now - entry[0] < self.interval_s:
                entry[1] += 1
                return None
            suppressed = int(entry[1]) if entry is not None else 0
            if entry is None and len(self._seen) >= _MAX_TRACKED_CLIENTS:
                self._seen.clear()
            self._seen[key] = [now, 0]
            return suppressed


# ── audit log ───────────────────────────────────────────────────────
def _clean_field(value: Any) -> str | None:
    if value is None:
        return None
    text = sanitize_untrusted_text(str(value), max_len=10 * _MAX_AUDIT_FIELD)
    text = text.replace("\n", " ").replace("\t", " ")
    return text[:_MAX_AUDIT_FIELD]


class AuditLog:
    """Append-only JSONL audit file per UTC day. ``write`` never raises."""

    def __init__(self, directory: Path | str, *, now: Callable[[], datetime] | None = None) -> None:
        self.directory = Path(directory).expanduser()
        self._now = now or (lambda: datetime.now(UTC))
        self._lock = threading.Lock()

    def write(self, event: Mapping[str, Any]) -> None:
        when = self._now()
        if when.tzinfo is None:
            when = when.replace(tzinfo=UTC)
        when = when.astimezone(UTC)
        record: dict[str, Any] = {
            "time": when.isoformat(timespec="seconds"),
            "event": _clean_field(event.get("event")),
            "client": _clean_field(event.get("client")),
            "scope": _clean_field(event.get("scope")),
            "tool": _clean_field(event.get("tool")),
            "outcome": _clean_field(event.get("outcome")),
        }
        suppressed = event.get("suppressed")
        if isinstance(suppressed, int) and suppressed > 0:
            record["suppressed"] = suppressed
        line = (json.dumps(record, ensure_ascii=False) + "\n").encode("utf-8")
        path = self.directory / f"http-{when:%Y%m%d}.jsonl"
        with self._lock:
            try:
                self._append(path, line)
            except OSError as e:
                log.warning("cannot write the HTTP audit log %s: %s", path, e.strerror or type(e).__name__)

    def _append(self, path: Path, line: bytes) -> None:
        if not self.directory.is_dir():
            self.directory.mkdir(parents=True, exist_ok=True)
            secure_dir(self.directory)
        created = not path.exists()
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags, 0o600)
        try:
            os.write(fd, line)
        finally:
            os.close(fd)
        if created:
            secure_file(path)


# ── ASGI pieces ─────────────────────────────────────────────────────
async def _deny(scope: Scope, receive: Receive, send: Send, status: int, code: str, message: str,
                headers: Mapping[str, str] | None = None) -> None:
    body = {"error": {"code": code, "message": message}}
    await JSONResponse(body, status_code=status, headers=dict(headers or {}))(scope, receive, send)


class _Guard:
    """Allowlist -> rate limit -> bearer authentication; sets ``scope[SCOPE_KEY]``."""

    def __init__(self, app: ASGIApp, *, client_filter: _ClientFilter, limiter: _RateLimiter,
                 token_digests: Mapping[str, bytes], audit: AuditLog, throttle: _DenialThrottle) -> None:
        self.app = app
        self.client_filter = client_filter
        self.limiter = limiter
        self.token_digests = dict(token_digests)
        self.audit = audit
        self.throttle = throttle

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        if scope["type"] != "http":  # lifespan
            await self.app(scope, receive, send)
            return
        host = (scope.get("client") or (None, None))[0]
        ip = parse_client_ip(host)
        label = _client_label(host) or "unknown"
        key = client_key(ip) if ip is not None else label
        if not self.client_filter.allows(ip):
            self._audit_denial(key, label, "FORBIDDEN")
            await _deny(scope, receive, send, 403, "FORBIDDEN", "client address is not allowed")
            return
        wait_s = self.limiter.take(key)
        if wait_s > 0:
            self._audit_denial(key, label, "RATE_LIMITED")
            await _deny(scope, receive, send, 429, "RATE_LIMITED", "too many requests",
                        {"Retry-After": str(max(1, math.ceil(wait_s)))})
            return
        granted = self._authenticate(scope)
        if granted is None:
            self._audit_denial(key, label, "UNAUTHORIZED")
            await _deny(scope, receive, send, 401, "UNAUTHORIZED", "missing or invalid bearer token",
                        {"WWW-Authenticate": 'Bearer realm="x64dbg-vm-gateway"'})
            return
        scope[SCOPE_KEY] = granted
        await self.app(scope, receive, send)

    def _authenticate(self, scope: Scope) -> str | None:
        values = [v for k, v in scope.get("headers", []) if k.lower() == b"authorization"]
        if len(values) != 1:
            return None
        try:
            text = values[0].decode("ascii")
        except UnicodeDecodeError:
            return None
        scheme, _, token = text.strip().partition(" ")
        token = token.strip()
        if scheme.lower() != "bearer" or not token:
            return None
        presented = hashlib.sha256(token.encode("ascii")).digest()
        granted: str | None = None
        for scope_name, digest in self.token_digests.items():  # no early exit
            if hmac.compare_digest(presented, digest):
                granted = scope_name
        return granted

    def _audit_denial(self, key: str, client: str, outcome: str) -> None:
        suppressed = self.throttle.admit(key, outcome)
        if suppressed is None:
            return
        self.audit.write({"event": "http_denied", "client": client, "scope": None, "tool": None,
                          "outcome": outcome, "suppressed": suppressed})


class _ScopeRouter:
    """Routes an authenticated request to its scope's session manager (one per scope)."""

    def __init__(self, servers: Mapping[str, Server[Any]], *, security: TransportSecuritySettings | None,
                 json_response: bool) -> None:
        self.servers = dict(servers)
        self.security = security
        self.json_response = json_response
        self.managers: dict[str, StreamableHTTPSessionManager] = {}

    @contextlib.asynccontextmanager
    async def lifespan(self, _app: Any) -> AsyncIterator[None]:
        # A manager can run only once, so each start of the ASGI app gets fresh ones.
        managers = {
            scope: StreamableHTTPSessionManager(app=server, json_response=self.json_response,
                                                security_settings=self.security,
                                                max_sessions=MAX_SESSIONS_PER_SCOPE)
            for scope, server in self.servers.items()
        }
        async with contextlib.AsyncExitStack() as stack:
            for manager in managers.values():
                await stack.enter_async_context(manager.run())
            self.managers = managers
            try:
                yield
            finally:
                self.managers = {}

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        granted = scope.get(SCOPE_KEY)
        if granted is None:
            await _deny(scope, receive, send, 401, "UNAUTHORIZED", "missing or invalid bearer token")
            return
        manager = self.managers.get(granted)
        if manager is None:
            await _deny(scope, receive, send, 503, "UNAVAILABLE", "the MCP endpoint is not running")
            return
        await manager.handle_request(scope, receive, send)


def _security_settings(bind: str) -> TransportSecuritySettings | None:
    if not _is_loopback_host(bind):
        # Remote mode: TLS + bearer tokens + allowlist; clients reach us under any host name.
        return None
    hosts = ["127.0.0.1", "localhost", "[::1]"]
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[*hosts, *(f"{h}:*" for h in hosts)],
        allowed_origins=[f"{scheme}://{h}:*" for scheme in ("http", "https") for h in hosts],
    )


def build_asgi_app(
    app: GatewayApp,
    http_cfg: HttpServerConfig,
    *,
    audit_dir: Path | str,
    environ: Mapping[str, str] | None = None,
    rate_per_s: float = DEFAULT_RATE_PER_S,
    burst: int = DEFAULT_BURST,
    clock: Callable[[], float] | None = None,
    now: Callable[[], datetime] | None = None,
    json_response: bool = False,
) -> Starlette:
    """Build the guarded ASGI app (no socket is opened). Raises ConfigError on unsafe settings.

    ``audit_dir`` receives the audit files (``serve_http`` uses ``<jobs_root>/_audit``).
    """
    tokens = check_http_config(http_cfg, environ)
    monotonic = clock or time.monotonic
    audit = AuditLog(audit_dir, now=now)

    def audit_tool_call(record: ToolCallRecord) -> None:
        audit.write({"event": "tool_call", "client": _client_label(record.client), "scope": record.scope,
                     "tool": record.tool, "outcome": record.outcome})

    servers = {scope: build_server(app, scope=scope, audit=audit_tool_call) for scope in tokens}
    router = _ScopeRouter(servers, security=_security_settings(http_cfg.bind), json_response=json_response)
    digests = {scope: hashlib.sha256(secret.reveal().encode("ascii")).digest()
               for scope, secret in tokens.items()}
    guard_kwargs: dict[str, Any] = {
        "client_filter": _ClientFilter(tuple(http_cfg.allow_clients)),
        "limiter": _RateLimiter(rate_per_s, burst, monotonic),
        "token_digests": digests,
        "audit": audit,
        "throttle": _DenialThrottle(monotonic),
    }
    return Starlette(
        routes=[Route(MCP_PATH, endpoint=router)],
        middleware=[Middleware(_Guard, **guard_kwargs)],
        lifespan=router.lifespan,
    )


def serve_http(app: GatewayApp, http_cfg: HttpServerConfig, *, jobs_root: Path | str,
               environ: Mapping[str, str] | None = None) -> None:
    """Serve ``app`` over streamable HTTP until interrupted (blocking).

    ``jobs_root`` is the configured jobs root (``GatewayConfig.jobs_root_path``);
    the audit log goes to ``<jobs_root>/_audit``.
    """
    asgi = build_asgi_app(app, http_cfg, environ=environ, audit_dir=Path(jobs_root).expanduser() / "_audit")
    for key, value in (("http.tls_cert", http_cfg.tls_cert), ("http.tls_key", http_cfg.tls_key)):
        if value is not None and not Path(value).expanduser().is_file():
            raise ConfigError(f"config key {key}: file not found: {value}", stage="http",
                              details={"key": key})
    tls = bool(http_cfg.tls_cert and http_cfg.tls_key)
    scheme = "https" if tls else "http"
    log.info("serving MCP on %s://%s:%d%s", scheme, http_cfg.bind, http_cfg.port, MCP_PATH)
    config = uvicorn.Config(
        asgi,
        host=http_cfg.bind,
        port=http_cfg.port,
        ssl_certfile=str(Path(http_cfg.tls_cert).expanduser()) if tls and http_cfg.tls_cert else None,
        ssl_keyfile=str(Path(http_cfg.tls_key).expanduser()) if tls and http_cfg.tls_key else None,
        proxy_headers=False,  # never trust X-Forwarded-For: the allowlist uses the TCP peer
        server_header=False,
        lifespan="on",
        timeout_keep_alive=5,
        timeout_graceful_shutdown=10,
        limit_concurrency=LIMIT_CONCURRENCY,
        log_level="info",
    )
    uvicorn.Server(config).run()
