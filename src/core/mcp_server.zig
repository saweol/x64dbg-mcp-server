// MCP server — Streamable HTTP and (optional) SSE transports.
//
// Threading model
//   - start()/stop() are called from the x64dbg GUI thread, the config
//     dialog thread or a plugin command; `lifecycle_lock` serialises them.
//   - One accept thread (serverLoop) admits connections. The peer address is
//     checked against the allowlist and the MaxClients cap is enforced
//     BEFORE a per-connection thread is created (netpolicy.admit).
//   - Each connection thread reads one request (5 s header / 10 s total
//     budget, see netpolicy.recvTimeoutMs), routes it (http.route: auth
//     lockout -> 429, bad token -> 401, then method and path), dispatches it
//     and closes the socket. SSE connections keep their thread and only
//     write frames that were queued in `sse_hub`. Loopback peers are never
//     locked out (see netpolicy.AuthLimiter).
//   - notifyEvent() runs on the x64dbg callback thread. It only touches the
//     locked pending-event ring and enqueues SSE frames; it never writes to a
//     socket, so a stalled SSE client cannot block the debugger.
//   - State-changing tool handlers are serialised by `tool_lock`
//     (see mcp/toolpolicy.zig for the exemptions). Long waits inside a
//     locked handler poll requestAbandoned() so a client that disconnected
//     does not keep the lock for the rest of the wait.
//   - `settings` is written by applyConfig() under `settings_lock` and read
//     by connection threads under the shared lock.

const std = @import("std");
const bridge = @import("bridge.zig");
const tools_mod = @import("../mcp/tools.zig");
const json_mod = @import("../mcp/json.zig");
const toolpolicy = @import("../mcp/toolpolicy.zig");
const cfgjson = @import("cfgjson.zig");
const netpolicy = @import("netpolicy.zig");
const http = @import("http.zig");
const ring = @import("ring.zig");
const ssehub = @import("ssehub.zig");
const sync = @import("sync.zig");
const JsonWriter = json_mod.JsonWriter;

const ws2 = std.os.windows.ws2_32;
const SOCKET = ws2.SOCKET;
const INVALID_SOCKET = ws2.INVALID_SOCKET;

const PROTOCOL_VERSION = "2024-11-05";
const SERVER_NAME = "x64dbg-MCP Server";
pub const SERVER_VERSION = "1.10";

const LOG_PREFIX = "[x64dbg-MCP Server] ";

// SO_EXCLUSIVEADDRUSE is defined as ((int)(~SO_REUSEADDR)).
const SO_EXCLUSIVEADDRUSE: i32 = ~@as(i32, ws2.SO.REUSEADDR);
const SD_BOTH: i32 = 2;
const SEND_TIMEOUT_MS: u32 = 10_000;
const SSE_SEND_TIMEOUT_MS: u32 = 5_000;
const SSE_KEEPALIVE_MS: u64 = 5_000;
const SSE_POLL_MS: u32 = 50;
const RECV_BUF_SIZE = 65536;
const LISTEN_BACKLOG = 64;
const BIND_RETRY_INTERVAL_MS: u32 = 1_000;
const BIND_RETRY_LOG_MS: u64 = 60_000;
const GRACEFUL_CLOSE_MS: u32 = 1_000;
const AUTH_FAILURE_WINDOW_MS: u64 = 60_000;
const DENIED_LOG_INTERVAL_MS: u64 = 5_000;
const CLIENT_DRAIN_MS: u64 = 2_000;
// Request a 2 MiB stack *reservation* for connection threads (the request
// path keeps several 64-128 KiB buffers on the stack).
const CLIENT_STACK_RESERVE: usize = 2 * 1024 * 1024;
const STACK_SIZE_PARAM_IS_A_RESERVATION: u32 = 0x00010000;

// Win32 threading
const HANDLE = ?*anyopaque;
extern "kernel32" fn Sleep(ms: u32) callconv(.winapi) void;
extern "kernel32" fn CreateThread(
    lpThreadAttributes: ?*anyopaque,
    dwStackSize: usize,
    lpStartAddress: *const fn (?*anyopaque) callconv(.winapi) u32,
    lpParameter: ?*anyopaque,
    dwCreationFlags: u32,
    lpThreadId: ?*u32,
) callconv(.winapi) HANDLE;
extern "kernel32" fn CloseHandle(hObject: HANDLE) callconv(.winapi) i32;
extern "kernel32" fn WaitForSingleObject(hHandle: ?*anyopaque, dwMilliseconds: u32) callconv(.winapi) u32;
extern "kernel32" fn GetTickCount64() callconv(.winapi) u64;

// ── Runtime state ──────────────────────────────────────────────────

/// True while the server should be serving (set by start(), cleared by
/// stop() or by serverLoop on a fatal error).
var running = std.atomic.Value(bool).init(false);
/// Mirrors settings.enable_sse for the callback thread (lock-free read).
var sse_enabled = std.atomic.Value(bool).init(true);
/// Listening socket as an integer so start/stop/serverLoop can swap it
/// atomically; whoever swaps it to NO_SOCKET owns closing it.
const NO_SOCKET: usize = ~@as(usize, 0); // == @intFromPtr(INVALID_SOCKET)
var listen_sock = std.atomic.Value(usize).init(NO_SOCKET);
/// Accept thread handle; only touched under `lifecycle_lock`.
var server_handle: HANDLE = null;
var lifecycle_lock: sync.RwLock = .{};

/// Serialises mutating tool handlers.
var tool_lock: sync.RwLock = .{};

var client_slots: netpolicy.ClientSlots = .{};
var sse_hub = ssehub.Hub.init(std.heap.page_allocator, .{});

var auth_lock: sync.RwLock = .{};
var auth_limiter = netpolicy.AuthLimiter.init(cfgjson.DEFAULT_AUTH_MAX_FAILURES, AUTH_FAILURE_WINDOW_MS, @as(u64, cfgjson.DEFAULT_AUTH_LOCKOUT_SECONDS) * 1000);

/// Low 32 bits of GetTickCount64() at the last "rejected" log line (0 =
/// never). 32-bit so the atomic also works on the x32 build; intervals are
/// compared with wrapping arithmetic.
var last_denied_log = std.atomic.Value(u32).init(0);

const Settings = struct {
    port: u16 = 9094,
    ip_buf: [cfgjson.MAX_IP_LEN + 1]u8 = undefined,
    ip_len: usize = 0,
    token_buf: [netpolicy.MAX_TOKEN_LEN]u8 = undefined,
    token_len: usize = 0,
    max_clients: u32 = cfgjson.DEFAULT_MAX_CLIENTS,
    enable_sse: bool = true,
    /// Result of netpolicy.planStartup for the applied config.
    plan: ?netpolicy.StartupPlan = null,
    plan_error: ?netpolicy.StartupError = error.MissingToken,
    diag: netpolicy.StartupDiag = .{},
    /// The config file could not be parsed; never start.
    config_invalid: bool = false,

    fn ip(self: *const Settings) []const u8 {
        return self.ip_buf[0..self.ip_len];
    }
    fn token(self: *const Settings) []const u8 {
        return self.token_buf[0..self.token_len];
    }
};
var settings: Settings = .{};
var settings_lock: sync.RwLock = .{};

pub fn isRunning() bool {
    return running.load(.acquire);
}

/// Applies a parsed configuration. Takes effect on the next start().
pub fn applyConfig(cfg: *const cfgjson.Config) void {
    {
        settings_lock.lock();
        defer settings_lock.unlock();
        const s = &settings;
        s.port = cfg.port;
        s.ip_len = @min(cfg.ip_address.len, s.ip_buf.len);
        @memcpy(s.ip_buf[0..s.ip_len], cfg.ip_address[0..s.ip_len]);
        s.token_len = @min(cfg.auth_token.len, s.token_buf.len);
        @memcpy(s.token_buf[0..s.token_len], cfg.auth_token[0..s.token_len]);
        s.max_clients = cfg.max_clients;
        s.enable_sse = cfg.enable_sse;
        s.config_invalid = false;
        s.diag = .{};
        if (netpolicy.planStartup(.{
            .ip_address = cfg.ip_address,
            .allow_external = cfg.allow_external,
            .allowed_clients = cfg.allowed_clients,
            .token = cfg.auth_token,
        }, &s.diag)) |plan| {
            s.plan = plan;
            s.plan_error = null;
        } else |err| {
            s.plan = null;
            s.plan_error = err;
        }
    }
    auth_lock.lock();
    defer auth_lock.unlock();
    auth_limiter = netpolicy.AuthLimiter.init(cfg.auth_max_failures, AUTH_FAILURE_WINDOW_MS, @as(u64, cfg.auth_lockout_seconds) * 1000);
}

/// Marks the configuration as unusable (mcp_config.json failed to parse).
pub fn markConfigInvalid() void {
    settings_lock.lock();
    defer settings_lock.unlock();
    settings.config_invalid = true;
}

// ── Logging ────────────────────────────────────────────────────────

fn logMsg(comptime fmt: []const u8, args: anytype) void {
    var buf: [600]u8 = undefined;
    const s = std.fmt.bufPrintZ(&buf, LOG_PREFIX ++ fmt, args) catch {
        bridge.logPuts(LOG_PREFIX ++ "(log message truncated)");
        return;
    };
    bridge.logPuts(s.ptr);
}

fn fmtIp(ip: netpolicy.Ipv4, buf: *[16]u8) []const u8 {
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] }) catch buf[0..0];
}

fn logDenied(ip: netpolicy.Ipv4, reason: []const u8) void {
    // Rate-limited so a scan cannot flood the x64dbg log.
    const now: u32 = @truncate(GetTickCount64());
    const last = last_denied_log.load(.monotonic);
    if (last != 0 and now -% last < DENIED_LOG_INTERVAL_MS) return;
    if (last_denied_log.cmpxchgStrong(last, if (now == 0) 1 else now, .monotonic, .monotonic) != null) return;
    var ip_buf: [16]u8 = undefined;
    logMsg("Rejected connection from {s}: {s}.", .{ fmtIp(ip, &ip_buf), reason });
}

fn logStartupError(err: netpolicy.StartupError, s: *const Settings) void {
    switch (err) {
        error.InvalidIpAddress => logMsg("Refusing to start: IpAddress \"{s}\" is not a valid IPv4 address.", .{s.ip()}),
        error.ExternalBindNotAllowed => logMsg("Refusing to start: binding {s} exposes the server beyond this machine. Set \"AllowExternal\": true and \"AllowedClients\" in mcp_config.json, or use 127.0.0.1.", .{s.ip()}),
        error.AllowedClientsRequired => logMsg("Refusing to start: a non-loopback bind requires a non-empty \"AllowedClients\" list in mcp_config.json.", .{}),
        error.InvalidAllowedClient => logMsg("Refusing to start: AllowedClients entry #{d} is not a valid IPv4 address or CIDR range.", .{s.diag.bad_client_index}),
        error.TooManyAllowedClients => logMsg("Refusing to start: AllowedClients has more than {d} entries.", .{netpolicy.MAX_ALLOWED_CLIENTS}),
        error.MissingToken => logMsg("Refusing to start: AuthToken is empty.", .{}),
        error.TokenTooLong => logMsg("Refusing to start: AuthToken is longer than {d} characters.", .{netpolicy.MAX_TOKEN_LEN}),
        error.TokenTooShort => logMsg("Refusing to start: \"AllowExternal\": true requires an AuthToken of at least {d} characters.", .{netpolicy.MIN_EXTERNAL_TOKEN_LEN}),
    }
}

// ── Pending events queue (for HTTP clients that can't receive SSE) ──
const MAX_PENDING_EVENTS = 16;
const MAX_EVENT_LEN = 128;
var pending: ring.LockedRing(MAX_PENDING_EVENTS, MAX_EVENT_LEN) = .{};

pub fn pendingHasEvents() bool {
    return pending.len() > 0;
}

pub fn pendingDrainToBuffer(out: []u8) usize {
    return pending.drainJoined(out, '\n');
}

fn pendingDrain(w: *JsonWriter) void {
    var tmp: [MAX_EVENT_LEN]u8 = undefined;
    while (pending.popOldest(&tmp)) |event_text| {
        w.raw(",");
        w.beginObject();
        w.fieldStr("type", "text");
        w.key("text");
        w.writeString(event_text);
        w.endObject();
    }
}

/// Called on the x64dbg callback thread. Never blocks on the network.
pub fn notifyEvent(level: []const u8, msg: []const u8) void {
    if (!running.load(.acquire)) return;

    // Queue for HTTP clients — plain text with level prefix
    var pend_buf: [MAX_EVENT_LEN]u8 = undefined;
    const pend_msg = std.fmt.bufPrint(&pend_buf, "[event:{s}] {s}", .{ level, msg }) catch msg;
    pending.push(pend_msg);

    if (!sse_enabled.load(.acquire)) return;
    // Build the notification through JsonWriter so quotes, backslashes and
    // control bytes in msg are escaped.
    var buf: [1024]u8 = undefined;
    var w = JsonWriter.init(&buf);
    w.beginObject();
    w.fieldStr("jsonrpc", "2.0");
    w.fieldStr("method", "notifications/message");
    w.key("params");
    w.beginObject();
    w.fieldStr("level", level);
    w.fieldStr("data", msg);
    w.endObject();
    w.endObject();
    if (w.overflow) return;
    _ = sse_hub.broadcast("message", w.slice());
}

// ── Lifecycle ──────────────────────────────────────────────────────

pub fn start() void {
    lifecycle_lock.lock();
    defer lifecycle_lock.unlock();

    if (running.load(.acquire)) {
        logMsg("Server already running.", .{});
        return;
    }
    // Reap a previous accept thread that exited on its own (e.g. bind error).
    if (server_handle) |h| {
        _ = WaitForSingleObject(h, 5000);
        _ = CloseHandle(h);
        server_handle = null;
    }

    var ip_buf: [cfgjson.MAX_IP_LEN + 1]u8 = undefined;
    var ip_len: usize = 0;
    var port: u16 = 0;
    {
        settings_lock.lockShared();
        defer settings_lock.unlockShared();
        if (settings.config_invalid) {
            logMsg("Refusing to start: mcp_config.json is invalid (see the earlier log line). Fix the file or save the configuration dialog.", .{});
            return;
        }
        if (settings.plan_error) |err| {
            logStartupError(err, &settings);
            return;
        }
        const plan = settings.plan.?;
        if (plan.warn_short_token)
            logMsg("WARNING: AuthToken is shorter than {d} characters. Generate a new one in the configuration dialog.", .{netpolicy.MIN_EXTERNAL_TOKEN_LEN});
        if (plan.warn_allow_all)
            logMsg("WARNING: AllowedClients contains 0.0.0.0/0 - any IPv4 address may connect.", .{});
        if (plan.warn_unusual_token)
            logMsg("WARNING: AuthToken contains spaces or non-ASCII characters; some MCP clients cannot send it. Generate a new one in the configuration dialog.", .{});
        sse_enabled.store(settings.enable_sse, .release);
        ip_len = settings.ip_len;
        @memcpy(ip_buf[0..ip_len], settings.ip_buf[0..ip_len]);
        port = settings.port;
    }

    running.store(true, .release);
    server_handle = CreateThread(null, 0, serverThreadProc, null, 0, null);
    if (server_handle == null) {
        running.store(false, .release);
        logMsg("Failed to create server thread.", .{});
        return;
    }
    logMsg("Starting MCP server on {s}:{d}...", .{ ip_buf[0..ip_len], port });
}

pub fn stop() void {
    lifecycle_lock.lock();
    defer lifecycle_lock.unlock();

    const was_running = running.swap(false, .acq_rel);
    if (!was_running and server_handle == null) return;

    // Wake SSE connection threads; they close their own sockets.
    sse_hub.killAll();

    // Close the listening socket to unblock accept().
    closeListenSocket();

    if (server_handle) |h| {
        _ = WaitForSingleObject(h, 5000);
        _ = CloseHandle(h);
        server_handle = null;
    }
    if (was_running) {
        settings_lock.lockShared();
        defer settings_lock.unlockShared();
        logMsg("MCP server stopped (was on {s}:{d})", .{ settings.ip(), settings.port });
    }
}

/// Closes the listening socket exactly once, whichever thread gets here first.
fn closeListenSocket() void {
    const ls = listen_sock.swap(NO_SOCKET, .acq_rel);
    if (ls != NO_SOCKET) _ = ws2.closesocket(@ptrFromInt(ls));
}

fn serverThreadProc(_: ?*anyopaque) callconv(.winapi) u32 {
    serverLoop();
    return 0;
}

fn setSockTimeout(sock: SOCKET, opt: i32, ms: u32) void {
    const v: u32 = ms;
    _ = ws2.setsockopt(sock, ws2.SOL.SOCKET, opt, std.mem.asBytes(&v), @sizeOf(u32));
}

fn serverLoop() void {
    var wsa_data: ws2.WSADATA = undefined;
    if (ws2.WSAStartup(0x0202, &wsa_data) != 0) {
        running.store(false, .release);
        logMsg("WSAStartup failed.", .{});
        return;
    }
    defer _ = ws2.WSACleanup();

    var bind_ip: netpolicy.Ipv4 = undefined;
    var port: u16 = undefined;
    {
        settings_lock.lockShared();
        defer settings_lock.unlockShared();
        const plan = settings.plan orelse {
            running.store(false, .release);
            return;
        };
        bind_ip = plan.bind;
        port = settings.port;
    }

    const sock = ws2.socket(ws2.AF.INET, ws2.SOCK.STREAM, 0);
    if (sock == INVALID_SOCKET) {
        running.store(false, .release);
        logMsg("socket() failed.", .{});
        return;
    }
    listen_sock.store(@intFromPtr(sock), .release);
    defer closeListenSocket();
    // stop() may have run before the socket was published.
    if (!running.load(.acquire)) return;

    // Exclusive use: no other process can bind the same port, not even
    // with SO_REUSEADDR (which the server used before v1.10).
    const one: i32 = 1;
    if (ws2.setsockopt(sock, ws2.SOL.SOCKET, SO_EXCLUSIVEADDRUSE, std.mem.asBytes(&one), @sizeOf(i32)) != 0)
        logMsg("WARNING: SO_EXCLUSIVEADDRUSE could not be set.", .{});

    var addr: ws2.sockaddr.in = .{
        .family = ws2.AF.INET,
        .port = std.mem.nativeToBig(u16, port),
        .addr = netpolicy.toNetworkU32(bind_ip),
    };

    // With SO_EXCLUSIVEADDRUSE the port stays busy while connections of a
    // previous server instance are still open (e.g. a long `run` call that
    // started before a configuration change) or, per the Winsock docs, in
    // TIME_WAIT. Retry while that can be the reason and give up otherwise
    // (another process owns the port), see netpolicy.BindRetry.
    var retry = netpolicy.BindRetry.init(GetTickCount64());
    var last_retry_log: u64 = 0;
    while (ws2.bind(sock, @ptrCast(&addr), @sizeOf(ws2.sockaddr.in)) != 0) {
        const err = ws2.WSAGetLastError();
        // stop() may have closed the socket under us: exit quietly.
        if (!running.load(.acquire)) return;
        if (err != .WSAEADDRINUSE) {
            running.store(false, .release);
            logMsg("bind() failed (WSA error {d}).", .{@intFromEnum(err)});
            return;
        }
        const now = GetTickCount64();
        if (!retry.shouldRetry(now, client_slots.count())) {
            running.store(false, .release);
            logMsg("Port {d} is still in use after {d} s (another process, e.g. a second x64dbg, owns it). Server stopped; start it again from the plugin menu (or with the StartMCPServer command) once the port is free.", .{ port, (now -| retry.start_ms) / 1000 });
            return;
        }
        if (last_retry_log == 0 or now -| last_retry_log >= BIND_RETRY_LOG_MS) {
            logMsg("Port {d} is in use (another process, or connections of the previous server instance are still open); retrying every {d} s.", .{ port, BIND_RETRY_INTERVAL_MS / 1000 });
            last_retry_log = now;
        }
        Sleep(BIND_RETRY_INTERVAL_MS);
    }

    if (ws2.listen(sock, LISTEN_BACKLOG) != 0) {
        running.store(false, .release);
        logMsg("listen() failed.", .{});
        return;
    }

    {
        var ip_buf: [16]u8 = undefined;
        logMsg("MCP (Streamable) listening on http://{s}:{d}/", .{ fmtIp(bind_ip, &ip_buf), port });
    }

    while (running.load(.acquire)) {
        var peer: ws2.sockaddr.in = undefined;
        var peer_len: i32 = @sizeOf(ws2.sockaddr.in);
        const client = ws2.accept(sock, @ptrCast(&peer), &peer_len);
        if (client == INVALID_SOCKET) {
            if (!running.load(.acquire)) break;
            Sleep(10); // avoid spinning on a persistent accept() error
            continue;
        }
        admit(client, &peer, peer_len);
    }

    // Give connection threads a moment to finish (each one holds its own
    // WSAStartup reference, so late ones still work after this returns).
    sse_hub.killAll();
    const drain_start = GetTickCount64();
    while (client_slots.count() > 0 and GetTickCount64() -| drain_start < CLIENT_DRAIN_MS) Sleep(20);
}

/// Closes with RST instead of FIN: for connections rejected before any
/// request was read there is nothing to deliver, and this leaves no
/// TIME_WAIT entry on the server port.
fn abortiveClose(sock: SOCKET) void {
    const lg = ws2.linger{ .onoff = 1, .linger = 0 };
    _ = ws2.setsockopt(sock, ws2.SOL.SOCKET, ws2.SO.LINGER, std.mem.asBytes(&lg), @sizeOf(ws2.linger));
    _ = ws2.closesocket(sock);
}

/// Lets the client close first (it does so after reading a
/// "Connection: close" response), so the server side does not pile up
/// TIME_WAIT entries that would keep an SO_EXCLUSIVEADDRUSE port busy after
/// a restart. Waits at most GRACEFUL_CLOSE_MS for the peer's FIN.
fn gracefulClose(sock: SOCKET) void {
    setSockTimeout(sock, ws2.SO.RCVTIMEO, GRACEFUL_CLOSE_MS);
    var scratch: [512]u8 = undefined;
    const t0 = GetTickCount64();
    while (GetTickCount64() -| t0 < GRACEFUL_CLOSE_MS) {
        const n = ws2.recv(sock, &scratch, scratch.len, 0);
        if (n <= 0) break;
    }
    _ = ws2.closesocket(sock);
}

/// Decides on a freshly accepted connection before any thread is spent on it
/// (netpolicy.admit: allowlist, then MaxClients). Locked-out peers are
/// admitted and answered with 429 by handleClient.
fn admit(client: SOCKET, peer: *const ws2.sockaddr.in, peer_len: i32) void {
    if (peer_len < @sizeOf(ws2.sockaddr.in) or peer.family != ws2.AF.INET) {
        abortiveClose(client);
        return;
    }
    const ip = netpolicy.fromNetworkU32(peer.addr);

    const decision: netpolicy.Admission = blk: {
        settings_lock.lockShared();
        defer settings_lock.unlockShared();
        const plan = if (settings.plan) |*p| p else break :blk .not_allowed;
        break :blk netpolicy.admit(&plan.allowlist, ip, &client_slots, settings.max_clients);
    };
    switch (decision) {
        .accept => {},
        .not_allowed => {
            logDenied(ip, "not in AllowedClients");
            abortiveClose(client);
            return;
        },
        .at_capacity => {
            logDenied(ip, "MaxClients reached");
            abortiveClose(client);
            return;
        },
    }
    const h = CreateThread(null, CLIENT_STACK_RESERVE, clientThreadProc, @ptrCast(client), STACK_SIZE_PARAM_IS_A_RESERVATION, null);
    if (h == null) {
        client_slots.release();
        abortiveClose(client);
    } else {
        _ = CloseHandle(h);
    }
}

fn clientThreadProc(param: ?*anyopaque) callconv(.winapi) u32 {
    const sock: SOCKET = @ptrCast(@alignCast(param));
    // Hold a Winsock reference for the lifetime of this connection so a
    // concurrent stop() cannot tear Winsock down underneath it.
    var wsa_data: ws2.WSADATA = undefined;
    const wsa_ok = ws2.WSAStartup(0x0202, &wsa_data) == 0;
    defer client_slots.release();
    defer releaseWinsock(wsa_ok);
    defer gracefulClose(sock);
    handleClient(sock);
    return 0;
}

fn releaseWinsock(started: bool) void {
    if (started) _ = ws2.WSACleanup();
}

// ── Auth lockout ───────────────────────────────────────────────────

fn isLockedOut(ip: netpolicy.Ipv4) bool {
    auth_lock.lock();
    defer auth_lock.unlock();
    return auth_limiter.isLocked(ip, GetTickCount64());
}

fn recordAuthFailure(ip: netpolicy.Ipv4) void {
    var locked = false;
    var lockout_s: u64 = 0;
    {
        auth_lock.lock();
        defer auth_lock.unlock();
        locked = auth_limiter.recordFailure(ip, GetTickCount64(), .bad_credentials);
        lockout_s = auth_limiter.lockout_ms / 1000;
    }
    if (locked) {
        var ip_buf: [16]u8 = undefined;
        logMsg("Too many failed authentication attempts from {s}; blocked for {d} s.", .{ fmtIp(ip, &ip_buf), lockout_s });
    }
}

fn recordAuthSuccess(ip: netpolicy.Ipv4) void {
    auth_lock.lock();
    defer auth_lock.unlock();
    auth_limiter.recordSuccess(ip);
}

fn authorized(head: []const u8) bool {
    const presented = http.bearerToken(head) orelse return false;
    settings_lock.lockShared();
    defer settings_lock.unlockShared();
    return netpolicy.tokenEql(settings.token(), presented);
}

// ── Connection handling ────────────────────────────────────────────

fn peerAddress(sock: SOCKET) ?netpolicy.Ipv4 {
    var peer: ws2.sockaddr.in = undefined;
    var len: i32 = @sizeOf(ws2.sockaddr.in);
    if (ws2.getpeername(sock, @ptrCast(&peer), &len) != 0) return null;
    if (len < @sizeOf(ws2.sockaddr.in) or peer.family != ws2.AF.INET) return null;
    return netpolicy.fromNetworkU32(peer.addr);
}

const ReadResult = union(enum) {
    ok: struct { len: usize, header_end: usize, body_len: usize },
    closed,
    timeout,
    too_large,
    bad,
};

/// Reads one request into `buf` under the header/total time budget.
fn readRequest(sock: SOCKET, buf: []u8) ReadResult {
    const t0 = GetTickCount64();
    var len: usize = 0;
    while (true) {
        switch (http.requestState(buf[0..len], buf.len)) {
            .complete => |c| return .{ .ok = .{ .len = len, .header_end = c.header_end, .body_len = c.body_len } },
            .too_large => return .too_large,
            .bad => return .bad,
            .incomplete => {},
        }
        const headers_done = http.findHeaderEnd(buf[0..len]) != null;
        const timeout = netpolicy.recvTimeoutMs(t0, GetTickCount64(), headers_done) orelse return .timeout;
        setSockTimeout(sock, ws2.SO.RCVTIMEO, timeout);
        const room: i32 = @intCast(@min(buf.len - len, std.math.maxInt(i32)));
        const n = ws2.recv(sock, buf[len..].ptr, room, 0);
        if (n == 0) return .closed;
        if (n < 0) return if (ws2.WSAGetLastError() == .WSAETIMEDOUT) .timeout else .closed;
        len += @intCast(n);
    }
}

/// Connection whose request this thread is currently serving.
threadlocal var request_sock: ?SOCKET = null;

/// True when the client of the request served on the calling thread has
/// closed or reset its connection. Long waits in tool handlers (run,
/// ExecuteDebuggerCommand) poll this so a client that gave up does not keep
/// the mutating-tool lock for the rest of the wait. Never blocks; always
/// false on threads that are not serving a request.
pub fn requestAbandoned() bool {
    const sock = request_sock orelse return false;
    var fds: ws2.fd_set = .{ .fd_count = 1, .fd_array = undefined };
    fds.fd_array[0] = sock;
    const tv: ws2.timeval = .{ .sec = 0, .usec = 0 };
    if (ws2.select(0, &fds, null, null, &tv) != 1) return false;
    var b: [1]u8 = undefined;
    const n = ws2.recv(sock, &b, 1, ws2.MSG.PEEK);
    // Extra bytes (a pipelined request) are not abandonment.
    if (n > 0) return false;
    if (n == 0) return true; // orderly close
    return switch (ws2.WSAGetLastError()) {
        .WSAECONNRESET, .WSAECONNABORTED, .WSAENETRESET, .WSAESHUTDOWN => true,
        else => false,
    };
}

fn handleClient(sock: SOCKET) void {
    const peer_ip = peerAddress(sock) orelse return;
    setSockTimeout(sock, ws2.SO.SNDTIMEO, SEND_TIMEOUT_MS);

    var req_buf: [RECV_BUF_SIZE]u8 = undefined;
    const req = switch (readRequest(sock, &req_buf)) {
        .ok => |r| r,
        .too_large => return sendStatus(sock, "413 Payload Too Large"),
        .bad => return sendStatus(sock, "400 Bad Request"),
        .closed, .timeout => return,
    };
    const head = req_buf[0..req.header_end];
    const body = req_buf[req.header_end + 4 ..][0..req.body_len];
    const rl = http.parseRequestLine(head) orelse return sendStatus(sock, "400 Bad Request");

    const locked = isLockedOut(peer_ip);
    const r = http.route(.{
        .method = rl.method,
        .path = rl.path,
        .authorized = !locked and authorized(head),
        .locked_out = locked,
        .sse_enabled = sse_enabled.load(.acquire),
    });
    switch (r) {
        .locked_out => return sendJsonStatus(sock, "429 Too Many Requests", "", "{\"error\":\"Too many failed authentication attempts\"}"),
        .unauthorized => {
            recordAuthFailure(peer_ip);
            return sendJsonStatus(sock, "401 Unauthorized", "WWW-Authenticate: Bearer\r\n", "{\"error\":\"Unauthorized\"}");
        },
        else => recordAuthSuccess(peer_ip),
    }

    request_sock = sock;
    defer request_sock = null;
    switch (r) {
        .locked_out, .unauthorized => unreachable, // answered above
        // Includes OPTIONS: MCP clients are not browsers, so no CORS.
        .method_not_allowed => sendAll(sock, "HTTP/1.1 405 Method Not Allowed\r\nAllow: GET, POST\r\nContent-Length: 0\r\nConnection: close\r\n\r\n") catch {},
        .not_found => sendStatus(sock, "404 Not Found"),
        .server_info => sendServerInfo(sock),
        .sse_connect => handleSseConnect(sock),
        .sse_message => {
            const session_id = http.queryParam(rl.path, "sessionId") orelse http.headerValue(head, "Mcp-Session-Id");
            handleSseMessage(sock, body, session_id);
        },
        .json_rpc => handleJsonRpc(sock, body),
    }
}

fn handleJsonRpc(sock: SOCKET, body: []const u8) void {
    const parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, body, .{}) catch {
        sendJsonRpcError(sock, null, -32700, "Parse error");
        return;
    };
    defer parsed.deinit();

    const root = parsed.value;
    const method_val = json_mod.getStringField(root, "method") orelse {
        sendJsonRpcError(sock, null, -32600, "Invalid request: missing method");
        return;
    };
    const id = json_mod.getObjectField(root, "id");

    if (id == null or std.mem.startsWith(u8, method_val, "notifications/")) {
        sendStatus(sock, "202 Accepted");
        return;
    }

    if (std.mem.eql(u8, method_val, "initialize")) {
        handleInitialize(sock, id);
    } else if (std.mem.eql(u8, method_val, "tools/list")) {
        handleToolsList(sock, id);
    } else if (std.mem.eql(u8, method_val, "tools/call")) {
        handleToolsCall(sock, id, root);
    } else if (std.mem.eql(u8, method_val, "ping")) {
        sendJsonRpcResult(sock, id, "{}");
    } else {
        sendJsonRpcError(sock, id, -32601, "Method not found");
    }
}

fn handleInitialize(sock: SOCKET, id: ?std.json.Value) void {
    var buf: [4096]u8 = undefined;
    var w = JsonWriter.init(&buf);
    buildInitializeResult(&w);
    if (w.overflow) return sendJsonRpcError(sock, id, -32603, "Internal error: initialize result overflow");
    sendJsonRpcResult(sock, id, w.slice());
}

fn handleToolsList(sock: SOCKET, id: ?std.json.Value) void {
    var buf: [65536]u8 = undefined;
    var w = JsonWriter.init(&buf);
    buildToolsListResult(&w);
    // A truncated tool list would be invalid JSON; report it instead.
    if (w.overflow) return sendJsonRpcError(sock, id, -32603, "Internal error: tools/list result exceeds the response buffer");
    sendJsonRpcResult(sock, id, w.slice());
}

fn handleToolsCall(sock: SOCKET, id: ?std.json.Value, root: std.json.Value) void {
    var buf: [131072]u8 = undefined;
    var w = JsonWriter.init(&buf);
    buildToolsCallResult(&w, root);
    if (w.overflow) {
        sendJsonRpcError(sock, id, -32603, "Result too large — response buffer overflow");
        return;
    }
    const result_str = w.slice();
    if (std.mem.startsWith(u8, result_str, "{\"error\":")) {
        sendJsonRpcError(sock, id, -32602, result_str);
    } else {
        sendJsonRpcResult(sock, id, result_str);
    }
}

// ── SSE transport ──────────────────────────────────────────────────

fn handleSseConnect(sock: SOCKET) void {
    const h = sse_hub.add() orelse return sendStatus(sock, "503 Service Unavailable");
    defer sse_hub.remove(h);
    var sid_buf: [ssehub.SESSION_ID_MAX]u8 = undefined;
    const session_id = sse_hub.sessionId(h, &sid_buf) orelse return;

    // A client that stops reading is dropped after this long.
    setSockTimeout(sock, ws2.SO.SNDTIMEO, SSE_SEND_TIMEOUT_MS);
    sendAll(sock, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n") catch return;
    var endpoint_buf: [96]u8 = undefined;
    const endpoint = std.fmt.bufPrint(&endpoint_buf, "event: endpoint\ndata: /messages?sessionId={s}\n\n", .{session_id}) catch return;
    sendAll(sock, endpoint) catch return;

    logMsg("SSE client connected.", .{});
    defer logMsg("SSE client disconnected.", .{});

    var last_write = GetTickCount64();
    while (running.load(.acquire) and sse_hub.isAlive(h)) {
        while (sse_hub.pop(h)) |frame| {
            defer sse_hub.free(frame);
            sendAll(sock, frame) catch {
                sse_hub.markDead(h);
                return;
            };
            last_write = GetTickCount64();
        }
        if (GetTickCount64() -| last_write >= SSE_KEEPALIVE_MS) {
            sendAll(sock, ": keepalive\n\n") catch return;
            last_write = GetTickCount64();
        }
        Sleep(SSE_POLL_MS);
    }
}

fn handleSseMessage(sock: SOCKET, body: []const u8, session_id: ?[]const u8) void {
    const parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, body, .{}) catch {
        sendJsonRpcError(sock, null, -32700, "Parse error");
        return;
    };
    defer parsed.deinit();

    const root = parsed.value;
    const method_val = json_mod.getStringField(root, "method") orelse {
        sendJsonRpcError(sock, null, -32600, "Invalid request: missing method");
        return;
    };
    const id = json_mod.getObjectField(root, "id");

    // Notifications get 202
    if (id == null or std.mem.startsWith(u8, method_val, "notifications/")) {
        sendStatus(sock, "202 Accepted");
        return;
    }

    // Process the RPC call and build the result
    var result_buf: [131072]u8 = undefined;
    var rw = JsonWriter.init(&result_buf);

    if (std.mem.eql(u8, method_val, "initialize")) {
        buildInitializeResult(&rw);
    } else if (std.mem.eql(u8, method_val, "tools/list")) {
        buildToolsListResult(&rw);
    } else if (std.mem.eql(u8, method_val, "tools/call")) {
        buildToolsCallResult(&rw, root);
    } else if (std.mem.eql(u8, method_val, "ping")) {
        rw.raw("{}");
    } else {
        // Method not found — respond directly on POST socket
        sendJsonRpcError(sock, id, -32601, "Method not found");
        return;
    }

    // Build full JSON-RPC response
    var resp_buf: [131072]u8 = undefined;
    var w = JsonWriter.init(&resp_buf);
    w.raw("{\"jsonrpc\":\"2.0\",\"id\":");
    writeJsonValue(&w, id);
    w.raw(",\"result\":");
    w.raw(rw.slice());
    w.raw("}");
    if (rw.overflow or w.overflow) {
        // Never push truncated JSON: report the overflow instead.
        w = JsonWriter.init(&resp_buf);
        w.raw("{\"jsonrpc\":\"2.0\",\"id\":");
        writeJsonValue(&w, id);
        w.raw(",\"error\":{\"code\":-32603,\"message\":\"Result too large — response buffer overflow\"}}");
    }

    // Push the response via the SSE channel (queued; the SSE connection's
    // own thread writes it).
    if (!w.overflow) {
        if (session_id) |sid| _ = sse_hub.sendTo(sid, "message", w.slice());
    }

    // Also respond on the POST connection
    sendStatus(sock, "200 OK");
}

fn buildInitializeResult(w: *JsonWriter) void {
    w.beginObject();
    w.fieldStr("protocolVersion", PROTOCOL_VERSION);
    w.key("serverInfo");
    w.beginObject();
    w.fieldStr("name", SERVER_NAME);
    w.fieldStr("version", SERVER_VERSION);
    w.endObject();
    w.raw(",");
    w.key("capabilities");
    w.beginObject();
    w.key("tools");
    w.raw("{\"listChanged\":true},");
    w.endObject();
    w.raw(",");
    w.fieldStr("instructions",
        \\You are controlling x64dbg, a Windows debugger, via MCP tools.
        \\
        \\CRITICAL RULES:
        \\1. ALWAYS call GetDebugState first to understand the current state before doing anything.
        \\2. After every stepping operation (StepInto, StepOver, StepOut), the response includes the new address and disassembly. Read it carefully before deciding your next action.
        \\3. The target must be PAUSED to read memory, disassemble, or inspect state. If it is RUNNING, call PauseDebug or WaitForPause first.
        \\4. After calling run, ALWAYS call WaitForEvent or WaitForPause immediately to detect breakpoint hits, exceptions, and state changes. NEVER go idle or ask the user to tell you when something happens — you MUST actively monitor by calling WaitForEvent. This is your only way to know when the debugger state changes over HTTP.
        \\5. Use EvalExpression to resolve symbols and addresses (e.g. kernel32:CreateFileA, cip, eax+4).
        \\6. When analyzing a binary: LoadBinary, then WaitForPause, then GetDebugState, then proceed with analysis.
        \\7. Breakpoint workflow: SetBreakpoint, run, WaitForEvent (or WaitForPause), then inspect state. Never wait for user confirmation — monitor actively.
        \\8. For function analysis: use DisassembleFunction (needs analysis, run ExecuteDebuggerCommand with analr <address> first).
        \\9. SearchSymbols searches exports across all loaded modules. Use it to find API functions.
        \\10. Keep track of what binary is loaded and where you are in the code. Reference addresses and module names in your explanations.
        \\11. Every tool response includes a [state] line and any queued [event:*] lines from debugger events that fired since your last call. Always read these — they tell you exactly what happened.
        \\12. When the user is interacting with the GUI (clicking buttons, navigating menus) while you wait for a breakpoint, call WaitForEvent with a longer timeout (e.g. 60000-120000ms) to stay monitoring. Loop WaitForEvent calls if needed until the expected event fires.
    );
    w.endObject();
}

fn buildToolsListResult(w: *JsonWriter) void {
    w.beginObject();
    w.key("tools");
    w.beginArray();
    for (&tools_mod.tools) |*t| {
        w.beginObject();
        w.fieldStr("name", t.name);
        w.fieldStr("description", t.description);
        w.key("inputSchema");
        t.schema_fn(w);
        w.raw(",");
        w.key("annotations");
        w.beginObject();
        w.fieldBool("readOnlyHint", t.read_only);
        w.fieldBool("openWorldHint", false);
        w.endObject();
        w.raw(",");
        w.endObject();
        w.raw(",");
    }
    w.endArray();
    w.endObject();
}

const BUSY_TEXT = "BUSY: another state-changing tool is still running (for example run, ExecuteDebuggerCommand or LoadBinary; a blocking run holds it until the target pauses or its timeoutMs expires). This call was not executed. Call PauseDebug or WaitForPause, then retry.";

fn buildToolsCallResult(w: *JsonWriter, root: std.json.Value) void {
    const params_obj = json_mod.getObjectField(root, "params");
    const tool_name = if (params_obj) |p| json_mod.getStringField(p, "name") else null;
    if (tool_name == null) {
        w.raw("{\"error\":\"Missing params.name\"}");
        return;
    }
    const name = tool_name.?;
    const arguments = if (params_obj) |p| json_mod.getObjectField(p, "arguments") else null;

    for (&tools_mod.tools) |*t| {
        if (std.mem.eql(u8, t.name, name)) {
            if (t.debug_only and !bridge.isDebugging()) {
                w.raw("{\"error\":\"Tool requires an active debug session.\"}");
                return;
            }
            var out_buf: [65536]u8 = undefined;
            const tr = runTool(t, arguments, &out_buf);

            w.beginObject();
            w.key("content");
            w.beginArray();
            w.beginObject();
            w.fieldStr("type", "text");
            w.key("text");
            w.writeString(tr.text);
            w.endObject();

            // Drain any pending events (breakpoint hit, paused, etc.) that arrived between calls
            pendingDrain(w);

            // Append debugger state to every response (skip GetDebugState itself to avoid redundancy)
            if (!std.mem.eql(u8, name, "GetDebugState") and !std.mem.eql(u8, name, "Echo")) {
                var state_buf: [256]u8 = undefined;
                const state_str = buildStateSnippet(&state_buf);
                if (state_str.len > 0) {
                    w.raw(",");
                    w.beginObject();
                    w.fieldStr("type", "text");
                    w.key("text");
                    w.writeString(state_str);
                    w.endObject();
                }
            }

            w.endArray();
            w.raw(",");
            if (tr.is_error) {
                w.fieldBool("isError", true);
            }
            w.endObject();
            return;
        }
    }
    w.raw("{\"error\":\"Tool not found.\"}");
}

/// Runs a tool handler, holding the mutating-tool lock unless exempt.
fn runTool(t: *const tools_mod.ToolDef, arguments: ?std.json.Value, out: []u8) tools_mod.ToolResult {
    if (toolpolicy.bypassesMutationLock(t.name, t.read_only)) return t.handler(arguments, out);
    if (!sync.tryLockFor(&tool_lock, toolpolicy.LOCK_WAIT_MS)) return .{ .text = BUSY_TEXT, .is_error = true };
    defer tool_lock.unlock();
    return t.handler(arguments, out);
}

fn buildStateSnippet(buf: *[256]u8) []const u8 {
    const debugging = bridge.isDebugging();
    if (!debugging) {
        const s = "[state] NO_TARGET";
        @memcpy(buf[0..s.len], s);
        return buf[0..s.len];
    }
    const running_now = bridge.isRunning();
    if (running_now) {
        const s = "[state] RUNNING — call WaitForPause before inspecting";
        @memcpy(buf[0..s.len], s);
        return buf[0..s.len];
    }
    const cip = bridge.valFromString("cip");
    var mod_buf: [bridge.MAX_MODULE_SIZE]u8 = undefined;
    const has_mod = bridge.getModuleAt(cip, &mod_buf);
    const mod_name = if (has_mod) bridge.cstrSlice(&mod_buf) else "unknown";

    var dis_buf: [256]u8 = undefined;
    const has_dis = if (bridge.GuiGetDisassembly) |f| f(cip, &dis_buf) != 0 else false;
    const dis_text = if (has_dis) bridge.cstrSlice(&dis_buf) else "";

    return std.fmt.bufPrint(buf, "[state] PAUSED at 0x{X} ({s}) | {s}", .{ cip, mod_name, dis_text }) catch buf[0..0];
}

// ── HTTP helpers ────────────────────────────────────────────────────

fn sendAll(sock: SOCKET, data: []const u8) error{SendFailed}!void {
    var sent: usize = 0;
    while (sent < data.len) {
        const chunk: i32 = @intCast(@min(data.len - sent, 0x7FFFFFFF));
        const n = ws2.send(sock, data[sent..].ptr, chunk, 0);
        if (n <= 0) return error.SendFailed;
        sent += @intCast(n);
    }
}

/// Sends a bodiless response, e.g. sendStatus(sock, "404 Not Found").
fn sendStatus(sock: SOCKET, comptime status: []const u8) void {
    sendAll(sock, "HTTP/1.1 " ++ status ++ "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n") catch {};
}

/// Sends a fixed JSON body; `extra_headers` must end with CRLF if non-empty.
fn sendJsonStatus(sock: SOCKET, comptime status: []const u8, comptime extra_headers: []const u8, comptime body: []const u8) void {
    const resp = std.fmt.comptimePrint(
        "HTTP/1.1 {s}\r\n{s}Content-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}",
        .{ status, extra_headers, body.len, body },
    );
    sendAll(sock, resp) catch {};
}

fn sendServerInfo(sock: SOCKET) void {
    var body_buf: [256]u8 = undefined;
    const body = std.fmt.bufPrint(&body_buf, "{{\"name\":\"{s}\",\"version\":\"{s}\",\"transport\":\"streamable-http\",\"endpoint\":\"/\"}}", .{ SERVER_NAME, SERVER_VERSION }) catch return;
    var buf: [512]u8 = undefined;
    const resp = std.fmt.bufPrint(&buf, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ body.len, body }) catch return;
    sendAll(sock, resp) catch {};
}

/// Sends {"jsonrpc":"2.0","id":<id>,"result":<result_json>} without copying
/// the (up to 128 KiB) result into another buffer.
fn sendJsonRpcResult(sock: SOCKET, id: ?std.json.Value, result_json: []const u8) void {
    var prefix_buf: [1024]u8 = undefined;
    var pw = JsonWriter.init(&prefix_buf);
    pw.raw("{\"jsonrpc\":\"2.0\",\"id\":");
    writeJsonValue(&pw, id);
    pw.raw(",\"result\":");
    if (pw.overflow) return sendJsonRpcError(sock, null, -32600, "Invalid request: id too long");
    const prefix = pw.slice();
    const suffix = "}";

    var header_buf: [256]u8 = undefined;
    const header = std.fmt.bufPrint(&header_buf, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{prefix.len + result_json.len + suffix.len}) catch return;
    sendAll(sock, header) catch return;
    sendAll(sock, prefix) catch return;
    sendAll(sock, result_json) catch return;
    sendAll(sock, suffix) catch return;
}

fn sendJsonRpcError(sock: SOCKET, id: ?std.json.Value, code: i32, message: []const u8) void {
    var body_buf: [4096]u8 = undefined;
    var w = JsonWriter.init(&body_buf);
    w.raw("{\"jsonrpc\":\"2.0\",\"id\":");
    writeJsonValue(&w, id);
    w.raw(",\"error\":{\"code\":");
    w.writeInt(code);
    w.raw(",\"message\":");
    w.writeString(message);
    w.raw("}}");
    if (w.overflow) {
        // Fall back to a fixed message that always fits.
        w = JsonWriter.init(&body_buf);
        w.raw("{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":");
        w.writeInt(code);
        w.raw(",\"message\":\"Error message too long\"}}");
    }

    const body_slice = w.slice();
    var header_buf: [256]u8 = undefined;
    const header = std.fmt.bufPrint(&header_buf, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{body_slice.len}) catch return;

    sendAll(sock, header) catch return;
    sendAll(sock, body_slice) catch return;
}

fn writeJsonValue(w: *JsonWriter, val: ?std.json.Value) void {
    if (val == null) {
        w.raw("null");
        return;
    }
    switch (val.?) {
        .integer => |i| w.writeInt(i),
        .string => |s| w.writeString(s),
        .null => w.raw("null"),
        .float => |f| {
            var tmp: [32]u8 = undefined;
            const s = std.fmt.bufPrint(&tmp, "{d}", .{f}) catch "0";
            w.raw(s);
        },
        .bool => |b| w.raw(if (b) "true" else "false"),
        else => w.raw("null"),
    }
}
