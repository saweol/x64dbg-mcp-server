//! Network access policy for the MCP HTTP server (pure logic, host-testable).
//!
//! - strict IPv4 parsing (errors instead of falling back to INADDR_ANY)
//! - CIDR parsing and matching, client allowlist evaluation
//! - startup validation of bind address / AllowExternal / token length
//! - constant-time bearer token comparison
//! - per-IP authentication failure lockout driven by an injected clock
//! - bounded concurrent client slots
//! - request receive deadlines (header / total budget)
//!
//! Thread-safety: the parsing and evaluation functions are pure. `AuthLimiter`
//! is NOT thread-safe (callers wrap it in a lock). `ClientSlots` is lock-free
//! and safe to share between threads.

const std = @import("std");

/// IPv4 address as four octets in network order (a.b.c.d -> {a, b, c, d}).
pub const Ipv4 = [4]u8;

pub const ParseError = error{InvalidAddress};

pub const MAX_ALLOWED_CLIENTS = 64;
pub const MIN_EXTERNAL_TOKEN_LEN = 32;
pub const MAX_TOKEN_LEN = 64;

/// Parses dotted-quad IPv4 strictly: exactly four decimal octets 0-255,
/// no leading zeros (avoids octal ambiguity), no whitespace or suffixes.
pub fn parseIpv4(s: []const u8) ParseError!Ipv4 {
    var out: Ipv4 = undefined;
    var it = std.mem.splitScalar(u8, s, '.');
    var i: usize = 0;
    while (it.next()) |part| : (i += 1) {
        if (i >= 4) return error.InvalidAddress;
        out[i] = try parseOctet(part);
    }
    if (i != 4) return error.InvalidAddress;
    return out;
}

fn parseOctet(part: []const u8) ParseError!u8 {
    if (part.len == 0 or part.len > 3) return error.InvalidAddress;
    if (part.len > 1 and part[0] == '0') return error.InvalidAddress;
    var v: u16 = 0;
    for (part) |c| {
        if (c < '0' or c > '9') return error.InvalidAddress;
        v = v * 10 + (c - '0');
    }
    if (v > 255) return error.InvalidAddress;
    return @intCast(v);
}

fn hostOrder(ip: Ipv4) u32 {
    return std.mem.readInt(u32, &ip, .big);
}

/// The value to store in `sockaddr_in.sin_addr` (memory = network order).
pub fn toNetworkU32(ip: Ipv4) u32 {
    return @bitCast(ip);
}

/// Inverse of `toNetworkU32` (e.g. for the peer address from accept()).
pub fn fromNetworkU32(v: u32) Ipv4 {
    return @bitCast(v);
}

pub fn isLoopback(ip: Ipv4) bool {
    return ip[0] == 127;
}

pub const Cidr = struct {
    /// Network address in host byte order with host bits cleared.
    base: u32,
    prefix: u6,

    pub fn contains(self: Cidr, ip: Ipv4) bool {
        return (hostOrder(ip) & maskFor(self.prefix)) == self.base;
    }

    pub fn isAllAddresses(self: Cidr) bool {
        return self.prefix == 0;
    }
};

/// Parses "a.b.c.d/n" (n = 0..32) or a bare address (= /32). Host bits are
/// cleared, so "10.0.0.5/24" means 10.0.0.0/24.
pub fn parseCidr(s: []const u8) ParseError!Cidr {
    var addr_part = s;
    var prefix: u6 = 32;
    if (std.mem.indexOfScalar(u8, s, '/')) |slash| {
        addr_part = s[0..slash];
        const p = s[slash + 1 ..];
        if (p.len == 0 or p.len > 2) return error.InvalidAddress;
        if (p.len > 1 and p[0] == '0') return error.InvalidAddress;
        var v: u8 = 0;
        for (p) |c| {
            if (c < '0' or c > '9') return error.InvalidAddress;
            v = v * 10 + (c - '0');
        }
        if (v > 32) return error.InvalidAddress;
        prefix = @intCast(v);
    }
    const ip = try parseIpv4(addr_part);
    return .{ .base = hostOrder(ip) & maskFor(prefix), .prefix = prefix };
}

fn maskFor(prefix: u6) u32 {
    if (prefix == 0) return 0;
    const shift: u5 = @intCast(32 - @as(u6, prefix));
    return @as(u32, 0xFFFF_FFFF) << shift;
}

pub const AllowlistError = error{ InvalidAllowedClient, TooManyAllowedClients };

/// Client allowlist. Loopback peers (127.0.0.0/8) are always permitted: they
/// are on the same machine and still have to present the bearer token.
/// Every other peer must match an entry; an empty list admits no remote peer.
pub const Allowlist = struct {
    entries: [MAX_ALLOWED_CLIENTS]Cidr = undefined,
    len: usize = 0,

    /// On InvalidAllowedClient, `bad_index` receives the offending index.
    pub fn fromStrings(items: []const []const u8, bad_index: *usize) AllowlistError!Allowlist {
        if (items.len > MAX_ALLOWED_CLIENTS) return error.TooManyAllowedClients;
        var list: Allowlist = .{};
        for (items, 0..) |item, i| {
            list.entries[i] = parseCidr(item) catch {
                bad_index.* = i;
                return error.InvalidAllowedClient;
            };
        }
        list.len = items.len;
        return list;
    }

    pub fn permits(self: *const Allowlist, peer: Ipv4) bool {
        if (isLoopback(peer)) return true;
        for (self.entries[0..self.len]) |e| {
            if (e.contains(peer)) return true;
        }
        return false;
    }

    pub fn allowsAll(self: *const Allowlist) bool {
        for (self.entries[0..self.len]) |e| if (e.isAllAddresses()) return true;
        return false;
    }
};

pub const StartupError = error{
    InvalidIpAddress,
    ExternalBindNotAllowed,
    AllowedClientsRequired,
    InvalidAllowedClient,
    TooManyAllowedClients,
    MissingToken,
    TokenTooLong,
    TokenTooShort,
};

pub const StartupInput = struct {
    ip_address: []const u8,
    allow_external: bool,
    allowed_clients: []const []const u8,
    token: []const u8,
};

pub const StartupPlan = struct {
    bind: Ipv4,
    allowlist: Allowlist,
    /// Token shorter than MIN_EXTERNAL_TOKEN_LEN on a loopback-only setup.
    warn_short_token: bool,
    /// An AllowedClients entry is 0.0.0.0/0.
    warn_allow_all: bool,
};

pub const StartupDiag = struct {
    /// Index into allowed_clients for InvalidAllowedClient.
    bad_client_index: usize = 0,
};

/// Decides whether the server may start with the given settings.
/// Rules (fail closed):
///   - IpAddress must parse as IPv4.
///   - A token is required (1..64 chars).
///   - Every AllowedClients entry must parse as IPv4 or CIDR.
///   - A non-loopback bind (including 0.0.0.0) needs AllowExternal=true and a
///     non-empty AllowedClients.
///   - With AllowExternal=true the token must be >= 32 chars; on a
///     loopback-only setup a short token only produces a warning.
pub fn planStartup(input: StartupInput, diag: *StartupDiag) StartupError!StartupPlan {
    const bind = parseIpv4(input.ip_address) catch return error.InvalidIpAddress;
    if (input.token.len == 0) return error.MissingToken;
    if (input.token.len > MAX_TOKEN_LEN) return error.TokenTooLong;

    const allowlist = Allowlist.fromStrings(input.allowed_clients, &diag.bad_client_index) catch |err| return switch (err) {
        error.InvalidAllowedClient => error.InvalidAllowedClient,
        error.TooManyAllowedClients => error.TooManyAllowedClients,
    };

    if (!isLoopback(bind)) {
        if (!input.allow_external) return error.ExternalBindNotAllowed;
        if (allowlist.len == 0) return error.AllowedClientsRequired;
    }
    const short = input.token.len < MIN_EXTERNAL_TOKEN_LEN;
    if (input.allow_external and short) return error.TokenTooShort;

    return .{
        .bind = bind,
        .allowlist = allowlist,
        .warn_short_token = short,
        .warn_allow_all = allowlist.allowsAll(),
    };
}

/// Constant-time comparison of a presented bearer token with the expected
/// one. Both are padded to MAX_TOKEN_LEN so the timing does not depend on
/// where they differ. Never matches an empty expected token.
pub fn tokenEql(expected: []const u8, presented: []const u8) bool {
    if (expected.len == 0 or expected.len > MAX_TOKEN_LEN) return false;
    // The presented length is chosen by the client, so rejecting an
    // over-long value early reveals nothing about the expected token.
    if (presented.len > MAX_TOKEN_LEN) return false;
    var a = [_]u8{0} ** MAX_TOKEN_LEN;
    var b = [_]u8{0} ** MAX_TOKEN_LEN;
    @memcpy(a[0..expected.len], expected);
    @memcpy(b[0..presented.len], presented);
    const bytes_equal = std.crypto.timing_safe.eql([MAX_TOKEN_LEN]u8, a, b);
    const len_equal = expected.len == presented.len;
    // Combine without short-circuiting.
    return (@intFromBool(bytes_equal) & @intFromBool(len_equal)) == 1;
}

/// Per-IP authentication failure tracking with temporary lockout.
/// `max_failures` failures within `window_ms` lock the address for
/// `lockout_ms`. Time is injected (milliseconds from any monotonic clock).
/// Not thread-safe.
pub const AuthLimiter = struct {
    pub const CAPACITY = 128;

    const Entry = struct {
        ip: Ipv4 = .{ 0, 0, 0, 0 },
        used: bool = false,
        failures: u32 = 0,
        window_start: u64 = 0,
        locked_until: u64 = 0,
        last_seen: u64 = 0,
    };

    max_failures: u32,
    window_ms: u64,
    lockout_ms: u64,
    entries: [CAPACITY]Entry = [_]Entry{.{}} ** CAPACITY,

    pub fn init(max_failures: u32, window_ms: u64, lockout_ms: u64) AuthLimiter {
        return .{ .max_failures = @max(max_failures, 1), .window_ms = window_ms, .lockout_ms = lockout_ms };
    }

    pub fn isLocked(self: *const AuthLimiter, ip: Ipv4, now_ms: u64) bool {
        const i = self.indexOf(ip) orelse return false;
        return self.entries[i].locked_until > now_ms;
    }

    /// Records a failed authentication. Returns true when this failure
    /// started a lockout.
    pub fn recordFailure(self: *AuthLimiter, ip: Ipv4, now_ms: u64) bool {
        const e = self.findOrClaim(ip, now_ms);
        e.last_seen = now_ms;
        if (e.locked_until > now_ms) return false; // already locked
        if (e.failures == 0 or now_ms -| e.window_start >= self.window_ms) {
            e.failures = 0;
            e.window_start = now_ms;
        }
        e.failures += 1;
        if (e.failures >= self.max_failures) {
            e.failures = 0;
            e.locked_until = now_ms +| self.lockout_ms;
            return true;
        }
        return false;
    }

    pub fn recordSuccess(self: *AuthLimiter, ip: Ipv4) void {
        const i = self.indexOf(ip) orelse return;
        // A successful request never lifts an active lockout (it could not
        // have been served), so just forget the failure history.
        self.entries[i].failures = 0;
    }

    fn indexOf(self: *const AuthLimiter, ip: Ipv4) ?usize {
        for (&self.entries, 0..) |*e, i| {
            if (e.used and std.mem.eql(u8, &e.ip, &ip)) return i;
        }
        return null;
    }

    /// Returns the entry for `ip`, claiming a slot if needed. When the table
    /// is full, the unlocked entry with the oldest activity is evicted; only
    /// when every entry is locked is the one whose lock expires first reused.
    fn findOrClaim(self: *AuthLimiter, ip: Ipv4, now_ms: u64) *Entry {
        if (self.indexOf(ip)) |i| return &self.entries[i];
        var victim: *Entry = &self.entries[0];
        for (&self.entries) |*e| {
            if (!e.used) {
                victim = e;
                break;
            }
            const e_locked = e.locked_until > now_ms;
            const v_locked = victim.locked_until > now_ms;
            if (v_locked and !e_locked) {
                victim = e;
            } else if (v_locked == e_locked) {
                const better = if (e_locked) e.locked_until < victim.locked_until else e.last_seen < victim.last_seen;
                if (better) victim = e;
            }
        }
        victim.* = .{ .ip = ip, .used = true, .last_seen = now_ms };
        return victim;
    }
};

/// Bounded counter of concurrently served client connections.
pub const ClientSlots = struct {
    active: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    pub fn tryAcquire(self: *ClientSlots, max: u32) bool {
        var cur = self.active.load(.acquire);
        while (cur < max) {
            cur = self.active.cmpxchgWeak(cur, cur + 1, .acq_rel, .acquire) orelse return true;
        }
        return false;
    }

    pub fn release(self: *ClientSlots) void {
        const prev = self.active.fetchSub(1, .acq_rel);
        std.debug.assert(prev > 0);
    }

    pub fn count(self: *const ClientSlots) u32 {
        return self.active.load(.acquire);
    }
};

/// Request read deadlines: headers must arrive within HEADER_TIMEOUT_MS and
/// the whole request within TOTAL_TIMEOUT_MS of the connection being accepted.
pub const HEADER_TIMEOUT_MS: u64 = 5000;
pub const TOTAL_TIMEOUT_MS: u64 = 10000;

/// Timeout to apply to the next recv() call, or null when the budget for the
/// current phase is exhausted. Never returns 0 (0 means "infinite" to
/// SO_RCVTIMEO).
pub fn recvTimeoutMs(start_ms: u64, now_ms: u64, headers_done: bool) ?u32 {
    const elapsed = now_ms -| start_ms;
    const limit = if (headers_done) TOTAL_TIMEOUT_MS else HEADER_TIMEOUT_MS;
    if (elapsed >= limit) return null;
    return @intCast(limit - elapsed);
}

// ── Tests ───────────────────────────────────────────────────────────

const testing = std.testing;

test "parseIpv4 accepts canonical dotted quads" {
    try testing.expectEqual(Ipv4{ 127, 0, 0, 1 }, try parseIpv4("127.0.0.1"));
    try testing.expectEqual(Ipv4{ 0, 0, 0, 0 }, try parseIpv4("0.0.0.0"));
    try testing.expectEqual(Ipv4{ 255, 255, 255, 255 }, try parseIpv4("255.255.255.255"));
    try testing.expectEqual(Ipv4{ 192, 168, 10, 15 }, try parseIpv4("192.168.10.15"));
    try testing.expectEqual(Ipv4{ 10, 0, 100, 9 }, try parseIpv4("10.0.100.9"));
}

test "parseIpv4 rejects malformed input instead of returning INADDR_ANY" {
    const bad = [_][]const u8{
        "",                "1.2.3",       "1.2.3.4.5",  "256.0.0.1",  "1..2.3",
        "1.2.3.",          ".1.2.3",      " 1.2.3.4",   "1.2.3.4 ",   "01.2.3.4",
        "1.2.3.4a",        "a.b.c.d",     "1.2.3.-4",   "1234.1.1.1", "localhost",
        "::1",             "127.0.0.l",   "1.2.3.4/32", "0x7f.0.0.1", "1.2.3.00",
        "999.999.999.999", "1.2.3.4\x00",
    };
    for (bad) |s| {
        if (parseIpv4(s)) |_| {
            std.debug.print("accepted invalid address: '{s}'\n", .{s});
            return error.TestUnexpectedResult;
        } else |err| try testing.expectEqual(error.InvalidAddress, err);
    }
}

test "network u32 round trip matches sockaddr memory layout" {
    const ip = Ipv4{ 192, 168, 10, 15 };
    const v = toNetworkU32(ip);
    try testing.expectEqualSlices(u8, &ip, std.mem.asBytes(&v));
    try testing.expectEqual(ip, fromNetworkU32(v));
}

test "isLoopback covers 127.0.0.0/8 only" {
    try testing.expect(isLoopback(.{ 127, 0, 0, 1 }));
    try testing.expect(isLoopback(.{ 127, 255, 1, 2 }));
    try testing.expect(!isLoopback(.{ 128, 0, 0, 1 }));
    try testing.expect(!isLoopback(.{ 0, 0, 0, 0 }));
}

test "parseCidr matches networks and normalises host bits" {
    const net8 = try parseCidr("10.0.0.0/8");
    try testing.expect(net8.contains(.{ 10, 255, 1, 2 }));
    try testing.expect(!net8.contains(.{ 11, 0, 0, 1 }));

    const host = try parseCidr("192.168.10.15");
    try testing.expectEqual(@as(u6, 32), host.prefix);
    try testing.expect(host.contains(.{ 192, 168, 10, 15 }));
    try testing.expect(!host.contains(.{ 192, 168, 10, 16 }));

    const norm = try parseCidr("10.0.0.5/24");
    try testing.expect(norm.contains(.{ 10, 0, 0, 200 }));
    try testing.expect(!norm.contains(.{ 10, 0, 1, 0 }));

    const all = try parseCidr("0.0.0.0/0");
    try testing.expect(all.contains(.{ 8, 8, 8, 8 }));
    try testing.expect(all.isAllAddresses());

    const slash32 = try parseCidr("192.168.56.10/32");
    try testing.expect(slash32.contains(.{ 192, 168, 56, 10 }));
    try testing.expect(!slash32.contains(.{ 192, 168, 56, 11 }));
}

test "parseCidr rejects malformed prefixes" {
    const bad = [_][]const u8{ "10.0.0.0/33", "10.0.0.0/", "/8", "10.0.0.0/8/8", "10.0.0.0/-1", "10.0.0.0/08", "10.0.0.0/ 8", "10.0.0/8", "", "10.0.0.0/8 " };
    for (bad) |s| {
        if (parseCidr(s)) |_| {
            std.debug.print("accepted invalid cidr: '{s}'\n", .{s});
            return error.TestUnexpectedResult;
        } else |_| {}
    }
}

test "Allowlist always admits loopback, otherwise only listed networks" {
    var bad: usize = 0;
    const empty = try Allowlist.fromStrings(&.{}, &bad);
    try testing.expect(empty.permits(.{ 127, 0, 0, 1 }));
    try testing.expect(!empty.permits(.{ 192, 168, 10, 1 }));

    const list = try Allowlist.fromStrings(&.{ "192.168.10.0/24", "10.1.2.3" }, &bad);
    try testing.expectEqual(@as(usize, 2), list.len);
    try testing.expect(list.permits(.{ 192, 168, 10, 77 }));
    try testing.expect(list.permits(.{ 10, 1, 2, 3 }));
    try testing.expect(!list.permits(.{ 10, 1, 2, 4 }));
    try testing.expect(!list.permits(.{ 192, 168, 1, 1 }));
    try testing.expect(list.permits(.{ 127, 0, 0, 1 }));
}

test "Allowlist reports the first invalid entry" {
    var bad: usize = 99;
    try testing.expectError(error.InvalidAllowedClient, Allowlist.fromStrings(&.{ "10.0.0.0/8", "nope", "1.2.3.4" }, &bad));
    try testing.expectEqual(@as(usize, 1), bad);
}

test "Allowlist rejects more than MAX_ALLOWED_CLIENTS entries" {
    var items: [MAX_ALLOWED_CLIENTS + 1][]const u8 = undefined;
    for (&items) |*it| it.* = "10.0.0.1";
    var bad: usize = 0;
    try testing.expectError(error.TooManyAllowedClients, Allowlist.fromStrings(&items, &bad));
}

const token32 = "0123456789abcdef0123456789abcdef";

test "planStartup accepts the default loopback setup" {
    var diag: StartupDiag = .{};
    const plan = try planStartup(.{ .ip_address = "127.0.0.1", .allow_external = false, .allowed_clients = &.{}, .token = token32 }, &diag);
    try testing.expectEqual(Ipv4{ 127, 0, 0, 1 }, plan.bind);
    try testing.expect(!plan.warn_short_token);
    try testing.expectEqual(@as(usize, 0), plan.allowlist.len);
}

test "planStartup fails closed on an unparsable or empty bind address" {
    var diag: StartupDiag = .{};
    try testing.expectError(error.InvalidIpAddress, planStartup(.{ .ip_address = "127.0.0.l", .allow_external = false, .allowed_clients = &.{}, .token = token32 }, &diag));
    try testing.expectError(error.InvalidIpAddress, planStartup(.{ .ip_address = "", .allow_external = false, .allowed_clients = &.{}, .token = token32 }, &diag));
}

test "planStartup refuses non-loopback binds without AllowExternal" {
    var diag: StartupDiag = .{};
    try testing.expectError(error.ExternalBindNotAllowed, planStartup(.{ .ip_address = "0.0.0.0", .allow_external = false, .allowed_clients = &.{"10.0.0.0/8"}, .token = token32 }, &diag));
    try testing.expectError(error.ExternalBindNotAllowed, planStartup(.{ .ip_address = "192.168.10.15", .allow_external = false, .allowed_clients = &.{}, .token = token32 }, &diag));
}

test "planStartup requires AllowedClients for external binds" {
    var diag: StartupDiag = .{};
    try testing.expectError(error.AllowedClientsRequired, planStartup(.{ .ip_address = "0.0.0.0", .allow_external = true, .allowed_clients = &.{}, .token = token32 }, &diag));
}

test "planStartup enforces the 32-char token when AllowExternal is set" {
    var diag: StartupDiag = .{};
    try testing.expectError(error.TokenTooShort, planStartup(.{ .ip_address = "0.0.0.0", .allow_external = true, .allowed_clients = &.{"192.168.10.0/24"}, .token = token32[0..31] }, &diag));
    // Even on loopback, AllowExternal=true keeps the strict rule.
    try testing.expectError(error.TokenTooShort, planStartup(.{ .ip_address = "127.0.0.1", .allow_external = true, .allowed_clients = &.{}, .token = "short" }, &diag));
    const plan = try planStartup(.{ .ip_address = "0.0.0.0", .allow_external = true, .allowed_clients = &.{"192.168.10.0/24"}, .token = token32 }, &diag);
    try testing.expectEqual(Ipv4{ 0, 0, 0, 0 }, plan.bind);
    try testing.expectEqual(@as(usize, 1), plan.allowlist.len);
}

test "planStartup only warns about a short token on loopback" {
    var diag: StartupDiag = .{};
    const plan = try planStartup(.{ .ip_address = "127.0.0.1", .allow_external = false, .allowed_clients = &.{}, .token = "abc" }, &diag);
    try testing.expect(plan.warn_short_token);
    // 127.0.0.2 is loopback too.
    _ = try planStartup(.{ .ip_address = "127.0.0.2", .allow_external = false, .allowed_clients = &.{}, .token = token32 }, &diag);
}

test "planStartup requires a token and bounds its length" {
    var diag: StartupDiag = .{};
    try testing.expectError(error.MissingToken, planStartup(.{ .ip_address = "127.0.0.1", .allow_external = false, .allowed_clients = &.{}, .token = "" }, &diag));
    const long = "x" ** (MAX_TOKEN_LEN + 1);
    try testing.expectError(error.TokenTooLong, planStartup(.{ .ip_address = "127.0.0.1", .allow_external = false, .allowed_clients = &.{}, .token = long }, &diag));
}

test "planStartup reports invalid allowlist entries" {
    var diag: StartupDiag = .{};
    try testing.expectError(error.InvalidAllowedClient, planStartup(.{ .ip_address = "0.0.0.0", .allow_external = true, .allowed_clients = &.{ "10.0.0.0/8", "10.0.0.0/40" }, .token = token32 }, &diag));
    try testing.expectEqual(@as(usize, 1), diag.bad_client_index);
}

test "planStartup flags an allow-all entry" {
    var diag: StartupDiag = .{};
    const plan = try planStartup(.{ .ip_address = "0.0.0.0", .allow_external = true, .allowed_clients = &.{"0.0.0.0/0"}, .token = token32 }, &diag);
    try testing.expect(plan.warn_allow_all);
}

test "tokenEql compares exactly" {
    try testing.expect(tokenEql(token32, token32));
    try testing.expect(!tokenEql(token32, "0123456789abcdef0123456789abcdeF"));
    try testing.expect(!tokenEql(token32, token32[0..31]));
    try testing.expect(!tokenEql(token32[0..31], token32));
    try testing.expect(!tokenEql("", ""));
    try testing.expect(!tokenEql("abc", "abc\x00"));
    const t64 = "z" ** 64;
    try testing.expect(tokenEql(t64, t64));
    try testing.expect(!tokenEql(t64, t64 ++ "z"));
}

test "AuthLimiter locks after max failures and unlocks after the lockout" {
    var lim = AuthLimiter.init(5, 60_000, 300_000);
    const ip = Ipv4{ 192, 168, 10, 9 };
    var t: u64 = 1000;
    for (0..4) |_| {
        try testing.expect(!lim.recordFailure(ip, t));
        t += 10;
    }
    try testing.expect(!lim.isLocked(ip, t));
    try testing.expect(lim.recordFailure(ip, t));
    try testing.expect(lim.isLocked(ip, t));
    try testing.expect(lim.isLocked(ip, t + 299_999));
    try testing.expect(!lim.isLocked(ip, t + 300_000));
    // The counter restarts after the lockout expires.
    try testing.expect(!lim.recordFailure(ip, t + 300_001));
    try testing.expect(!lim.isLocked(ip, t + 300_002));
}

test "AuthLimiter forgets failures outside the window" {
    var lim = AuthLimiter.init(3, 1000, 5000);
    const ip = Ipv4{ 10, 0, 0, 1 };
    _ = lim.recordFailure(ip, 0);
    _ = lim.recordFailure(ip, 10);
    // Third failure arrives after the window: counts as the first again.
    try testing.expect(!lim.recordFailure(ip, 2000));
    try testing.expect(!lim.recordFailure(ip, 2010));
    try testing.expect(lim.recordFailure(ip, 2020));
}

test "AuthLimiter success clears the failure count; IPs are independent" {
    var lim = AuthLimiter.init(2, 60_000, 60_000);
    const a = Ipv4{ 10, 0, 0, 1 };
    const b = Ipv4{ 10, 0, 0, 2 };
    _ = lim.recordFailure(a, 0);
    lim.recordSuccess(a);
    try testing.expect(!lim.recordFailure(a, 1));
    try testing.expect(lim.recordFailure(a, 2));
    try testing.expect(lim.isLocked(a, 3));
    try testing.expect(!lim.isLocked(b, 3));
    try testing.expect(!lim.recordFailure(b, 4));
}

test "AuthLimiter keeps locked entries when the table overflows" {
    var lim = AuthLimiter.init(2, 60_000, 60_000);
    const victim = Ipv4{ 172, 16, 0, 1 };
    _ = lim.recordFailure(victim, 0);
    try testing.expect(lim.recordFailure(victim, 0));
    // Flood the table with other addresses, one (non-locking) failure each,
    // trying to evict the locked entry.
    var i: u32 = 0;
    while (i < AuthLimiter.CAPACITY * 2) : (i += 1) {
        const ip = Ipv4{ 10, @intCast((i >> 16) & 0xff), @intCast((i >> 8) & 0xff), @intCast(i & 0xff) };
        _ = lim.recordFailure(ip, 1 + i);
    }
    try testing.expect(lim.isLocked(victim, 1000));
}

test "ClientSlots caps concurrent clients" {
    var slots: ClientSlots = .{};
    try testing.expect(slots.tryAcquire(2));
    try testing.expect(slots.tryAcquire(2));
    try testing.expect(!slots.tryAcquire(2));
    try testing.expectEqual(@as(u32, 2), slots.count());
    slots.release();
    try testing.expect(slots.tryAcquire(2));
    slots.release();
    slots.release();
    try testing.expectEqual(@as(u32, 0), slots.count());
}

test "ClientSlots never exceeds the cap under contention" {
    const Ctx = struct {
        slots: ClientSlots = .{},
        max_seen: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
        fn work(self: *@This()) void {
            for (0..5000) |_| {
                if (self.slots.tryAcquire(3)) {
                    const c = self.slots.count();
                    _ = self.max_seen.fetchMax(c, .monotonic);
                    self.slots.release();
                }
            }
        }
    };
    var ctx: Ctx = .{};
    var threads: [6]std.Thread = undefined;
    for (&threads) |*t| t.* = try std.Thread.spawn(.{}, Ctx.work, .{&ctx});
    for (threads) |t| t.join();
    try testing.expect(ctx.max_seen.load(.monotonic) <= 3);
    try testing.expectEqual(@as(u32, 0), ctx.slots.count());
}

test "recvTimeoutMs enforces the header and total budgets" {
    try testing.expectEqual(@as(?u32, 5000), recvTimeoutMs(1000, 1000, false));
    try testing.expectEqual(@as(?u32, 2000), recvTimeoutMs(1000, 4000, false));
    try testing.expectEqual(@as(?u32, null), recvTimeoutMs(1000, 6000, false));
    try testing.expectEqual(@as(?u32, 5000), recvTimeoutMs(1000, 6000, true));
    try testing.expectEqual(@as(?u32, null), recvTimeoutMs(1000, 11000, true));
    try testing.expectEqual(@as(?u32, 1), recvTimeoutMs(1000, 10999, true));
    // A clock that went backwards must not produce a huge timeout.
    try testing.expectEqual(@as(?u32, 5000), recvTimeoutMs(1000, 500, false));
}
