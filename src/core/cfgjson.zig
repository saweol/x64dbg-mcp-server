//! mcp_config.json parsing and serialisation (pure, host-testable).
//!
//! Backward compatible with the v1.9 file ({"IpAddress","Port","AutoStart",
//! "AuthToken"}); adds file-only keys for the hardened server. Parsing is
//! strict for known keys (wrong type or out of range = error naming the key)
//! and tolerant of unknown keys, which are preserved verbatim on save.
//! No fixed-size buffers: all strings live in an arena owned by `Owned`.
//!
//! Thread-safety: functions are pure; an `Owned` value must not be shared
//! between threads without external synchronisation.

const std = @import("std");
const netpolicy = @import("netpolicy.zig");
const pathutil = @import("pathutil.zig");

const Allocator = std.mem.Allocator;

pub const MAX_CONFIG_BYTES: usize = 64 * 1024;
pub const MAX_IP_LEN = 63;
pub const MAX_TOKEN_LEN = netpolicy.MAX_TOKEN_LEN;
pub const MAX_CLIENT_ENTRY_LEN = 31;
pub const MAX_ALLOWED_CLIENTS = netpolicy.MAX_ALLOWED_CLIENTS;

pub const DEFAULT_IP = "127.0.0.1";
pub const DEFAULT_MAX_CLIENTS: u32 = 16;
pub const MAX_MAX_CLIENTS: u32 = 256;
pub const DEFAULT_AUTH_MAX_FAILURES: u32 = 5;
pub const MAX_AUTH_MAX_FAILURES: u32 = 1000;
pub const DEFAULT_AUTH_LOCKOUT_SECONDS: u32 = 300;
pub const MAX_AUTH_LOCKOUT_SECONDS: u32 = 86400;

pub const key = struct {
    pub const ip_address = "IpAddress";
    pub const port = "Port";
    pub const auto_start = "AutoStart";
    pub const auth_token = "AuthToken";
    pub const allow_external = "AllowExternal";
    pub const allowed_clients = "AllowedClients";
    pub const max_clients = "MaxClients";
    pub const enable_sse = "EnableSse";
    pub const artifact_dir = "ArtifactDir";
    pub const auth_max_failures = "AuthMaxFailures";
    pub const auth_lockout_seconds = "AuthLockoutSeconds";
};

/// An unknown top-level key and its value re-serialised as compact JSON.
pub const Extra = struct { name: []const u8, json: []const u8 };

pub const Config = struct {
    ip_address: []const u8 = DEFAULT_IP,
    port: u16,
    auto_start: bool = true,
    /// Empty means "not configured yet" (the plugin generates one).
    auth_token: []const u8 = "",
    allow_external: bool = false,
    allowed_clients: []const []const u8 = &.{},
    max_clients: u32 = DEFAULT_MAX_CLIENTS,
    enable_sse: bool = true,
    /// Empty means unset.
    artifact_dir: []const u8 = "",
    auth_max_failures: u32 = DEFAULT_AUTH_MAX_FAILURES,
    auth_lockout_seconds: u32 = DEFAULT_AUTH_LOCKOUT_SECONDS,
    extra: []const Extra = &.{},
};

/// A Config together with the arena that owns its strings.
pub const Owned = struct {
    arena: std.heap.ArenaAllocator,
    config: Config,

    pub fn deinit(self: *Owned) void {
        self.arena.deinit();
    }

    /// Copies `s` into the arena (use when replacing a string field).
    pub fn dupe(self: *Owned, s: []const u8) Allocator.Error![]const u8 {
        return self.arena.allocator().dupe(u8, s);
    }
};

pub fn initDefault(backing: Allocator, default_port: u16) Owned {
    return .{ .arena = std.heap.ArenaAllocator.init(backing), .config = .{ .port = default_port } };
}

pub const Error = error{ ConfigTooLarge, InvalidJson, NotAnObject, InvalidValue, OutOfMemory };

pub const Diagnostic = struct {
    /// Offending key (static string) for InvalidValue.
    key: []const u8 = "",
    /// Static, human-readable reason.
    reason: []const u8 = "",
};

/// Parses the config text. Missing keys take their defaults.
pub fn parse(backing: Allocator, text: []const u8, default_port: u16, diag: *Diagnostic) Error!Owned {
    _ = backing;
    _ = text;
    _ = default_port;
    _ = diag;
    return error.InvalidJson;
}

/// Serialises `cfg` as pretty JSON. The four v1.9 keys come first so an
/// older plugin (which only reads the first 512 bytes) still finds them.
pub fn serialize(allocator: Allocator, cfg: *const Config) Allocator.Error![]u8 {
    _ = cfg;
    return allocator.alloc(u8, 0);
}

/// True when `token` is acceptable as AuthToken: 1..64 visible ASCII chars.
pub fn isValidToken(token: []const u8) bool {
    _ = token;
    return false;
}

// ── Tests ───────────────────────────────────────────────────────────

const testing = std.testing;

fn parseOk(text: []const u8) !Owned {
    var diag: Diagnostic = .{};
    return parse(testing.allocator, text, 9094, &diag) catch |err| {
        std.debug.print("unexpected {s}: key={s} reason={s}\n", .{ @errorName(err), diag.key, diag.reason });
        return err;
    };
}

fn expectInvalid(text: []const u8, expected_key: []const u8) !void {
    var diag: Diagnostic = .{};
    if (parse(testing.allocator, text, 9094, &diag)) |owned| {
        var o = owned;
        o.deinit();
        std.debug.print("accepted invalid config: {s}\n", .{text});
        return error.TestUnexpectedResult;
    } else |err| {
        try testing.expectEqual(error.InvalidValue, err);
        try testing.expectEqualStrings(expected_key, diag.key);
        try testing.expect(diag.reason.len > 0);
    }
}

test "parses a v1.9 config and applies defaults for new keys" {
    var o = try parseOk(
        \\{"IpAddress":"127.0.0.1","Port":9095,"AutoStart":false,"AuthToken":"0123456789abcdef0123456789abcdef"}
    );
    defer o.deinit();
    const c = o.config;
    try testing.expectEqualStrings("127.0.0.1", c.ip_address);
    try testing.expectEqual(@as(u16, 9095), c.port);
    try testing.expect(!c.auto_start);
    try testing.expectEqualStrings("0123456789abcdef0123456789abcdef", c.auth_token);
    try testing.expect(!c.allow_external);
    try testing.expectEqual(@as(usize, 0), c.allowed_clients.len);
    try testing.expectEqual(DEFAULT_MAX_CLIENTS, c.max_clients);
    try testing.expect(c.enable_sse);
    try testing.expectEqualStrings("", c.artifact_dir);
    try testing.expectEqual(DEFAULT_AUTH_MAX_FAILURES, c.auth_max_failures);
    try testing.expectEqual(DEFAULT_AUTH_LOCKOUT_SECONDS, c.auth_lockout_seconds);
}

test "missing keys use defaults including the arch default port" {
    var diag: Diagnostic = .{};
    var o = try parse(testing.allocator, "{}", 9095, &diag);
    defer o.deinit();
    try testing.expectEqualStrings(DEFAULT_IP, o.config.ip_address);
    try testing.expectEqual(@as(u16, 9095), o.config.port);
    try testing.expect(o.config.auto_start);
    try testing.expectEqualStrings("", o.config.auth_token);
}

test "parses the new file-only keys" {
    var o = try parseOk(
        \\{
        \\  "IpAddress": "0.0.0.0",
        \\  "Port": 9094,
        \\  "AllowExternal": true,
        \\  "AllowedClients": ["192.168.10.0/24", "10.0.0.5"],
        \\  "MaxClients": 8,
        \\  "EnableSse": false,
        \\  "ArtifactDir": "C:\\mcp\\jobs\\1\\out",
        \\  "AuthMaxFailures": 3,
        \\  "AuthLockoutSeconds": 60
        \\}
    );
    defer o.deinit();
    const c = o.config;
    try testing.expect(c.allow_external);
    try testing.expectEqual(@as(usize, 2), c.allowed_clients.len);
    try testing.expectEqualStrings("192.168.10.0/24", c.allowed_clients[0]);
    try testing.expectEqualStrings("10.0.0.5", c.allowed_clients[1]);
    try testing.expectEqual(@as(u32, 8), c.max_clients);
    try testing.expect(!c.enable_sse);
    try testing.expectEqualStrings("C:\\mcp\\jobs\\1\\out", c.artifact_dir);
    try testing.expectEqual(@as(u32, 3), c.auth_max_failures);
    try testing.expectEqual(@as(u32, 60), c.auth_lockout_seconds);
}

test "accepts a UTF-8 BOM (files saved by Notepad)" {
    var o = try parseOk("\xEF\xBB\xBF{\"Port\":1234}");
    defer o.deinit();
    try testing.expectEqual(@as(u16, 1234), o.config.port);
}

test "rejects wrong types and out-of-range values, naming the key" {
    try expectInvalid("{\"Port\":\"9094\"}", "Port");
    try expectInvalid("{\"Port\":0}", "Port");
    try expectInvalid("{\"Port\":70000}", "Port");
    try expectInvalid("{\"Port\":9094.5}", "Port");
    try expectInvalid("{\"AutoStart\":1}", "AutoStart");
    try expectInvalid("{\"AllowExternal\":\"yes\"}", "AllowExternal");
    try expectInvalid("{\"IpAddress\":127}", "IpAddress");
    try expectInvalid("{\"IpAddress\":\"" ++ "1" ** 64 ++ "\"}", "IpAddress");
    try expectInvalid("{\"AuthToken\":\"has space\"}", "AuthToken");
    try expectInvalid("{\"AuthToken\":\"" ++ "a" ** 65 ++ "\"}", "AuthToken");
    try expectInvalid("{\"AllowedClients\":\"10.0.0.0/8\"}", "AllowedClients");
    try expectInvalid("{\"AllowedClients\":[1]}", "AllowedClients");
    try expectInvalid("{\"AllowedClients\":[\"bad\"]}", "AllowedClients");
    try expectInvalid("{\"AllowedClients\":[\"10.0.0.0/33\"]}", "AllowedClients");
    try expectInvalid("{\"MaxClients\":0}", "MaxClients");
    try expectInvalid("{\"MaxClients\":100000}", "MaxClients");
    try expectInvalid("{\"EnableSse\":null}", "EnableSse");
    try expectInvalid("{\"ArtifactDir\":\"relative\\\\dir\"}", "ArtifactDir");
    try expectInvalid("{\"ArtifactDir\":\"C:\\\\a\\\\..\\\\b\"}", "ArtifactDir");
    try expectInvalid("{\"AuthMaxFailures\":0}", "AuthMaxFailures");
    try expectInvalid("{\"AuthLockoutSeconds\":-5}", "AuthLockoutSeconds");
}

test "rejects too many AllowedClients" {
    var text: std.ArrayList(u8) = .init(testing.allocator);
    defer text.deinit();
    try text.appendSlice("{\"AllowedClients\":[");
    for (0..MAX_ALLOWED_CLIENTS + 1) |i| {
        if (i > 0) try text.append(',');
        try text.appendSlice("\"10.0.0.1\"");
    }
    try text.appendSlice("]}");
    try expectInvalid(text.items, "AllowedClients");
}

test "structural errors" {
    var diag: Diagnostic = .{};
    try testing.expectError(error.InvalidJson, parse(testing.allocator, "{\"Port\":", 9094, &diag));
    try testing.expectError(error.InvalidJson, parse(testing.allocator, "", 9094, &diag));
    try testing.expectError(error.NotAnObject, parse(testing.allocator, "[1,2]", 9094, &diag));
    // Duplicate keys are ambiguous (which AllowExternal wins?) -> reject.
    try testing.expectError(error.InvalidJson, parse(testing.allocator, "{\"AllowExternal\":false,\"AllowExternal\":true}", 9094, &diag));
    const big = try testing.allocator.alloc(u8, MAX_CONFIG_BYTES + 1);
    defer testing.allocator.free(big);
    @memset(big, ' ');
    big[0] = '{';
    big[big.len - 1] = '}';
    try testing.expectError(error.ConfigTooLarge, parse(testing.allocator, big, 9094, &diag));
}

test "configs larger than the old 512-byte limit parse fine" {
    var text: std.ArrayList(u8) = .init(testing.allocator);
    defer text.deinit();
    try text.appendSlice("{\"Comment\":\"");
    try text.appendNTimes('x', 2000);
    try text.appendSlice("\",\"AuthToken\":\"0123456789abcdef0123456789abcdef\",\"Port\":9999}");
    var o = try parseOk(text.items);
    defer o.deinit();
    try testing.expectEqual(@as(u16, 9999), o.config.port);
    try testing.expectEqualStrings("0123456789abcdef0123456789abcdef", o.config.auth_token);
}

test "serialize round-trips every key and preserves unknown keys" {
    var o = try parseOk(
        \\{"IpAddress":"0.0.0.0","Port":9094,"AutoStart":true,
        \\ "AuthToken":"0123456789abcdef0123456789abcdef",
        \\ "AllowExternal":true,"AllowedClients":["192.168.56.0/24"],
        \\ "MaxClients":4,"EnableSse":false,"ArtifactDir":"C:\\out dir",
        \\ "AuthMaxFailures":7,"AuthLockoutSeconds":90,
        \\ "FutureKey":{"nested":[1,2,"x"]},"_comment":"keep me"}
    );
    defer o.deinit();
    try testing.expectEqual(@as(usize, 2), o.config.extra.len);

    const text = try serialize(testing.allocator, &o.config);
    defer testing.allocator.free(text);

    var again = try parseOk(text);
    defer again.deinit();
    const a = o.config;
    const b = again.config;
    try testing.expectEqualStrings(a.ip_address, b.ip_address);
    try testing.expectEqual(a.port, b.port);
    try testing.expectEqual(a.auto_start, b.auto_start);
    try testing.expectEqualStrings(a.auth_token, b.auth_token);
    try testing.expectEqual(a.allow_external, b.allow_external);
    try testing.expectEqual(a.allowed_clients.len, b.allowed_clients.len);
    try testing.expectEqualStrings(a.allowed_clients[0], b.allowed_clients[0]);
    try testing.expectEqual(a.max_clients, b.max_clients);
    try testing.expectEqual(a.enable_sse, b.enable_sse);
    try testing.expectEqualStrings(a.artifact_dir, b.artifact_dir);
    try testing.expectEqual(a.auth_max_failures, b.auth_max_failures);
    try testing.expectEqual(a.auth_lockout_seconds, b.auth_lockout_seconds);
    try testing.expectEqual(@as(usize, 2), b.extra.len);
    try testing.expectEqualStrings("FutureKey", b.extra[0].name);
    try testing.expectEqualStrings("{\"nested\":[1,2,\"x\"]}", b.extra[0].json);
    try testing.expectEqualStrings("_comment", b.extra[1].name);
}

test "serialize puts the legacy keys first for older plugins" {
    var o = initDefault(testing.allocator, 9094);
    defer o.deinit();
    o.config.auth_token = try o.dupe("0123456789abcdef0123456789abcdef");
    const text = try serialize(testing.allocator, &o.config);
    defer testing.allocator.free(text);
    const ip = std.mem.indexOf(u8, text, "\"IpAddress\"").?;
    const port = std.mem.indexOf(u8, text, "\"Port\"").?;
    const auto = std.mem.indexOf(u8, text, "\"AutoStart\"").?;
    const tok = std.mem.indexOf(u8, text, "\"AuthToken\"").?;
    const ext = std.mem.indexOf(u8, text, "\"AllowExternal\"").?;
    try testing.expect(ip < port and port < auto and auto < tok and tok < ext);
    // The v1.9 reader stops after 512 bytes.
    try testing.expect(tok + 100 < 512);
}

test "serialize has no fixed-size limit" {
    var o = initDefault(testing.allocator, 9094);
    defer o.deinit();
    var clients: [MAX_ALLOWED_CLIENTS][]const u8 = undefined;
    for (&clients) |*c| c.* = "255.255.255.255/32";
    o.config.allowed_clients = &clients;
    o.config.artifact_dir = "C:\\" ++ "d" ** 600;
    const text = try serialize(testing.allocator, &o.config);
    defer testing.allocator.free(text);
    try testing.expect(text.len > 2000);
    var again = try parseOk(text);
    defer again.deinit();
    try testing.expectEqual(@as(usize, MAX_ALLOWED_CLIENTS), again.config.allowed_clients.len);
    try testing.expectEqualStrings(o.config.artifact_dir, again.config.artifact_dir);
}

test "isValidToken" {
    try testing.expect(isValidToken("abc"));
    try testing.expect(isValidToken("A-Z_0.9~!"));
    try testing.expect(!isValidToken(""));
    try testing.expect(!isValidToken("a b"));
    try testing.expect(!isValidToken("a\"b"));
    try testing.expect(!isValidToken("tab\there"));
    try testing.expect(!isValidToken("caf\xc3\xa9"));
    try testing.expect(!isValidToken("a" ** 65));
}
