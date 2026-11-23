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
pub fn parse(backing: Allocator, text_in: []const u8, default_port: u16, diag: *Diagnostic) Error!Owned {
    if (text_in.len > MAX_CONFIG_BYTES) {
        diag.* = .{ .reason = "file is larger than 64 KiB" };
        return error.ConfigTooLarge;
    }
    var text = text_in;
    if (std.mem.startsWith(u8, text, "\xEF\xBB\xBF")) text = text[3..];

    var owned = initDefault(backing, default_port);
    errdefer owned.deinit();
    const a = owned.arena.allocator();

    const root = std.json.parseFromSliceLeaky(std.json.Value, a, text, .{
        .duplicate_field_behavior = .@"error",
        .allocate = .alloc_always,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.DuplicateField => {
            diag.* = .{ .reason = "duplicate key" };
            return error.InvalidJson;
        },
        else => {
            diag.* = .{ .reason = "not valid JSON" };
            return error.InvalidJson;
        },
    };
    if (root != .object) {
        diag.* = .{ .reason = "top level must be a JSON object" };
        return error.NotAnObject;
    }

    const cfg = &owned.config;
    var extras: std.ArrayListUnmanaged(Extra) = .{};
    var it = root.object.iterator();
    while (it.next()) |entry| {
        const name = entry.key_ptr.*;
        const v = entry.value_ptr.*;
        if (std.mem.eql(u8, name, key.ip_address)) {
            cfg.ip_address = try getString(v, key.ip_address, MAX_IP_LEN, diag);
        } else if (std.mem.eql(u8, name, key.port)) {
            cfg.port = @intCast(try getInt(v, key.port, 1, 65535, diag));
        } else if (std.mem.eql(u8, name, key.auto_start)) {
            cfg.auto_start = try getBool(v, key.auto_start, diag);
        } else if (std.mem.eql(u8, name, key.auth_token)) {
            const tok = try getString(v, key.auth_token, MAX_TOKEN_LEN, diag);
            if (tok.len > 0 and !isValidToken(tok))
                return invalid(diag, key.auth_token, "must be 1-64 printable ASCII characters without spaces, quotes or backslashes");
            cfg.auth_token = tok;
        } else if (std.mem.eql(u8, name, key.allow_external)) {
            cfg.allow_external = try getBool(v, key.allow_external, diag);
        } else if (std.mem.eql(u8, name, key.allowed_clients)) {
            cfg.allowed_clients = try getClients(a, v, diag);
        } else if (std.mem.eql(u8, name, key.max_clients)) {
            cfg.max_clients = @intCast(try getInt(v, key.max_clients, 1, MAX_MAX_CLIENTS, diag));
        } else if (std.mem.eql(u8, name, key.enable_sse)) {
            cfg.enable_sse = try getBool(v, key.enable_sse, diag);
        } else if (std.mem.eql(u8, name, key.artifact_dir)) {
            const dir = try getString(v, key.artifact_dir, pathutil.MAX_PATH_LEN, diag);
            if (dir.len > 0) pathutil.validateArtifactDir(dir) catch |err|
                return invalid(diag, key.artifact_dir, pathutil.describe(err));
            cfg.artifact_dir = dir;
        } else if (std.mem.eql(u8, name, key.auth_max_failures)) {
            cfg.auth_max_failures = @intCast(try getInt(v, key.auth_max_failures, 1, MAX_AUTH_MAX_FAILURES, diag));
        } else if (std.mem.eql(u8, name, key.auth_lockout_seconds)) {
            cfg.auth_lockout_seconds = @intCast(try getInt(v, key.auth_lockout_seconds, 1, MAX_AUTH_LOCKOUT_SECONDS, diag));
        } else {
            // Unknown key: keep it so saving from the dialog does not drop it.
            const js = try std.json.stringifyAlloc(a, v, .{});
            try extras.append(a, .{ .name = name, .json = js });
        }
    }
    cfg.extra = extras.items;
    return owned;
}

fn invalid(diag: *Diagnostic, k: []const u8, reason: []const u8) Error {
    diag.* = .{ .key = k, .reason = reason };
    return error.InvalidValue;
}

fn getString(v: std.json.Value, k: []const u8, max_len: usize, diag: *Diagnostic) Error![]const u8 {
    if (v != .string) return invalid(diag, k, "must be a string");
    if (v.string.len > max_len) return invalid(diag, k, "is too long");
    for (v.string) |c| if (c < 0x20) return invalid(diag, k, "contains control characters");
    return v.string;
}

fn getBool(v: std.json.Value, k: []const u8, diag: *Diagnostic) Error!bool {
    if (v != .bool) return invalid(diag, k, "must be true or false");
    return v.bool;
}

fn getInt(v: std.json.Value, k: []const u8, min: i64, max: i64, diag: *Diagnostic) Error!i64 {
    if (v != .integer) return invalid(diag, k, "must be an integer");
    if (v.integer < min or v.integer > max) return invalid(diag, k, "is out of range");
    return v.integer;
}

fn getClients(a: Allocator, v: std.json.Value, diag: *Diagnostic) Error![]const []const u8 {
    const k = key.allowed_clients;
    if (v != .array) return invalid(diag, k, "must be an array of strings");
    const items = v.array.items;
    if (items.len > MAX_ALLOWED_CLIENTS) return invalid(diag, k, "has too many entries (max 64)");
    const out = try a.alloc([]const u8, items.len);
    for (items, 0..) |item, i| {
        if (item != .string) return invalid(diag, k, "must be an array of strings");
        if (item.string.len > MAX_CLIENT_ENTRY_LEN) return invalid(diag, k, "entry is too long");
        _ = netpolicy.parseCidr(item.string) catch
            return invalid(diag, k, "entries must be IPv4 addresses or CIDR ranges (a.b.c.d/n)");
        out[i] = item.string;
    }
    return out;
}

/// Serialises `cfg` as pretty JSON. The four v1.9 keys come first so an
/// older plugin (which only reads the first 512 bytes) still finds them.
pub fn serialize(allocator: Allocator, cfg: *const Config) Allocator.Error![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    const w = out.writer();

    try w.writeAll("{\n");
    try writeField(w, key.ip_address, cfg.ip_address);
    try w.print("  \"{s}\": {d},\n", .{ key.port, cfg.port });
    try w.print("  \"{s}\": {},\n", .{ key.auto_start, cfg.auto_start });
    try writeField(w, key.auth_token, cfg.auth_token);
    try w.print("  \"{s}\": {},\n", .{ key.allow_external, cfg.allow_external });
    try w.print("  \"{s}\": [", .{key.allowed_clients});
    for (cfg.allowed_clients, 0..) |c, i| {
        if (i > 0) try w.writeAll(", ");
        try std.json.stringify(c, .{}, w);
    }
    try w.writeAll("],\n");
    try w.print("  \"{s}\": {d},\n", .{ key.max_clients, cfg.max_clients });
    try w.print("  \"{s}\": {},\n", .{ key.enable_sse, cfg.enable_sse });
    try writeField(w, key.artifact_dir, cfg.artifact_dir);
    try w.print("  \"{s}\": {d},\n", .{ key.auth_max_failures, cfg.auth_max_failures });
    try w.print("  \"{s}\": {d}", .{ key.auth_lockout_seconds, cfg.auth_lockout_seconds });
    for (cfg.extra) |e| {
        try w.writeAll(",\n  ");
        try std.json.stringify(e.name, .{}, w);
        try w.writeAll(": ");
        try w.writeAll(e.json);
    }
    try w.writeAll("\n}\n");
    return out.toOwnedSlice();
}

fn writeField(w: anytype, name: []const u8, value: []const u8) !void {
    try w.print("  \"{s}\": ", .{name});
    try std.json.stringify(value, .{}, w);
    try w.writeAll(",\n");
}

/// True when `token` is acceptable as AuthToken: 1..64 printable ASCII
/// characters excluding space, double quote and backslash.
pub fn isValidToken(token: []const u8) bool {
    if (token.len == 0 or token.len > MAX_TOKEN_LEN) return false;
    for (token) |c| {
        if (c < 0x21 or c > 0x7E or c == '"' or c == '\\') return false;
    }
    return true;
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
