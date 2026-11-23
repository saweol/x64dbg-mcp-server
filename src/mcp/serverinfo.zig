//! GetServerInfo payload (pure, host-testable).
//!
//! Lets a client (the VM gateway) identify the backend it is talking to:
//! which debugger/arch answers on this port, which process (pid of the
//! x64dbg process itself, to detect port re-use after a restart), what is
//! loaded and where relative dump paths go.

const std = @import("std");
const json = @import("json.zig");
const JsonWriter = json.JsonWriter;

pub const ServerInfo = struct {
    arch: []const u8,
    version: []const u8,
    pid: u32,
    /// null when no debuggee is loaded.
    debuggee_path: ?[]const u8,
    /// null when no ArtifactDir is configured.
    artifact_dir: ?[]const u8,
};

/// "x64" for the .dp64 build, "x32" for the .dp32 build.
pub fn archName() []const u8 {
    return if (@sizeOf(usize) == 8) "x64" else "x32";
}

/// Writes {backend, arch, version, pid, debuggee_path, artifact_dir,
/// capabilities, max_chunk} as a JSON object.
pub fn write(w: *JsonWriter, info: ServerInfo) void {
    w.beginObject();
    w.fieldStr("backend", "x64dbg");
    w.fieldStr("arch", info.arch);
    w.fieldStr("version", info.version);
    w.fieldInt("pid", info.pid);
    if (info.debuggee_path) |p| w.fieldStr("debuggee_path", p) else w.fieldNull("debuggee_path");
    if (info.artifact_dir) |d| w.fieldStr("artifact_dir", d) else w.fieldNull("artifact_dir");
    // P7 file tools are not implemented, so no chunked transfer (max_chunk 0).
    w.fieldRaw("capabilities", "[\"artifact_dir\"]");
    w.fieldInt("max_chunk", 0);
    w.endObject();
}

// ── Tests ───────────────────────────────────────────────────────────

const testing = std.testing;

test "archName matches the pointer width" {
    const want = if (@sizeOf(usize) == 8) "x64" else "x32";
    try testing.expectEqualStrings(want, archName());
}

test "write produces the documented JSON object" {
    var buf: [1024]u8 = undefined;
    var w = JsonWriter.init(&buf);
    write(&w, .{
        .arch = "x64",
        .version = "1.10",
        .pid = 4242,
        .debuggee_path = "C:\\mcp\\jobs\\1\\in\\ab12.exe",
        .artifact_dir = "C:\\mcp\\jobs\\1\\out",
    });
    try testing.expect(!w.overflow);
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, w.slice(), .{});
    defer parsed.deinit();
    const o = parsed.value.object;
    try testing.expectEqualStrings("x64dbg", o.get("backend").?.string);
    try testing.expectEqualStrings("x64", o.get("arch").?.string);
    try testing.expectEqualStrings("1.10", o.get("version").?.string);
    try testing.expectEqual(@as(i64, 4242), o.get("pid").?.integer);
    try testing.expectEqualStrings("C:\\mcp\\jobs\\1\\in\\ab12.exe", o.get("debuggee_path").?.string);
    try testing.expectEqualStrings("C:\\mcp\\jobs\\1\\out", o.get("artifact_dir").?.string);
    const caps = o.get("capabilities").?.array.items;
    try testing.expectEqual(@as(usize, 1), caps.len);
    try testing.expectEqualStrings("artifact_dir", caps[0].string);
    try testing.expectEqual(@as(i64, 0), o.get("max_chunk").?.integer);
    try testing.expectEqual(@as(usize, 8), o.count());
}

test "write emits null for missing debuggee and artifact dir" {
    var buf: [512]u8 = undefined;
    var w = JsonWriter.init(&buf);
    write(&w, .{ .arch = "x32", .version = "1.10", .pid = 1, .debuggee_path = null, .artifact_dir = null });
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, w.slice(), .{});
    defer parsed.deinit();
    const o = parsed.value.object;
    try testing.expect(o.get("debuggee_path").? == .null);
    try testing.expect(o.get("artifact_dir").? == .null);
}
