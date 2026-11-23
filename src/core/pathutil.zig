//! Guest (Windows) path validation and ArtifactDir resolution
//! (pure, host-testable).
//!
//! Rules for file paths passed to dump/save tools:
//!   - absolute drive paths ("C:\x") and UNC paths ("\\server\share\x")
//!     are used as-is;
//!   - relative paths are joined to ArtifactDir (or passed through
//!     unchanged when no ArtifactDir is set, as in v1.9);
//!   - rejected everywhere: "..", NUL and other control characters,
//!     alternate data streams (":" other than the drive colon),
//!     device/namespace prefixes ("\\?\", "\\.\", "\??\"), rooted paths
//!     without a drive ("\x"), drive-relative paths ("C:x"), reserved
//!     device names (CON, NUL, COM1, ...), characters Windows does not
//!     allow in names (" < > | ? *) and components ending in "." or " ".
//! Forward slashes are normalised to backslashes in resolved output.
//!
//! Thread-safety: functions are pure. `ArtifactDirState` is internally locked.

const std = @import("std");
const sync = @import("sync.zig");

pub const MAX_PATH_LEN = 1024;

pub const Error = error{
    EmptyPath,
    PathTooLong,
    InvalidCharacter,
    AlternateDataStream,
    ParentTraversal,
    DevicePath,
    AmbiguousPath,
    InvalidUncPath,
    BadComponent,
    ReservedName,
    NotAbsolute,
};

pub const Kind = enum { relative, drive_absolute, unc };

/// Validates `p` and returns its kind.
pub fn validate(p: []const u8) Error!Kind {
    _ = p;
    return error.EmptyPath;
}

/// ArtifactDir must be a valid absolute (drive or UNC) path.
pub fn validateArtifactDir(dir: []const u8) Error!void {
    _ = dir;
    return error.EmptyPath;
}

/// Resolves `file_path` against `artifact_dir` into `buf`.
pub fn resolve(buf: []u8, artifact_dir: []const u8, file_path: []const u8) Error![]const u8 {
    _ = buf;
    _ = artifact_dir;
    _ = file_path;
    return error.EmptyPath;
}

/// Short human-readable explanation for tool error messages.
pub fn describe(err: Error) []const u8 {
    return switch (err) {
        else => "",
    };
}

/// Process-wide current ArtifactDir (set from config or SetArtifactDir).
pub const ArtifactDirState = struct {
    lock: sync.RwLock = .{},
    buf: [MAX_PATH_LEN]u8 = undefined,
    len: usize = 0,

    /// Validates and stores `dir`; an empty string clears it.
    pub fn set(self: *ArtifactDirState, dir: []const u8) Error!void {
        _ = self;
        _ = dir;
    }

    /// Copies the current value into `out` ("" when unset).
    pub fn get(self: *ArtifactDirState, out: *[MAX_PATH_LEN]u8) []const u8 {
        _ = self;
        return out[0..0];
    }
};

// ── Tests ───────────────────────────────────────────────────────────

const testing = std.testing;

fn expectResolved(dir: []const u8, file: []const u8, want: []const u8) !void {
    var buf: [MAX_PATH_LEN]u8 = undefined;
    const got = resolve(&buf, dir, file) catch |err| {
        std.debug.print("resolve('{s}', '{s}') failed: {s}\n", .{ dir, file, @errorName(err) });
        return err;
    };
    try testing.expectEqualStrings(want, got);
}

fn expectRejected(dir: []const u8, file: []const u8, want: Error) !void {
    var buf: [MAX_PATH_LEN]u8 = undefined;
    if (resolve(&buf, dir, file)) |got| {
        std.debug.print("resolve('{s}', '{s}') accepted -> '{s}'\n", .{ dir, file, got });
        return error.TestUnexpectedResult;
    } else |err| try testing.expectEqual(want, err);
}

const out_dir = "C:\\mcp\\jobs\\1\\out";

test "relative paths are joined to ArtifactDir" {
    try expectResolved(out_dir, "dump.bin", "C:\\mcp\\jobs\\1\\out\\dump.bin");
    try expectResolved(out_dir, "mods/kernel32.dll", "C:\\mcp\\jobs\\1\\out\\mods\\kernel32.dll");
    try expectResolved("C:\\out\\", "a.bin", "C:\\out\\a.bin");
    try expectResolved("C:\\", "a.bin", "C:\\a.bin");
    try expectResolved("\\\\srv\\share\\jobs", "a.bin", "\\\\srv\\share\\jobs\\a.bin");
    try expectResolved(out_dir, ".\\a.bin", "C:\\mcp\\jobs\\1\\out\\.\\a.bin");
}

test "absolute paths are used as-is" {
    try expectResolved(out_dir, "D:\\x\\y.bin", "D:\\x\\y.bin");
    try expectResolved(out_dir, "d:/x/y.bin", "d:\\x\\y.bin");
    try expectResolved(out_dir, "\\\\server\\share\\a.bin", "\\\\server\\share\\a.bin");
    try expectResolved("", "C:\\dumps\\a.bin", "C:\\dumps\\a.bin");
}

test "without ArtifactDir relative paths pass through (v1.9 behaviour)" {
    try expectResolved("", "dump.bin", "dump.bin");
    try expectResolved("", "sub/dump.bin", "sub\\dump.bin");
}

test "traversal, streams and device paths are rejected" {
    try expectRejected(out_dir, "..\\a.bin", error.ParentTraversal);
    try expectRejected(out_dir, "a/../../b", error.ParentTraversal);
    try expectRejected(out_dir, "C:\\out\\..\\x", error.ParentTraversal);
    try expectRejected(out_dir, "...\\a", error.BadComponent);
    try expectRejected(out_dir, "a.bin:stream", error.AlternateDataStream);
    try expectRejected(out_dir, "C:\\a:b", error.AlternateDataStream);
    try expectRejected(out_dir, "1:\\x", error.AlternateDataStream);
    try expectRejected(out_dir, "\\\\?\\C:\\a", error.DevicePath);
    try expectRejected(out_dir, "\\\\.\\PhysicalDrive0", error.DevicePath);
    try expectRejected(out_dir, "//./pipe/x", error.DevicePath);
    try expectRejected(out_dir, "\\??\\C:\\a", error.DevicePath);
    try expectRejected(out_dir, "\\rooted\\path", error.AmbiguousPath);
    try expectRejected(out_dir, "C:relative", error.AmbiguousPath);
    try expectRejected(out_dir, "\\\\server", error.InvalidUncPath);
    try expectRejected(out_dir, "\\\\server\\", error.InvalidUncPath);
}

test "bad characters and names are rejected" {
    try expectRejected(out_dir, "", error.EmptyPath);
    try expectRejected(out_dir, "a\x00b", error.InvalidCharacter);
    try expectRejected(out_dir, "a\nb", error.InvalidCharacter);
    try expectRejected(out_dir, "a\"b", error.InvalidCharacter);
    try expectRejected(out_dir, "a|b", error.InvalidCharacter);
    try expectRejected(out_dir, "a*b", error.InvalidCharacter);
    try expectRejected(out_dir, "a?b", error.InvalidCharacter);
    try expectRejected(out_dir, "a<b>", error.InvalidCharacter);
    try expectRejected(out_dir, "a.\\b", error.BadComponent);
    try expectRejected(out_dir, "a \\b", error.BadComponent);
    try expectRejected(out_dir, "dump.bin.", error.BadComponent);
    try expectRejected(out_dir, "CON", error.ReservedName);
    try expectRejected(out_dir, "sub\\nul.txt", error.ReservedName);
    try expectRejected(out_dir, "C:\\x\\Com1.bin", error.ReservedName);
    try expectRejected(out_dir, "lpt9", error.ReservedName);
}

test "reserved-name check does not over-match" {
    try expectResolved(out_dir, "console.bin", "C:\\mcp\\jobs\\1\\out\\console.bin");
    try expectResolved(out_dir, "com10.bin", "C:\\mcp\\jobs\\1\\out\\com10.bin");
    try expectResolved(out_dir, "nullable", "C:\\mcp\\jobs\\1\\out\\nullable");
}

test "overlong results are rejected" {
    const long = "a" ** (MAX_PATH_LEN - 4);
    try expectRejected(out_dir, long, error.PathTooLong);
    var small: [8]u8 = undefined;
    try testing.expectError(error.PathTooLong, resolve(&small, out_dir, "x.bin"));
}

test "validateArtifactDir requires an absolute path" {
    try validateArtifactDir("C:\\mcp");
    try validateArtifactDir("C:\\");
    try validateArtifactDir("e:/jobs/out");
    try validateArtifactDir("\\\\srv\\share\\x");
    try testing.expectError(error.NotAbsolute, validateArtifactDir("relative"));
    try testing.expectError(error.AmbiguousPath, validateArtifactDir("C:"));
    try testing.expectError(error.EmptyPath, validateArtifactDir(""));
    try testing.expectError(error.ParentTraversal, validateArtifactDir("C:\\a\\.."));
    try testing.expectError(error.DevicePath, validateArtifactDir("\\\\?\\C:\\x"));
}

test "validate classifies paths" {
    try testing.expectEqual(Kind.relative, try validate("a\\b.bin"));
    try testing.expectEqual(Kind.drive_absolute, try validate("Z:\\b.bin"));
    try testing.expectEqual(Kind.unc, try validate("\\\\h\\s\\b.bin"));
}

test "describe gives a message for every error" {
    inline for (@typeInfo(Error).error_set.?) |e| {
        try testing.expect(describe(@field(Error, e.name)).len > 0);
    }
}

test "ArtifactDirState stores, validates and clears" {
    var st: ArtifactDirState = .{};
    var out: [MAX_PATH_LEN]u8 = undefined;
    try testing.expectEqualStrings("", st.get(&out));
    try st.set("C:\\jobs\\out");
    try testing.expectEqualStrings("C:\\jobs\\out", st.get(&out));
    try testing.expectError(error.NotAbsolute, st.set("rel"));
    // A rejected value leaves the previous one in place.
    try testing.expectEqualStrings("C:\\jobs\\out", st.get(&out));
    try st.set("");
    try testing.expectEqualStrings("", st.get(&out));
}
