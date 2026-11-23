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

fn isSep(c: u8) bool {
    return c == '\\' or c == '/';
}

/// Classifies the path prefix. Index where the component list starts is
/// returned through `body_start`.
fn classify(p: []const u8, body_start: *usize) Error!Kind {
    if (p.len == 0) return error.EmptyPath;
    if (p.len >= 2 and isSep(p[0]) and isSep(p[1])) {
        // "\\?\", "\\.\" (Win32 device/namespace) and their "//" spellings.
        if (p.len >= 3 and (p[2] == '?' or p[2] == '.') and (p.len == 3 or isSep(p[3])))
            return error.DevicePath;
        // UNC: \\server\share[\...]; server and share are checked like any
        // other component.
        var it = std.mem.tokenizeAny(u8, p[2..], "\\/");
        _ = it.next() orelse return error.InvalidUncPath; // server
        _ = it.next() orelse return error.InvalidUncPath; // share
        body_start.* = 2;
        return .unc;
    }
    if (isSep(p[0])) {
        // "\??\" is the NT object-manager prefix.
        if (p.len >= 4 and p[1] == '?' and p[2] == '?' and isSep(p[3])) return error.DevicePath;
        return error.AmbiguousPath; // rooted on the current drive
    }
    if (p.len >= 2 and p[1] == ':' and std.ascii.isAlphabetic(p[0])) {
        if (p.len == 2 or !isSep(p[2])) return error.AmbiguousPath; // "C:" / "C:x"
        body_start.* = 3;
        return .drive_absolute;
    }
    body_start.* = 0;
    return .relative;
}

const reserved_names = [_][]const u8{
    "CON",  "PRN",  "AUX",  "NUL",
    "COM1", "COM2", "COM3", "COM4",
    "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3",
    "LPT4", "LPT5", "LPT6", "LPT7",
    "LPT8", "LPT9",
};

fn isReservedName(component: []const u8) bool {
    // Windows ignores the extension: "nul.txt" is still the NUL device.
    const dot = std.mem.indexOfScalar(u8, component, '.') orelse component.len;
    const base = std.mem.trimRight(u8, component[0..dot], " ");
    for (reserved_names) |r| {
        if (std.ascii.eqlIgnoreCase(base, r)) return true;
    }
    return false;
}

fn checkComponent(c: []const u8) Error!void {
    if (c.len == 0 or std.mem.eql(u8, c, ".")) return;
    if (std.mem.eql(u8, c, "..")) return error.ParentTraversal;
    // "...", trailing dots and trailing spaces are silently stripped by
    // Win32, which makes two different strings name the same file.
    const last = c[c.len - 1];
    if (last == '.' or last == ' ') return error.BadComponent;
    if (isReservedName(c)) return error.ReservedName;
}

/// Validates `p` and returns its kind.
pub fn validate(p: []const u8) Error!Kind {
    var body_start: usize = 0;
    const kind = try classify(p, &body_start);
    for (p, 0..) |c, i| {
        switch (c) {
            0...0x1F, '"', '<', '>', '|', '*', '?' => return error.InvalidCharacter,
            ':' => if (!(kind == .drive_absolute and i == 1)) return error.AlternateDataStream,
            else => {},
        }
    }
    var it = std.mem.splitAny(u8, p[body_start..], "\\/");
    while (it.next()) |comp| try checkComponent(comp);
    return kind;
}

/// ArtifactDir must be a valid absolute (drive or UNC) path.
pub fn validateArtifactDir(dir: []const u8) Error!void {
    const kind = try validate(dir);
    if (kind == .relative) return error.NotAbsolute;
}

/// Copies `s` to `out[pos..]`, converting '/' to '\'.
fn appendNormalized(out: []u8, pos: *usize, s: []const u8) Error!void {
    if (out.len - pos.* < s.len) return error.PathTooLong;
    for (s, 0..) |c, i| out[pos.* + i] = if (c == '/') '\\' else c;
    pos.* += s.len;
}

/// Resolves `file_path` against `artifact_dir` into `buf`.
pub fn resolve(buf: []u8, artifact_dir: []const u8, file_path: []const u8) Error![]const u8 {
    const out = buf[0..@min(buf.len, MAX_PATH_LEN)];
    const kind = try validate(file_path);
    var pos: usize = 0;
    if (kind == .relative and artifact_dir.len > 0) {
        try validateArtifactDir(artifact_dir);
        var dir = artifact_dir;
        while (dir.len > 0 and isSep(dir[dir.len - 1])) dir = dir[0 .. dir.len - 1];
        try appendNormalized(out, &pos, dir);
        try appendNormalized(out, &pos, "\\");
    }
    try appendNormalized(out, &pos, file_path);
    return out[0..pos];
}

/// Short human-readable explanation for tool error messages.
pub fn describe(err: Error) []const u8 {
    return switch (err) {
        error.EmptyPath => "path is empty",
        error.PathTooLong => "path is too long",
        error.InvalidCharacter => "path contains a control character or one of \" < > | ? *",
        error.AlternateDataStream => "':' is only allowed after the drive letter (no alternate data streams)",
        error.ParentTraversal => "'..' path components are not allowed",
        error.DevicePath => "device/namespace paths (\\\\?\\, \\\\.\\, \\??\\) are not allowed",
        error.AmbiguousPath => "path must be relative, 'X:\\...' or '\\\\server\\share\\...' (no '\\x' or 'X:x')",
        error.InvalidUncPath => "UNC path needs both a server and a share",
        error.BadComponent => "path components must not end with '.' or ' '",
        error.ReservedName => "reserved device name (CON, NUL, COM1, ...) in path",
        error.NotAbsolute => "ArtifactDir must be an absolute path",
    };
}

/// Process-wide current ArtifactDir (set from config or SetArtifactDir).
pub const ArtifactDirState = struct {
    lock: sync.RwLock = .{},
    buf: [MAX_PATH_LEN]u8 = undefined,
    len: usize = 0,

    /// Validates and stores `dir`; an empty string clears it.
    pub fn set(self: *ArtifactDirState, dir: []const u8) Error!void {
        if (dir.len > 0) try validateArtifactDir(dir);
        if (dir.len > MAX_PATH_LEN) return error.PathTooLong;
        self.lock.lock();
        defer self.lock.unlock();
        @memcpy(self.buf[0..dir.len], dir);
        self.len = dir.len;
    }

    /// Copies the current value into `out` ("" when unset).
    pub fn get(self: *ArtifactDirState, out: *[MAX_PATH_LEN]u8) []const u8 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        @memcpy(out[0..self.len], self.buf[0..self.len]);
        return out[0..self.len];
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
    try expectRejected(out_dir, "\\\\..\\share\\a", error.ParentTraversal);
    try expectRejected(out_dir, "\\\\srv\\..\\a", error.ParentTraversal);
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
