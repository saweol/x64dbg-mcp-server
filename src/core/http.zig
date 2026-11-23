//! Minimal HTTP/1.1 request parsing helpers (pure, host-testable).
//!
//! The server reads one request per connection into a fixed buffer; these
//! helpers decide when the request is complete and extract the pieces the
//! dispatcher needs. Header names are matched case-insensitively.
//! All functions are pure and thread-safe.

const std = @import("std");

pub fn findHeaderEnd(data: []const u8) ?usize {
    return std.mem.indexOf(u8, data, "\r\n\r\n");
}

/// Iterates header lines after the request line.
const HeaderIterator = struct {
    rest: []const u8,

    fn init(headers: []const u8) HeaderIterator {
        const first_end = std.mem.indexOf(u8, headers, "\r\n") orelse return .{ .rest = "" };
        return .{ .rest = headers[first_end + 2 ..] };
    }

    const Header = struct { name: []const u8, value: []const u8 };

    fn next(self: *HeaderIterator) ?Header {
        while (self.rest.len > 0) {
            const end = std.mem.indexOf(u8, self.rest, "\r\n") orelse self.rest.len;
            const line = self.rest[0..end];
            self.rest = if (end + 2 <= self.rest.len) self.rest[end + 2 ..] else "";
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
            return .{
                .name = std.mem.trim(u8, line[0..colon], " \t"),
                .value = std.mem.trim(u8, line[colon + 1 ..], " \t"),
            };
        }
        return null;
    }
};

/// Value of the first header called `name` (case-insensitive), with
/// surrounding spaces/tabs trimmed. `headers` is the request head (request
/// line + header lines, without the final CRLFCRLF); the request line is
/// skipped.
pub fn headerValue(headers: []const u8, name: []const u8) ?[]const u8 {
    var it = HeaderIterator.init(headers);
    while (it.next()) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
    }
    return null;
}

pub const ContentLengthError = error{InvalidContentLength};

/// Content-Length of the request: 0 when absent, an error when malformed,
/// overflowing, or repeated with different values.
pub fn contentLength(headers: []const u8) ContentLengthError!usize {
    var result: ?usize = null;
    var it = HeaderIterator.init(headers);
    while (it.next()) |h| {
        if (!std.ascii.eqlIgnoreCase(h.name, "Content-Length")) continue;
        if (h.value.len == 0) return error.InvalidContentLength;
        for (h.value) |c| if (c < '0' or c > '9') return error.InvalidContentLength;
        const v = std.fmt.parseInt(usize, h.value, 10) catch return error.InvalidContentLength;
        if (result) |prev| {
            if (prev != v) return error.InvalidContentLength;
        }
        result = v;
    }
    return result orelse 0;
}

pub const RequestState = union(enum) {
    /// More bytes are needed.
    incomplete,
    /// Request fully received. `header_end` is the index of CRLFCRLF.
    complete: struct { header_end: usize, body_len: usize },
    /// The request cannot fit in a buffer of the given capacity.
    too_large,
    /// Malformed framing (e.g. invalid Content-Length).
    bad,
};

/// Classifies the bytes received so far for a buffer of `capacity` bytes.
pub fn requestState(received: []const u8, capacity: usize) RequestState {
    const header_end = findHeaderEnd(received) orelse
        return if (received.len >= capacity) .too_large else .incomplete;
    const body_len = contentLength(received[0..header_end]) catch return .bad;
    const head_len = header_end + 4;
    if (body_len > capacity -| head_len) return .too_large;
    if (received.len < head_len + body_len) return .incomplete;
    return .{ .complete = .{ .header_end = header_end, .body_len = body_len } };
}

pub const RequestLine = struct { method: []const u8, path: []const u8 };

/// Splits "METHOD SP PATH SP VERSION" (only the first line is examined).
pub fn parseRequestLine(data: []const u8) ?RequestLine {
    const line_end = std.mem.indexOf(u8, data, "\r\n") orelse data.len;
    const line = data[0..line_end];
    var it = std.mem.splitScalar(u8, line, ' ');
    const method = it.next() orelse return null;
    const path = it.next() orelse return null;
    if (method.len == 0 or path.len == 0) return null;
    return .{ .method = method, .path = path };
}

/// Token from "Authorization: Bearer <token>" (scheme is case-insensitive).
pub fn bearerToken(headers: []const u8) ?[]const u8 {
    const v = headerValue(headers, "Authorization") orelse return null;
    const scheme = "bearer";
    if (v.len <= scheme.len) return null;
    if (!std.ascii.eqlIgnoreCase(v[0..scheme.len], scheme)) return null;
    if (v[scheme.len] != ' ' and v[scheme.len] != '\t') return null;
    const tok = std.mem.trim(u8, v[scheme.len..], " \t");
    return if (tok.len == 0) null else tok;
}

/// Value of `?name=value` / `&name=value` in a request path.
pub fn queryParam(path: []const u8, name: []const u8) ?[]const u8 {
    const q = std.mem.indexOfScalar(u8, path, '?') orelse return null;
    var it = std.mem.splitScalar(u8, path[q + 1 ..], '&');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        if (std.mem.eql(u8, pair[0..eq], name)) return pair[eq + 1 ..];
    }
    return null;
}

/// Path without the query string.
pub fn pathOnly(path: []const u8) []const u8 {
    const q = std.mem.indexOfScalar(u8, path, '?') orelse return path;
    return path[0..q];
}

// ── Tests ───────────────────────────────────────────────────────────

const testing = std.testing;

test "findHeaderEnd locates CRLFCRLF" {
    try testing.expectEqual(@as(?usize, 14), findHeaderEnd("GET / HTTP/1.1\r\n\r\nbody"));
    try testing.expectEqual(@as(?usize, null), findHeaderEnd("GET / HTTP/1.1\r\nHost: x\r\n"));
}

test "headerValue is case-insensitive, anchored and trimmed" {
    const h = "POST / HTTP/1.1\r\nX-Authorization: nope\r\nauthorization:   Bearer abc  \r\nContent-Type: application/json";
    try testing.expectEqualStrings("Bearer abc", headerValue(h, "Authorization").?);
    try testing.expectEqualStrings("application/json", headerValue(h, "content-type").?);
    try testing.expectEqual(@as(?[]const u8, null), headerValue(h, "Mcp-Session-Id"));
    try testing.expectEqualStrings("nope", headerValue(h, "X-Authorization").?);
}

test "headerValue ignores the request line and empty values work" {
    const h = "GET /Host: x HTTP/1.1\r\nHost:\r\nA: b";
    try testing.expectEqualStrings("", headerValue(h, "Host").?);
    try testing.expectEqualStrings("b", headerValue(h, "A").?);
}

test "contentLength parses strictly" {
    try testing.expectEqual(@as(usize, 12), try contentLength("POST / HTTP/1.1\r\nContent-Length: 12"));
    try testing.expectEqual(@as(usize, 7), try contentLength("POST / HTTP/1.1\r\ncontent-length:7"));
    try testing.expectEqual(@as(usize, 0), try contentLength("GET / HTTP/1.1\r\nHost: x"));
    try testing.expectEqual(@as(usize, 5), try contentLength("POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 5"));
    try testing.expectError(error.InvalidContentLength, contentLength("POST / HTTP/1.1\r\nContent-Length: abc"));
    try testing.expectError(error.InvalidContentLength, contentLength("POST / HTTP/1.1\r\nContent-Length: 1 2"));
    try testing.expectError(error.InvalidContentLength, contentLength("POST / HTTP/1.1\r\nContent-Length: -1"));
    try testing.expectError(error.InvalidContentLength, contentLength("POST / HTTP/1.1\r\nContent-Length: "));
    try testing.expectError(error.InvalidContentLength, contentLength("POST / HTTP/1.1\r\nContent-Length: 99999999999999999999999"));
    try testing.expectError(error.InvalidContentLength, contentLength("POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 6"));
}

test "requestState tracks completeness and size limits" {
    try testing.expect(requestState("GET / HTTP/1.1\r\nHost: x\r\n", 1024) == .incomplete);

    const get = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    switch (requestState(get, 1024)) {
        .complete => |c| {
            try testing.expectEqual(@as(usize, get.len - 4), c.header_end);
            try testing.expectEqual(@as(usize, 0), c.body_len);
        },
        else => return error.TestUnexpectedResult,
    }

    const partial = "POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\n12345";
    try testing.expect(requestState(partial, 1024) == .incomplete);

    const full = "POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\n12345";
    switch (requestState(full, 1024)) {
        .complete => |c| try testing.expectEqual(@as(usize, 5), c.body_len),
        else => return error.TestUnexpectedResult,
    }

    // Body announced larger than the buffer can ever hold.
    try testing.expect(requestState("POST / HTTP/1.1\r\nContent-Length: 2000\r\n\r\n", 1024) == .too_large);
    // Headers that never end within the buffer.
    const junk = "GET / HTTP/1.1\r\n" ++ "X: y\r\n" ** 20;
    try testing.expect(requestState(junk, junk.len) == .too_large);
    try testing.expect(requestState("POST / HTTP/1.1\r\nContent-Length: zz\r\n\r\n", 1024) == .bad);
}

test "parseRequestLine splits method and path" {
    const rl = parseRequestLine("POST /messages?sessionId=3 HTTP/1.1\r\nHost: x").?;
    try testing.expectEqualStrings("POST", rl.method);
    try testing.expectEqualStrings("/messages?sessionId=3", rl.path);
    const opt = parseRequestLine("OPTIONS / HTTP/1.1").?;
    try testing.expectEqualStrings("OPTIONS", opt.method);
    try testing.expectEqualStrings("/", opt.path);
    try testing.expectEqual(@as(?RequestLine, null), parseRequestLine("garbage"));
    try testing.expectEqual(@as(?RequestLine, null), parseRequestLine(""));
}

test "bearerToken extracts the token" {
    try testing.expectEqualStrings("abc", bearerToken("GET / HTTP/1.1\r\nAuthorization: Bearer abc").?);
    try testing.expectEqualStrings("abc", bearerToken("GET / HTTP/1.1\r\nauthorization: bearer   abc").?);
    try testing.expectEqual(@as(?[]const u8, null), bearerToken("GET / HTTP/1.1\r\nAuthorization: Basic abc"));
    try testing.expectEqual(@as(?[]const u8, null), bearerToken("GET / HTTP/1.1\r\nAuthorization: Bearer"));
    try testing.expectEqual(@as(?[]const u8, null), bearerToken("GET / HTTP/1.1\r\nAuthorization: Bearerabc"));
    try testing.expectEqual(@as(?[]const u8, null), bearerToken("GET / HTTP/1.1\r\nHost: x"));
}

test "queryParam and pathOnly" {
    try testing.expectEqualStrings("42", queryParam("/messages?a=1&sessionId=42", "sessionId").?);
    try testing.expectEqualStrings("1", queryParam("/messages?a=1&sessionId=42", "a").?);
    try testing.expectEqual(@as(?[]const u8, null), queryParam("/messages?a=1", "sessionId"));
    try testing.expectEqual(@as(?[]const u8, null), queryParam("/messages", "a"));
    try testing.expectEqual(@as(?[]const u8, null), queryParam("/m?flag&x", "flag"));
    try testing.expectEqualStrings("/messages", pathOnly("/messages?a=1"));
    try testing.expectEqualStrings("/", pathOnly("/"));
}
