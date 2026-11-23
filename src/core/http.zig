//! Minimal HTTP/1.1 request parsing helpers (pure, host-testable).
//!
//! The server reads one request per connection into a fixed buffer; these
//! helpers decide when the request is complete and extract the pieces the
//! dispatcher needs. Header names are matched case-insensitively.
//! All functions are pure and thread-safe.

const std = @import("std");

pub fn findHeaderEnd(data: []const u8) ?usize {
    _ = data;
    return null;
}

/// Value of the first header called `name` (case-insensitive), with
/// surrounding spaces/tabs trimmed. `headers` excludes the final CRLFCRLF.
pub fn headerValue(headers: []const u8, name: []const u8) ?[]const u8 {
    _ = headers;
    _ = name;
    return null;
}

pub const ContentLengthError = error{InvalidContentLength};

/// Content-Length of the request: 0 when absent, an error when malformed,
/// overflowing, or repeated with different values.
pub fn contentLength(headers: []const u8) ContentLengthError!usize {
    _ = headers;
    return error.InvalidContentLength;
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
    _ = received;
    _ = capacity;
    return .bad;
}

pub const RequestLine = struct { method: []const u8, path: []const u8 };

/// Splits "METHOD SP PATH SP VERSION" (only the first line is examined).
pub fn parseRequestLine(data: []const u8) ?RequestLine {
    _ = data;
    return null;
}

/// Token from "Authorization: Bearer <token>" (scheme is case-insensitive).
pub fn bearerToken(headers: []const u8) ?[]const u8 {
    _ = headers;
    return null;
}

/// Value of `?name=value` / `&name=value` in a request path.
pub fn queryParam(path: []const u8, name: []const u8) ?[]const u8 {
    _ = path;
    _ = name;
    return null;
}

/// Path without the query string.
pub fn pathOnly(path: []const u8) []const u8 {
    _ = path;
    return "";
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
