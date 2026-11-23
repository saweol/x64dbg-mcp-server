//! Benign E2E test sample for x64dbg-vm-gateway (no network, no persistence).
//! Prints a marker, writes a small file next to itself, loops a few times so a
//! debugger can break in, then exits 0.
const std = @import("std");
const windows = std.os.windows;

extern "kernel32" fn GetTickCount() callconv(.winapi) u32;
extern "kernel32" fn Sleep(ms: u32) callconv(.winapi) void;

export var e2e_marker: [32]u8 = "X64DBG-VM-GATEWAY-E2E-MARKER\x00\x00\x00\x00".*;

fn work(i: u32) u32 {
    // Distinct, easy-to-find function for breakpoint tests.
    return (i *% 2654435761) ^ GetTickCount();
}

pub fn main() !void {
    const out = std.io.getStdOut().writer();
    try out.print("e2e sample start {s}\n", .{std.mem.sliceTo(&e2e_marker, 0)});
    var acc: u32 = 0;
    var i: u32 = 0;
    while (i < 5) : (i += 1) {
        acc +%= work(i);
        Sleep(500);
    }
    const f = try std.fs.cwd().createFile("e2e_sample_output.txt", .{});
    defer f.close();
    try f.writer().print("acc={d}\n", .{acc});
    try out.print("e2e sample done\n", .{});
}
