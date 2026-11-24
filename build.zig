const std = @import("std");

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});

    // ── x32 plugin (.dp32) ──────────────────────────────────────────
    const x32_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = b.resolveTargetQuery(.{
            .cpu_arch = .x86,
            .os_tag = .windows,
            .abi = .gnu,
        }),
        .optimize = optimize,
    });
    x32_mod.linkSystemLibrary("kernel32", .{});
    x32_mod.linkSystemLibrary("ws2_32", .{});
    x32_mod.linkSystemLibrary("user32", .{});

    const x32 = b.addLibrary(.{
        .name = "x64dbg-MCP-Server",
        .root_module = x32_mod,
        .linkage = .dynamic,
    });

    const install_x32 = b.addInstallArtifact(x32, .{
        .dest_dir = .{ .override = .{ .custom = "x32/plugins" } },
        .dest_sub_path = "x64dbg-MCP-Server.dp32",
        .implib_dir = .disabled,
        .pdb_dir = .disabled,
    });

    // ── x64 plugin (.dp64) ──────────────────────────────────────────
    const x64_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = b.resolveTargetQuery(.{
            .cpu_arch = .x86_64,
            .os_tag = .windows,
            .abi = .gnu,
        }),
        .optimize = optimize,
    });
    x64_mod.linkSystemLibrary("kernel32", .{});
    x64_mod.linkSystemLibrary("ws2_32", .{});
    x64_mod.linkSystemLibrary("user32", .{});

    const x64 = b.addLibrary(.{
        .name = "x64dbg-MCP-Server",
        .root_module = x64_mod,
        .linkage = .dynamic,
    });

    const install_x64 = b.addInstallArtifact(x64, .{
        .dest_dir = .{ .override = .{ .custom = "x64/plugins" } },
        .dest_sub_path = "x64dbg-MCP-Server.dp64",
        .implib_dir = .disabled,
        .pdb_dir = .disabled,
    });

    b.default_step.dependOn(&install_x32.step);
    b.default_step.dependOn(&install_x64.step);

    // ── Tests (host target, no x64dbg / Win32 UI deps) ───────────────
    // Each file below is pure logic that the plugin wires in; they must not
    // import bridge.zig or anything that needs x64dbg at runtime.
    const test_step = b.step("test", "Run unit tests");
    const test_files = [_][]const u8{
        "src/mcp/json.zig",
        "src/mcp/cmdline.zig",
        "src/mcp/serverinfo.zig",
        "src/mcp/toolpolicy.zig",
        "src/mcp/debugstate.zig",
        "src/mcp/dbsave.zig",
        "src/core/sync.zig",
        "src/core/ring.zig",
        "src/core/netpolicy.zig",
        "src/core/http.zig",
        "src/core/cfgjson.zig",
        "src/core/pathutil.zig",
        "src/core/launch.zig",
        "src/core/ssehub.zig",
    };
    for (test_files) |path| {
        const test_mod = b.createModule(.{
            .root_source_file = b.path(path),
            .target = b.graph.host,
            .optimize = optimize,
        });
        const unit_tests = b.addTest(.{ .root_module = test_mod });
        const run_tests = b.addRunArtifact(unit_tests);
        test_step.dependOn(&run_tests.step);
    }
}
