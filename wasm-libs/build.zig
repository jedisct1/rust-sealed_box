const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{ .default_target = .{ .cpu_arch = .wasm32, .os_tag = .wasi } });
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseFast });
    const lib = b.addStaticLibrary(.{
        .name = "sealedbox",
        .root_source_file = .{ .path = "sealedbox.zig" },
        .target = target,
        .optimize = optimize,
    });
    lib.strip = true;
    b.installArtifact(lib);
}
