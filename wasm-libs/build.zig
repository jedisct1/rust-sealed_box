const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{ .default_target = .{ .cpu_arch = .wasm32, .os_tag = .wasi } });
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .fast });
    const lib = b.addLibrary(.{
        .linkage = .static,
        .name = "sealedbox",
        .root_module = b.createModule(.{
            .root_source_file = b.path("sealedbox.zig"),
            .target = target,
            .optimize = optimize,
            .strip = true,
        }),
    });
    b.installArtifact(lib);
}
