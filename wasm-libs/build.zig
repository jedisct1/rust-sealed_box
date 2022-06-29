const std = @import("std");

pub fn build(b: *std.build.Builder) !void {
    const target = try std.zig.CrossTarget.parse(.{ .arch_os_abi = "wasm32-wasi" });
    const lib = b.addStaticLibrary("sealedbox", "sealedbox.zig");
    lib.setTarget(target);
    lib.setBuildMode(.ReleaseSmall);
    lib.strip = true;
    lib.install();
}
