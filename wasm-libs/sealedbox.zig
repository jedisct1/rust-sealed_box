const std = @import("std");
const SealedBox = std.crypto.nacl.SealedBox;

export fn seal(c: [*c]u8, c_len: usize, m: [*c]const u8, m_len: usize, pk: [*c]const [SealedBox.public_length]u8) callconv(.C) i32 {
    SealedBox.seal(c[0..c_len], m[0..m_len], pk.*) catch |_| return -1;
    return 0;
}

export fn open(m: [*c]u8, m_len: usize, c: [*c]const u8, c_len: usize, pk: [*c]const [SealedBox.public_length]u8, sk: [*c]const [SealedBox.secret_length]u8) callconv(.C) i32 {
    SealedBox.open(m[0..m_len], c[0..c_len], .{ .public_key = pk.*, .secret_key = sk.* }) catch |_| return -1;
    return 0;
}

export fn keygen(pk: [*c][SealedBox.public_length]u8, sk: [*c][SealedBox.secret_length]u8) callconv(.C) void {
    const kp = SealedBox.KeyPair.create(null) catch unreachable;
    pk.* = kp.public_key;
    sk.* = kp.secret_key;
}
