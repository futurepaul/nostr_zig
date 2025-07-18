const std = @import("std");
const mls_zig_lib = @import("mls_zig_lib");

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    
    // Test basic cipher suite functionality from the library
    const cs = mls_zig_lib.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    const hash_len = cs.hashLength();
    
    try stdout.print("Hello from MLS Zig!\n", .{});
    try stdout.print("Testing library: Cipher suite hash length = {}\n", .{hash_len});
    try stdout.print("This is vibes-based cryptography - use at your own risk! 🎉\n", .{});
}