const std = @import("std");
const testing = std.testing;

// Import the simplified module
const key_package_simple = @import("deps/mls_zig/src/key_package_simple.zig");

test "simple KeyPackage test" {
    // Test the fixed-size arrays approach
    var init_key: [32]u8 = undefined;
    var enc_key: [32]u8 = undefined;
    var sig_key: [32]u8 = undefined;
    var signature: [64]u8 = undefined;
    
    // Fill with test data
    @memset(&init_key, 0x01);
    @memset(&enc_key, 0x02);
    @memset(&sig_key, 0x03);
    @memset(&signature, 0x04);
    
    const cs = key_package_simple.cipher_suite.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    
    const key_package = key_package_simple.KeyPackage.init(
        cs,
        init_key,
        enc_key,
        sig_key,
        "test@example.com",
        signature,
    );
    
    // Verify fixed sizes - no corruption possible
    try testing.expectEqual(@as(usize, 32), key_package.init_key.len);
    try testing.expectEqual(@as(usize, 32), key_package.encryption_key.len);
    try testing.expectEqual(@as(usize, 32), key_package.signature_key.len);
    try testing.expectEqual(@as(usize, 64), key_package.signature.len);
    
    // Verify MLS compliance
    try testing.expectEqual(key_package_simple.MLS_PROTOCOL_VERSION, key_package.protocol_version);
    try testing.expectEqual(cs, key_package.cipher_suite);
    
    std.debug.print("✅ Simple KeyPackage test passed!\n", .{});
}