const std = @import("std");
const nip44 = @import("../src/nip44/v2.zig");
const crypto = @import("../src/crypto.zig");

test "NIP-44 raw bytes encryption/decryption" {
    const allocator = std.testing.allocator;
    
    std.debug.print("\n🧪 Testing NIP-44 Raw Bytes Encryption/Decryption...\n", .{});
    
    // Test 1: Basic encrypt/decrypt with exporter secret
    std.debug.print("\n1. Testing basic NIP-44 encryption with raw bytes...\n", .{});
    
    // Generate a test exporter secret
    const exporter_secret = crypto.generatePrivateKey() catch unreachable;
    
    const test_message = "Hello, NIP-44 raw bytes!";
    
    // Ensure the key is valid for secp256k1
    const private_key = crypto.generateValidSecp256k1Key(exporter_secret) catch unreachable;
    const public_key = crypto.getPublicKeyForNip44(private_key) catch unreachable;
    
    // Encrypt the message
    const encrypted = try nip44.encryptRaw(
        allocator,
        private_key,
        public_key,
        test_message,
    );
    defer allocator.free(encrypted);
    
    std.debug.print("  ✅ Encrypted {} bytes -> {} bytes\n", .{ test_message.len, encrypted.len });
    std.debug.print("  First 16 bytes: {x}\n", .{encrypted[0..@min(16, encrypted.len)]});
    
    // Decrypt the message
    const decrypted = try nip44.decryptBytes(
        allocator,
        private_key,
        public_key,
        encrypted,
    );
    defer allocator.free(decrypted);
    
    std.debug.print("  ✅ Decrypted back to {} bytes\n", .{decrypted.len});
    
    // Verify content matches
    try std.testing.expectEqualSlices(u8, test_message, decrypted);
    std.debug.print("  ✅ Content matches: '{s}'\n", .{decrypted});
}

test "NIP-44 with various message sizes" {
    const allocator = std.testing.allocator;
    
    std.debug.print("\n2. Testing NIP-44 with various message sizes...\n", .{});
    
    const test_sizes = [_]usize{ 0, 1, 16, 31, 32, 33, 64, 128, 256, 1000 };
    
    const private_key = crypto.generateValidSecp256k1Key(crypto.generatePrivateKey() catch unreachable) catch unreachable;
    const public_key = crypto.getPublicKeyForNip44(private_key) catch unreachable;
    
    for (test_sizes) |size| {
        // Create test message of specific size
        const message = try allocator.alloc(u8, size);
        defer allocator.free(message);
        @memset(message, 'A');
        
        // Encrypt
        const encrypted = try nip44.encryptRaw(allocator, private_key, public_key, message);
        defer allocator.free(encrypted);
        
        // Decrypt
        const decrypted = try nip44.decryptBytes(allocator, private_key, public_key, encrypted);
        defer allocator.free(decrypted);
        
        // Verify
        try std.testing.expectEqualSlices(u8, message, decrypted);
        
        const padded_len = nip44.calcPaddedLen(size);
        std.debug.print("  Size {} -> padded {} -> encrypted {} bytes ✅\n", .{ size, padded_len, encrypted.len });
    }
}

test "NIP-44 padding calculation" {
    std.debug.print("\n3. Testing NIP-44 padding calculation...\n", .{});
    
    // Test cases from NIP-44 spec
    const test_cases = [_]struct { input: usize, expected: usize }{
        .{ .input = 0, .expected = 32 },
        .{ .input = 1, .expected = 32 },
        .{ .input = 16, .expected = 32 },
        .{ .input = 31, .expected = 32 },
        .{ .input = 32, .expected = 32 },
        .{ .input = 33, .expected = 64 },
        .{ .input = 64, .expected = 64 },
        .{ .input = 65, .expected = 96 },
        .{ .input = 128, .expected = 128 },
        .{ .input = 129, .expected = 192 },
        .{ .input = 256, .expected = 256 },
        .{ .input = 257, .expected = 320 },
        .{ .input = 384, .expected = 384 },
        .{ .input = 385, .expected = 448 },
    };
    
    for (test_cases) |tc| {
        const result = nip44.calcPaddedLen(tc.input);
        try std.testing.expectEqual(tc.expected, result);
        std.debug.print("  calcPaddedLen({}) = {} ✅\n", .{ tc.input, result });
    }
}

test "NIP-44 error handling" {
    const allocator = std.testing.allocator;
    
    std.debug.print("\n4. Testing NIP-44 error handling...\n", .{});
    
    // Test with invalid ciphertext (too short)
    const too_short = [_]u8{0x02}; // Just version byte
    const private_key = crypto.generatePrivateKey() catch unreachable;
    const public_key = crypto.getPublicKey(private_key) catch unreachable;
    
    const result = nip44.decryptBytes(allocator, private_key, public_key, &too_short);
    try std.testing.expectError(nip44.Nip44Error.InvalidPayload, result);
    std.debug.print("  ✅ Correctly rejected too-short ciphertext\n", .{});
    
    // Test with wrong version
    var bad_version: [97]u8 = undefined;
    bad_version[0] = 0x99; // Invalid version
    @memset(bad_version[1..], 0);
    
    const result2 = nip44.decryptBytes(allocator, private_key, public_key, &bad_version);
    try std.testing.expectError(nip44.Nip44Error.UnsupportedVersion, result2);
    std.debug.print("  ✅ Correctly rejected invalid version\n", .{});
}