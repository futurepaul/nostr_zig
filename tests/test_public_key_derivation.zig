const std = @import("std");
const testing = std.testing;
const crypto = @import("nostr").crypto;

/// Test public key derivation against known secp256k1 test vectors
/// These vectors come from the secp256k1 library test suite and BIP340
test "Public key derivation with known test vectors" {
    
    // Test vector 1: Private key 0x0000...0001
    {
        var private_key: [32]u8 = undefined;
        @memset(&private_key, 0);
        private_key[31] = 0x01;
        
        const public_key = try crypto.getPublicKey(private_key);
        const public_key_hex = try std.fmt.allocPrint(testing.allocator, "{s}", .{std.fmt.fmtSliceHexLower(&public_key)});
        defer testing.allocator.free(public_key_hex);
        
        // Expected x-only public key for private key 0x01
        const expected = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        
        std.debug.print("\nTest vector 1 (privkey 0x01):\n", .{});
        std.debug.print("  Private key: {s}\n", .{std.fmt.fmtSliceHexLower(&private_key)});
        std.debug.print("  Public key:  {s}\n", .{public_key_hex});
        std.debug.print("  Expected:    {s}\n", .{expected});
        std.debug.print("  Match: {}\n", .{std.mem.eql(u8, public_key_hex, expected)});
        
        try testing.expectEqualStrings(expected, public_key_hex);
    }
    
    // Test vector 2: Private key 0x0000...0003
    {
        var private_key: [32]u8 = undefined;
        @memset(&private_key, 0);
        private_key[31] = 0x03;
        
        const public_key = try crypto.getPublicKey(private_key);
        const public_key_hex = try std.fmt.allocPrint(testing.allocator, "{s}", .{std.fmt.fmtSliceHexLower(&public_key)});
        defer testing.allocator.free(public_key_hex);
        
        // Expected x-only public key for private key 0x03
        const expected = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
        
        std.debug.print("\nTest vector 2 (privkey 0x03):\n", .{});
        std.debug.print("  Private key: {s}\n", .{std.fmt.fmtSliceHexLower(&private_key)});
        std.debug.print("  Public key:  {s}\n", .{public_key_hex});
        std.debug.print("  Expected:    {s}\n", .{expected});
        std.debug.print("  Match: {}\n", .{std.mem.eql(u8, public_key_hex, expected)});
        
        try testing.expectEqualStrings(expected, public_key_hex);
    }
    
    // Test vector 3: Private key 0xB7E1...51E0 (BIP340 test vector)
    {
        const private_key_hex = "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF";
        var private_key: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&private_key, private_key_hex);
        
        const public_key = try crypto.getPublicKey(private_key);
        const public_key_hex = try std.fmt.allocPrint(testing.allocator, "{s}", .{std.fmt.fmtSliceHexLower(&public_key)});
        defer testing.allocator.free(public_key_hex);
        
        // Expected x-only public key for this private key
        const expected = "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659";
        
        std.debug.print("\nTest vector 3 (BIP340 vector):\n", .{});
        std.debug.print("  Private key: {s}\n", .{std.fmt.fmtSliceHexLower(&private_key)});
        std.debug.print("  Public key:  {s}\n", .{public_key_hex});
        std.debug.print("  Expected:    {s}\n", .{expected});
        std.debug.print("  Match: {}\n", .{std.mem.eql(u8, public_key_hex, expected)});
        
        try testing.expectEqualStrings(expected, public_key_hex);
    }
}

/// Test that sign and verify work with our public keys
test "Sign and verify consistency" {
    // Test with private key 0x03
    var private_key: [32]u8 = undefined;
    @memset(&private_key, 0);
    private_key[31] = 0x03;
    
    const public_key = try crypto.getPublicKey(private_key);
    
    // Create a test message
    var message: [32]u8 = undefined;
    @memset(&message, 0);
    
    std.debug.print("\nSign/verify consistency test:\n", .{});
    std.debug.print("  Private key: {s}\n", .{std.fmt.fmtSliceHexLower(&private_key)});
    std.debug.print("  Public key:  {s}\n", .{std.fmt.fmtSliceHexLower(&public_key)});
    std.debug.print("  Message:     {s}\n", .{std.fmt.fmtSliceHexLower(&message)});
    
    // Sign the message
    const signature = try crypto.signMessage(&message, private_key);
    std.debug.print("  Signature:   {s}\n", .{std.fmt.fmtSliceHexLower(&signature)});
    
    // Verify the signature
    const is_valid = try crypto.verifyMessageSignature(&message, signature, public_key);
    std.debug.print("  Verified:    {}\n", .{is_valid});
    
    try testing.expect(is_valid);
    
    // Test with wrong message should fail
    var wrong_message: [32]u8 = undefined;
    @memset(&wrong_message, 0);
    wrong_message[0] = 0x01;
    
    const is_invalid = try crypto.verifyMessageSignature(&wrong_message, signature, public_key);
    std.debug.print("  Wrong msg:   {} (should be false)\n", .{is_invalid});
    try testing.expect(!is_invalid);
}

/// Test event signing and verification
test "Event signing with test vectors" {
    // Use private key 0x03
    var private_key: [32]u8 = undefined;
    @memset(&private_key, 0);
    private_key[31] = 0x03;
    
    const public_key = try crypto.getPublicKey(private_key);
    const public_key_hex = try std.fmt.allocPrint(testing.allocator, "{s}", .{std.fmt.fmtSliceHexLower(&public_key)});
    defer testing.allocator.free(public_key_hex);
    
    // Create a test event ID (should be 64 hex chars)
    const event_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    
    std.debug.print("\nEvent signing test:\n", .{});
    std.debug.print("  Private key: {s}\n", .{std.fmt.fmtSliceHexLower(&private_key)});
    std.debug.print("  Public key:  {s}\n", .{public_key_hex});
    std.debug.print("  Event ID:    {s}\n", .{event_id});
    
    // Sign the event
    const signature = try crypto.signEvent(event_id, private_key);
    const signature_hex = try std.fmt.allocPrint(testing.allocator, "{s}", .{std.fmt.fmtSliceHexLower(&signature)});
    defer testing.allocator.free(signature_hex);
    
    std.debug.print("  Signature:   {s}\n", .{signature_hex});
    
    // Verify the signature
    const is_valid = try crypto.verifySignature(event_id, signature, public_key);
    std.debug.print("  Verified:    {}\n", .{is_valid});
    
    try testing.expect(is_valid);
}