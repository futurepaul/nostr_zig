const std = @import("std");
const testing = std.testing;
const crypto = @import("nostr").crypto;

test "Schnorr sign and verify" {
    const allocator = testing.allocator;
    
    // Test 1: Basic sign and verify
    {
        // Generate a test private key
        const private_key = try crypto.generatePrivateKey();
        const public_key = try crypto.getPublicKey(private_key);
        
        // Create a test message
        var message: [32]u8 = undefined;
        message[0] = 0x01;
        for (1..32) |i| {
            message[i] = 0x00;
        }
        
        // Sign the message
        const signature = try crypto.signMessage(&message, private_key);
        
        // Verify the signature
        const is_valid = try crypto.verifyMessageSignature(&message, signature, public_key);
        try testing.expect(is_valid);
        
        // Test with wrong message should fail
        var wrong_message: [32]u8 = undefined;
        wrong_message[0] = 0x02;
        for (1..32) |i| {
            wrong_message[i] = 0x00;
        }
        const is_invalid = try crypto.verifyMessageSignature(&wrong_message, signature, public_key);
        try testing.expect(!is_invalid);
    }
    
    // Test 2: Event signing and verification
    {
        const private_key = try crypto.generatePrivateKey();
        const public_key = try crypto.getPublicKey(private_key);
        
        // Create a test event ID
        const event_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        
        // Sign the event
        const signature = try crypto.signEvent(event_id, private_key);
        
        // Verify the signature
        const is_valid = try crypto.verifySignature(event_id, signature, public_key);
        try testing.expect(is_valid);
    }
    
    // Test 3: Known test vector
    {
        // Use the same test key as in TypeScript
        var private_key: [32]u8 = undefined;
        private_key[0] = 0x01;
        for (1..32) |i| {
            private_key[i] = 0x00;
        }
        
        const public_key = try crypto.getPublicKey(private_key);
        
        // Print for comparison
        std.debug.print("\nTest vector:\n", .{});
        std.debug.print("Private key: {s}\n", .{std.fmt.fmtSliceHexLower(&private_key)});
        std.debug.print("Public key: {s}\n", .{std.fmt.fmtSliceHexLower(&public_key)});
        
        // Sign a message
        var message: [32]u8 = undefined;
        message[0] = 0x01;
        for (1..32) |i| {
            message[i] = 0x00;
        }
        
        const signature = try crypto.signMessage(&message, private_key);
        std.debug.print("Message: {s}\n", .{std.fmt.fmtSliceHexLower(&message)});
        std.debug.print("Signature: {s}\n", .{std.fmt.fmtSliceHexLower(&signature)});
        
        // Verify
        const is_valid = try crypto.verifyMessageSignature(&message, signature, public_key);
        std.debug.print("Verification result: {}\n", .{is_valid});
        try testing.expect(is_valid);
    }
}