const std = @import("std");

// External function for randomness
extern fn getRandomValues(buf: [*]u8, len: usize) void;

// Simple key generation that just uses random bytes for testing
export fn wasm_generate_simple_keys(out_private_key: [*]u8, out_public_key: [*]u8) bool {
    // Generate random private key
    getRandomValues(out_private_key, 32);
    
    // For now, just use a simple transformation for the public key
    // In real implementation, this would use secp256k1
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        out_public_key[i] = out_private_key[i] ^ 0xFF;
    }
    
    return true;
}

// Test if we can at least generate random bytes
export fn wasm_test_random_generation(out_bytes: [*]u8, len: usize) void {
    getRandomValues(out_bytes, len);
}