const std = @import("std");

/// WebAssembly random number generation support
/// This module provides cryptographically secure randomness in WASM environments
/// by calling out to the browser's crypto.getRandomValues()

// Declare the JS function that will be provided by the host
extern fn getRandomValues(buf: [*]u8, len: usize) void;

/// Fill a buffer with cryptographically secure random bytes from the browser
pub fn fillSecureRandom(buf: []u8) void {
    // Always use external random in WASM builds
    const builtin = @import("builtin");
    if (builtin.target.cpu.arch == .wasm32) {
        // In WASM, use the browser's crypto API
        getRandomValues(buf.ptr, buf.len);
    } else {
        // On native platforms, use the standard library
        std.crypto.random.bytes(buf);
    }
}

/// Generate secure random bytes
pub fn random_bytes(buf: [*]u8, len: usize) void {
    fillSecureRandom(buf[0..len]);
}

/// Get secure randomness that works in both WASM and native environments
pub const secure_random = struct {
    pub fn bytes(buf: []u8) void {
        fillSecureRandom(buf);
    }
};

test "secure random generation" {
    var buf: [32]u8 = undefined;
    secure_random.bytes(&buf);
    
    // Verify not all zeros
    var all_zero = true;
    for (buf) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
}