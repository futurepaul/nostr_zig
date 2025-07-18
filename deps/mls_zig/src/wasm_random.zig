const std = @import("std");
const builtin = @import("builtin");

/// WebAssembly-compatible random number generation
/// This module provides cryptographically secure randomness that works in both
/// WASM and native environments.

// External random function that can be provided from the host environment
extern fn getRandomValues(buf: [*]u8, len: usize) void;

/// Fill a buffer with cryptographically secure random bytes
/// Works in both WASM and native environments
pub fn fillSecureRandom(buf: []u8) void {
    if (builtin.target.cpu.arch == .wasm32) {
        // In WASM, use the host-provided random function
        getRandomValues(buf.ptr, buf.len);
    } else {
        // On native platforms, use the standard library
        std.crypto.random.bytes(buf);
    }
}

/// Generate secure random bytes (legacy compatibility)
pub fn random_bytes(buf: [*]u8, len: usize) void {
    fillSecureRandom(buf[0..len]);
}

/// Get secure randomness with a crypto.random-like interface
pub const secure_random = struct {
    pub fn bytes(buf: []u8) void {
        fillSecureRandom(buf);
    }
};

/// Random function signature for dependency injection
pub const RandomFunction = fn ([]u8) void;

/// Get the appropriate random function for the current environment
pub fn getRandomFunction() RandomFunction {
    return secure_random.bytes;
}

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