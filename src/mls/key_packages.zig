const std = @import("std");
const types = @import("types.zig");
const mls_zig = @import("mls_zig");

/// Key package generation parameters
pub const KeyPackageParams = struct {
    /// Cipher suite to use
    cipher_suite: types.Ciphersuite = .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
    
    /// Lifetime in seconds (default 30 days)
    lifetime_seconds: u64 = 30 * 24 * 60 * 60,
    
    /// Extensions to include
    extensions: []const types.Extension = &.{},
};

// =============================================================================
// IMPORTANT: This file is mostly deprecated. We now use flat KeyPackages from
// mls_zig.key_package_flat which use fixed-size arrays and don't need complex
// memory management.
//
// New code should use:
//   - mls_zig.key_package_flat.KeyPackageBundle for creating KeyPackages
//   - mls_zig.key_package_flat.KeyPackage for the flat KeyPackage structure
//   - KeyPackage.tlsSerialize() and KeyPackage.tlsDeserialize() for serialization
// =============================================================================

/// Check if cipher suite is supported
pub fn isSupportedCipherSuite(cipher_suite: types.Ciphersuite) bool {
    return switch (cipher_suite) {
        .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        .MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
        => true,
        else => false,
    };
}

/// Check if string is valid hex
pub fn isHexString(s: []const u8) bool {
    if (s.len == 0 or s.len % 2 != 0) return false;
    for (s) |c| {
        if (!std.ascii.isHex(c)) return false;
    }
    return true;
}

// All the legacy functions have been removed.
// Use mls_zig.key_package_flat instead for KeyPackage operations.