//! MLS-Zig: Vibes-based MLS implementation for NIP-EE integration
//! 
//! This is the main library entry point. Import this as `@import("mls_zig")`
//! to get access to all the MLS functionality.
//!
//! WARNING: THIS IS ALL VIBES, NOT ACTUAL CRYPTOGRAPHY!

const std = @import("std");
const testing = std.testing;

// Core MLS modules - these are the main APIs you'll use
pub const cipher_suite = @import("cipher_suite.zig");
pub const mls_group = @import("mls_group.zig");
pub const key_package = @import("key_package.zig");
pub const credentials = @import("credentials.zig");
pub const nostr_extensions = @import("nostr_extensions.zig");
pub const key_package_flat = @import("key_package_flat.zig");
pub const key_schedule = @import("key_schedule.zig");

// Lower-level modules - you probably don't need these directly
pub const tree_math = @import("tree_math.zig");
pub const binary_tree = @import("binary_tree.zig");
pub const binary_tree_diff = @import("binary_tree_diff.zig");
pub const tls_encode = @import("tls_encode.zig");
pub const leaf_node = @import("leaf_node.zig");
pub const tree_kem = @import("tree_kem.zig");

// HPKE module exposure for external use
pub const hpke = @import("hpke");

// Re-export the most commonly used types for convenience
pub const CipherSuite = cipher_suite.CipherSuite;
pub const Secret = cipher_suite.Secret;
pub const MlsGroup = mls_group.MlsGroup;
// Use flat KeyPackage as the default (WASM-safe, corruption-free)
pub const KeyPackageBundle = key_package_flat.KeyPackageBundle;
pub const KeyPackage = key_package_flat.KeyPackage;
pub const BasicCredential = credentials.BasicCredential;
pub const Credential = credentials.Credential;
pub const KeySchedule = key_schedule.KeySchedule;
pub const EpochSecrets = key_schedule.EpochSecrets;

test "library loads and basic functionality works" {
    // Test that we can create a cipher suite (basic vibes check)
    const cs = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    try testing.expect(cs.hashLength() == 32);
}
