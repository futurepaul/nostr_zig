const std = @import("std");

// Import the C library functions
pub const c = @cImport({
    @cInclude("secp256k1.h");
    @cInclude("secp256k1_extrakeys.h");
    @cInclude("secp256k1_schnorrsig.h");
});

// Re-export commonly used constants
pub const SECP256K1_CONTEXT_SIGN = c.SECP256K1_CONTEXT_SIGN;
pub const SECP256K1_CONTEXT_VERIFY = c.SECP256K1_CONTEXT_VERIFY;
pub const SECP256K1_EC_COMPRESSED = c.SECP256K1_EC_COMPRESSED;
pub const SECP256K1_EC_UNCOMPRESSED = c.SECP256K1_EC_UNCOMPRESSED;

// Re-export types
pub const secp256k1_context = c.secp256k1_context;
pub const secp256k1_pubkey = c.secp256k1_pubkey;
pub const secp256k1_keypair = c.secp256k1_keypair;
pub const secp256k1_xonly_pubkey = c.secp256k1_xonly_pubkey;

// Context management
pub const secp256k1_context_create = c.secp256k1_context_create;
pub const secp256k1_context_destroy = c.secp256k1_context_destroy;
pub const secp256k1_context_randomize = c.secp256k1_context_randomize;

// Key operations
pub const secp256k1_ec_seckey_verify = c.secp256k1_ec_seckey_verify;
pub const secp256k1_ec_pubkey_create = c.secp256k1_ec_pubkey_create;
pub const secp256k1_ec_pubkey_serialize = c.secp256k1_ec_pubkey_serialize;

// Keypair operations (for Schnorr)
pub const secp256k1_keypair_create = c.secp256k1_keypair_create;
pub const secp256k1_keypair_pub = c.secp256k1_keypair_pub;
pub const secp256k1_keypair_xonly_pub = c.secp256k1_keypair_xonly_pub;

// X-only public key operations
pub const secp256k1_xonly_pubkey_parse = c.secp256k1_xonly_pubkey_parse;
pub const secp256k1_xonly_pubkey_serialize = c.secp256k1_xonly_pubkey_serialize;
pub const secp256k1_xonly_pubkey_from_pubkey = c.secp256k1_xonly_pubkey_from_pubkey;

// Schnorr signature operations (BIP340)
pub const secp256k1_schnorrsig_sign32 = c.secp256k1_schnorrsig_sign32;
pub const secp256k1_schnorrsig_verify = c.secp256k1_schnorrsig_verify;

// Tagged SHA256 (used by Schnorr)
pub const secp256k1_tagged_sha256 = c.secp256k1_tagged_sha256;

// Utility functions for Zig integration
pub fn createContext(flags: u32) !*secp256k1_context {
    return secp256k1_context_create(flags) orelse error.ContextCreationFailed;
}

pub fn destroyContext(ctx: *secp256k1_context) void {
    secp256k1_context_destroy(ctx);
}

// Test to ensure the module compiles and links correctly
test "secp256k1 basic test" {
    const ctx = try createContext(SECP256K1_CONTEXT_SIGN);
    defer destroyContext(ctx);
    
    // Test with a known private key
    const private_key = [_]u8{
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    };
    
    // Verify the private key is valid
    try std.testing.expect(secp256k1_ec_seckey_verify(ctx, &private_key) == 1);
    
    // Create keypair for Schnorr operations
    var keypair: secp256k1_keypair = undefined;
    try std.testing.expect(secp256k1_keypair_create(ctx, &keypair, &private_key) == 1);
    
    // Extract x-only public key
    var xonly_pubkey: secp256k1_xonly_pubkey = undefined;
    var pk_parity: c_int = undefined;
    try std.testing.expect(secp256k1_keypair_xonly_pub(ctx, &xonly_pubkey, &pk_parity, &keypair) == 1);
    
    // Serialize x-only public key
    var pubkey_bytes: [32]u8 = undefined;
    try std.testing.expect(secp256k1_xonly_pubkey_serialize(ctx, &pubkey_bytes, &xonly_pubkey) == 1);
    
    // The public key should not be all zeros
    var all_zeros = true;
    for (pubkey_bytes) |byte| {
        if (byte != 0) {
            all_zeros = false;
            break;
        }
    }
    try std.testing.expect(!all_zeros);
}