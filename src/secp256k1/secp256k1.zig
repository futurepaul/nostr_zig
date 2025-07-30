const std = @import("std");
const crypto = std.crypto;

// Import the C library functions
pub const c = @cImport({
    @cInclude("secp256k1.h");
    @cInclude("secp256k1_extrakeys.h");
    @cInclude("secp256k1_schnorrsig.h");
    @cInclude("secp256k1_ecdh.h");
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

// High-level API wrapper
pub const Secp256k1 = struct {
    ctx: ?*secp256k1_context,
    
    pub fn genNew() Secp256k1 {
        const ctx = c.secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        return Secp256k1{ .ctx = ctx };
    }
    
    pub fn randomize(self: *Secp256k1, seed: *const [32]u8) void {
        if (self.ctx) |ctx| {
            _ = c.secp256k1_context_randomize(ctx, seed);
        }
    }
    
    pub fn deinit(self: Secp256k1) void {
        if (self.ctx) |ctx| {
            c.secp256k1_context_destroy(ctx);
        }
    }
};

pub const SecretKey = struct {
    data: [32]u8,
    
    pub fn fromSlice(bytes: *const [32]u8) !SecretKey {
        // Create a temporary context for validation
        const ctx = c.secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
        defer c.secp256k1_context_destroy(ctx);
        
        if (ctx == null) return error.ContextCreationFailed;
        
        // Verify the key is valid
        if (c.secp256k1_ec_seckey_verify(ctx, bytes) != 1) {
            return error.InvalidSecretKey;
        }
        
        return SecretKey{ .data = bytes.* };
    }
};

pub const PublicKey = struct {
    inner: secp256k1_pubkey,
    
    pub fn fromSecretKey(secp: Secp256k1, sk: SecretKey) !PublicKey {
        const ctx = secp.ctx orelse return error.InvalidContext;
        
        var pubkey: secp256k1_pubkey = undefined;
        if (c.secp256k1_ec_pubkey_create(ctx, &pubkey, &sk.data) != 1) {
            return error.PublicKeyCreationFailed;
        }
        
        return PublicKey{ .inner = pubkey };
    }
    
    pub fn serialize(self: PublicKey, secp: Secp256k1) ![33]u8 {
        const ctx = secp.ctx orelse return error.InvalidContext;
        
        var result: [33]u8 = undefined;
        var result_len: usize = 33;
        
        if (c.secp256k1_ec_pubkey_serialize(
            ctx,
            &result,
            &result_len,
            &self.inner,
            c.SECP256K1_EC_COMPRESSED
        ) != 1) {
            return error.SerializationFailed;
        }
        
        if (result_len != 33) {
            return error.UnexpectedSerializedLength;
        }
        
        return result;
    }
};
pub const secp256k1_xonly_pubkey = c.secp256k1_xonly_pubkey;

// Context management
pub const secp256k1_context_create = c.secp256k1_context_create;
pub const secp256k1_context_destroy = c.secp256k1_context_destroy;
pub const secp256k1_context_randomize = c.secp256k1_context_randomize;

// Key operations
pub const secp256k1_ec_seckey_verify = c.secp256k1_ec_seckey_verify;
pub const secp256k1_ec_pubkey_create = c.secp256k1_ec_pubkey_create;
pub const secp256k1_ec_pubkey_serialize = c.secp256k1_ec_pubkey_serialize;
pub const secp256k1_ec_pubkey_parse = c.secp256k1_ec_pubkey_parse;

// ECDH operations
pub const secp256k1_ecdh = c.secp256k1_ecdh;

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