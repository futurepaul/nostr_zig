const std = @import("std");
pub const v2 = @import("v2.zig");

/// NIP-44 error types
pub const Nip44Error = error{
    InvalidVersion,
    InvalidLength,
    InvalidHmac,
    InvalidPadding,
    MessageEmpty,
    MessageTooLong,
    Base64DecodeError,
    HexDecodeError,
    CryptoError,
    InvalidSecretKey,
    InvalidPublicKey,
    OutOfMemory,
};

/// Supported NIP-44 versions
pub const Version = enum(u8) {
    v2 = 0x02,
    
    pub fn fromByte(byte: u8) Nip44Error!Version {
        return switch (byte) {
            0x02 => .v2,
            else => Nip44Error.InvalidVersion,
        };
    }
};

/// Encrypt a message using NIP-44
/// Returns base64-encoded payload
pub fn encrypt(
    allocator: std.mem.Allocator,
    secret_key: [32]u8,
    public_key: [32]u8,
    content: []const u8,
) Nip44Error![]u8 {
    return v2.encrypt(allocator, secret_key, public_key, content);
}

/// Derive public key from secret key using secp256k1
pub fn derivePublicKey(secret_key: [32]u8) Nip44Error![32]u8 {
    const secp = @import("secp256k1");
    
    const ctx = secp.secp256k1_context_create(secp.SECP256K1_CONTEXT_SIGN) orelse return Nip44Error.CryptoError;
    defer secp.secp256k1_context_destroy(ctx);
    
    // Verify secret key
    if (secp.secp256k1_ec_seckey_verify(ctx, &secret_key) != 1) {
        return Nip44Error.InvalidSecretKey;
    }
    
    // Generate public key
    var pubkey: secp.secp256k1_pubkey = undefined;
    if (secp.secp256k1_ec_pubkey_create(ctx, &pubkey, &secret_key) != 1) {
        return Nip44Error.CryptoError;
    }
    
    // Serialize public key in compressed format
    var public_key_bytes: [33]u8 = undefined;
    var output_len: usize = 33;
    if (secp.secp256k1_ec_pubkey_serialize(ctx, &public_key_bytes, &output_len, &pubkey, secp.SECP256K1_EC_COMPRESSED) != 1) {
        return Nip44Error.CryptoError;
    }
    
    // Return 32-byte x-only public key (skip the prefix byte)
    var result: [32]u8 = undefined;
    @memcpy(&result, public_key_bytes[1..33]);
    return result;
}

/// Decrypt a NIP-44 encrypted message
/// Accepts base64-encoded payload
/// The second parameter can be either a public key or secret key
pub fn decrypt(
    allocator: std.mem.Allocator,
    secret_key: [32]u8,
    public_key_or_secret_key: [32]u8,
    payload: []const u8,
) Nip44Error![]u8 {
    // Try to use the second parameter as a public key first
    const result = decryptWithKey(allocator, secret_key, public_key_or_secret_key, payload);
    if (result) |res| {
        return res;
    } else |err| {
        if (err == Nip44Error.InvalidPublicKey) {
            // Try treating the second parameter as a secret key and derive public key
            const derived_public_key = derivePublicKey(public_key_or_secret_key) catch return err;
            return decryptWithKey(allocator, secret_key, derived_public_key, payload);
        } else {
            return err;
        }
    }
}

/// Internal decrypt implementation that expects a public key
fn decryptWithKey(
    allocator: std.mem.Allocator,
    secret_key: [32]u8,
    public_key: [32]u8,
    payload: []const u8,
) Nip44Error![]u8 {
    // Decode base64 payload
    const decoded_payload = std.base64.standard.Decoder.calcSizeForSlice(payload) catch return Nip44Error.Base64DecodeError;
    const payload_bytes = try allocator.alloc(u8, decoded_payload);
    defer allocator.free(payload_bytes);
    
    _ = std.base64.standard.Decoder.decode(payload_bytes, payload) catch return Nip44Error.Base64DecodeError;
    
    if (payload_bytes.len == 0) return Nip44Error.InvalidLength;
    
    // Check version and route to appropriate implementation
    const version = Version.fromByte(payload_bytes[0]) catch return Nip44Error.InvalidVersion;
    
    return switch (version) {
        .v2 => v2.decryptBytes(allocator, secret_key, public_key, payload_bytes),
    };
}

/// Get conversation key from ECDH shared secret
pub fn getConversationKey(secret_key: [32]u8, public_key: [32]u8) Nip44Error!v2.ConversationKey {
    return v2.ConversationKey.fromKeys(secret_key, public_key);
}

test {
    std.testing.refAllDecls(@This());
}