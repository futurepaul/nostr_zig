const std = @import("std");
const mls_zig = @import("mls_zig");
const crypto = @import("../crypto.zig");
const secp256k1 = @import("secp256k1");
const provider = @import("provider.zig");
const hkdf = @import("../crypto/hkdf.zig");

/// HKDF expand operation using shared implementation
pub fn hkdfExpand(allocator: std.mem.Allocator, prk: []const u8, info: []const u8, length: usize) ![]u8 {
    return try hkdf.expand(allocator, prk, info, length);
}

/// HKDF extract operation using shared implementation
pub fn hkdfExtract(allocator: std.mem.Allocator, salt: []const u8, ikm: []const u8) ![]u8 {
    return try hkdf.extract(allocator, salt, ikm);
}

/// Derive MLS signing key from Nostr private key
pub fn deriveMlsSigningKey(allocator: std.mem.Allocator, nostr_private_key: [32]u8) ![]u8 {
    // Derive MLS signing key from Nostr private key using HKDF
    const salt = "nostr-to-mls-signing-key";
    const prk = try hkdfExtract(allocator, salt, &nostr_private_key);
    defer allocator.free(prk);
    
    const info = "mls-signing-key";
    const signing_key = try hkdfExpand(allocator, prk, info, 32);
    
    return signing_key;
}

/// Derive MLS HPKE key from Nostr private key
pub fn deriveMlsHpkeKey(allocator: std.mem.Allocator, nostr_private_key: [32]u8) ![]u8 {
    // Derive MLS HPKE key from Nostr private key using HKDF
    const salt = "nostr-to-mls-hpke-key";
    const prk = try hkdfExtract(allocator, salt, &nostr_private_key);
    defer allocator.free(prk);
    
    const info = "mls-hpke-key";
    const hpke_key = try hkdfExpand(allocator, prk, info, 32);
    
    return hpke_key;
}

/// Derive MLS public key from MLS private key using Ed25519
pub fn deriveMlsPublicKey(allocator: std.mem.Allocator, mls_private_key: []const u8) ![32]u8 {
    _ = allocator;
    
    if (mls_private_key.len != 32) {
        return error.InvalidKeyLength;
    }
    
    const key_pair = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(mls_private_key[0..32].*) catch |err| return err;
    return key_pair.public_key.bytes;
}

/// Create deterministic ephemeral keypair for a given input seed
pub fn createEphemeralKeypair(allocator: std.mem.Allocator, seed: []const u8) !struct { private_key: [32]u8, public_key: [32]u8 } {
    // Use HKDF to derive a deterministic key from the seed
    const salt = "ephemeral-keypair";
    const prk = try hkdfExtract(allocator, salt, seed);
    defer allocator.free(prk);
    
    const info = "secp256k1-key";
    const key_material = try hkdfExpand(allocator, prk, info, 32);
    defer allocator.free(key_material);
    
    var private_key: [32]u8 = undefined;
    @memcpy(&private_key, key_material[0..32]);
    
    // Ensure the key is valid for secp256k1
    const ctx = secp256k1.getContext();
    var keypair: secp256k1.secp256k1_keypair = undefined;
    const result = secp256k1.secp256k1_keypair_create(ctx, &keypair, &private_key);
    if (result != 1) {
        return error.InvalidPrivateKey;
    }
    
    // Extract public key
    var pubkey: secp256k1.secp256k1_pubkey = undefined;
    _ = secp256k1.secp256k1_keypair_pub(ctx, &pubkey, &keypair);
    
    var public_key: [32]u8 = undefined;
    _ = secp256k1.secp256k1_xonly_pubkey_from_pubkey(ctx, @ptrCast(&public_key), null, &pubkey);
    
    return .{
        .private_key = private_key,
        .public_key = public_key,
    };
}

test "hkdf operations" {
    const allocator = std.testing.allocator;
    
    // Test HKDF extract
    const salt = "test-salt";
    const ikm = "test-input-key-material";
    const prk = try hkdfExtract(allocator, salt, ikm);
    defer allocator.free(prk);
    try std.testing.expectEqual(@as(usize, 32), prk.len);
    
    // Test HKDF expand
    const info = "test-info";
    const output = try hkdfExpand(allocator, prk, info, 64);
    defer allocator.free(output);
    try std.testing.expectEqual(@as(usize, 64), output.len);
}

test "key derivation" {
    const allocator = std.testing.allocator;
    
    // Test key with all zeros (just for testing)
    var nostr_key: [32]u8 = [_]u8{0} ** 32;
    nostr_key[0] = 1; // Make it non-zero
    
    // Test MLS signing key derivation
    const signing_key = try deriveMlsSigningKey(allocator, nostr_key);
    defer allocator.free(signing_key);
    try std.testing.expectEqual(@as(usize, 32), signing_key.len);
    
    // Test MLS HPKE key derivation
    const hpke_key = try deriveMlsHpkeKey(allocator, nostr_key);
    defer allocator.free(hpke_key);
    try std.testing.expectEqual(@as(usize, 32), hpke_key.len);
    
    // Keys should be different
    try std.testing.expect(!std.mem.eql(u8, signing_key, hpke_key));
}