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

/// Derive MLS signing key from Nostr private key for a specific epoch
/// This function now requires an epoch parameter for automatic key rotation
pub fn deriveMlsSigningKey(allocator: std.mem.Allocator, nostr_private_key: [32]u8, epoch: u64) ![]u8 {
    return deriveMlsSigningKeyForEpoch(allocator, nostr_private_key, epoch);
}

/// Derive MLS signing key from Nostr private key for a specific epoch
/// This enables automatic key rotation by generating different keys per epoch
pub fn deriveMlsSigningKeyForEpoch(allocator: std.mem.Allocator, nostr_private_key: [32]u8, epoch: u64) ![]u8 {
    // Derive MLS signing key from Nostr private key using HKDF with epoch number
    const salt = "nostr-to-mls-signing-key";
    const prk = try hkdfExtract(allocator, salt, &nostr_private_key);
    defer allocator.free(prk);
    
    // Include epoch number in the info parameter for key rotation
    const info = try std.fmt.allocPrint(allocator, "mls-signing-key-epoch-{d}", .{epoch});
    defer allocator.free(info);
    
    const signing_key = try hkdfExpand(allocator, prk, info, 32);
    
    // Ensure the derived key is valid for Ed25519
    // Ed25519 accepts any 32-byte seed, but we should ensure it's not all zeros
    var all_zeros = true;
    for (signing_key) |byte| {
        if (byte != 0) {
            all_zeros = false;
            break;
        }
    }
    if (all_zeros) {
        // If somehow we got all zeros, modify it slightly
        signing_key[0] = 1;
    }
    
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
    
    // Use a properly generated test key
    const nostr_key = try crypto.deriveValidKeyFromSeed([_]u8{42} ** 32);
    
    // Test MLS signing key derivation with epoch
    const signing_key = try deriveMlsSigningKey(allocator, nostr_key, 0);
    defer allocator.free(signing_key);
    try std.testing.expectEqual(@as(usize, 32), signing_key.len);
    
    // Test MLS HPKE key derivation
    const hpke_key = try deriveMlsHpkeKey(allocator, nostr_key);
    defer allocator.free(hpke_key);
    try std.testing.expectEqual(@as(usize, 32), hpke_key.len);
    
    // Keys should be different
    try std.testing.expect(!std.mem.eql(u8, signing_key, hpke_key));
}

test "epoch-based key derivation" {
    const allocator = std.testing.allocator;
    
    // Use a properly generated test key
    const nostr_key = try crypto.deriveValidKeyFromSeed([_]u8{123} ** 32);
    
    // Test that different epochs produce different keys
    const key_epoch_0 = try deriveMlsSigningKeyForEpoch(allocator, nostr_key, 0);
    defer allocator.free(key_epoch_0);
    
    const key_epoch_1 = try deriveMlsSigningKeyForEpoch(allocator, nostr_key, 1);
    defer allocator.free(key_epoch_1);
    
    const key_epoch_5 = try deriveMlsSigningKeyForEpoch(allocator, nostr_key, 5);
    defer allocator.free(key_epoch_5);
    
    // All keys should be valid length
    try std.testing.expectEqual(@as(usize, 32), key_epoch_0.len);
    try std.testing.expectEqual(@as(usize, 32), key_epoch_1.len);
    try std.testing.expectEqual(@as(usize, 32), key_epoch_5.len);
    
    // All keys should be different
    try std.testing.expect(!std.mem.eql(u8, key_epoch_0, key_epoch_1));
    try std.testing.expect(!std.mem.eql(u8, key_epoch_0, key_epoch_5));
    try std.testing.expect(!std.mem.eql(u8, key_epoch_1, key_epoch_5));
    
    // Test that the same epoch produces the same key (deterministic)
    const key_epoch_1_again = try deriveMlsSigningKeyForEpoch(allocator, nostr_key, 1);
    defer allocator.free(key_epoch_1_again);
    try std.testing.expect(std.mem.eql(u8, key_epoch_1, key_epoch_1_again));
    
    // Test epoch 0 matches the main function with epoch parameter
    const key_main_function = try deriveMlsSigningKey(allocator, nostr_key, 0);
    defer allocator.free(key_main_function);
    try std.testing.expect(std.mem.eql(u8, key_epoch_0, key_main_function));
}