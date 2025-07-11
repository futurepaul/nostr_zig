const std = @import("std");
const secp = @import("secp256k1");

/// Derive public key from secret key using secp256k1
fn derivePublicKey(secret_key: [32]u8) ![33]u8 {
    const ctx = secp.secp256k1_context_create(secp.SECP256K1_CONTEXT_SIGN) orelse return error.CryptoError;
    defer secp.secp256k1_context_destroy(ctx);
    
    // Verify secret key
    if (secp.secp256k1_ec_seckey_verify(ctx, &secret_key) != 1) {
        return error.InvalidSecretKey;
    }
    
    // Generate public key
    var pubkey: secp.secp256k1_pubkey = undefined;
    if (secp.secp256k1_ec_pubkey_create(ctx, &pubkey, &secret_key) != 1) {
        return error.CryptoError;
    }
    
    // Serialize public key in compressed format
    var public_key_bytes: [33]u8 = undefined;
    var output_len: usize = 33;
    if (secp.secp256k1_ec_pubkey_serialize(ctx, &public_key_bytes, &output_len, &pubkey, secp.SECP256K1_EC_COMPRESSED) != 1) {
        return error.CryptoError;
    }
    
    return public_key_bytes;
}

pub fn main() !void {
    std.debug.print("🔍 Testing public key derivation\n", .{});
    
    // Test vector secret keys
    const sec1_hex = "0000000000000000000000000000000000000000000000000000000000000001";
    const sec2_hex = "0000000000000000000000000000000000000000000000000000000000000002";
    
    var sec1: [32]u8 = undefined;
    var sec2: [32]u8 = undefined;
    
    _ = try std.fmt.hexToBytes(&sec1, sec1_hex);
    _ = try std.fmt.hexToBytes(&sec2, sec2_hex);
    
    std.debug.print("Secret key 1: {s}\n", .{std.fmt.fmtSliceHexLower(&sec1)});
    std.debug.print("Secret key 2: {s}\n", .{std.fmt.fmtSliceHexLower(&sec2)});
    
    // Derive public keys
    const pub1_full = try derivePublicKey(sec1);
    const pub2_full = try derivePublicKey(sec2);
    
    std.debug.print("Public key 1 (full): {s}\n", .{std.fmt.fmtSliceHexLower(&pub1_full)});
    std.debug.print("Public key 2 (full): {s}\n", .{std.fmt.fmtSliceHexLower(&pub2_full)});
    
    // x-only versions (skip prefix byte)
    var pub1_xonly: [32]u8 = undefined;
    var pub2_xonly: [32]u8 = undefined;
    @memcpy(&pub1_xonly, pub1_full[1..33]);
    @memcpy(&pub2_xonly, pub2_full[1..33]);
    
    std.debug.print("Public key 1 (x-only): {s}\n", .{std.fmt.fmtSliceHexLower(&pub1_xonly)});
    std.debug.print("Public key 2 (x-only): {s}\n", .{std.fmt.fmtSliceHexLower(&pub2_xonly)});
}