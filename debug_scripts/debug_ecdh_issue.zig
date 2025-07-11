const std = @import("std");
const crypto = std.crypto;
const secp = @import("src/secp256k1/secp256k1.zig");

/// Custom ECDH hash function for NIP-44
/// This function copies the x-coordinate directly without hashing, as per NIP-44 spec
fn nip44EcdhHashFunction(
    output: [*c]u8,
    x32: [*c]const u8,
    y32: [*c]const u8,
    data: ?*anyopaque,
) callconv(.C) c_int {
    _ = y32; // y-coordinate is not used in NIP-44
    _ = data; // no additional data needed
    
    // Copy x-coordinate directly to output
    @memcpy(output[0..32], x32[0..32]);
    
    return 32; // Return number of bytes written
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Test vector values
    var sec1: [32]u8 = undefined;
    var sec2: [32]u8 = undefined;
    
    _ = try std.fmt.hexToBytes(&sec1, "0000000000000000000000000000000000000000000000000000000000000001");
    _ = try std.fmt.hexToBytes(&sec2, "0000000000000000000000000000000000000000000000000000000000000002");
    
    std.debug.print("=== NIP-44 ECDH Debug ===\n", .{});
    std.debug.print("sec1: {s}\n", .{std.fmt.fmtSliceHexLower(&sec1)});
    std.debug.print("sec2: {s}\n", .{std.fmt.fmtSliceHexLower(&sec2)});
    
    // Create secp256k1 context
    const ctx = secp.secp256k1_context_create(secp.SECP256K1_CONTEXT_SIGN) orelse return error.CryptoError;
    defer secp.secp256k1_context_destroy(ctx);
    
    // Step 1: Generate pub2 from sec2
    var pubkey2: secp.secp256k1_pubkey = undefined;
    if (secp.secp256k1_ec_pubkey_create(ctx, &pubkey2, &sec2) != 1) {
        return error.CryptoError;
    }
    
    // Serialize to compressed format
    var pub2_bytes: [33]u8 = undefined;
    var output_len: usize = 33;
    if (secp.secp256k1_ec_pubkey_serialize(ctx, &pub2_bytes, &output_len, &pubkey2, secp.SECP256K1_EC_COMPRESSED) != 1) {
        return error.CryptoError;
    }
    
    std.debug.print("\npub2 (compressed): {s}\n", .{std.fmt.fmtSliceHexLower(&pub2_bytes)});
    std.debug.print("pub2 (x-only): {s}\n", .{std.fmt.fmtSliceHexLower(pub2_bytes[1..33])});
    
    // Step 2: Perform ECDH with sec1 and pub2
    var shared_secret: [32]u8 = undefined;
    if (secp.secp256k1_ecdh(ctx, &shared_secret, &pubkey2, &sec1, nip44EcdhHashFunction, null) != 1) {
        return error.CryptoError;
    }
    
    std.debug.print("\nShared secret (x-coordinate): {s}\n", .{std.fmt.fmtSliceHexLower(&shared_secret)});
    
    // Step 3: Apply HKDF-Extract to get conversation key
    const salt = "nip44-v2";
    const conversation_key = crypto.kdf.hkdf.HkdfSha256.extract(salt, &shared_secret);
    
    std.debug.print("Conversation key: {s}\n", .{std.fmt.fmtSliceHexLower(&conversation_key)});
    
    // Expected values
    std.debug.print("\n=== Expected values ===\n", .{});
    std.debug.print("Expected pub2 (x-only): c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5\n", .{});
    std.debug.print("Expected conversation key: c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d\n", .{});
    
    // Let's also try the reverse: sec2 with pub1
    std.debug.print("\n=== Testing reverse (sec2 with pub1) ===\n", .{});
    
    // Generate pub1 from sec1
    var pubkey1: secp.secp256k1_pubkey = undefined;
    if (secp.secp256k1_ec_pubkey_create(ctx, &pubkey1, &sec1) != 1) {
        return error.CryptoError;
    }
    
    var pub1_bytes: [33]u8 = undefined;
    output_len = 33;
    if (secp.secp256k1_ec_pubkey_serialize(ctx, &pub1_bytes, &output_len, &pubkey1, secp.SECP256K1_EC_COMPRESSED) != 1) {
        return error.CryptoError;
    }
    
    std.debug.print("pub1 (compressed): {s}\n", .{std.fmt.fmtSliceHexLower(&pub1_bytes)});
    std.debug.print("pub1 (x-only): {s}\n", .{std.fmt.fmtSliceHexLower(pub1_bytes[1..33])});
    
    // ECDH with sec2 and pub1
    var shared_secret2: [32]u8 = undefined;
    if (secp.secp256k1_ecdh(ctx, &shared_secret2, &pubkey1, &sec2, nip44EcdhHashFunction, null) != 1) {
        return error.CryptoError;
    }
    
    std.debug.print("Shared secret (reverse): {s}\n", .{std.fmt.fmtSliceHexLower(&shared_secret2)});
    
    const conversation_key2 = crypto.kdf.hkdf.HkdfSha256.extract(salt, &shared_secret2);
    std.debug.print("Conversation key (reverse): {s}\n", .{std.fmt.fmtSliceHexLower(&conversation_key2)});
    
    // Check if they match
    if (std.mem.eql(u8, &shared_secret, &shared_secret2)) {
        std.debug.print("\n✅ Shared secrets match (as expected)\n", .{});
    } else {
        std.debug.print("\n❌ Shared secrets don't match!\n", .{});
    }
}