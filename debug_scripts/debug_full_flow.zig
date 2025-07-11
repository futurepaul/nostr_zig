const std = @import("std");
const crypto = std.crypto;
const secp = @import("src/secp256k1/secp256k1.zig");

fn hexToBytes(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    const bytes = try allocator.alloc(u8, hex.len / 2);
    for (0..bytes.len) |i| {
        const hex_byte = hex[i * 2..i * 2 + 2];
        bytes[i] = std.fmt.parseInt(u8, hex_byte, 16) catch return error.InvalidHex;
    }
    return bytes;
}

fn bytesToHex(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const hex = try allocator.alloc(u8, bytes.len * 2);
    for (bytes, 0..) |byte, i| {
        _ = std.fmt.bufPrint(hex[i * 2..i * 2 + 2], "{x:0>2}", .{byte}) catch unreachable;
    }
    return hex;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Test vector values
    const sec1_hex = "0000000000000000000000000000000000000000000000000000000000000001";
    const sec2_hex = "0000000000000000000000000000000000000000000000000000000000000002";
    const expected_conversation_key_hex = "c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d";
    
    const sec1_bytes = try hexToBytes(allocator, sec1_hex);
    defer allocator.free(sec1_bytes);
    const sec2_bytes = try hexToBytes(allocator, sec2_hex);
    defer allocator.free(sec2_bytes);
    
    var sec1: [32]u8 = undefined;
    var sec2: [32]u8 = undefined;
    @memcpy(&sec1, sec1_bytes);
    @memcpy(&sec2, sec2_bytes);
    
    std.debug.print("=== NIP-44 Full Flow Debug ===\n", .{});
    std.debug.print("Secret key 1: {s}\n", .{sec1_hex});
    std.debug.print("Secret key 2: {s}\n", .{sec2_hex});
    
    // Initialize secp256k1
    const ctx = secp.secp256k1_context_create(secp.SECP256K1_CONTEXT_SIGN) orelse {
        std.debug.print("Failed to create secp256k1 context\n", .{});
        return;
    };
    defer secp.secp256k1_context_destroy(ctx);
    
    // Get public key from sec2
    var keypair2: secp.secp256k1_keypair = undefined;
    if (secp.secp256k1_keypair_create(ctx, &keypair2, &sec2) != 1) {
        std.debug.print("Failed to create keypair from sec2\n", .{});
        return;
    }
    
    var pub2_xonly: secp.secp256k1_xonly_pubkey = undefined;
    var pub2_parity: c_int = undefined;
    if (secp.secp256k1_keypair_xonly_pub(ctx, &pub2_xonly, &pub2_parity, &keypair2) != 1) {
        std.debug.print("Failed to get xonly pubkey\n", .{});
        return;
    }
    
    var pub2_bytes: [32]u8 = undefined;
    if (secp.secp256k1_xonly_pubkey_serialize(ctx, &pub2_bytes, &pub2_xonly) != 1) {
        std.debug.print("Failed to serialize xonly pubkey\n", .{});
        return;
    }
    
    const pub2_hex = try bytesToHex(allocator, &pub2_bytes);
    defer allocator.free(pub2_hex);
    std.debug.print("Public key 2 (x-only): {s}\n", .{pub2_hex});
    
    // Now let's do ECDH to get shared secret
    // For NIP-44, we need to compute the shared secret using the x-coordinate only
    
    // Reconstruct full pubkey for ECDH (using even y-coordinate as per NIP-44)
    var full_pubkey_bytes: [33]u8 = undefined;
    full_pubkey_bytes[0] = 0x02; // Even y-coordinate
    @memcpy(full_pubkey_bytes[1..33], &pub2_bytes);
    
    var pubkey2: secp.secp256k1_pubkey = undefined;
    if (secp.secp256k1_ec_pubkey_parse(ctx, &pubkey2, &full_pubkey_bytes, 33) != 1) {
        std.debug.print("Failed to parse pubkey\n", .{});
        return;
    }
    
    // Custom ECDH hash function that returns x-coordinate only
    const nip44EcdhHashFunction = struct {
        fn hash(
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
    }.hash;
    
    // Perform ECDH
    var shared_secret: [32]u8 = undefined;
    if (secp.secp256k1_ecdh(ctx, &shared_secret, &pubkey2, &sec1, nip44EcdhHashFunction, null) != 1) {
        std.debug.print("ECDH failed\n", .{});
        return;
    }
    
    const shared_secret_hex = try bytesToHex(allocator, &shared_secret);
    defer allocator.free(shared_secret_hex);
    std.debug.print("\nShared secret (x-coordinate): {s}\n", .{shared_secret_hex});
    
    // Apply HKDF-Extract to get conversation key
    const salt = "nip44-v2";
    const conversation_key = crypto.kdf.hkdf.HkdfSha256.extract(salt, &shared_secret);
    
    const conversation_key_hex = try bytesToHex(allocator, &conversation_key);
    defer allocator.free(conversation_key_hex);
    std.debug.print("Conversation key: {s}\n", .{conversation_key_hex});
    std.debug.print("Expected:         {s}\n", .{expected_conversation_key_hex});
    std.debug.print("Match: {}\n", .{std.mem.eql(u8, conversation_key_hex, expected_conversation_key_hex)});
}