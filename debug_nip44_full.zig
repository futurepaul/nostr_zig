const std = @import("std");
const crypto = std.crypto;

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
    
    // Test inputs from test vector - maybe these are shared secrets, not conversation keys!
    const maybe_shared_secret_hex = "c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d";
    const nonce_hex = "0000000000000000000000000000000000000000000000000000000000000001";
    const expected_chacha_key_hex = "8c8b181c7bb23c1410ad0234d8ad35cbc7b6c6b827e5e0d2b3cf3d6e8c1de9e5";
    
    const maybe_shared_secret_bytes = try hexToBytes(allocator, maybe_shared_secret_hex);
    defer allocator.free(maybe_shared_secret_bytes);
    const nonce_bytes = try hexToBytes(allocator, nonce_hex);
    defer allocator.free(nonce_bytes);
    
    var maybe_shared_secret: [32]u8 = undefined;
    var nonce: [32]u8 = undefined;
    @memcpy(&maybe_shared_secret, maybe_shared_secret_bytes);
    @memcpy(&nonce, nonce_bytes);
    
    std.debug.print("Testing NIP-44 full HKDF chain...\n", .{});
    std.debug.print("Input (might be shared secret): {s}\n", .{maybe_shared_secret_hex});
    std.debug.print("Nonce: {s}\n", .{nonce_hex});
    std.debug.print("Expected ChaCha key: {s}\n", .{expected_chacha_key_hex});
    std.debug.print("\n", .{});
    
    // Test 1: Maybe the test vector value is the shared secret, not conversation key
    // Following NIP-44: conversation_key = HKDF-Extract(salt="nip44-v2", ikm=shared_secret)
    std.debug.print("Method A: Full NIP-44 chain with 'nip44-v2' salt\n", .{});
    const salt = "nip44-v2";
    const conversation_key_a = crypto.kdf.hkdf.HkdfSha256.extract(salt, &maybe_shared_secret);
    
    const conv_key_a_hex = try bytesToHex(allocator, &conversation_key_a);
    defer allocator.free(conv_key_a_hex);
    std.debug.print("  Conversation key: {s}\n", .{conv_key_a_hex});
    
    // Then: message_keys = HKDF-Expand(conversation_key, nonce, 76)
    var expanded_a: [76]u8 = undefined;
    crypto.kdf.hkdf.HkdfSha256.expand(&expanded_a, &nonce, conversation_key_a);
    const chacha_key_a = expanded_a[0..32];
    
    const result_a_hex = try bytesToHex(allocator, chacha_key_a);
    defer allocator.free(result_a_hex);
    std.debug.print("  ChaCha key: {s}\n", .{result_a_hex});
    
    // Test 2: Maybe the test vector value is the shared secret, no salt
    std.debug.print("\nMethod B: HKDF-Extract with empty salt\n", .{});
    const conversation_key_b = crypto.kdf.hkdf.HkdfSha256.extract("", &maybe_shared_secret);
    
    const conv_key_b_hex = try bytesToHex(allocator, &conversation_key_b);
    defer allocator.free(conv_key_b_hex);
    std.debug.print("  Conversation key: {s}\n", .{conv_key_b_hex});
    
    var expanded_b: [76]u8 = undefined;
    crypto.kdf.hkdf.HkdfSha256.expand(&expanded_b, &nonce, conversation_key_b);
    const chacha_key_b = expanded_b[0..32];
    
    const result_b_hex = try bytesToHex(allocator, chacha_key_b);
    defer allocator.free(result_b_hex);
    std.debug.print("  ChaCha key: {s}\n", .{result_b_hex});
    
    // Test 3: Direct use as conversation key (original approach)
    std.debug.print("\nMethod C: Use test vector value directly as conversation key\n", .{});
    var expanded_c: [76]u8 = undefined;
    crypto.kdf.hkdf.HkdfSha256.expand(&expanded_c, &nonce, maybe_shared_secret);
    const chacha_key_c = expanded_c[0..32];
    
    const result_c_hex = try bytesToHex(allocator, chacha_key_c);
    defer allocator.free(result_c_hex);
    std.debug.print("  ChaCha key: {s}\n", .{result_c_hex});
    
    std.debug.print("\n=== RESULTS ===\n", .{});
    std.debug.print("Expected: {s}\n", .{expected_chacha_key_hex});
    std.debug.print("Method A: {s} {s}\n", .{ result_a_hex, if (std.mem.eql(u8, result_a_hex, expected_chacha_key_hex)) "✅" else "❌" });
    std.debug.print("Method B: {s} {s}\n", .{ result_b_hex, if (std.mem.eql(u8, result_b_hex, expected_chacha_key_hex)) "✅" else "❌" });
    std.debug.print("Method C: {s} {s}\n", .{ result_c_hex, if (std.mem.eql(u8, result_c_hex, expected_chacha_key_hex)) "✅" else "❌" });
}