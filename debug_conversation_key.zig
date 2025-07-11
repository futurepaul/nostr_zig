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

    // From test vector - this should be the conversation key directly
    const given_conversation_key_hex = "c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d";
    
    // But let's check - maybe it's actually a shared secret and we need to apply HKDF-Extract
    const given_bytes = try hexToBytes(allocator, given_conversation_key_hex);
    defer allocator.free(given_bytes);
    
    var given_key: [32]u8 = undefined;
    @memcpy(&given_key, given_bytes);
    
    std.debug.print("=== NIP-44 Conversation Key Debug ===\n", .{});
    std.debug.print("Given value from test vector: {s}\n", .{given_conversation_key_hex});
    
    // Try applying HKDF-Extract with salt "nip44-v2"
    const salt = "nip44-v2";
    const extracted_key = crypto.kdf.hkdf.HkdfSha256.extract(salt, &given_key);
    
    const extracted_hex = try bytesToHex(allocator, &extracted_key);
    defer allocator.free(extracted_hex);
    
    std.debug.print("After HKDF-Extract with 'nip44-v2': {s}\n", .{extracted_hex});
    
    // Let's also test message key derivation with both
    const nonce_hex = "0000000000000000000000000000000000000000000000000000000000000001";
    const nonce_bytes = try hexToBytes(allocator, nonce_hex);
    defer allocator.free(nonce_bytes);
    
    var nonce: [32]u8 = undefined;
    @memcpy(&nonce, nonce_bytes);
    
    std.debug.print("\nTesting message key derivation with nonce: {s}\n", .{nonce_hex});
    
    // Test 1: Use given value directly as conversation key
    std.debug.print("\n1. Using given value directly as conversation key:\n", .{});
    var expanded1: [76]u8 = undefined;
    crypto.kdf.hkdf.HkdfSha256.expand(&expanded1, &nonce, given_key);
    
    const hmac_key1 = expanded1[44..76];
    const hmac_key1_hex = try bytesToHex(allocator, hmac_key1);
    defer allocator.free(hmac_key1_hex);
    std.debug.print("   HMAC key: {s}\n", .{hmac_key1_hex});
    
    // Test 2: Use extracted value as conversation key
    std.debug.print("\n2. Using HKDF-extracted value as conversation key:\n", .{});
    var expanded2: [76]u8 = undefined;
    crypto.kdf.hkdf.HkdfSha256.expand(&expanded2, &nonce, extracted_key);
    
    const hmac_key2 = expanded2[44..76];
    const hmac_key2_hex = try bytesToHex(allocator, hmac_key2);
    defer allocator.free(hmac_key2_hex);
    std.debug.print("   HMAC key: {s}\n", .{hmac_key2_hex});
    
    // Let's check what the expected HMAC key should be by working backwards
    std.debug.print("\n=== Working backwards from expected HMAC ===\n", .{});
    
    // We know the expected HMAC from the test vector
    const expected_hmac_hex = "794259929a02bb06ad8e8cf709ee4ccc567e9d514cdf5781af27a3e905e55b1b";
    const expected_payload_hex = "02000000000000000000000000000000000000000000000000000000000000000179ed06e5548ad3ff58ca920e6c0b4329f6040230f7e6e5641f20741780f0adc35a09";
    
    std.debug.print("Expected HMAC: {s}\n", .{expected_hmac_hex});
    std.debug.print("Payload (without HMAC): {s}\n", .{expected_payload_hex});
    
    // We can't easily reverse engineer the HMAC key, but we can verify which approach gives correct results
}