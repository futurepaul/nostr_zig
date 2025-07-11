const std = @import("std");
const crypto = std.crypto;
const nip44 = @import("src/nip44/v2.zig");
const ChaCha20IETF = std.crypto.stream.chacha.ChaCha20IETF;

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

    // Test vector from nip44.vectors.json
    // Looking at first valid encrypt_decrypt test case
    const conversation_key_hex = "c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d";
    const nonce_hex = "0000000000000000000000000000000000000000000000000000000000000001";
    const plaintext = "a";
    const expected_payload = "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABee0G5VSK0/9YypIObAtDKfYEAjD35uVkHyB0F4DwrcNaCXlCWZKaArsGrY6M9wnuTMxWfp1RTN9Xga8no+kF5Vsb";
    
    // Decode expected payload to inspect structure
    const decoder = std.base64.standard.Decoder;
    const decoded_size = try decoder.calcSizeForSlice(expected_payload);
    const decoded_payload = try allocator.alloc(u8, decoded_size);
    try decoder.decode(decoded_payload, expected_payload);
    defer allocator.free(decoded_payload);
    
    std.debug.print("=== NIP-44 HMAC Debug ===\n", .{});
    std.debug.print("Payload length: {} bytes\n", .{decoded_payload.len});
    std.debug.print("Payload structure:\n", .{});
    std.debug.print("  Version: 0x{x:0>2}\n", .{decoded_payload[0]});
    std.debug.print("  Nonce: ", .{});
    for (decoded_payload[1..33]) |b| {
        std.debug.print("{x:0>2}", .{b});
    }
    std.debug.print("\n", .{});
    
    const encrypted_len = decoded_payload.len - 65; // Total - version(1) - nonce(32) - hmac(32)
    std.debug.print("  Encrypted length: {} bytes\n", .{encrypted_len});
    std.debug.print("  HMAC: ", .{});
    for (decoded_payload[decoded_payload.len - 32..]) |b| {
        std.debug.print("{x:0>2}", .{b});
    }
    std.debug.print("\n\n", .{});
    
    // Now let's compute the HMAC ourselves
    const conversation_key_bytes = try hexToBytes(allocator, conversation_key_hex);
    defer allocator.free(conversation_key_bytes);
    const nonce_bytes = try hexToBytes(allocator, nonce_hex);
    defer allocator.free(nonce_bytes);
    
    var conversation_key: [32]u8 = undefined;
    var nonce: [32]u8 = undefined;
    @memcpy(&conversation_key, conversation_key_bytes);
    @memcpy(&nonce, nonce_bytes);
    
    // Derive message keys
    var expanded: [76]u8 = undefined;
    crypto.kdf.hkdf.HkdfSha256.expand(&expanded, &nonce, conversation_key);
    
    const chacha_key = expanded[0..32];
    const chacha_nonce = expanded[32..44];
    const hmac_key = expanded[44..76];
    
    std.debug.print("Derived keys:\n", .{});
    std.debug.print("  ChaCha key: ", .{});
    for (chacha_key) |b| {
        std.debug.print("{x:0>2}", .{b});
    }
    std.debug.print("\n", .{});
    std.debug.print("  HMAC key: ", .{});
    for (hmac_key) |b| {
        std.debug.print("{x:0>2}", .{b});
    }
    std.debug.print("\n\n", .{});
    
    // HMAC should be computed over everything except the HMAC itself
    const hmac_input = decoded_payload[0..decoded_payload.len - 32];
    
    std.debug.print("HMAC input length: {} bytes\n", .{hmac_input.len});
    std.debug.print("HMAC input (hex): ", .{});
    for (hmac_input) |b| {
        std.debug.print("{x:0>2}", .{b});
    }
    std.debug.print("\n\n", .{});
    
    // Compute HMAC
    var computed_hmac: [32]u8 = undefined;
    crypto.auth.hmac.Hmac(crypto.hash.sha2.Sha256).create(&computed_hmac, hmac_input, hmac_key);
    
    std.debug.print("Computed HMAC: ", .{});
    for (computed_hmac) |b| {
        std.debug.print("{x:0>2}", .{b});
    }
    std.debug.print("\n", .{});
    
    std.debug.print("Expected HMAC: ", .{});
    for (decoded_payload[decoded_payload.len - 32..]) |b| {
        std.debug.print("{x:0>2}", .{b});
    }
    std.debug.print("\n", .{});
    
    var expected_hmac: [32]u8 = undefined;
    @memcpy(&expected_hmac, decoded_payload[decoded_payload.len - 32..]);
    
    const match = crypto.utils.timingSafeEql([32]u8, computed_hmac, expected_hmac);
    std.debug.print("\nHMAC match: {}\n", .{match});
    
    // Let's also test encryption to see if we get the same result
    std.debug.print("\n=== Testing Encryption ===\n", .{});
    
    // Pad the message
    const padded = try nip44.padMessage(allocator, plaintext);
    defer allocator.free(padded);
    
    std.debug.print("Padded message length: {} bytes\n", .{padded.len});
    std.debug.print("Padded message: ", .{});
    for (padded) |b| {
        std.debug.print("{x:0>2}", .{b});
    }
    std.debug.print("\n", .{});
    
    // Encrypt with ChaCha20
    const encrypted = try allocator.alloc(u8, padded.len);
    defer allocator.free(encrypted);
    
    ChaCha20IETF.xor(encrypted, padded, 0, chacha_key.*, chacha_nonce.*);
    
    std.debug.print("Encrypted: ", .{});
    for (encrypted) |b| {
        std.debug.print("{x:0>2}", .{b});
    }
    std.debug.print("\n", .{});
    
    // Build payload
    const payload_len = 1 + 32 + encrypted.len + 32;
    const payload = try allocator.alloc(u8, payload_len);
    defer allocator.free(payload);
    
    payload[0] = 0x02; // VERSION
    @memcpy(payload[1..33], &nonce);
    @memcpy(payload[33..33 + encrypted.len], encrypted);
    
    // Compute HMAC over version + nonce + encrypted
    const our_hmac_input = payload[0..33 + encrypted.len];
    var our_hmac: [32]u8 = undefined;
    crypto.auth.hmac.Hmac(crypto.hash.sha2.Sha256).create(&our_hmac, our_hmac_input, hmac_key);
    @memcpy(payload[33 + encrypted.len..], &our_hmac);
    
    std.debug.print("\nOur payload: ", .{});
    for (payload) |b| {
        std.debug.print("{x:0>2}", .{b});
    }
    std.debug.print("\n", .{});
    
    std.debug.print("Expected:    ", .{});
    for (decoded_payload) |b| {
        std.debug.print("{x:0>2}", .{b});
    }
    std.debug.print("\n", .{});
    
    const payloads_match = std.mem.eql(u8, payload, decoded_payload);
    std.debug.print("\nPayloads match: {}\n", .{payloads_match});
}