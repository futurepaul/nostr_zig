const std = @import("std");
const v2 = @import("src/nip44/v2.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // Use the test from test_vectors.zig to see what it's doing
    const conv_key_hex = "8fc262099ce0d0bb9b89bac05bb9e04f9bc0090acc181fef6840ccee470371ed";
    const nonce_hex = "326bcb2c943cd6bb717588c9e5a7e738edf6ed14ec5f5344caa6ef56f0b9cff7";
    const pattern = "x";
    const repeat: usize = 65535;
    
    const conv_key_bytes = try hexToBytes(allocator, conv_key_hex);
    defer allocator.free(conv_key_bytes);
    const nonce_bytes = try hexToBytes(allocator, nonce_hex);
    defer allocator.free(nonce_bytes);
    
    var conv_key: [32]u8 = undefined;
    var nonce_array: [32]u8 = undefined;
    @memcpy(&conv_key, conv_key_bytes);
    @memcpy(&nonce_array, nonce_bytes);
    
    const conversation_key = v2.ConversationKey{ .key = conv_key };
    
    // Generate the long message by repeating the pattern
    const plaintext = try allocator.alloc(u8, pattern.len * repeat);
    defer allocator.free(plaintext);
    
    for (0..repeat) |j| {
        @memcpy(plaintext[j * pattern.len..(j + 1) * pattern.len], pattern);
    }
    
    // Encrypt the message using our implementation
    const payload = try v2.encryptWithNonce(allocator, conversation_key, nonce_array, plaintext);
    defer allocator.free(payload);
    
    // Calculate payload hash of raw bytes
    var payload_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload, &payload_hash, .{});
    
    std.debug.print("Payload length: {}\n", .{payload.len});
    std.debug.print("Raw payload SHA256: {s}\n", .{std.fmt.fmtSliceHexLower(&payload_hash)});
    
    // Now base64 encode and hash that
    const encoded_len = std.base64.standard.Encoder.calcSize(payload.len);
    const encoded = try allocator.alloc(u8, encoded_len);
    defer allocator.free(encoded);
    _ = std.base64.standard.Encoder.encode(encoded, payload);
    
    var encoded_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(encoded, &encoded_hash, .{});
    
    std.debug.print("Base64 payload SHA256: {s}\n", .{std.fmt.fmtSliceHexLower(&encoded_hash)});
    std.debug.print("Expected:              90714492225faba06310bff2f249ebdc2a5e609d65a629f1c87f2d4ffc55330a\n", .{});
    
    // Let's also print the first and last few bytes of the payload
    std.debug.print("\nFirst 16 bytes: {s}\n", .{std.fmt.fmtSliceHexLower(payload[0..16])});
    std.debug.print("Last 16 bytes:  {s}\n", .{std.fmt.fmtSliceHexLower(payload[payload.len-16..])});
}

fn hexToBytes(allocator: std.mem.Allocator, hex_string: []const u8) ![]u8 {
    if (hex_string.len % 2 != 0) return error.InvalidHexLength;
    const bytes = try allocator.alloc(u8, hex_string.len / 2);
    var i: usize = 0;
    while (i < hex_string.len) : (i += 2) {
        bytes[i / 2] = try std.fmt.parseInt(u8, hex_string[i..i + 2], 16);
    }
    return bytes;
}