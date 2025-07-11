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
    
    // Test inputs from test vector
    const conv_key_hex = "c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d";
    const nonce_hex = "0000000000000000000000000000000000000000000000000000000000000001";
    const expected_chacha_key_hex = "8c8b181c7bb23c1410ad0234d8ad35cbc7b6c6b827e5e0d2b3cf3d6e8c1de9e5";
    
    const conv_key_bytes = try hexToBytes(allocator, conv_key_hex);
    defer allocator.free(conv_key_bytes);
    const nonce_bytes = try hexToBytes(allocator, nonce_hex);
    defer allocator.free(nonce_bytes);
    
    var conv_key: [32]u8 = undefined;
    var nonce: [32]u8 = undefined;
    @memcpy(&conv_key, conv_key_bytes);
    @memcpy(&nonce, nonce_bytes);
    
    // Debug: print the inputs
    const conv_key_hex_check = try bytesToHex(allocator, &conv_key);
    defer allocator.free(conv_key_hex_check);
    const nonce_hex_check = try bytesToHex(allocator, &nonce);
    defer allocator.free(nonce_hex_check);
    
    std.debug.print("Conversation key: {s}\n", .{conv_key_hex_check});
    std.debug.print("Nonce: {s}\n", .{nonce_hex_check});
    
    // Try HKDF with different parameter orders
    var expanded1: [76]u8 = undefined;
    var expanded2: [76]u8 = undefined;
    var expanded3: [76]u8 = undefined;
    
    // Method 1: expand(out, ctx, prk) - ctx=nonce, prk=conv_key  
    crypto.kdf.hkdf.HkdfSha256.expand(&expanded1, &nonce, conv_key);
    
    // Method 2: expand(out, ctx, prk) - ctx=conv_key_bytes, prk=nonce
    crypto.kdf.hkdf.HkdfSha256.expand(&expanded2, conv_key_bytes, nonce);
    
    // Method 3: try with nonce as slice  
    crypto.kdf.hkdf.HkdfSha256.expand(&expanded3, nonce_bytes, conv_key);
    
    const chacha_key1 = expanded1[0..32];
    const chacha_key2 = expanded2[0..32];
    const chacha_key3 = expanded3[0..32];
    
    const result1_hex = try bytesToHex(allocator, chacha_key1);
    defer allocator.free(result1_hex);
    const result2_hex = try bytesToHex(allocator, chacha_key2);
    defer allocator.free(result2_hex);
    const result3_hex = try bytesToHex(allocator, chacha_key3);
    defer allocator.free(result3_hex);
    
    std.debug.print("Expected: {s}\n", .{expected_chacha_key_hex});
    std.debug.print("Method 1 (&nonce as ctx, conv_key as prk): {s}\n", .{result1_hex});
    std.debug.print("Method 2 (conv_key_bytes as ctx, nonce as prk): {s}\n", .{result2_hex});
    std.debug.print("Method 3 (nonce_bytes as ctx, conv_key as prk): {s}\n", .{result3_hex});
    
    if (std.mem.eql(u8, result1_hex, expected_chacha_key_hex)) {
        std.debug.print("✅ Method 1 matches!\n", .{});
    }
    if (std.mem.eql(u8, result2_hex, expected_chacha_key_hex)) {
        std.debug.print("✅ Method 2 matches!\n", .{});
    }
    if (std.mem.eql(u8, result3_hex, expected_chacha_key_hex)) {
        std.debug.print("✅ Method 3 matches!\n", .{});
    }
}