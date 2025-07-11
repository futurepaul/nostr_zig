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

// Implement the Rust HKDF expand logic exactly
fn rustHkdfExpand(allocator: std.mem.Allocator, prk: []const u8, info: []const u8, output_len: usize) ![]u8 {
    var output = std.ArrayList(u8).init(allocator);
    defer output.deinit();
    
    var t = std.ArrayList(u8).init(allocator);
    defer t.deinit();
    
    var i: u8 = 1;
    while (output.items.len < output_len) {
        var hmac_sha256 = crypto.auth.hmac.Hmac(crypto.hash.sha2.Sha256).init(prk);
        
        if (t.items.len > 0) {
            hmac_sha256.update(t.items);
        }
        
        hmac_sha256.update(info);
        hmac_sha256.update(&[_]u8{i});
        
        var t_result: [32]u8 = undefined;
        hmac_sha256.final(&t_result);
        
        try t.resize(32);
        @memcpy(t.items, &t_result);
        try output.appendSlice(&t_result);
        
        i += 1;
    }
    
    const result = try allocator.alloc(u8, output_len);
    @memcpy(result, output.items[0..output_len]);
    return result;
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
    
    std.debug.print("Testing Rust HKDF implementation...\n", .{});
    std.debug.print("Conversation key: {s}\n", .{conv_key_hex});
    std.debug.print("Nonce: {s}\n", .{nonce_hex});
    std.debug.print("Expected ChaCha key: {s}\n", .{expected_chacha_key_hex});
    std.debug.print("\n", .{});
    
    // Test 1: Zig standard library HKDF
    std.debug.print("Method 1: Zig standard library HKDF\n", .{});
    var expanded_zig: [76]u8 = undefined;
    crypto.kdf.hkdf.HkdfSha256.expand(&expanded_zig, &nonce, conv_key);
    const chacha_key_zig = expanded_zig[0..32];
    
    const result_zig_hex = try bytesToHex(allocator, chacha_key_zig);
    defer allocator.free(result_zig_hex);
    std.debug.print("  ChaCha key: {s}\n", .{result_zig_hex});
    
    // Test 2: Custom Rust-style HKDF implementation
    std.debug.print("\nMethod 2: Rust-style HKDF implementation\n", .{});
    const expanded_rust = try rustHkdfExpand(allocator, &conv_key, &nonce, 76);
    defer allocator.free(expanded_rust);
    const chacha_key_rust = expanded_rust[0..32];
    
    const result_rust_hex = try bytesToHex(allocator, chacha_key_rust);
    defer allocator.free(result_rust_hex);
    std.debug.print("  ChaCha key: {s}\n", .{result_rust_hex});
    
    std.debug.print("\n=== RESULTS ===\n", .{});
    std.debug.print("Expected: {s}\n", .{expected_chacha_key_hex});
    std.debug.print("Zig std:  {s} {s}\n", .{ result_zig_hex, if (std.mem.eql(u8, result_zig_hex, expected_chacha_key_hex)) "✅" else "❌" });
    std.debug.print("Rust style: {s} {s}\n", .{ result_rust_hex, if (std.mem.eql(u8, result_rust_hex, expected_chacha_key_hex)) "✅" else "❌" });
}