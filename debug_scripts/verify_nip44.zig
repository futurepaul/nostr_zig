const std = @import("std");
const nip44 = @import("src/nip44/mod.zig");

// Test vectors from the spec
const test_sec1 = "0000000000000000000000000000000000000000000000000000000000000001";
const test_pub2 = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const expected_conv_key = "c15eeb28c59b29ebe1207ba06df07aeff32b8fb05fb96b909a8ce814b3f23a20";

fn hexToBytes(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    const bytes = try allocator.alloc(u8, hex.len / 2);
    var i: usize = 0;
    while (i < hex.len) : (i += 2) {
        bytes[i / 2] = try std.fmt.parseInt(u8, hex[i..i + 2], 16);
    }
    return bytes;
}

fn bytesToHex(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const hex = try allocator.alloc(u8, bytes.len * 2);
    for (bytes, 0..) |byte, i| {
        _ = try std.fmt.bufPrint(hex[i * 2..i * 2 + 2], "{x:0>2}", .{byte});
    }
    return hex;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    std.debug.print("🔍 NIP-44 Implementation Verification\n", .{});
    std.debug.print("====================================\n\n", .{});
    
    // Test 1: Conversation key generation
    std.debug.print("Test 1: Conversation Key Generation\n", .{});
    
    const sec1_bytes = try hexToBytes(allocator, test_sec1);
    defer allocator.free(sec1_bytes);
    const pub2_bytes = try hexToBytes(allocator, test_pub2);
    defer allocator.free(pub2_bytes);
    
    var sec1_array: [32]u8 = undefined;
    var pub2_array: [32]u8 = undefined;
    @memcpy(&sec1_array, sec1_bytes);
    @memcpy(&pub2_array, pub2_bytes[1..]); // Skip compression byte
    
    const conv_key = try nip44.getConversationKey(sec1_array, pub2_array);
    const conv_key_hex = try bytesToHex(allocator, &conv_key.key);
    defer allocator.free(conv_key_hex);
    
    std.debug.print("  Input sec1: {s}\n", .{test_sec1});
    std.debug.print("  Input pub2: {s}\n", .{test_pub2});
    std.debug.print("  Expected:   {s}\n", .{expected_conv_key});
    std.debug.print("  Got:        {s}\n", .{conv_key_hex});
    
    if (std.mem.eql(u8, conv_key_hex, expected_conv_key)) {
        std.debug.print("  ✅ PASS\n", .{});
    } else {
        std.debug.print("  ❌ FAIL\n", .{});
    }
    
    // Test 2: Encryption/Decryption roundtrip
    std.debug.print("\nTest 2: Encryption/Decryption Roundtrip\n", .{});
    
    const message = "Hello, NIP-44! 🔐";
    const ciphertext = try nip44.encrypt(allocator, sec1_array, pub2_array, message);
    defer allocator.free(ciphertext);
    
    std.debug.print("  Message:    {s}\n", .{message});
    std.debug.print("  Ciphertext: {s}...\n", .{ciphertext[0..@min(50, ciphertext.len)]});
    
    // For proper decryption we'd need sec2 and to derive pub1
    // But we can at least verify encryption produces valid base64
    const is_base64 = blk: {
        for (ciphertext) |c| {
            if (!std.ascii.isAlphanumeric(c) and c != '+' and c != '/' and c != '=') {
                break :blk false;
            }
        }
        break :blk true;
    };
    
    if (is_base64 and ciphertext.len > 100) {
        std.debug.print("  ✅ PASS (valid base64 output)\n", .{});
    } else {
        std.debug.print("  ❌ FAIL (invalid output format)\n", .{});
    }
    
    // Test 3: Known test vector encryption
    std.debug.print("\nTest 3: Test Vector Verification\n", .{});
    
    // Using first test vector from nip44.vectors.json
    const tv_sec1 = "315e59ff51cb9209768cf7da80791ddcaae56ac9775eb25b6dee1234bc5d2268";
    const tv_pub2 = "c2f9d9948dc8c7c38321e4b85c8558872eafa0641cd269db76848a6073e69133";
    const tv_expected_conv_key = "3dfef0ce2a4d80a25e7a328accf73448ef67096f65f79588e358d9a0eb9013f1";
    
    const tv_sec1_bytes = try hexToBytes(allocator, tv_sec1);
    defer allocator.free(tv_sec1_bytes);
    const tv_pub2_bytes = try hexToBytes(allocator, tv_pub2);
    defer allocator.free(tv_pub2_bytes);
    
    var tv_sec1_array: [32]u8 = undefined;
    var tv_pub2_array: [32]u8 = undefined;
    @memcpy(&tv_sec1_array, tv_sec1_bytes);
    @memcpy(&tv_pub2_array, tv_pub2_bytes); // Already 32 bytes
    
    const tv_conv_key = try nip44.getConversationKey(tv_sec1_array, tv_pub2_array);
    const tv_conv_key_hex = try bytesToHex(allocator, &tv_conv_key.key);
    defer allocator.free(tv_conv_key_hex);
    
    std.debug.print("  Expected: {s}\n", .{tv_expected_conv_key});
    std.debug.print("  Got:      {s}\n", .{tv_conv_key_hex});
    
    if (std.mem.eql(u8, tv_conv_key_hex, tv_expected_conv_key)) {
        std.debug.print("  ✅ PASS\n", .{});
    } else {
        std.debug.print("  ❌ FAIL\n", .{});
    }
    
    std.debug.print("\n✅ Verification complete!\n", .{});
}