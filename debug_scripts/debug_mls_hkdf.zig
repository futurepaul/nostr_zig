const std = @import("std");
const mls_zig = @import("mls_zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    std.debug.print("🔍 Testing HKDF with mls_zig to match NIP-44 test vectors\n", .{});
    
    // Test vector values from PROBLEMS.md
    const conversation_key_hex = "c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d";
    const nonce_hex = "0000000000000000000000000000000000000000000000000000000000000001";
    const expected_chacha_key_hex = "8c8b181c7bb23c1410ad0234d8ad35cbc7b6c6b827e5e0d2b3cf3d6e8c1de9e5";
    
    // Convert hex strings to bytes
    var conversation_key: [32]u8 = undefined;
    var nonce: [32]u8 = undefined;
    var expected_chacha_key: [32]u8 = undefined;
    
    _ = try std.fmt.hexToBytes(&conversation_key, conversation_key_hex);
    _ = try std.fmt.hexToBytes(&nonce, nonce_hex);
    _ = try std.fmt.hexToBytes(&expected_chacha_key, expected_chacha_key_hex);
    
    std.debug.print("📋 Input conversation key: {s}\n", .{std.fmt.fmtSliceHexLower(&conversation_key)});
    std.debug.print("📋 Input nonce: {s}\n", .{std.fmt.fmtSliceHexLower(&nonce)});
    std.debug.print("📋 Expected ChaCha key: {s}\n", .{std.fmt.fmtSliceHexLower(&expected_chacha_key)});
    
    // Test with mls_zig CipherSuite HKDF approach (based on the example)
    std.debug.print("\n🧪 Testing mls_zig CipherSuite HKDF...\n", .{});
    
    // Use the same approach as the nip44_hkdf.zig example
    if (@hasDecl(mls_zig, "cipher_suite")) {
        std.debug.print("✅ Found cipher_suite in mls_zig\n", .{});
        
        const cipher_suite = mls_zig.cipher_suite.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        
        // Try HKDF-Expand directly with conversation key as PRK and nonce as info
        std.debug.print("🔬 Attempting HKDF-Expand with conversation_key as PRK and nonce as info...\n", .{});
        
        var expanded_secret = cipher_suite.hkdfExpand(allocator, &conversation_key, &nonce, 76) catch |err| {
            std.debug.print("❌ hkdfExpand failed: {}\n", .{err});
            return;
        };
        defer expanded_secret.deinit();
        
        const chacha_key = expanded_secret.asSlice()[0..32];
        std.debug.print("📋 HKDF output (ChaCha key): {s}\n", .{std.fmt.fmtSliceHexLower(chacha_key)});
        
        if (std.mem.eql(u8, chacha_key, &expected_chacha_key)) {
            std.debug.print("🎉 SUCCESS! mls_zig HKDF matches expected output!\n", .{});
        } else {
            std.debug.print("❌ mls_zig HKDF doesn't match expected output\n", .{});
            
            // Let's also try the reverse: nonce as PRK, conversation_key as info
            std.debug.print("🔬 Trying reverse: nonce as PRK, conversation_key as info...\n", .{});
            
            var expanded_secret2 = cipher_suite.hkdfExpand(allocator, &nonce, &conversation_key, 76) catch |err| {
                std.debug.print("❌ reverse hkdfExpand failed: {}\n", .{err});
                return;
            };
            defer expanded_secret2.deinit();
            
            const chacha_key2 = expanded_secret2.asSlice()[0..32];
            std.debug.print("📋 Reverse HKDF output (ChaCha key): {s}\n", .{std.fmt.fmtSliceHexLower(chacha_key2)});
            
            if (std.mem.eql(u8, chacha_key2, &expected_chacha_key)) {
                std.debug.print("🎉 SUCCESS! Reverse mls_zig HKDF matches expected output!\n", .{});
            } else {
                std.debug.print("❌ Reverse mls_zig HKDF doesn't match either\n", .{});
            }
        }
    } else {
        std.debug.print("❌ No cipher_suite found in mls_zig\n", .{});
    }
}