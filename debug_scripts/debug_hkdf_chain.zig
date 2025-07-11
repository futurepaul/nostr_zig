const std = @import("std");
const mls_zig = @import("mls_zig");
const secp = @import("secp256k1");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    std.debug.print("🔍 Testing complete HKDF chain from ECDH to message keys\n", .{});
    
    // Test vector values from the new JSON (first test case)
    const conversation_key_hex = "a1a3d60f3470a8612633924e91febf96dc5366ce130f658b1f0fc652c20b3b54";
    const nonce_hex = "e1e6f880560d6d149ed83dcc7e5861ee62a5ee051f7fde9975fe5d25d2a02d72";
    const expected_chacha_key_hex = "f145f3bed47cb70dbeaac07f3a3fe683e822b3715edb7c4fe310829014ce7d76";
    const expected_chacha_nonce_hex = "c4ad129bb01180c0933a160c";
    const expected_hmac_key_hex = "027c1db445f05e2eee864a0975b0ddef5b7110583c8c192de3732571ca5838c4";
    
    // Convert hex strings to bytes
    var conversation_key: [32]u8 = undefined;
    var nonce: [32]u8 = undefined;
    var expected_chacha_key: [32]u8 = undefined;
    var expected_chacha_nonce: [12]u8 = undefined;
    var expected_hmac_key: [32]u8 = undefined;
    
    _ = try std.fmt.hexToBytes(&conversation_key, conversation_key_hex);
    _ = try std.fmt.hexToBytes(&nonce, nonce_hex);
    _ = try std.fmt.hexToBytes(&expected_chacha_key, expected_chacha_key_hex);
    _ = try std.fmt.hexToBytes(&expected_chacha_nonce, expected_chacha_nonce_hex);
    _ = try std.fmt.hexToBytes(&expected_hmac_key, expected_hmac_key_hex);
    
    std.debug.print("📋 Conversation key: {s}\n", .{std.fmt.fmtSliceHexLower(&conversation_key)});
    std.debug.print("📋 Nonce: {s}\n", .{std.fmt.fmtSliceHexLower(&nonce)});
    std.debug.print("📋 Expected ChaCha key: {s}\n", .{std.fmt.fmtSliceHexLower(&expected_chacha_key)});
    std.debug.print("📋 Expected ChaCha nonce: {s}\n", .{std.fmt.fmtSliceHexLower(&expected_chacha_nonce)});
    std.debug.print("📋 Expected HMAC key: {s}\n", .{std.fmt.fmtSliceHexLower(&expected_hmac_key)});
    
    // Test HKDF-Expand directly with the given conversation key and nonce
    std.debug.print("\n🔬 Testing HKDF-Expand with new test vectors...\n", .{});
    
    const cipher_suite = mls_zig.cipher_suite.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    
    var message_keys_secret = try cipher_suite.hkdfExpand(allocator, &conversation_key, &nonce, 76);
    defer message_keys_secret.deinit();
    
    const message_keys = message_keys_secret.asSlice();
    const chacha_key = message_keys[0..32];
    const chacha_nonce_bytes = message_keys[32..44];
    const hmac_key = message_keys[44..76];
    
    std.debug.print("✅ ChaCha key: {s}\n", .{std.fmt.fmtSliceHexLower(chacha_key)});
    std.debug.print("✅ ChaCha nonce: {s}\n", .{std.fmt.fmtSliceHexLower(chacha_nonce_bytes)});
    std.debug.print("✅ HMAC key: {s}\n", .{std.fmt.fmtSliceHexLower(hmac_key)});
    
    var all_match = true;
    
    if (std.mem.eql(u8, chacha_key, &expected_chacha_key)) {
        std.debug.print("🎉 ChaCha key matches!\n", .{});
    } else {
        std.debug.print("❌ ChaCha key doesn't match\n", .{});
        all_match = false;
    }
    
    if (std.mem.eql(u8, chacha_nonce_bytes, &expected_chacha_nonce)) {
        std.debug.print("🎉 ChaCha nonce matches!\n", .{});
    } else {
        std.debug.print("❌ ChaCha nonce doesn't match\n", .{});
        all_match = false;
    }
    
    if (std.mem.eql(u8, hmac_key, &expected_hmac_key)) {
        std.debug.print("🎉 HMAC key matches!\n", .{});
    } else {
        std.debug.print("❌ HMAC key doesn't match\n", .{});
        all_match = false;
    }
    
    if (all_match) {
        std.debug.print("\n🎉🎉🎉 SUCCESS! All keys match the new test vectors! 🎉🎉🎉\n", .{});
    } else {
        std.debug.print("\n❌ Some keys don't match - need further investigation\n", .{});
    }
}