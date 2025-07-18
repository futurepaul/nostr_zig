const std = @import("std");
const mls = @import("mls_zig");

/// Demonstrate HKDF support for NIP-44 key derivation
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("=== HKDF for NIP-44 Key Derivation ===", .{});

    const cipher_suite = mls.cipher_suite.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    // Example 1: Basic NIP-44 key derivation pattern
    std.log.info("1. NIP-44 conversation key derivation...", .{});
    
    // Simulate shared secret from ECDH (would come from nostr key exchange)
    const shared_secret = [_]u8{
        0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90,
        0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90
    };
    
    // NIP-44 Step 1: HKDF-Extract with empty salt
    var prk = try cipher_suite.hkdfExtract(allocator, "", &shared_secret);
    defer prk.deinit();
    
    std.log.info("   ✅ HKDF-Extract: {} bytes", .{prk.len()});
    
    // NIP-44 Step 2: HKDF-Expand with "nip44-v2" info
    var nip44_key = try cipher_suite.hkdfExpand(allocator, prk.asSlice(), "nip44-v2", 32);
    defer nip44_key.deinit();
    
    std.log.info("   ✅ NIP-44 key: {x}", .{nip44_key.asSlice()[0..8]});

    // Example 2: Multiple hash functions available
    std.log.info("2. Testing different hash functions...", .{});
    
    const sha384_suite = mls.cipher_suite.CipherSuite.MLS_256_DHKEMP384_AES256GCM_SHA384_P384;
    var prk_384 = try sha384_suite.hkdfExtract(allocator, "salt", &shared_secret);
    defer prk_384.deinit();
    
    var key_384 = try sha384_suite.hkdfExpand(allocator, prk_384.asSlice(), "test", 48);
    defer key_384.deinit();
    
    std.log.info("   ✅ SHA-384 key: {} bytes", .{key_384.len()});

    // Example 3: Key derivation for different purposes
    std.log.info("3. Multiple key contexts...", .{});
    
    var chat_key = try cipher_suite.hkdfExpand(allocator, prk.asSlice(), "nip44-chat", 32);
    defer chat_key.deinit();
    
    var auth_key = try cipher_suite.hkdfExpand(allocator, prk.asSlice(), "nip44-auth", 32);
    defer auth_key.deinit();
    
    std.log.info("   ✅ Chat key: {x}", .{chat_key.asSlice()[0..8]});
    std.log.info("   ✅ Auth key: {x}", .{auth_key.asSlice()[0..8]});

    std.log.info("🔑 HKDF support ready for NIP-44 integration!", .{});
}