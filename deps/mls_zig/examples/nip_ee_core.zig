const std = @import("std");
const mls = @import("mls_zig");

/// Core NIP-EE functionality example - demonstrates the key derivation that works today
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("=== MLS-Zig Core NIP-EE Example ===", .{});

    // Step 1: Core cryptographic functionality that's ready today
    std.log.info("1. Testing cipher suite selection...", .{});
    const cipher_suite = mls.cipher_suite.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    std.log.info("   Selected: {}", .{cipher_suite});

    // Step 2: Demonstrate exporter secret derivation (the key NIP-EE function)
    std.log.info("2. Testing exporter secret derivation for NIP-EE...", .{});
    
    // Simulate a group exporter secret (in practice this comes from MLS group state)
    const mock_exporter_secret = [_]u8{
        0x5a, 0x09, 0x7e, 0x14, 0x9f, 0x2a, 0x37, 0x5d, 0x0b, 0x9e, 0x1d, 0x1f, 0x4d, 0xc3, 0xa9, 0xc6,
        0xc1, 0x78, 0x8d, 0xf8, 0x88, 0xe5, 0x44, 0x1f, 0x41, 0xa8, 0x79, 0x1f, 0x4d, 0xc5, 0x6c, 0xea
    };
    
    // Derive NIP-44 encryption key (this is what you'd use with nostr_zig)
    var nip44_key = try cipher_suite.exporterSecret(
        allocator,
        &mock_exporter_secret,
        "nostr",                    // Standard NIP-EE label
        "conversation_key_v1",      // Context for this specific chat
        32                          // NIP-44 key length
    );
    defer nip44_key.deinit();
    
    std.log.info("   ✅ Derived NIP-44 key: {} bytes", .{nip44_key.len()});
    std.log.info("   🔑 Key (hex): {x}", .{nip44_key.asSlice()});

    // Step 3: Demonstrate multiple key derivation for different contexts
    std.log.info("3. Testing multiple key contexts...", .{});
    
    var dm_key = try cipher_suite.exporterSecret(
        allocator,
        &mock_exporter_secret,
        "nostr",
        "dm_key_v1",
        32
    );
    defer dm_key.deinit();
    
    var metadata_key = try cipher_suite.exporterSecret(
        allocator,
        &mock_exporter_secret,
        "nostr", 
        "metadata_key_v1",
        32
    );
    defer metadata_key.deinit();
    
    std.log.info("   ✅ DM key:       {x}", .{dm_key.asSlice()[0..8]});
    std.log.info("   ✅ Metadata key: {x}", .{metadata_key.asSlice()[0..8]});

    // Step 4: Test Nostr extensions (this works!)
    std.log.info("4. Testing Nostr extensions...", .{});
    
    var extensions = mls.key_package.Extensions.init(allocator);
    defer extensions.deinit();
    
    try mls.nostr_extensions.addNostrGroupData(
        &extensions,
        "deadbeef1234567890abcdef",
        &[_][]const u8{"wss://relay.example.com"},
        "npub1creator...",
        "{\"name\":\"Test Group\"}"
    );
    
    try mls.nostr_extensions.addLastResort(&extensions);
    
    std.log.info("   ✅ Added {} Nostr extensions", .{extensions.extensions.len});

    // Step 5: Show what's ready for nostr_zig integration
    std.log.info("5. Integration summary:", .{});
    std.log.info("   ✅ Cipher suites: 8 available", .{});
    std.log.info("   ✅ Key derivation: Working", .{});
    std.log.info("   ✅ Nostr extensions: Working", .{});
    std.log.info("   ⏳ Full group management: API stabilization in progress", .{});
    
    std.log.info("🎉 Core NIP-EE functionality ready for integration!", .{});
}