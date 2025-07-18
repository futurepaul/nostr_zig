const std = @import("std");
const mls = @import("mls_zig");

/// Basic example showing how to use mls_zig for NIP-EE (Nostr Event Encryption)
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("=== MLS-Zig NIP-EE Example ===", .{});

    // Step 1: Create a credential for your Nostr identity
    std.log.info("1. Creating Nostr credential...", .{});
    var basic_credential = try mls.credentials.BasicCredential.init(
        allocator,
        "npub1example1234567890abcdef1234567890abcdef1234567890abcdef12"
    );
    defer basic_credential.deinit();
    
    var credential = try mls.credentials.Credential.fromBasic(allocator, &basic_credential);
    defer credential.deinit();

    // Step 2: Generate a key package bundle for group membership
    std.log.info("2. Generating key package bundle...", .{});
    var key_package_bundle = try mls.key_package.KeyPackageBundle.init(
        allocator,
        .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        credential,
        null
    );
    defer key_package_bundle.deinit();

    // Add Nostr-specific extensions to prevent key package reuse
    try mls.nostr_extensions.addLastResort(&key_package_bundle.key_package.payload.extensions);
    std.log.info("   ✅ Added last_resort extension for security", .{});

    // Step 3: Create a new MLS group
    std.log.info("3. Creating MLS group...", .{});
    var group = try mls.mls_group.MlsGroup.createGroup(
        allocator,
        .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        key_package_bundle,
        null
    );
    defer group.deinit();

    // Step 4: Add Nostr-specific group metadata
    std.log.info("4. Adding Nostr group metadata...", .{});
    var group_extensions = mls.key_package.Extensions.init(allocator);
    defer group_extensions.deinit();
    
    try mls.nostr_extensions.addNostrGroupData(
        &group_extensions,
        "deadbeef1234567890abcdef", // nostr group id
        &[_][]const u8{"wss://relay.example.com", "wss://relay2.example.com"}, // relay URLs
        "npub1creator1234567890abcdef1234567890abcdef1234567890abcdef12", // creator's nostr pubkey
        "{\"name\":\"My Secret Group\",\"description\":\"A private group chat\"}" // group metadata JSON
    );
    std.log.info("   ✅ Added Nostr group metadata", .{});

    // Step 5: Demonstrate key derivation (once group has epoch secrets)
    std.log.info("5. Testing key derivation...", .{});
    
    // Note: In a real implementation, epoch secrets would be established through commits
    // For this example, we'll show what the API looks like
    const result = try group.deriveNipeeKey(allocator, "conversation_key_v1", 32);
    if (result) |nip44_key| {
        defer nip44_key.deinit();
        std.log.info("   ✅ Successfully derived NIP-44 key: {} bytes", .{nip44_key.len()});
        std.log.info("   🔑 Key (first 8 bytes): {x}", .{nip44_key.asSlice()[0..8]});
    } else {
        std.log.info("   ⏳ Group not ready for key derivation (need epoch secrets)", .{});
        std.log.info("      In practice, epoch secrets are established after commits", .{});
    }

    // Step 6: Show how to get basic group information
    std.log.info("6. Group information:", .{});
    std.log.info("   Group ID: {x}", .{group.groupId()});
    std.log.info("   Epoch: {}", .{group.epoch()});
    std.log.info("   Cipher Suite: {}", .{group.cipher_suite});

    std.log.info("✅ NIP-EE integration example completed successfully!", .{});
}