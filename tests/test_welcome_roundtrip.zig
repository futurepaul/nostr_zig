const std = @import("std");
const testing = std.testing;
const nostr = @import("nostr");
const mls_zig = @import("mls_zig");

test "full MLS welcome roundtrip" {
    const allocator = testing.allocator;
    
    // Initialize global key storage
    const key_storage = nostr.mls.key_storage;
    _ = try key_storage.getGlobalStorage(allocator);
    defer key_storage.deinitGlobalStorage();
    
    // 1. Generate keypairs for Alice and Bob
    std.debug.print("\n=== MLS Welcome Roundtrip Test ===\n\n", .{});
    
    // Bob's keys
    const bob_secret_key = [_]u8{2} ++ [_]u8{0} ** 31;
    const bob_public_key = try nostr.crypto.getPublicKey(bob_secret_key);
    const bob_public_hex = try nostr.crypto.bytesToHex(allocator, &bob_public_key);
    defer allocator.free(bob_public_hex);
    
    std.debug.print("1. Bob's public key: {s}\n", .{bob_public_hex});
    
    // Alice's keys
    const alice_secret_key = [_]u8{1} ++ [_]u8{0} ** 31;
    const alice_public_key = try nostr.crypto.getPublicKey(alice_secret_key);
    const alice_public_hex = try nostr.crypto.bytesToHex(allocator, &alice_public_key);
    defer allocator.free(alice_public_hex);
    
    std.debug.print("2. Alice's public key: {s}\n", .{alice_public_hex});
    
    // 2. Bob creates and publishes his KeyPackage
    std.debug.print("\n3. Bob creates his KeyPackage...\n", .{});
    
    const cipher_suite = mls_zig.cipher_suite.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    
    // Create Bob's KeyPackageBundle
    var bob_bundle = try mls_zig.key_package_flat.KeyPackageBundle.init(
        allocator,
        cipher_suite,
        bob_public_hex,
        null, // Use native randomness
    );
    defer bob_bundle.deinit();
    
    // Serialize Bob's KeyPackage
    const bob_kp_serialized = try bob_bundle.key_package.tlsSerialize(allocator);
    defer allocator.free(bob_kp_serialized);
    
    // Store Bob's HPKE private keys
    const storage = try key_storage.getGlobalStorage(allocator);
    const fake_event_id = "test_bob_keypackage_event";
    try storage.storeBundle(bob_public_hex, bob_bundle, fake_event_id);
    
    std.debug.print("   ✅ Bob's KeyPackage created ({} bytes)\n", .{bob_kp_serialized.len});
    std.debug.print("   ✅ Bob's HPKE keys stored\n", .{});
    
    // 3. Alice fetches Bob's KeyPackage and creates a group
    std.debug.print("\n4. Alice creates a group and invites Bob...\n", .{});
    
    // Parse Bob's KeyPackage
    const bob_kp = try mls_zig.key_package_flat.KeyPackage.tlsDeserialize(allocator, bob_kp_serialized);
    
    std.debug.print("   ✅ Alice parsed Bob's KeyPackage\n", .{});
    
    // Create MLS provider
    var mls_provider = nostr.mls.provider.MlsProvider.init(allocator);
    
    // Create group parameters
    const group_params = nostr.mls.groups.GroupParams{
        .name = "Test Group",
        .description = "Testing MLS roundtrip",
        .relays = &[_][]const u8{"ws://localhost:10547"},
    };
    
    // Convert Bob's flat KeyPackage to the format needed by createGroup
    // We need to create a proper types.KeyPackage structure
    const bob_types_kp = nostr.mls.types.KeyPackage{
        .version = .mls10,
        .cipher_suite = .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        .init_key = nostr.mls.types.HPKEPublicKey{
            .data = try allocator.dupe(u8, &bob_kp.init_key),
        },
        .leaf_node = nostr.mls.types.LeafNode{
            .encryption_key = nostr.mls.types.HPKEPublicKey{
                .data = try allocator.dupe(u8, &bob_kp.encryption_key),
            },
            .signature_key = nostr.mls.types.SignaturePublicKey{
                .data = try allocator.dupe(u8, &bob_kp.signature_key),
            },
            .credential = .{ .basic = .{ .identity = bob_public_hex } },
            .capabilities = .{
                .versions = &[_]u16{1},
                .ciphersuites = &[_]nostr.mls.types.Ciphersuite{.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519},
                .extensions = &[_]u16{},
                .proposals = &[_]u16{},
                .credentials = &[_]u16{},
            },
            .source = .by_value,
            .extensions = &[_]nostr.mls.types.Extension{},
        },
        .extensions = &[_]nostr.mls.types.Extension{},
        .signature = &[_]u8{0} ** 64, // Placeholder signature
    };
    defer {
        allocator.free(bob_types_kp.init_key.data);
        allocator.free(bob_types_kp.leaf_node.encryption_key.data);
        allocator.free(bob_types_kp.leaf_node.signature_key.data);
    }
    
    const members = [_]nostr.mls.types.KeyPackage{bob_types_kp};
    
    const group_result = try nostr.mls.groups.createGroup(
        allocator,
        &mls_provider,
        alice_secret_key,
        group_params,
        &members,
    );
    defer {
        allocator.free(group_result.used_key_packages);
        // Note: In real code we'd also free the welcome messages
    }
    
    const group_id_hex = try nostr.crypto.bytesToHex(allocator, &group_result.state.group_id.data);
    defer allocator.free(group_id_hex);
    
    std.debug.print("   ✅ Group created! ID: {s}\n", .{group_id_hex});
    std.debug.print("   ✅ Welcome messages: {}\n", .{group_result.welcome_messages.len});
    
    // 4. Extract the Welcome message for Bob
    try testing.expect(group_result.welcome_messages.len == 1);
    const welcome_for_bob = group_result.welcome_messages[0];
    
    // Serialize the Welcome
    const welcome_bytes = try nostr.mls.welcomes.serializeWelcome(allocator, welcome_for_bob);
    defer allocator.free(welcome_bytes);
    
    std.debug.print("\n5. Bob processes the Welcome message...\n", .{});
    
    // 5. Bob receives and processes the Welcome
    const welcome_parsed = try nostr.mls.types.parseWelcome(allocator, welcome_bytes);
    
    // Bob joins the group using the Welcome
    const join_result = try nostr.mls.welcomes.joinFromWelcome(
        allocator,
        &mls_provider,
        welcome_parsed,
        bob_secret_key,
    );
    
    const bob_group_id_hex = try nostr.crypto.bytesToHex(allocator, &join_result.state.group_id.data);
    defer allocator.free(bob_group_id_hex);
    
    std.debug.print("   ✅ Bob joined the group!\n", .{});
    std.debug.print("   Group ID: {s}\n", .{bob_group_id_hex});
    std.debug.print("   Epoch: {}\n", .{join_result.state.epoch});
    std.debug.print("   Members: {}\n", .{join_result.state.members.len});
    
    // Verify both have the same group ID
    try testing.expectEqualStrings(group_id_hex, bob_group_id_hex);
    
    std.debug.print("\n🎉 Success! Full MLS welcome roundtrip completed!\n", .{});
    std.debug.print("   - Bob published KeyPackage with stored HPKE keys\n", .{});
    std.debug.print("   - Alice created group and sent Welcome\n", .{});
    std.debug.print("   - Bob joined group using stored HPKE keys\n", .{});
    std.debug.print("   - Both have same group ID\n\n", .{});
}