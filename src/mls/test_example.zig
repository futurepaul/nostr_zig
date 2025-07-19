const std = @import("std");
const mls = @import("mls.zig");
const crypto = @import("../crypto.zig");

/// Example demonstrating Nostr MLS functionality
pub fn main() !void {
    const allocator = std.heap.page_allocator;
    
    // Initialize MLS provider
    var mls_provider = mls.provider.MlsProvider.init(allocator);
    
    // Generate valid keys for three users
    const alice_key = try crypto.generatePrivateKey();
    const bob_key = try crypto.generatePrivateKey();
    const carol_key = try crypto.generatePrivateKey();
    
    std.debug.print("=== Nostr MLS Example ===\n", .{});
    
    // Step 1: Generate key packages
    std.debug.print("\n1. Generating key packages...\n", .{});
    
    const bob_kp = try mls.key_packages.generateKeyPackage(
        allocator,
        &mls_provider,
        bob_key,
        .{},
    );
    defer mls.key_packages.freeKeyPackage(allocator, bob_kp);
    
    const carol_kp = try mls.key_packages.generateKeyPackage(
        allocator,
        &mls_provider,
        carol_key,
        .{},
    );
    defer mls.key_packages.freeKeyPackage(allocator, carol_kp);
    
    // Step 2: Create key package events
    std.debug.print("\n2. Creating key package events...\n", .{});
    
    const bob_kp_event = try mls.nip_ee.KeyPackageEvent.create(
        allocator,
        bob_key,
        bob_kp,
    );
    defer allocator.free(bob_kp_event.event.content);
    
    const carol_kp_event = try mls.nip_ee.KeyPackageEvent.create(
        allocator,
        carol_key,
        carol_kp,
    );
    defer allocator.free(carol_kp_event.event.content);
    
    std.debug.print("  Bob's key package event: kind={}, id={s}\n", .{
        bob_kp_event.event.kind,
        std.fmt.fmtSliceHexLower(&bob_kp_event.event.id),
    });
    
    // Step 3: Alice creates a group
    std.debug.print("\n3. Alice creates a group...\n", .{});
    
    var alice_pubkey: [32]u8 = undefined;
    alice_pubkey = try crypto.getPublicKey(alice_key);
    
    const group_params = mls.groups.GroupCreationParams{
        .name = "Nostr Dev Chat",
        .description = "Secure group for Nostr developers",
        .admins = &[_][32]u8{alice_pubkey},
        .relays = &[_][]const u8{
            "wss://relay.nostr.band",
            "wss://nos.lol",
        },
        .image = null,
    };
    
    const creation_result = try mls.groups.createGroup(
        allocator,
        &mls_provider,
        alice_key,
        group_params,
        &[_]mls.types.KeyPackage{ bob_kp, carol_kp },
    );
    defer freeGroupCreationResult(allocator, creation_result);
    
    std.debug.print("  Group created: id={s}, epoch={}, members={}\n", .{
        std.fmt.fmtSliceHexLower(&creation_result.state.group_id),
        creation_result.state.epoch,
        creation_result.state.members.len,
    });
    
    // Step 4: Create welcome events
    std.debug.print("\n4. Creating welcome events...\n", .{});
    
    for (creation_result.welcomes, 0..) |welcome, i| {
        const recipient_pubkey = if (i == 0) blk: {
            var pk: [32]u8 = undefined;
            pk = try crypto.getPublicKey(bob_key);
            break :blk pk;
        } else blk: {
            var pk: [32]u8 = undefined;
            pk = try crypto.getPublicKey(carol_key);
            break :blk pk;
        };
        
        const welcome_event = try mls.nip_ee.WelcomeEvent.create(
            allocator,
            alice_key,
            recipient_pubkey,
            creation_result.state.group_id,
            welcome,
        );
        defer {
            allocator.free(welcome_event.event.content);
            for (welcome_event.event.tags) |tag| {
                for (tag) |t| {
                    allocator.free(t);
                }
                allocator.free(tag);
            }
            allocator.free(welcome_event.event.tags);
        }
        
        std.debug.print("  Welcome event {} created: kind={}, recipient={s}\n", .{
            i + 1,
            welcome_event.event.kind,
            std.fmt.fmtSliceHexLower(&recipient_pubkey),
        });
    }
    
    // Step 5: Encrypt a message
    std.debug.print("\n5. Alice sends an encrypted message...\n", .{});
    
    const message = "Hello, secure Nostr group! 🔐";
    const encrypted_msg = try mls.messages.encryptGroupMessage(
        allocator,
        &mls_provider,
        &creation_result.state,
        message,
        alice_key,
        .{},
    );
    defer {
        allocator.free(encrypted_msg.mls_ciphertext);
        allocator.free(encrypted_msg.nip44_ciphertext);
    }
    
    std.debug.print("  Message encrypted: epoch={}, size={} bytes\n", .{
        encrypted_msg.epoch,
        encrypted_msg.nip44_ciphertext.len,
    });
    
    // Step 6: Create group message event
    std.debug.print("\n6. Creating group message event...\n", .{});
    
    var ephemeral_key: [32]u8 = undefined;
    std.crypto.random.bytes(&ephemeral_key);
    
    const msg_event = try mls.messages.createGroupMessageEvent(
        allocator,
        encrypted_msg,
        creation_result.state.group_id,
        ephemeral_key,
    );
    defer {
        allocator.free(msg_event.event.content);
        for (msg_event.event.tags) |tag| {
            for (tag) |t| {
                allocator.free(t);
            }
            allocator.free(tag);
        }
        allocator.free(msg_event.event.tags);
        if (msg_event.message_type) |mt| allocator.free(mt);
    }
    
    std.debug.print("  Group message event created: kind={}, epoch={}\n", .{
        msg_event.event.kind,
        msg_event.epoch.?,
    });
    
    // Step 7: Demonstrate member addition (proposal)
    std.debug.print("\n7. Adding a new member...\n", .{});
    
    var dave_key: [32]u8 = undefined;
    std.crypto.random.bytes(&dave_key);
    
    const dave_kp = try mls.key_packages.generateKeyPackage(
        allocator,
        &mls_provider,
        dave_key,
        .{},
    );
    defer mls.key_packages.freeKeyPackage(allocator, dave_kp);
    
    // Note: In a real implementation, addMember would be fully implemented
    std.debug.print("  Would add Dave to the group (not fully implemented)\n", .{});
    
    std.debug.print("\n=== Example Complete ===\n", .{});
}

// Helper functions to free allocated memory
// Note: Using mls.key_packages.freeKeyPackage instead of local function

fn freeGroupCreationResult(allocator: std.mem.Allocator, result: mls.GroupCreationResult) void {
    for (result.state.members) |member| {
        switch (member.credential) {
            .basic => |basic| allocator.free(basic.identity),
            else => {},
        }
    }
    allocator.free(result.state.members);
    
    for (result.state.group_context.extensions) |ext| {
        allocator.free(ext.extension_data);
    }
    allocator.free(result.state.group_context.extensions);
    
    for (result.welcomes) |welcome| {
        for (welcome.secrets) |secrets| {
            allocator.free(secrets.new_member);
            allocator.free(secrets.encrypted_group_secrets);
        }
        allocator.free(welcome.secrets);
        allocator.free(welcome.encrypted_group_info);
    }
    allocator.free(result.welcomes);
    
    // Free the non-shared parts of used key packages
    // The credentials are shared with group state members, but other parts need to be freed
    for (result.used_key_packages) |kp| {
        // Free the parts that aren't shared with group state
        allocator.free(kp.init_key.data);
        allocator.free(kp.leaf_node.encryption_key.data);
        allocator.free(kp.leaf_node.signature_key.data);
        allocator.free(kp.leaf_node.capabilities.versions);
        allocator.free(kp.leaf_node.capabilities.ciphersuites);
        allocator.free(kp.leaf_node.capabilities.extensions);
        allocator.free(kp.leaf_node.capabilities.proposals);
        allocator.free(kp.leaf_node.capabilities.credentials);
        allocator.free(kp.extensions);
        for (kp.leaf_node.extensions) |ext| {
            allocator.free(ext.extension_data);
        }
        allocator.free(kp.leaf_node.extensions);
        allocator.free(kp.leaf_node.signature);
        allocator.free(kp.signature);
        // Note: We don't free kp.leaf_node.credential because it's shared with group members
    }
}

test "MLS workflow example" {
    // This test demonstrates the basic MLS workflow
    const allocator = std.testing.allocator;
    var mls_provider = mls.provider.MlsProvider.init(allocator);
    
    // Generate test keys - use SHA256 of known strings as seeds for deterministic tests
    const alice_seed_str = "alice_test_seed_for_mls_workflow";
    const bob_seed_str = "bob_test_seed_for_mls_workflow";
    
    var alice_seed: [32]u8 = undefined;
    var bob_seed: [32]u8 = undefined;
    
    std.crypto.hash.sha2.Sha256.hash(alice_seed_str, &alice_seed, .{});
    std.crypto.hash.sha2.Sha256.hash(bob_seed_str, &bob_seed, .{});
    
    const alice_key = try crypto.deriveValidKeyFromSeed(alice_seed);
    const bob_key = try crypto.deriveValidKeyFromSeed(bob_seed);
    
    // Verify the keys are valid secp256k1 keys
    _ = try crypto.getPublicKey(alice_key);
    _ = try crypto.getPublicKey(bob_key);
    
    // Bob generates a key package
    const bob_kp = try mls.key_packages.generateKeyPackage(
        allocator,
        &mls_provider,
        bob_key,
        .{},
    );
    // Note: bob_kp will be consumed by createGroup, so we don't free it here
    
    // Alice creates a group
    var alice_pubkey: [32]u8 = undefined;
    alice_pubkey = try crypto.getPublicKey(alice_key);
    
    const params = mls.groups.GroupCreationParams{
        .name = "Test Group",
        .description = "Test",
        .admins = &[_][32]u8{alice_pubkey},
        .relays = &[_][]const u8{"wss://test.relay"},
        .image = null,
    };
    
    const result = try mls.groups.createGroup(
        allocator,
        &mls_provider,
        alice_key,
        params,
        &[_]mls.types.KeyPackage{bob_kp},
    );
    defer freeGroupCreationResult(allocator, result);
    
    // Verify group was created correctly
    try std.testing.expectEqual(@as(mls.types.Epoch, 0), result.state.epoch);
    try std.testing.expectEqual(@as(usize, 2), result.state.members.len); // Alice + Bob
    try std.testing.expectEqual(@as(usize, 1), result.welcomes.len); // Welcome for Bob
}

test "NostrGroupData extension round-trip" {
    const allocator = std.testing.allocator;
    
    const group_id = mls.types.GroupId.init([_]u8{42} ** 32);
    // Use valid secp256k1 public key
    const admin_privkey = try crypto.deriveValidKeyFromSeed([_]u8{1} ** 32);
    const admin_key = try crypto.getPublicKey(admin_privkey);
    
    const original_data = mls.extension.NostrGroupData{
        .group_id = group_id,
        .name = "Extension Test Group",
        .description = "Testing the NostrGroupData extension",
        .admins = &[_][32]u8{admin_key},
        .relays = &[_][]const u8{
            "wss://relay1.test",
            "wss://relay2.test",
        },
        .image = "data:image/png;base64,iVBORw0KGgo...",
    };
    
    // Create extension
    const ext = try mls.extension.createNostrGroupDataExtension(allocator, original_data);
    defer allocator.free(ext.extension_data);
    
    // Verify extension type
    try std.testing.expectEqual(mls.types.ExtensionType.nostr_group_data, ext.extension_type);
    
    // Extract data back
    const extracted = try mls.extension.extractNostrGroupData(allocator, ext);
    defer {
        allocator.free(extracted.name);
        allocator.free(extracted.description);
        allocator.free(extracted.admins);
        for (extracted.relays) |relay| {
            allocator.free(relay);
        }
        allocator.free(extracted.relays);
        if (extracted.image) |img| {
            allocator.free(img);
        }
    }
    
    // Verify all fields match
    try std.testing.expect(original_data.group_id.eql(extracted.group_id));
    try std.testing.expectEqualStrings(original_data.name, extracted.name);
    try std.testing.expectEqualStrings(original_data.description, extracted.description);
    try std.testing.expectEqual(original_data.admins.len, extracted.admins.len);
    try std.testing.expectEqualStrings(original_data.image.?, extracted.image.?);
}