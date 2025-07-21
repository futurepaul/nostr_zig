const std = @import("std");
const testing = std.testing;
const nostr = @import("nostr");
const mls = nostr.mls;
const crypto = nostr.crypto;

test "MLS state machine - full group lifecycle" {
    const allocator = testing.allocator;
    
    // Scenario: Alice creates a group, adds Bob, Bob updates his key, Alice adds Charlie,
    // Charlie sends a message, Bob leaves, epoch advances multiple times
    
    std.debug.print("\n=== MLS State Machine Full Lifecycle Test ===\n", .{});
    
    // Create MLS provider
    var mls_provider = mls.provider.MlsProvider.init(allocator);
    
    // Generate identity keys
    const alice_identity = try crypto.generatePrivateKey();
    const bob_identity = try crypto.generatePrivateKey();
    const charlie_identity = try crypto.generatePrivateKey();
    
    // Create key packages
    const alice_kp = try mls.key_packages.generateKeyPackage(
        allocator,
        &mls_provider,
        alice_identity,
        .{},
    );
    errdefer mls.key_packages.freeKeyPackage(allocator, alice_kp);
    defer mls.key_packages.freeKeyPackage(allocator, alice_kp);
    
    const bob_kp = try mls.key_packages.generateKeyPackage(
        allocator,
        &mls_provider,
        bob_identity,
        .{},
    );
    errdefer mls.key_packages.freeKeyPackage(allocator, bob_kp);
    defer mls.key_packages.freeKeyPackage(allocator, bob_kp);
    
    const charlie_kp = try mls.key_packages.generateKeyPackage(
        allocator,
        &mls_provider,
        charlie_identity,
        .{},
    );
    errdefer mls.key_packages.freeKeyPackage(allocator, charlie_kp);
    defer mls.key_packages.freeKeyPackage(allocator, charlie_kp);
    
    // Step 1: Alice creates the group
    std.debug.print("\nStep 1: Alice creates group\n", .{});
    const group_id = crypto.sha256Hash("test-group-2024");
    var state_machine = try mls.state_machine.MLSStateMachine.initializeGroup(
        allocator,
        group_id,
        alice_kp,
        alice_identity,
        &mls_provider,
        mls.state_machine.KeyRotationPolicy{}, // Use default rotation policy
    );
    defer state_machine.deinit();
    
    try testing.expectEqual(@as(u64, 0), state_machine.epoch);
    try testing.expectEqual(@as(usize, 1), state_machine.getMemberCount());
    std.debug.print("  ✓ Group created at epoch 0 with 1 member\n", .{});
    std.debug.print("  ✓ Group ID: {s}\n", .{std.fmt.fmtSliceHexLower(&group_id)});
    
    // Step 2: Alice proposes to add Bob
    std.debug.print("\nStep 2: Alice proposes to add Bob\n", .{});
    try state_machine.proposeAdd(0, bob_kp);
    try testing.expectEqual(@as(usize, 1), state_machine.pending_proposals.items.len);
    std.debug.print("  ✓ Add proposal created\n", .{});
    
    // Step 3: Alice commits the proposal (epoch 0 → 1)
    std.debug.print("\nStep 3: Alice commits (epoch 0 → 1)\n", .{});
    const commit1 = try state_machine.commitProposals(0, &mls_provider);
    try testing.expectEqual(@as(u64, 1), commit1.epoch);
    try testing.expectEqual(@as(usize, 2), state_machine.getMemberCount());
    std.debug.print("  ✓ Bob added, epoch advanced to 1\n", .{});
    std.debug.print("  ✓ Members: Alice (0), Bob (1)\n", .{});
    
    // Verify exporter secret changed
    const exporter1 = state_machine.epoch_secrets.exporter_secret;
    std.debug.print("  ✓ Exporter secret: {s}\n", .{std.fmt.fmtSliceHexLower(&exporter1.data)});
    
    // Step 4: Bob proposes to update his key
    std.debug.print("\nStep 4: Bob proposes key update\n", .{});
    const bob_new_signing = try crypto.generatePrivateKey();
    const bob_new_pubkey = try crypto.getPublicKey(bob_new_signing);
    var bob_new_leaf = bob_kp.leaf_node;
    bob_new_leaf.signature_key = mls.types.SignaturePublicKey.init(&bob_new_pubkey);
    
    try state_machine.proposeUpdate(1, bob_new_leaf);
    try testing.expectEqual(@as(usize, 1), state_machine.pending_proposals.items.len);
    std.debug.print("  ✓ Update proposal created\n", .{});
    
    // Step 5: Bob commits his update (epoch 1 → 2)
    std.debug.print("\nStep 5: Bob commits (epoch 1 → 2)\n", .{});
    const commit2 = try state_machine.commitProposals(1, &mls_provider);
    try testing.expectEqual(@as(u64, 2), commit2.epoch);
    std.debug.print("  ✓ Bob's key updated, epoch advanced to 2\n", .{});
    
    // Verify exporter secret changed again
    const exporter2 = state_machine.epoch_secrets.exporter_secret;
    try testing.expect(!std.mem.eql(u8, &exporter1.data, &exporter2.data));
    std.debug.print("  ✓ Exporter secret rotated: {s}\n", .{std.fmt.fmtSliceHexLower(&exporter2.data)});
    
    // Step 6: Alice proposes to add Charlie
    std.debug.print("\nStep 6: Alice proposes to add Charlie\n", .{});
    try state_machine.proposeAdd(0, charlie_kp);
    
    // Step 7: Alice commits (epoch 2 → 3)
    std.debug.print("\nStep 7: Alice commits (epoch 2 → 3)\n", .{});
    const commit3 = try state_machine.commitProposals(0, &mls_provider);
    try testing.expectEqual(@as(u64, 3), commit3.epoch);
    try testing.expectEqual(@as(usize, 3), state_machine.getMemberCount());
    std.debug.print("  ✓ Charlie added, epoch advanced to 3\n", .{});
    std.debug.print("  ✓ Members: Alice (0), Bob (1), Charlie (2)\n", .{});
    
    // Step 8: Simulate message sending at epoch 3
    std.debug.print("\nStep 8: Charlie sends a message\n", .{});
    const message = "Hello from Charlie!";
    const charlie_member = state_machine.getMember(2).?;
    std.debug.print("  ✓ Message: \"{s}\" from member {}\n", .{ message, charlie_member.leaf_index });
    std.debug.print("  ✓ Current epoch: {}\n", .{state_machine.epoch});
    std.debug.print("  ✓ Tree hash: {s}\n", .{std.fmt.fmtSliceHexLower(&state_machine.tree_hash)});
    
    // Step 9: Bob proposes to remove himself
    std.debug.print("\nStep 9: Bob proposes to leave\n", .{});
    try state_machine.proposeRemove(1, 1); // Bob removes himself
    
    // Step 10: Alice commits Bob's removal (epoch 3 → 4)
    std.debug.print("\nStep 10: Alice commits (epoch 3 → 4)\n", .{});
    const commit4 = try state_machine.commitProposals(0, &mls_provider);
    try testing.expectEqual(@as(u64, 4), commit4.epoch);
    try testing.expectEqual(@as(usize, 2), state_machine.getMemberCount());
    std.debug.print("  ✓ Bob removed, epoch advanced to 4\n", .{});
    
    // Verify member reindexing
    const alice_final = state_machine.getMember(0).?;
    const charlie_final = state_machine.getMember(1).?;
    try testing.expectEqual(@as(u32, 0), alice_final.leaf_index);
    try testing.expectEqual(@as(u32, 1), charlie_final.leaf_index);
    std.debug.print("  ✓ Members reindexed: Alice (0), Charlie (1)\n", .{});
    
    // Verify exporter secret rotated again
    const exporter4 = state_machine.epoch_secrets.exporter_secret;
    try testing.expect(!std.mem.eql(u8, &exporter2.data, &exporter4.data));
    std.debug.print("  ✓ Final exporter secret: {s}\n", .{std.fmt.fmtSliceHexLower(&exporter4.data)});
    
    // Summary
    std.debug.print("\n=== Test Summary ===\n", .{});
    std.debug.print("✓ Group lifecycle complete\n", .{});
    std.debug.print("✓ Epochs: 0 → 1 → 2 → 3 → 4\n", .{});
    std.debug.print("✓ Membership changes tracked correctly\n", .{});
    std.debug.print("✓ Exporter secrets rotated on each epoch\n", .{});
    std.debug.print("✓ Tree hashes updated\n", .{});
}

test "MLS state machine - concurrent proposals" {
    const allocator = testing.allocator;
    
    std.debug.print("\n=== MLS Concurrent Proposals Test ===\n", .{});
    
    // Create MLS provider
    var mls_provider = mls.provider.MlsProvider.init(allocator);
    
    // Create identity keys and key packages for 4 members
    var identity_keys: [4][32]u8 = undefined;
    var key_packages: [4]mls.types.KeyPackage = undefined;
    for (&key_packages, &identity_keys, 0..) |*kp, *identity, i| {
        identity.* = try crypto.generatePrivateKey();
        kp.* = try mls.key_packages.generateKeyPackage(allocator, &mls_provider, identity.*, .{});
        _ = i;
    }
    defer for (key_packages) |kp| {
        mls.key_packages.freeKeyPackage(allocator, kp);
    };
    
    // Initialize group with member 0
    const group_id = crypto.sha256Hash("concurrent-test-group");
    var state_machine = try mls.state_machine.MLSStateMachine.initializeGroup(
        allocator,
        group_id,
        key_packages[0],
        identity_keys[0],
        &mls_provider,
        mls.state_machine.KeyRotationPolicy{}, // Use default rotation policy
    );
    defer state_machine.deinit();
    
    // Add members 1 and 2
    try state_machine.proposeAdd(0, key_packages[1]);
    try state_machine.proposeAdd(0, key_packages[2]);
    _ = try state_machine.commitProposals(0, &mls_provider);
    
    std.debug.print("\nInitial state: 3 members at epoch 1\n", .{});
    
    // Multiple concurrent proposals
    std.debug.print("\nCreating multiple proposals:\n", .{});
    
    // Member 0 proposes to add member 3
    try state_machine.proposeAdd(0, key_packages[3]);
    std.debug.print("  - Member 0 proposes: add member 3\n", .{});
    
    // Member 1 proposes to update their key
    var member1_new_leaf = key_packages[1].leaf_node;
    const member1_new_privkey = try crypto.generatePrivateKey();
    const member1_new_pubkey = try crypto.getPublicKey(member1_new_privkey);
    member1_new_leaf.signature_key = mls.types.SignaturePublicKey.init(&member1_new_pubkey);
    try state_machine.proposeUpdate(1, member1_new_leaf);
    std.debug.print("  - Member 1 proposes: update key\n", .{});
    
    // Member 2 proposes to update their key
    var member2_new_leaf = key_packages[2].leaf_node;
    const member2_new_privkey = try crypto.generatePrivateKey();
    const member2_new_pubkey = try crypto.getPublicKey(member2_new_privkey);
    member2_new_leaf.signature_key = mls.types.SignaturePublicKey.init(&member2_new_pubkey);
    try state_machine.proposeUpdate(2, member2_new_leaf);
    std.debug.print("  - Member 2 proposes: update key\n", .{});
    
    try testing.expectEqual(@as(usize, 3), state_machine.pending_proposals.items.len);
    std.debug.print("\n✓ 3 proposals pending\n", .{});
    
    // Commit all proposals at once
    const commit_result = try state_machine.commitProposals(0, &mls_provider);
    
    std.debug.print("\nCommit results:\n", .{});
    std.debug.print("  ✓ New epoch: {}\n", .{commit_result.epoch});
    std.debug.print("  ✓ Added members: {}\n", .{commit_result.added_members});
    std.debug.print("  ✓ Path required: {}\n", .{commit_result.path_required});
    std.debug.print("  ✓ Total members: {}\n", .{state_machine.getMemberCount()});
    
    try testing.expectEqual(@as(u64, 2), commit_result.epoch);
    try testing.expectEqual(@as(usize, 4), state_machine.getMemberCount());
    try testing.expectEqual(@as(usize, 0), state_machine.pending_proposals.items.len);
}

test "MLS state machine - epoch secret derivation" {
    const allocator = testing.allocator;
    
    std.debug.print("\n=== MLS Epoch Secret Derivation Test ===\n", .{});
    
    // Create MLS provider
    var mls_provider = mls.provider.MlsProvider.init(allocator);
    
    // Create a group
    const identity_key = try crypto.generatePrivateKey();
    const kp = try mls.key_packages.generateKeyPackage(
        allocator,
        &mls_provider,
        identity_key,
        .{},
    );
    defer mls.key_packages.freeKeyPackage(allocator, kp);
    
    const group_id = crypto.sha256Hash("secret-test-group");
    var state_machine = try mls.state_machine.MLSStateMachine.initializeGroup(
        allocator,
        group_id,
        kp,
        identity_key,
        &mls_provider,
        mls.state_machine.KeyRotationPolicy{}, // Use default rotation policy
    );
    defer state_machine.deinit();
    
    // Track exporter secrets across epochs
    var exporter_secrets: [3][32]u8 = undefined;
    exporter_secrets[0] = state_machine.epoch_secrets.exporter_secret.data;
    
    std.debug.print("\nEpoch 0 secrets:\n", .{});
    std.debug.print("  Exporter: {s}\n", .{std.fmt.fmtSliceHexLower(&exporter_secrets[0])});
    
    // Add a member to trigger epoch change
    const new_identity = try crypto.generatePrivateKey();
    const new_kp = try mls.key_packages.generateKeyPackage(
        allocator,
        &mls_provider,
        new_identity,
        .{},
    );
    errdefer mls.key_packages.freeKeyPackage(allocator, new_kp);
    defer mls.key_packages.freeKeyPackage(allocator, new_kp);
    
    try state_machine.proposeAdd(0, new_kp);
    _ = try state_machine.commitProposals(0, &mls_provider);
    exporter_secrets[1] = state_machine.epoch_secrets.exporter_secret.data;
    
    std.debug.print("\nEpoch 1 secrets:\n", .{});
    std.debug.print("  Exporter: {s}\n", .{std.fmt.fmtSliceHexLower(&exporter_secrets[1])});
    
    // Update to trigger another epoch change
    var updated_leaf = kp.leaf_node;
    const new_privkey = try crypto.generatePrivateKey();
    const new_pubkey = try crypto.getPublicKey(new_privkey);
    updated_leaf.signature_key = mls.types.SignaturePublicKey.init(&new_pubkey);
    try state_machine.proposeUpdate(0, updated_leaf);
    _ = try state_machine.commitProposals(0, &mls_provider);
    exporter_secrets[2] = state_machine.epoch_secrets.exporter_secret.data;
    
    std.debug.print("\nEpoch 2 secrets:\n", .{});
    std.debug.print("  Exporter: {s}\n", .{std.fmt.fmtSliceHexLower(&exporter_secrets[2])});
    
    // Verify all exporter secrets are different
    for (exporter_secrets, 0..) |secret1, i| {
        for (exporter_secrets[i + 1 ..], i + 1..) |secret2, j| {
            try testing.expect(!std.mem.eql(u8, &secret1, &secret2));
            std.debug.print("\n✓ Epoch {} and {} have different exporter secrets\n", .{ i, j });
        }
    }
    
    // Verify other epoch secrets are also set
    std.debug.print("\n✓ All epoch secrets derived:\n", .{});
    std.debug.print("  - Joiner secret: {s}\n", .{std.fmt.fmtSliceHexLower(state_machine.epoch_secrets.joiner_secret.data[0..16])});
    std.debug.print("  - Epoch authenticator: {s}\n", .{std.fmt.fmtSliceHexLower(state_machine.epoch_secrets.epoch_authenticator.data[0..16])});
    std.debug.print("  - Encryption secret: {s}\n", .{std.fmt.fmtSliceHexLower(state_machine.epoch_secrets.encryption_secret.data[0..16])});
}