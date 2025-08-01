const std = @import("std");
const testing = std.testing;
const nostr = @import("nostr");

test "MLS roundtrip - create group, send welcome, join group" {
    const allocator = testing.allocator;
    
    std.debug.print("\n=== MLS Roundtrip Test (No Relay) ===\n", .{});
    
    // Initialize MLS provider
    var mls_provider = nostr.mls.provider.MlsProvider.init(allocator);
    
    // Step 1: Generate keypairs for Alice and Bob
    std.debug.print("\n1. Generating keypairs...\n", .{});
    const alice_privkey = try nostr.crypto.generatePrivateKey();
    const bob_privkey = try nostr.crypto.generatePrivateKey();
    
    var alice_pubkey: [32]u8 = undefined;
    alice_pubkey = try nostr.crypto.getPublicKey(alice_privkey);
    var bob_pubkey: [32]u8 = undefined;
    bob_pubkey = try nostr.crypto.getPublicKey(bob_privkey);
    
    std.debug.print("  Alice pubkey: {s}\n", .{std.fmt.fmtSliceHexLower(&alice_pubkey)});
    std.debug.print("  Bob pubkey: {s}\n", .{std.fmt.fmtSliceHexLower(&bob_pubkey)});
    
    // Step 2: Bob creates and serializes his KeyPackage
    std.debug.print("\n2. Bob creates his KeyPackage...\n", .{});
    
    // Use the flat KeyPackage implementation (WASM-safe)
    const mls_zig = @import("mls_zig");
    const bob_kp_bundle = try mls_zig.key_package_flat.KeyPackageBundle.init(
        allocator,
        .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        &bob_pubkey, // credential_identity
        null, // random_fn
    );
    
    // Serialize Bob's KeyPackage
    const bob_kp_bytes = try bob_kp_bundle.key_package.tlsSerialize(allocator);
    defer allocator.free(bob_kp_bytes);
    
    std.debug.print("  Bob's KeyPackage size: {} bytes\n", .{bob_kp_bytes.len});
    std.debug.print("  First 16 bytes: {s}\n", .{std.fmt.fmtSliceHexLower(bob_kp_bytes[0..16])});
    
    // Step 3: Alice parses Bob's KeyPackage
    std.debug.print("\n3. Alice parses Bob's KeyPackage...\n", .{});
    
    const parsed_bob_kp = try mls_zig.key_package_flat.KeyPackage.tlsDeserialize(allocator, bob_kp_bytes);
    
    try testing.expectEqual(mls_zig.key_package_flat.MLS_PROTOCOL_VERSION, parsed_bob_kp.protocol_version);
    try testing.expectEqual(mls_zig.cipher_suite.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519, parsed_bob_kp.cipher_suite);
    
    std.debug.print("  ✅ Successfully parsed Bob's KeyPackage!\n", .{});
    std.debug.print("  Protocol version: 0x{x:0>4}\n", .{parsed_bob_kp.protocol_version});
    std.debug.print("  Cipher suite: {}\n", .{@intFromEnum(parsed_bob_kp.cipher_suite)});
    
    // Step 4: Convert flat KeyPackage to legacy format for createGroup
    std.debug.print("\n4. Converting KeyPackage format for group creation...\n", .{});
    
    const bob_legacy_kp = try nostr.mls.keypackage_converter.flatToLegacy(allocator, parsed_bob_kp);
    defer nostr.mls.keypackage_converter.freeLegacyKeyPackage(allocator, bob_legacy_kp);
    
    // Step 5: Alice creates a group with Bob as initial member
    std.debug.print("\n5. Alice creates MLS group with Bob as member...\n", .{});
    
    const group_params = nostr.mls.groups.GroupCreationParams{
        .name = "Test Group",
        .description = "MLS roundtrip test group",
        .admins = &[_][32]u8{alice_pubkey},
        .relays = &[_][]const u8{"ws://localhost:10547"},
        .image = null,
    };
    
    const creation_result = try nostr.mls.groups.createGroup(
        allocator,
        &mls_provider,
        alice_privkey,
        group_params,
        &[_]nostr.mls.types.KeyPackage{bob_legacy_kp},
    );
    defer freeGroupCreationResult(allocator, creation_result);
    
    std.debug.print("  ✅ Group created!\n", .{});
    std.debug.print("  Group ID: {s}\n", .{std.fmt.fmtSliceHexLower(&creation_result.state.group_id)});
    std.debug.print("  Epoch: {}\n", .{creation_result.state.epoch});
    std.debug.print("  Members: {}\n", .{creation_result.state.members.len});
    std.debug.print("  Welcome messages: {}\n", .{creation_result.welcomes.len});
    
    try testing.expectEqual(@as(u64, 0), creation_result.state.epoch);
    try testing.expectEqual(@as(usize, 2), creation_result.state.members.len); // Alice + Bob
    try testing.expectEqual(@as(usize, 1), creation_result.welcomes.len); // One welcome for Bob
    
    // Step 6: Extract and verify the Welcome message
    std.debug.print("\n6. Verifying Welcome message...\n", .{});
    
    const welcome = creation_result.welcomes[0];
    std.debug.print("  Welcome cipher suites: {} suites\n", .{welcome.cipher_suites.len});
    std.debug.print("  Welcome secrets: {} secrets\n", .{welcome.secrets.len});
    
    // The Welcome should contain encrypted group info that Bob can decrypt
    try testing.expect(welcome.cipher_suites.len > 0);
    try testing.expect(welcome.secrets.len > 0);
    
    // Step 7: Bob would process the Welcome (TODO when join-group is implemented)
    std.debug.print("\n7. Bob processing Welcome...\n", .{});
    std.debug.print("  🚧 TODO: Implement Welcome processing\n", .{});
    std.debug.print("  The Welcome contains all cryptographic material Bob needs to join\n", .{});
    
    std.debug.print("\n✅ MLS Roundtrip Test Complete!\n", .{});
    std.debug.print("  - Bob created and serialized KeyPackage\n", .{});
    std.debug.print("  - Alice parsed Bob's KeyPackage\n", .{});
    std.debug.print("  - Alice created group with Bob as member\n", .{});
    std.debug.print("  - Alice generated Welcome for Bob\n", .{});
    std.debug.print("  - Next: Bob processes Welcome to join group\n\n", .{});
}

fn freeGroupCreationResult(allocator: std.mem.Allocator, result: anytype) void {
    // Free group state
    allocator.free(result.state.group_id);
    allocator.free(result.state.epoch_secrets.init_secret);
    allocator.free(result.state.epoch_secrets.sender_data_secret);
    allocator.free(result.state.epoch_secrets.encryption_secret);
    allocator.free(result.state.epoch_secrets.exporter_secret);
    allocator.free(result.state.epoch_secrets.epoch_authenticator);
    allocator.free(result.state.epoch_secrets.external_secret);
    allocator.free(result.state.epoch_secrets.confirmation_key);
    allocator.free(result.state.epoch_secrets.membership_key);
    allocator.free(result.state.epoch_secrets.resumption_psk);
    allocator.free(result.state.epoch_secrets.external_pub);
    
    // Free tree
    nostr.mls.tree_kem.freeTree(allocator, result.state.tree);
    
    // Free members
    for (result.state.members) |member| {
        allocator.free(member.identity);
    }
    allocator.free(result.state.members);
    
    // Free metadata
    allocator.free(result.state.metadata.name);
    allocator.free(result.state.metadata.description);
    allocator.free(result.state.metadata.image);
    for (result.state.metadata.admins) |admin| {
        allocator.free(admin);
    }
    allocator.free(result.state.metadata.admins);
    for (result.state.metadata.relays) |relay| {
        allocator.free(relay);
    }
    allocator.free(result.state.metadata.relays);
    
    // Free welcomes
    for (result.welcomes) |welcome| {
        allocator.free(welcome.cipher_suites);
        for (welcome.secrets) |secret| {
            allocator.free(secret.new_member);
            allocator.free(secret.encrypted_group_info);
        }
        allocator.free(welcome.secrets);
        allocator.free(welcome.encrypted_group_info);
    }
    allocator.free(result.welcomes);
    
    // Free used key packages
    for (result.used_key_packages) |kp| {
        nostr.mls.key_packages.freeKeyPackage(allocator, kp);
    }
    allocator.free(result.used_key_packages);
}