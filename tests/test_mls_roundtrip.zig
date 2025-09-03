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
    
    // Step 4: Use flat KeyPackage directly for createGroup
    std.debug.print("\n4. Using flat KeyPackage for group creation...\n", .{});
    
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
        &[_]mls_zig.key_package_flat.KeyPackage{parsed_bob_kp},
    );
    defer freeGroupCreationResult(allocator, creation_result);
    
    std.debug.print("  ✅ Group created!\n", .{});
    std.debug.print("  Group ID: {s}\n", .{std.fmt.fmtSliceHexLower(&creation_result.state.group_id.data)});
    std.debug.print("  Epoch: {}\n", .{creation_result.state.epoch});
    std.debug.print("  Members: {}\n", .{creation_result.state.members.len});
    std.debug.print("  Welcome messages: {}\n", .{creation_result.welcomes.len});
    
    try testing.expectEqual(@as(u64, 0), creation_result.state.epoch);
    try testing.expectEqual(@as(usize, 2), creation_result.state.members.len); // Alice + Bob
    try testing.expectEqual(@as(usize, 1), creation_result.welcomes.len); // One welcome for Bob
    
    // Step 6: Extract and verify the Welcome message
    std.debug.print("\n6. Verifying Welcome message...\n", .{});
    
    const welcome = creation_result.welcomes[0];
    std.debug.print("  Welcome cipher suite: {}\n", .{welcome.cipher_suite});
    std.debug.print("  Welcome secrets: {} secrets\n", .{welcome.secrets.len});
    
    // The Welcome should contain encrypted group info that Bob can decrypt
    try testing.expect(welcome.secrets.len > 0);
    try testing.expect(welcome.encrypted_group_info.len > 0);
    
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

fn freeGroupCreationResult(allocator: std.mem.Allocator, result: nostr.mls.GroupCreationResult) void {
    // Free state members
    allocator.free(result.state.members);
    
    // Free ratchet tree
    allocator.free(result.state.ratchet_tree);
    
    // Free welcomes
    for (result.welcomes) |welcome| {
        nostr.mls.welcomes.freeWelcome(allocator, welcome);
    }
    allocator.free(result.welcomes);
    
    // Free used key packages (flat KeyPackages don't need individual freeing)
    allocator.free(result.used_key_packages);
}