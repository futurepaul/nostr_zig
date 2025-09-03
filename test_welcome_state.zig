// Standalone test runner for welcome roundtrip with state machine
const std = @import("std");
const testing = std.testing;
const nostr = @import("nostr");
const mls_zig = @import("mls_zig");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    
    std.debug.print("\n=== MLS Welcome Roundtrip with State Machine Test ===\n\n", .{});
    
    // Initialize global key storage
    const key_storage = nostr.mls.key_storage;
    _ = try key_storage.getGlobalStorage(allocator);
    defer key_storage.deinitGlobalStorage();
    
    // 1. Generate keypairs for Alice and Bob
    std.debug.print("1. Generating identities...\n", .{});
    
    // Bob's keys
    const bob_secret_key = [_]u8{2} ++ [_]u8{0} ** 31;
    const bob_public_key = try nostr.crypto.getPublicKey(bob_secret_key);
    const bob_public_hex = try nostr.crypto.bytesToHex(allocator, &bob_public_key);
    defer allocator.free(bob_public_hex);
    
    std.debug.print("   Bob's public key: {s}\n", .{bob_public_hex});
    
    // Alice's keys
    const alice_secret_key = [_]u8{1} ++ [_]u8{0} ** 31;
    const alice_public_key = try nostr.crypto.getPublicKey(alice_secret_key);
    const alice_public_hex = try nostr.crypto.bytesToHex(allocator, &alice_public_key);
    defer allocator.free(alice_public_hex);
    
    std.debug.print("   Alice's public key: {s}\n", .{alice_public_hex});
    
    // 2. Bob creates and publishes his KeyPackage
    std.debug.print("\n2. Bob creates his KeyPackage...\n", .{});
    
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
    
    // 3. Alice creates a group and invites Bob
    std.debug.print("\n3. Alice creates a group and invites Bob...\n", .{});
    
    // Parse Bob's KeyPackage
    const bob_kp = try mls_zig.key_package_flat.KeyPackage.tlsDeserialize(allocator, bob_kp_serialized);
    
    // Create MLS provider
    var mls_provider = nostr.mls.provider.MlsProvider.init(allocator);
    
    // Create group parameters
    const group_params = nostr.mls.groups.GroupCreationParams{
        .name = "Test Group",
        .description = "Testing MLS with state machine",
        .admins = &[_][32]u8{alice_public_key},
        .relays = &[_][]const u8{"ws://localhost:10547"},
        .image = null,
    };
    
    const members = [_]mls_zig.key_package_flat.KeyPackage{bob_kp};
    
    const group_result = try nostr.mls.groups.createGroup(
        allocator,
        &mls_provider,
        alice_secret_key,
        group_params,
        &members,
    );
    defer allocator.free(group_result.used_key_packages);
    
    const group_id_hex = try nostr.crypto.bytesToHex(allocator, &group_result.state.group_id.data);
    defer allocator.free(group_id_hex);
    
    std.debug.print("   ✅ Group created! ID: {s}\n", .{group_id_hex});
    
    // 4. Bob joins the group
    std.debug.print("\n4. Bob processes the Welcome message...\n", .{});
    
    const welcome_for_bob = group_result.welcomes[0];
    const welcome_bytes = try nostr.mls.welcomes.serializeWelcome(allocator, welcome_for_bob);
    defer allocator.free(welcome_bytes);
    
    const join_result = try nostr.mls.welcomes.joinFromWelcome(
        allocator,
        &mls_provider,
        welcome_bytes,
        bob_secret_key,
    );
    
    std.debug.print("   ✅ Bob joined the group!\n", .{});
    
    // 5. Test state machine functionality
    std.debug.print("\n5. Testing state machine with messaging...\n", .{});
    
    // Check if state machines have real epoch secrets
    const alice_has_real_secrets = group_result.state.epoch_secrets.exporter_secret[0] != 0x07;
    const bob_has_real_secrets = join_result.state.epoch_secrets.exporter_secret[0] != 0x07;
    
    std.debug.print("   Alice has real secrets: {}\n", .{alice_has_real_secrets});
    std.debug.print("   Bob has real secrets: {}\n", .{bob_has_real_secrets});
    
    if (!alice_has_real_secrets or !bob_has_real_secrets) {
        std.debug.print("\n⚠️  WARNING: State machine is using placeholder secrets!\n", .{});
        std.debug.print("   This means we're not using real MLS cryptography.\n", .{});
        std.debug.print("   The state machine needs to be fixed to use real epoch secrets.\n", .{});
    } else {
        std.debug.print("\n✅ SUCCESS: State machine is using real MLS epoch secrets!\n", .{});
    }
    
    // Test message encryption/decryption
    const alice_message = "Hello Bob! This is Alice.";
    std.debug.print("\n6. Testing message encryption...\n", .{});
    std.debug.print("   Alice's message: \"{s}\"\n", .{alice_message});
    
    // Use exporter secret for encryption as per NIP-EE
    const alice_exporter = group_result.state.epoch_secrets.exporter_secret;
    const bob_exporter = join_result.state.epoch_secrets.exporter_secret;
    
    // Debug: Show what secrets we're comparing
    std.debug.print("\n   Debug: Epoch secrets comparison:\n", .{});
    std.debug.print("   Alice joiner_secret: {s}\n", .{std.fmt.fmtSliceHexLower(&group_result.state.epoch_secrets.joiner_secret)});
    std.debug.print("   Bob joiner_secret:   {s}\n", .{std.fmt.fmtSliceHexLower(&join_result.state.epoch_secrets.joiner_secret)});
    std.debug.print("   Alice epoch_secret:  {s}\n", .{std.fmt.fmtSliceHexLower(&group_result.state.epoch_secrets.epoch_secret)});
    std.debug.print("   Bob epoch_secret:    {s}\n", .{std.fmt.fmtSliceHexLower(&join_result.state.epoch_secrets.epoch_secret)});
    
    // Verify they match
    if (std.mem.eql(u8, &alice_exporter, &bob_exporter)) {
        std.debug.print("\n   ✅ Exporter secrets match!\n", .{});
    } else {
        std.debug.print("\n   ❌ ERROR: Exporter secrets don't match!\n", .{});
        std.debug.print("   Alice exporter: {s}\n", .{std.fmt.fmtSliceHexLower(&alice_exporter)});
        std.debug.print("   Bob exporter:   {s}\n", .{std.fmt.fmtSliceHexLower(&bob_exporter)});
    }
    
    std.debug.print("\n=== Test Complete ===\n", .{});
}