const std = @import("std");
const lib = @import("src/root.zig");
const mls_zig = @import("deps/mls_zig/src/root.zig");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    
    std.debug.print("\n=== MLS Roundtrip Test (Standalone) ===\n", .{});
    
    // Initialize MLS provider
    var mls_provider = lib.mls.provider.MlsProvider.init(allocator);
    
    // Step 1: Generate keypairs for Alice and Bob
    std.debug.print("\n1. Generating keypairs...\n", .{});
    const alice_privkey = try lib.crypto.generatePrivateKey();
    const bob_privkey = try lib.crypto.generatePrivateKey();
    
    var alice_pubkey: [32]u8 = undefined;
    alice_pubkey = try lib.crypto.getPublicKey(alice_privkey);
    var bob_pubkey: [32]u8 = undefined;
    bob_pubkey = try lib.crypto.getPublicKey(bob_privkey);
    
    const alice_hex = try lib.crypto.bytesToHex(allocator, &alice_pubkey);
    defer allocator.free(alice_hex);
    const bob_hex = try lib.crypto.bytesToHex(allocator, &bob_pubkey);
    defer allocator.free(bob_hex);
    
    std.debug.print("  Alice pubkey: {s}\n", .{alice_hex});
    std.debug.print("  Bob pubkey: {s}\n", .{bob_hex});
    
    // Step 2: Bob creates and serializes his KeyPackage
    std.debug.print("\n2. Bob creates his KeyPackage...\n", .{});
    
    // Create Bob's KeyPackage using flat implementation
    const bob_kp_bundle = try mls_zig.key_package_flat.KeyPackageBundle.init(
        allocator,
        .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        &bob_pubkey,
        null,
    );
    
    // Serialize Bob's KeyPackage
    const bob_kp_bytes = try bob_kp_bundle.key_package.tlsSerialize(allocator);
    defer allocator.free(bob_kp_bytes);
    
    std.debug.print("  Bob's KeyPackage size: {} bytes\n", .{bob_kp_bytes.len});
    const first_bytes = try lib.crypto.bytesToHex(allocator, bob_kp_bytes[0..@min(16, bob_kp_bytes.len)]);
    defer allocator.free(first_bytes);
    std.debug.print("  First 16 bytes: {s}\n", .{first_bytes});
    
    // Step 3: Alice parses Bob's KeyPackage
    std.debug.print("\n3. Alice parses Bob's KeyPackage...\n", .{});
    
    const parsed_bob_kp = try mls_zig.key_package_flat.KeyPackage.tlsDeserialize(allocator, bob_kp_bytes);
    
    if (parsed_bob_kp.protocol_version != mls_zig.key_package_flat.MLS_PROTOCOL_VERSION) {
        return error.InvalidProtocolVersion;
    }
    
    std.debug.print("  ✅ Successfully parsed Bob's KeyPackage!\n", .{});
    std.debug.print("  Protocol version: 0x{x:0>4}\n", .{parsed_bob_kp.protocol_version});
    std.debug.print("  Cipher suite: {}\n", .{@intFromEnum(parsed_bob_kp.cipher_suite)});
    
    // Step 4: Use flat KeyPackage directly for createGroup
    std.debug.print("\n4. Using flat KeyPackage for group creation...\n", .{});
    
    // Step 5: Alice creates a group with Bob as initial member
    std.debug.print("\n5. Alice creates MLS group with Bob as member...\n", .{});
    
    const group_params = lib.mls.groups.GroupCreationParams{
        .name = "Test Group",
        .description = "MLS roundtrip test group",
        .admins = &[_][32]u8{alice_pubkey},
        .relays = &[_][]const u8{"ws://localhost:10547"},
        .image = null,
    };
    
    const creation_result = try lib.mls.groups.createGroup(
        allocator,
        &mls_provider,
        alice_privkey,
        group_params,
        &[_]mls_zig.key_package_flat.KeyPackage{parsed_bob_kp},
    );
    defer freeGroupCreationResult(allocator, creation_result);
    
    const group_id_hex = try lib.crypto.bytesToHex(allocator, &creation_result.state.group_id);
    defer allocator.free(group_id_hex);
    
    std.debug.print("  ✅ Group created!\n", .{});
    std.debug.print("  Group ID: {s}\n", .{group_id_hex});
    std.debug.print("  Epoch: {}\n", .{creation_result.state.epoch});
    std.debug.print("  Members: {}\n", .{creation_result.state.members.len});
    std.debug.print("  Welcome messages: {}\n", .{creation_result.welcomes.len});
    
    // Verify expectations
    if (creation_result.state.epoch != 0) {
        return error.UnexpectedEpoch;
    }
    if (creation_result.state.members.len != 2) { // Alice + Bob
        return error.UnexpectedMemberCount;
    }
    if (creation_result.welcomes.len != 1) { // One welcome for Bob
        return error.UnexpectedWelcomeCount;
    }
    
    // Step 6: Extract and verify the Welcome message
    std.debug.print("\n6. Verifying Welcome message...\n", .{});
    
    const welcome = creation_result.welcomes[0];
    std.debug.print("  Welcome cipher suites: {} suites\n", .{welcome.cipher_suites.len});
    std.debug.print("  Welcome secrets: {} secrets\n", .{welcome.secrets.len});
    
    if (welcome.cipher_suites.len == 0) {
        return error.NoWelcomeCipherSuites;
    }
    if (welcome.secrets.len == 0) {
        return error.NoWelcomeSecrets;
    }
    
    // Step 7: Serialize the Welcome message
    std.debug.print("\n7. Serializing Welcome message...\n", .{});
    
    // This demonstrates that we can serialize the Welcome for transport
    var welcome_buffer = std.ArrayList(u8).init(allocator);
    defer welcome_buffer.deinit();
    
    const welcome_writer = welcome_buffer.writer();
    try lib.mls.serialization.Serializer.serializeWelcome(welcome_writer, welcome);
    
    const welcome_bytes = welcome_buffer.items;
    std.debug.print("  Serialized Welcome size: {} bytes\n", .{welcome_bytes.len});
    
    // Step 8: Bob would process the Welcome
    std.debug.print("\n8. Bob processing Welcome...\n", .{});
    std.debug.print("  🚧 TODO: Implement Welcome processing\n", .{});
    std.debug.print("  The Welcome contains:\n", .{});
    std.debug.print("    - Encrypted GroupInfo with group parameters\n", .{});
    std.debug.print("    - Path secrets for Bob to derive epoch secrets\n", .{});
    std.debug.print("    - Everything needed to initialize Bob's group state\n", .{});
    
    std.debug.print("\n✅ MLS Roundtrip Test Complete!\n", .{});
    std.debug.print("Summary:\n", .{});
    std.debug.print("  1. Bob created a {} byte KeyPackage\n", .{bob_kp_bytes.len});
    std.debug.print("  2. Alice successfully parsed it\n", .{});
    std.debug.print("  3. Alice created group with ID: {s}\n", .{group_id_hex[0..16]});
    std.debug.print("  4. Alice generated Welcome message ({} bytes)\n", .{welcome_bytes.len});
    std.debug.print("  5. Ready for Bob to join (implementation pending)\n", .{});
    std.debug.print("\nThis proves we can read our own KeyPackages and create valid MLS groups!\n", .{});
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
    lib.mls.tree_kem.freeTree(allocator, result.state.tree);
    
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
        lib.mls.key_packages.freeKeyPackage(allocator, kp);
    }
    allocator.free(result.used_key_packages);
}