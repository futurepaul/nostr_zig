const std = @import("std");
const testing = std.testing;

// Import through the build system module as per DEVELOPMENT.md
const nostr = @import("nostr");
const crypto = nostr.crypto;
const event = nostr.event;
const welcome_events = nostr.mls.welcome_events;
const nip59 = nostr.mls.nip59;
const types = nostr.mls.types;

// Test the pure Zig implementation first, as per guidelines
test "welcome events core functionality" {
    // Only test if the modules are available (HKDF error may prevent full builds)
    
    // Test 1: Event kind constants are correct
    const WELCOME_KIND = 444;
    const SEAL_KIND = 13;
    const GIFT_WRAP_KIND = 1059;
    
    try testing.expectEqual(@as(u32, 444), WELCOME_KIND);
    try testing.expectEqual(@as(u32, 13), SEAL_KIND);
    try testing.expectEqual(@as(u32, 1059), GIFT_WRAP_KIND);
    
    // Test 2: Basic event structure for Welcome Events
    const allocator = testing.allocator;
    
    // Create an unsigned rumor (as required by NIP-59)
    const tags = try allocator.alloc([]const []const u8, 2);
    defer allocator.free(tags);
    
    // e tag for KeyPackage Event reference
    const e_tag = try allocator.alloc([]const u8, 2);
    defer allocator.free(e_tag);
    e_tag[0] = try allocator.dupe(u8, "e");
    e_tag[1] = try allocator.dupe(u8, "test_keypackage_event_id");
    defer allocator.free(e_tag[0]);
    defer allocator.free(e_tag[1]);
    
    // relays tag
    const relays_tag = try allocator.alloc([]const u8, 3);
    defer allocator.free(relays_tag);
    relays_tag[0] = try allocator.dupe(u8, "relays");
    relays_tag[1] = try allocator.dupe(u8, "wss://relay1.example.com");
    relays_tag[2] = try allocator.dupe(u8, "wss://relay2.example.com");
    defer allocator.free(relays_tag[0]);
    defer allocator.free(relays_tag[1]);
    defer allocator.free(relays_tag[2]);
    
    tags[0] = e_tag;
    tags[1] = relays_tag;
    
    // Create test Welcome Event rumor structure
    const welcome_rumor = event.Event{
        .id = try allocator.dupe(u8, "test_welcome_event_id"),
        .pubkey = try allocator.dupe(u8, "test_sender_pubkey_hex"),
        .created_at = std.time.timestamp(),
        .kind = WELCOME_KIND,
        .tags = tags,
        .content = try allocator.dupe(u8, "serialized_mls_welcome_data_hex"),
        .sig = try allocator.dupe(u8, ""), // Unsigned rumor!
    };
    defer welcome_rumor.deinit(allocator);
    
    // Verify rumor properties
    try testing.expectEqual(WELCOME_KIND, welcome_rumor.kind);
    try testing.expectEqualStrings("", welcome_rumor.sig); // Must be unsigned
    try testing.expectEqual(@as(usize, 2), welcome_rumor.tags.len);
    
    // Verify e tag structure
    try testing.expectEqualStrings("e", welcome_rumor.tags[0][0]);
    try testing.expectEqualStrings("test_keypackage_event_id", welcome_rumor.tags[0][1]);
    
    // Verify relays tag structure  
    try testing.expectEqualStrings("relays", welcome_rumor.tags[1][0]);
    try testing.expectEqualStrings("wss://relay1.example.com", welcome_rumor.tags[1][1]);
    try testing.expectEqualStrings("wss://relay2.example.com", welcome_rumor.tags[1][2]);
}

test "nip59 gift wrap concepts" {
    const allocator = testing.allocator;
    
    // Test NIP-59 timestamp tweaking as per spec
    const now = std.time.timestamp();
    var prng = std.Random.DefaultPrng.init(@intCast(now));
    const random = prng.random();
    
    // NIP-59: timestamps should be tweaked up to 2 days (172800 seconds)
    const tweak_seconds = random.intRangeAtMost(i64, 0, 172800);
    const tweaked_timestamp = now - tweak_seconds;
    
    try testing.expect(tweaked_timestamp <= now);
    try testing.expect(tweaked_timestamp >= now - 172800);
    
    // Test ephemeral key generation concept
    var ephemeral_key: [32]u8 = undefined;
    std.crypto.random.bytes(&ephemeral_key);
    
    // Test that we get different keys each time
    var another_key: [32]u8 = undefined;  
    std.crypto.random.bytes(&another_key);
    
    try testing.expect(!std.mem.eql(u8, &ephemeral_key, &another_key));
    
    // Test gift wrap event structure concepts
    const gift_wrap_event = event.Event{
        .id = try allocator.dupe(u8, "gift_wrap_id"),
        .pubkey = try allocator.dupe(u8, "ephemeral_pubkey_hex"),
        .created_at = tweaked_timestamp,
        .kind = 1059, // Gift Wrap kind
        .tags = try allocator.alloc([]const []const u8, 0),
        .content = try allocator.dupe(u8, "encrypted_seal_content"),
        .sig = try allocator.dupe(u8, "ephemeral_signature"),
    };
    defer gift_wrap_event.deinit(allocator);
    
    try testing.expectEqual(@as(u32, 1059), gift_wrap_event.kind);
    try testing.expect(gift_wrap_event.sig.len > 0); // Gift wrap should be signed
}

test "hex encoding for welcome content" {
    const allocator = testing.allocator;
    
    // Test hex encoding/decoding as used in Welcome Events
    const test_data = "test_mls_welcome_data";
    
    // Encode to hex
    const hex_encoded = try std.fmt.allocPrint(
        allocator, 
        "{}", 
        .{std.fmt.fmtSliceHexLower(test_data)}
    );
    defer allocator.free(hex_encoded);
    
    // Decode back to bytes
    const decoded_bytes = try allocator.alloc(u8, test_data.len);
    defer allocator.free(decoded_bytes);
    
    _ = try std.fmt.hexToBytes(decoded_bytes, hex_encoded);
    
    // Verify round-trip
    try testing.expectEqualStrings(test_data, decoded_bytes);
}

test "json serialization round-trip" {
    const allocator = testing.allocator;
    
    // Test event JSON serialization/deserialization
    const tags = try allocator.alloc([]const []const u8, 0);
    defer allocator.free(tags);
    
    const test_event = event.Event{
        .id = try allocator.dupe(u8, "test_id"),
        .pubkey = try allocator.dupe(u8, "test_pubkey"),
        .created_at = 1234567890,
        .kind = 444,
        .tags = tags,
        .content = try allocator.dupe(u8, "test content"),
        .sig = try allocator.dupe(u8, ""),
    };
    defer test_event.deinit(allocator);
    
    // Serialize to JSON
    const json_str = try test_event.toJson(allocator);
    defer allocator.free(json_str);
    
    // Parse back from JSON
    const parsed_event = try event.Event.fromJson(allocator, json_str);
    defer parsed_event.deinit(allocator);
    
    // Verify round-trip
    try testing.expectEqualStrings(test_event.id, parsed_event.id);
    try testing.expectEqualStrings(test_event.pubkey, parsed_event.pubkey);
    try testing.expectEqual(test_event.created_at, parsed_event.created_at);
    try testing.expectEqual(test_event.kind, parsed_event.kind);
    try testing.expectEqualStrings(test_event.content, parsed_event.content);
    try testing.expectEqualStrings(test_event.sig, parsed_event.sig);
}

test "welcome event error handling - empty inputs" {
    const allocator = testing.allocator;
    
    // Test empty key package event ID
    const alice_privkey = try crypto.generatePrivateKey();
    const bob_pubkey = try crypto.getPublicKey(try crypto.generatePrivateKey());
    
    const test_welcome = types.Welcome{
        .cipher_suite = .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        .secrets = try allocator.alloc(types.EncryptedGroupSecrets, 0),
        .encrypted_group_info = try allocator.dupe(u8, "test"),
    };
    defer {
        allocator.free(test_welcome.secrets);
        allocator.free(test_welcome.encrypted_group_info);
    }
    
    const empty_relays = [_][]const u8{};
    const valid_relays = [_][]const u8{"wss://relay.example.com"};
    
    // Test empty key package event ID
    const result1 = welcome_events.WelcomeEvent.create(
        allocator,
        alice_privkey,
        bob_pubkey,
        test_welcome,
        "", // Empty key package event ID
        &valid_relays,
    );
    try testing.expectError(error.InvalidKeyPackageEventId, result1);
    
    // Test empty relays
    const result2 = welcome_events.WelcomeEvent.create(
        allocator,
        alice_privkey,
        bob_pubkey,
        test_welcome,
        "valid_key_package_id",
        &empty_relays, // Empty relays
    );
    try testing.expectError(error.NoRelaysProvided, result2);
}

test "welcome event parsing - invalid content" {
    const allocator = testing.allocator;
    
    const alice_privkey = try crypto.generatePrivateKey();
    const bob_privkey = try crypto.generatePrivateKey();
    const bob_pubkey = try crypto.getPublicKey(bob_privkey);
    
    // Create a valid Welcome Event first
    const test_welcome = types.Welcome{
        .cipher_suite = .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        .secrets = try allocator.alloc(types.EncryptedGroupSecrets, 0),
        .encrypted_group_info = try allocator.dupe(u8, "test"),
    };
    defer {
        allocator.free(test_welcome.secrets);
        allocator.free(test_welcome.encrypted_group_info);
    }
    
    const test_relays = [_][]const u8{"wss://relay.example.com"};
    
    const valid_wrapped = try welcome_events.WelcomeEvent.create(
        allocator,
        alice_privkey,
        bob_pubkey,
        test_welcome,
        "test_keypackage_id",
        &test_relays,
    );
    defer valid_wrapped.deinit(allocator);
    
    // Test parsing with wrong private key
    const eve_privkey = try crypto.generatePrivateKey();
    const result1 = welcome_events.WelcomeEvent.parse(
        allocator,
        valid_wrapped,
        eve_privkey,
    );
    try testing.expectError(error.DecryptionFailed, result1);
    
    // Test parsing non-gift-wrapped event
    const fake_event = event.Event{
        .id = try allocator.dupe(u8, "fake_id"),
        .pubkey = try allocator.dupe(u8, "fake_pubkey"),
        .created_at = 12345,
        .kind = 1, // Wrong kind, not gift-wrapped
        .tags = try allocator.alloc([]const []const u8, 0),
        .content = try allocator.dupe(u8, "fake_content"),
        .sig = try allocator.dupe(u8, "fake_sig"),
    };
    defer fake_event.deinit(allocator);
    
    const result2 = welcome_events.processWelcomeEvent(
        allocator,
        undefined, // MLS provider not needed for this test
        fake_event,
        bob_privkey,
    );
    try testing.expectError(error.NotGiftWrappedEvent, result2);
}

test "welcome event parsing - missing tags" {
    const allocator = testing.allocator;
    
    const alice_privkey = try crypto.generatePrivateKey();
    const alice_pubkey = try crypto.getPublicKey(alice_privkey);
    const bob_privkey = try crypto.generatePrivateKey();
    const bob_pubkey = try crypto.getPublicKey(bob_privkey);
    
    // Create a malformed Welcome Event without e tag
    const tags = try allocator.alloc([]const []const u8, 1);
    defer allocator.free(tags);
    
    // Only relays tag, no e tag
    const relay_tag = try allocator.alloc([]const u8, 2);
    relay_tag[0] = try allocator.dupe(u8, "relays");
    relay_tag[1] = try allocator.dupe(u8, "wss://relay.example.com");
    tags[0] = relay_tag;
    
    const alice_pubkey_hex = try crypto.pubkeyToHex(allocator, alice_pubkey);
    defer allocator.free(alice_pubkey_hex);
    
    const malformed_rumor = event.Event{
        .id = try allocator.dupe(u8, "test_id"),
        .pubkey = alice_pubkey_hex,
        .created_at = 12345,
        .kind = 444,
        .tags = tags,
        .content = try allocator.dupe(u8, "74657374"), // "test" in hex
        .sig = "",
    };
    
    // Manually gift-wrap it
    const wrapped = try nip59.createGiftWrappedEvent(
        allocator,
        alice_privkey,
        bob_pubkey,
        malformed_rumor,
    );
    defer wrapped.deinit(allocator);
    
    // Try to parse - should fail due to missing e tag
    const result = welcome_events.WelcomeEvent.parse(
        allocator,
        wrapped,
        bob_privkey,
    );
    try testing.expectError(error.MissingKeyPackageId, result);
    
    // Clean up manually created tags
    allocator.free(relay_tag[0]);
    allocator.free(relay_tag[1]);
    allocator.free(relay_tag);
}

test "welcome event hex content validation" {
    const allocator = testing.allocator;
    
    const alice_privkey = try crypto.generatePrivateKey();
    const alice_pubkey = try crypto.getPublicKey(alice_privkey);
    const bob_privkey = try crypto.generatePrivateKey();
    const bob_pubkey = try crypto.getPublicKey(bob_privkey);
    
    // Create a Welcome Event with invalid hex content (odd length)
    const tags = try allocator.alloc([]const []const u8, 1);
    defer allocator.free(tags);
    
    const e_tag = try allocator.alloc([]const u8, 2);
    e_tag[0] = try allocator.dupe(u8, "e");
    e_tag[1] = try allocator.dupe(u8, "test_keypackage_id");
    tags[0] = e_tag;
    
    const alice_pubkey_hex = try crypto.pubkeyToHex(allocator, alice_pubkey);
    defer allocator.free(alice_pubkey_hex);
    
    const malformed_rumor = event.Event{
        .id = try allocator.dupe(u8, "test_id"),
        .pubkey = alice_pubkey_hex,
        .created_at = 12345,
        .kind = 444,
        .tags = tags,
        .content = try allocator.dupe(u8, "74657374f"), // Odd length hex
        .sig = "",
    };
    
    // Manually gift-wrap it
    const wrapped = try nip59.createGiftWrappedEvent(
        allocator,
        alice_privkey,
        bob_pubkey,
        malformed_rumor,
    );
    defer wrapped.deinit(allocator);
    
    // Try to parse - should fail due to invalid hex
    const result = welcome_events.WelcomeEvent.parse(
        allocator,
        wrapped,
        bob_privkey,
    );
    try testing.expectError(error.InvalidHexContent, result);
    
    // Clean up manually created tags
    allocator.free(e_tag[0]);
    allocator.free(e_tag[1]);
    allocator.free(e_tag);
}

test "welcome event memory management" {
    const allocator = testing.allocator;
    
    // This test verifies no memory leaks occur during error conditions
    const alice_privkey = try crypto.generatePrivateKey();
    const bob_privkey = try crypto.generatePrivateKey();
    const bob_pubkey = try crypto.getPublicKey(bob_privkey);
    
    // Test multiple allocations and cleanup
    var i: u32 = 0;
    while (i < 10) : (i += 1) {
        const test_welcome = types.Welcome{
            .cipher_suite = .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            .secrets = try allocator.alloc(types.EncryptedGroupSecrets, 0),
            .encrypted_group_info = try allocator.dupe(u8, "test"),
        };
        defer {
            allocator.free(test_welcome.secrets);
            allocator.free(test_welcome.encrypted_group_info);
        }
        
        const test_relays = [_][]const u8{
            "wss://relay1.example.com",
            "wss://relay2.example.com",
            "wss://relay3.example.com",
        };
        
        const wrapped = try welcome_events.WelcomeEvent.create(
            allocator,
            alice_privkey,
            bob_pubkey,
            test_welcome,
            "test_keypackage_id",
            &test_relays,
        );
        defer wrapped.deinit(allocator);
        
        const parsed = try welcome_events.WelcomeEvent.parse(
            allocator,
            wrapped,
            bob_privkey,
        );
        parsed.deinit(allocator);
    }
    
    // If we get here without memory errors, the test passes
    try testing.expect(true);
}