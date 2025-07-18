const std = @import("std");
const event = @import("../nostr/event.zig");
const crypto = @import("../crypto.zig");
const welcomes = @import("welcomes.zig");
const types = @import("types.zig");
const nip59 = @import("nip59.zig");
const provider = @import("provider.zig");
const mls = @import("mls.zig");
const wasm_random = @import("../wasm_random.zig");
const wasm_time = @import("../wasm_time.zig");

/// NIP-EE Welcome Event (kind: 444)
/// Welcome events are NIP-59 gift-wrapped to provide metadata protection
pub const WelcomeEvent = struct {
    /// The MLS Welcome message data
    welcome_data: []const u8,
    
    /// The KeyPackage Event ID that was used
    key_package_event_id: []const u8,
    
    /// Relays where group events can be found
    relays: []const []const u8,
    
    /// Create a Welcome Event from MLS Welcome data
    pub fn create(
        allocator: std.mem.Allocator,
        sender_privkey: [32]u8,
        recipient_pubkey: [32]u8,
        mls_welcome: types.Welcome,
        key_package_event_id: []const u8,
        group_relays: []const []const u8,
    ) !event.Event {
        // Validate inputs
        if (key_package_event_id.len == 0) {
            return error.InvalidKeyPackageEventId;
        }
        if (group_relays.len == 0) {
            return error.NoRelaysProvided;
        }
        
        // Serialize the MLS Welcome message
        const welcome_bytes = try welcomes.serializeWelcome(allocator, mls_welcome);
        defer allocator.free(welcome_bytes);
        
        // Create tags with proper error handling
        var tags_list = std.ArrayList([]const []const u8).init(allocator);
        defer tags_list.deinit();
        
        // Track allocations for cleanup
        var allocated_strings = std.ArrayList([]u8).init(allocator);
        defer {
            for (allocated_strings.items) |str| {
                allocator.free(str);
            }
            allocated_strings.deinit();
        }
        
        // Add e tag for KeyPackage Event reference
        const e_tag = try allocator.alloc([]const u8, 2);
        errdefer allocator.free(e_tag);
        
        const e_tag_name = try allocator.dupe(u8, "e");
        try allocated_strings.append(e_tag_name);
        e_tag[0] = e_tag_name;
        
        const e_tag_value = try allocator.dupe(u8, key_package_event_id);
        try allocated_strings.append(e_tag_value);
        e_tag[1] = e_tag_value;
        
        try tags_list.append(e_tag);
        
        // Add relays tag
        const relay_tag = try allocator.alloc([]const u8, 1 + group_relays.len);
        errdefer allocator.free(relay_tag);
        
        const relay_tag_name = try allocator.dupe(u8, "relays");
        try allocated_strings.append(relay_tag_name);
        relay_tag[0] = relay_tag_name;
        
        for (group_relays, 1..) |relay, i| {
            const relay_copy = try allocator.dupe(u8, relay);
            try allocated_strings.append(relay_copy);
            relay_tag[i] = relay_copy;
        }
        try tags_list.append(relay_tag);
        
        const tags = try tags_list.toOwnedSlice();
        errdefer {
            for (tags) |tag| {
                allocator.free(tag);
            }
            allocator.free(tags);
        }
        
        // Create the inner Welcome Event rumor (kind: 444)
        // As per NIP-59, this must be an unsigned rumor
        const sender_pubkey_hex = try crypto.pubkeyToHex(allocator, try crypto.getPublicKey(sender_privkey));
        errdefer allocator.free(sender_pubkey_hex);
        try allocated_strings.append(@constCast(sender_pubkey_hex));
        
        // Convert welcome_bytes to hex string for content
        const content_hex = try std.fmt.allocPrint(allocator, "{}", .{std.fmt.fmtSliceHexLower(welcome_bytes)});
        errdefer allocator.free(content_hex);
        try allocated_strings.append(content_hex);
        
        const event_id = try generateEventId(allocator);
        errdefer allocator.free(event_id);
        try allocated_strings.append(@constCast(event_id));
        
        const welcome_rumor = event.Event{
            .id = event_id, 
            .pubkey = sender_pubkey_hex,
            .created_at = wasm_time.timestamp(),
            .kind = 444,
            .tags = tags,
            .content = content_hex,
            .sig = "", // Unsigned rumor as per NIP-59
        };
        
        // Gift-wrap the Welcome Event rumor
        // If this succeeds, ownership of allocated memory transfers to the result
        const result = try nip59.createGiftWrappedEvent(
            allocator,
            sender_privkey,
            recipient_pubkey,
            welcome_rumor,
        );
        
        // Clear the allocated_strings list to prevent double-free
        // since ownership has been transferred
        allocated_strings.clearRetainingCapacity();
        
        return result;
    }
    
    /// Parse a gift-wrapped Welcome Event
    pub fn parse(
        allocator: std.mem.Allocator,
        wrapped_event: event.Event,
        recipient_privkey: [32]u8,
    ) !ParsedWelcome {
        // Unwrap the gift-wrapped event
        const inner_event = try nip59.GiftWrap.unwrapAndDecrypt(
            allocator,
            wrapped_event,
            recipient_privkey,
        );
        defer inner_event.deinit(allocator);
        
        // Verify it's a Welcome Event
        if (inner_event.kind != 444) {
            return error.NotWelcomeEvent;
        }
        
        // Extract KeyPackage Event ID from e tag
        var key_package_id: ?[]const u8 = null;
        errdefer if (key_package_id) |id| allocator.free(id);
        
        var relays = std.ArrayList([]const u8).init(allocator);
        errdefer {
            for (relays.items) |relay| {
                allocator.free(relay);
            }
            relays.deinit();
        }
        
        for (inner_event.tags) |tag| {
            if (tag.len >= 2 and std.mem.eql(u8, tag[0], "e")) {
                if (key_package_id != null) {
                    // Multiple e tags is an error
                    return error.DuplicateKeyPackageId;
                }
                key_package_id = try allocator.dupe(u8, tag[1]);
            } else if (tag.len >= 1 and std.mem.eql(u8, tag[0], "relays")) {
                for (tag[1..]) |relay| {
                    try relays.append(try allocator.dupe(u8, relay));
                }
            }
        }
        
        if (key_package_id == null) {
            return error.MissingKeyPackageId;
        }
        
        // Validate hex content length
        if (inner_event.content.len == 0 or inner_event.content.len % 2 != 0) {
            return error.InvalidHexContent;
        }
        
        // Decode hex content back to bytes
        const welcome_bytes = try allocator.alloc(u8, inner_event.content.len / 2);
        defer allocator.free(welcome_bytes);
        
        _ = try std.fmt.hexToBytes(welcome_bytes, inner_event.content);
        
        // Parse the MLS Welcome message
        const mls_welcome = try welcomes.parseWelcome(allocator, welcome_bytes);
        errdefer welcomes.freeWelcome(allocator, mls_welcome);
        
        // Parse sender pubkey
        const sender_pubkey = try crypto.hexToPubkey(inner_event.pubkey);
        
        // Take ownership of relays array
        const relays_owned = try relays.toOwnedSlice();
        errdefer {
            for (relays_owned) |relay| {
                allocator.free(relay);
            }
            allocator.free(relays_owned);
        }
        
        // Success - transfer ownership to ParsedWelcome
        return ParsedWelcome{
            .mls_welcome = mls_welcome,
            .key_package_event_id = key_package_id.?,
            .relays = relays_owned,
            .sender_pubkey = sender_pubkey,
        };
    }
};

/// Result of parsing a Welcome Event
pub const ParsedWelcome = struct {
    mls_welcome: types.Welcome,
    key_package_event_id: []const u8,
    relays: []const []const u8,
    sender_pubkey: [32]u8,
    
    pub fn deinit(self: ParsedWelcome, allocator: std.mem.Allocator) void {
        welcomes.freeWelcome(allocator, self.mls_welcome);
        allocator.free(self.key_package_event_id);
        for (self.relays) |relay| {
            allocator.free(relay);
        }
        allocator.free(self.relays);
    }
};

/// Create and send a Welcome Event when adding a new member
pub fn sendWelcomeToNewMember(
    allocator: std.mem.Allocator,
    mls_provider: *provider.MlsProvider,
    group_state: *const mls.MlsGroupState,
    group_metadata: *const mls.GroupMetadata,
    sender_privkey: [32]u8,
    new_member_key_package: types.KeyPackage,
    key_package_event_id: []const u8,
) !event.Event {
    // Validate inputs
    if (group_metadata.relays.len == 0) {
        return error.NoGroupRelays;
    }
    if (key_package_event_id.len == 0) {
        return error.InvalidKeyPackageEventId;
    }
    
    // Create MLS Welcome message
    const mls_welcome = try welcomes.createWelcome(
        allocator,
        mls_provider,
        group_state,
        new_member_key_package,
        sender_privkey,
    );
    defer welcomes.freeWelcome(allocator, mls_welcome);
    
    // Get recipient's public key from their KeyPackage credential
    const recipient_pubkey = switch (new_member_key_package.leaf_node.credential) {
        .basic => |basic| blk: {
            // Validate identity format
            if (basic.identity.len != 64) {
                return error.InvalidCredentialIdentity;
            }
            break :blk try crypto.hexToPubkey(basic.identity);
        },
        else => return error.UnsupportedCredentialType,
    };
    
    // Create and return the gift-wrapped Welcome Event
    return try WelcomeEvent.create(
        allocator,
        sender_privkey,
        recipient_pubkey,
        mls_welcome,
        key_package_event_id,
        group_metadata.relays,
    );
}

/// Process a received Welcome Event and join the group
pub fn processWelcomeEvent(
    allocator: std.mem.Allocator,
    mls_provider: *provider.MlsProvider,
    wrapped_welcome: event.Event,
    recipient_privkey: [32]u8,
) !mls.JoinResult {
    // Validate input event
    if (wrapped_welcome.kind != 1059) {
        return error.NotGiftWrappedEvent;
    }
    
    // Parse the Welcome Event
    const parsed = try WelcomeEvent.parse(allocator, wrapped_welcome, recipient_privkey);
    defer parsed.deinit(allocator);
    
    // Validate parsed data
    if (parsed.relays.len == 0) {
        return error.NoRelaysInWelcome;
    }
    
    // Extract MLS Welcome data
    const welcome_bytes = try welcomes.serializeWelcome(allocator, parsed.mls_welcome);
    defer allocator.free(welcome_bytes);
    
    // Join the group using the MLS Welcome
    return try welcomes.joinFromWelcome(
        allocator,
        mls_provider,
        welcome_bytes,
        recipient_privkey,
    );
}

// Helper functions

fn generateEventId(allocator: std.mem.Allocator) ![]const u8 {
    // Generate a temporary event ID
    var random_bytes: [32]u8 = undefined;
    wasm_random.secure_random.bytes(&random_bytes);
    
    const hex_id = try allocator.alloc(u8, 64);
    _ = std.fmt.bufPrint(hex_id, "{}", .{std.fmt.fmtSliceHexLower(&random_bytes)}) catch unreachable;
    
    return hex_id;
}

// Tests

test "create and parse welcome event" {
    const allocator = std.testing.allocator;
    
    // Setup test keys
    const alice_privkey = try crypto.generatePrivateKey();
    const bob_privkey = try crypto.generatePrivateKey();
    const bob_pubkey = try crypto.getPublicKey(bob_privkey);
    
    // Create a test MLS Welcome
    const test_welcome = types.Welcome{
        .cipher_suite = .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        .secrets = try allocator.alloc(types.EncryptedGroupSecrets, 1),
        .encrypted_group_info = try allocator.dupe(u8, "test_encrypted_info"),
    };
    test_welcome.secrets[0] = types.EncryptedGroupSecrets{
        .new_member = try allocator.dupe(u8, "test_member"),
        .encrypted_group_secrets = try allocator.dupe(u8, "test_secrets"),
    };
    defer {
        allocator.free(test_welcome.secrets[0].new_member);
        allocator.free(test_welcome.secrets[0].encrypted_group_secrets);
        allocator.free(test_welcome.secrets);
        allocator.free(test_welcome.encrypted_group_info);
    }
    
    const test_relays = [_][]const u8{
        "wss://relay1.example.com",
        "wss://relay2.example.com",
    };
    
    // Create Welcome Event
    const wrapped = try WelcomeEvent.create(
        allocator,
        alice_privkey,
        bob_pubkey,
        test_welcome,
        "test_keypackage_event_id",
        &test_relays,
    );
    defer wrapped.deinit(allocator);
    
    // Verify it's gift-wrapped
    try std.testing.expectEqual(@as(u32, 1059), wrapped.kind);
    
    // Parse it
    const parsed = try WelcomeEvent.parse(allocator, wrapped, bob_privkey);
    defer parsed.deinit(allocator);
    
    // Verify parsed data
    try std.testing.expectEqualStrings("test_keypackage_event_id", parsed.key_package_event_id);
    try std.testing.expectEqual(@as(usize, 2), parsed.relays.len);
    try std.testing.expectEqualStrings("wss://relay1.example.com", parsed.relays[0]);
    try std.testing.expectEqualStrings("wss://relay2.example.com", parsed.relays[1]);
}

test "welcome event metadata protection" {
    const allocator = std.testing.allocator;
    
    // Setup test keys
    const alice_privkey = try crypto.generatePrivateKey();
    const bob_privkey = try crypto.generatePrivateKey();
    const bob_pubkey = try crypto.getPublicKey(bob_privkey);
    const eve_privkey = try crypto.generatePrivateKey();
    
    // Create a test MLS Welcome
    const test_welcome = types.Welcome{
        .cipher_suite = .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        .secrets = try allocator.alloc(types.EncryptedGroupSecrets, 0),
        .encrypted_group_info = try allocator.dupe(u8, "secret_group_info"),
    };
    defer {
        allocator.free(test_welcome.secrets);
        allocator.free(test_welcome.encrypted_group_info);
    }
    
    const test_relays = [_][]const u8{"wss://secret.relay.com"};
    
    // Create Welcome Event
    const wrapped = try WelcomeEvent.create(
        allocator,
        alice_privkey,
        bob_pubkey,
        test_welcome,
        "secret_keypackage_id",
        &test_relays,
    );
    defer wrapped.deinit(allocator);
    
    // Eve shouldn't be able to decrypt it
    const eve_result = WelcomeEvent.parse(allocator, wrapped, eve_privkey);
    try std.testing.expectError(error.DecryptionFailed, eve_result);
    
    // But Bob can
    const parsed = try WelcomeEvent.parse(allocator, wrapped, bob_privkey);
    defer parsed.deinit(allocator);
    
    try std.testing.expectEqualStrings("secret_keypackage_id", parsed.key_package_event_id);
    try std.testing.expectEqualStrings("wss://secret.relay.com", parsed.relays[0]);
}