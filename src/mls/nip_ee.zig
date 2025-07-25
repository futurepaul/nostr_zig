const std = @import("std");
const nostr = @import("../nostr.zig");
const types = @import("types.zig");
const key_packages = @import("key_packages.zig");
const welcomes = @import("welcomes.zig");
const keypackage_discovery = @import("keypackage_discovery.zig");

/// NIP-EE event kinds
pub const EventKind = enum(u32) {
    key_package = 443,
    welcome = 444,
    group_message = 445,
    keypackage_relay_list = 10051,
};

/// Kind 443: MLS Key Package Event
/// Contains a user's key package for joining groups
pub const KeyPackageEvent = struct {
    /// Standard Nostr event fields
    event: nostr.Event,
    
    /// Parsed key package data
    key_package: ?types.KeyPackage,
    
    /// Create a new key package event
    pub fn create(
        allocator: std.mem.Allocator,
        private_key: [32]u8,
        key_package: types.KeyPackage,
    ) !KeyPackageEvent {
        // Serialize the key package to hex (per NIP-EE spec)
        const content = try key_packages.serializeForNostrEvent(allocator, key_package);
        defer allocator.free(content);
        
        // Use proper event signing infrastructure (no more undefined fields!)
        const event_signing = @import("event_signing.zig");
        const helper = event_signing.NipEEEventHelper.init(allocator, private_key);
        
        // Create cipher suite and protocol version from key package
        const cipher_suite = @intFromEnum(key_package.cipher_suite);
        const protocol_version = @intFromEnum(key_package.version);
        
        // Extract extension IDs from key package
        var extensions = std.ArrayList(u32).init(allocator);
        defer extensions.deinit();
        
        // Add extensions based on what's in the key package
        for (key_package.leaf_node.extensions) |ext| {
            try extensions.append(@intFromEnum(ext.extension_type));
        }
        
        // TODO: Get relays from configuration or pass as parameter
        const relays = [_][]const u8{"ws://localhost:10547"};
        
        // Create properly signed KeyPackage event
        const event = try helper.createKeyPackageEvent(
            content,
            cipher_suite,
            protocol_version,
            extensions.items,
            &relays,
        );
        
        return KeyPackageEvent{
            .event = event,
            .key_package = key_package,
        };
    }
    
    /// Parse a key package event
    pub fn parse(allocator: std.mem.Allocator, event: nostr.Event) !KeyPackageEvent {
        if (event.kind != @intFromEnum(EventKind.key_package)) {
            return error.InvalidEventKind;
        }
        
        // Parse from hex-encoded content (per NIP-EE spec)
        const key_package = try key_packages.parseFromNostrEvent(allocator, event.content);
        
        return KeyPackageEvent{
            .event = event,
            .key_package = key_package,
        };
    }
};

/// Kind 444: MLS Welcome Event
/// Contains an encrypted welcome message for a specific recipient
pub const WelcomeEvent = struct {
    /// Standard Nostr event fields
    event: nostr.Event,
    
    /// Recipient public key (from p tag)
    recipient_pubkey: ?[32]u8,
    
    /// Group ID (from g tag)
    group_id: ?types.GroupId,
    
    /// Decrypted welcome data (only available after decryption)
    welcome: ?types.Welcome,
    
    /// Create a new welcome event
    pub fn create(
        allocator: std.mem.Allocator,
        sender_private_key: [32]u8,
        recipient_pubkey: [32]u8,
        group_id: types.GroupId,
        welcome: types.Welcome,
    ) !WelcomeEvent {
        // Serialize the welcome
        const serialized = try serializeWelcome(allocator, welcome);
        defer allocator.free(serialized);
        
        // Encrypt with NIP-44 to recipient
        const nip44 = @import("../nip44/mod.zig");
        const encrypted = try nip44.encrypt(allocator, serialized, sender_private_key, recipient_pubkey);
        defer allocator.free(encrypted);
        
        // Create tags
        var tags = std.ArrayList([]const []const u8).init(allocator);
        defer tags.deinit();
        
        // Add p tag for recipient
        const p_tag = try allocator.alloc([]const u8, 2);
        p_tag[0] = try allocator.dupe(u8, "p");
        p_tag[1] = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(&recipient_pubkey)});
        try tags.append(p_tag);
        
        // Add g tag for group ID
        const g_tag = try allocator.alloc([]const u8, 2);
        g_tag[0] = try allocator.dupe(u8, "g");
        g_tag[1] = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(&group_id)});
        try tags.append(g_tag);
        
        // Create the event
        var event = nostr.Event{
            .id = undefined,
            .pubkey = undefined,
            .created_at = @intCast(std.time.timestamp()),
            .kind = @intFromEnum(EventKind.welcome),
            .tags = try tags.toOwnedSlice(),
            .content = encrypted,
            .sig = undefined,
        };
        
        // Set pubkey from private key
        event.pubkey = try crypto.getPublicKey(sender_private_key);
        
        // Calculate event ID and sign
        try event.calculateId(allocator);
        try event.sign(allocator, sender_private_key);
        
        return WelcomeEvent{
            .event = event,
            .recipient_pubkey = recipient_pubkey,
            .group_id = group_id,
            .welcome = welcome,
        };
    }
    
    /// Parse a welcome event (without decryption)
    pub fn parse(event: nostr.Event) !WelcomeEvent {
        if (event.kind != @intFromEnum(EventKind.welcome)) {
            return error.InvalidEventKind;
        }
        
        var recipient_pubkey: ?[32]u8 = null;
        var group_id: ?types.GroupId = null;
        
        // Extract tags
        for (event.tags) |tag| {
            if (tag.len >= 2) {
                if (std.mem.eql(u8, tag[0], "p")) {
                    var pubkey: [32]u8 = undefined;
                    _ = try std.fmt.hexToBytes(&pubkey, tag[1]);
                    recipient_pubkey = pubkey;
                } else if (std.mem.eql(u8, tag[0], "g")) {
                    var gid_data: [32]u8 = undefined;
                    _ = try std.fmt.hexToBytes(&gid_data, tag[1]);
                    group_id = types.GroupId.init(gid_data);
                }
            }
        }
        
        return WelcomeEvent{
            .event = event,
            .recipient_pubkey = recipient_pubkey,
            .group_id = group_id,
            .welcome = null,
        };
    }
    
    /// Decrypt the welcome message
    pub fn decrypt(
        self: *WelcomeEvent,
        allocator: std.mem.Allocator,
        recipient_private_key: [32]u8,
    ) !void {
        const nip44 = @import("../nip44/mod.zig");
        const decrypted = try nip44.decrypt(allocator, self.event.content, recipient_private_key, self.event.pubkey);
        defer allocator.free(decrypted);
        
        self.welcome = try deserializeWelcome(allocator, decrypted);
    }
};

/// Kind 445: MLS Group Message Event
/// Contains a double-encrypted group message
pub const GroupMessageEvent = struct {
    /// Standard Nostr event fields
    event: nostr.Event,
    
    /// Group ID (from g tag)
    group_id: ?types.GroupId,
    
    /// Epoch number (from epoch tag)
    epoch: ?types.Epoch,
    
    /// Message type (from mls tag)
    message_type: ?[]const u8,
    
    /// Create a new group message event
    pub fn create(
        allocator: std.mem.Allocator,
        ephemeral_private_key: [32]u8,
        group_id: types.GroupId,
        epoch: types.Epoch,
        message_type: []const u8,
        encrypted_content: []const u8,
    ) !GroupMessageEvent {
        // Use proper event signing infrastructure with ephemeral key
        const event_signing = @import("event_signing.zig");
        const helper = event_signing.NipEEEventHelper.init(allocator, ephemeral_private_key);
        
        // Create properly signed Group Message event
        const event = try helper.createGroupMessageEvent(
            ephemeral_private_key,
            &group_id.data,
            epoch,
            message_type,
            encrypted_content,
        );
        
        return GroupMessageEvent{
            .event = event,
            .group_id = group_id,
            .epoch = epoch,
            .message_type = try allocator.dupe(u8, message_type),
        };
    }
    
    /// Parse a group message event
    pub fn parse(allocator: std.mem.Allocator, event: nostr.Event) !GroupMessageEvent {
        if (event.kind != @intFromEnum(EventKind.group_message)) {
            return error.InvalidEventKind;
        }
        
        var group_id: ?types.GroupId = null;
        var epoch: ?types.Epoch = null;
        var message_type: ?[]const u8 = null;
        
        // Extract tags
        for (event.tags) |tag| {
            if (tag.len >= 2) {
                if (std.mem.eql(u8, tag[0], "g")) {
                    var gid_data: [32]u8 = undefined;
                    _ = try std.fmt.hexToBytes(&gid_data, tag[1]);
                    group_id = types.GroupId.init(gid_data);
                } else if (std.mem.eql(u8, tag[0], "epoch")) {
                    epoch = try std.fmt.parseInt(types.Epoch, tag[1], 10);
                } else if (std.mem.eql(u8, tag[0], "mls")) {
                    message_type = try allocator.dupe(u8, tag[1]);
                }
            }
        }
        
        return GroupMessageEvent{
            .event = event,
            .group_id = group_id,
            .epoch = epoch,
            .message_type = message_type,
        };
    }
};

/// KeyPackage Discovery API
/// High-level interface for managing KeyPackage discoverability
pub const KeyPackageDiscovery = struct {
    discovery_service: keypackage_discovery.KeyPackageDiscoveryService,
    
    pub fn init(allocator: std.mem.Allocator) KeyPackageDiscovery {
        return .{
            .discovery_service = keypackage_discovery.KeyPackageDiscoveryService.init(allocator),
        };
    }
    
    pub fn deinit(self: *KeyPackageDiscovery) void {
        self.discovery_service.deinit();
    }
    
    /// Publish a KeyPackage relay list event
    pub fn publishKeyPackageRelays(
        self: *KeyPackageDiscovery,
        private_key: [32]u8,
        relay_uris: []const []const u8,
        description: ?[]const u8,
    ) !keypackage_discovery.KeyPackageRelayListEvent {
        // Update our internal relay list
        for (relay_uris) |relay_uri| {
            try self.discovery_service.addRelay(relay_uri);
        }
        
        // Create and return the event
        return try self.discovery_service.publishRelayList(private_key, description);
    }
    
    /// Process a received relay list event from another user
    pub fn processRelayListEvent(
        self: *KeyPackageDiscovery,
        event: nostr.Event,
    ) !void {
        const relay_event = try keypackage_discovery.KeyPackageRelayListEvent.parse(
            self.discovery_service.allocator,
            event,
        );
        
        // Extract pubkey
        const pubkey = try keypackage_discovery.parsePublicKey(event.pubkey);
        
        // Cache the relay list
        try self.discovery_service.cacheRelayList(pubkey, relay_event);
    }
    
    /// Find relay URIs where a specific user's KeyPackages might be found
    pub fn findKeyPackageRelays(
        self: *const KeyPackageDiscovery,
        user_pubkey: [32]u8,
    ) ?[]const []const u8 {
        return self.discovery_service.getRelayListForUser(user_pubkey);
    }
    
    /// Get all known relay URIs for KeyPackage discovery
    pub fn getAllDiscoveryRelays(self: *const KeyPackageDiscovery) ![]const []const u8 {
        return try self.discovery_service.getAllKnownRelays();
    }
    
    /// Clean up expired relay list entries
    pub fn cleanupExpiredEntries(self: *KeyPackageDiscovery) !void {
        try self.discovery_service.cleanupExpiredEntries();
    }
    
    /// Get discovery statistics
    pub fn getStats(self: *const KeyPackageDiscovery) keypackage_discovery.DiscoveryStats {
        return self.discovery_service.getStats();
    }
};

const crypto = @import("../crypto.zig");

// Placeholder serialization functions - these would be implemented based on MLS wire format

fn serializeKeyPackage(allocator: std.mem.Allocator, key_package: types.KeyPackage) ![]u8 {
    _ = key_package;
    // TODO: Implement MLS wire format serialization
    return try allocator.dupe(u8, "serialized_key_package");
}

fn deserializeKeyPackage(allocator: std.mem.Allocator, data: []const u8) !types.KeyPackage {
    // Use the parseKeyPackage function we implemented
    return key_packages.parseKeyPackage(allocator, data);
}

fn serializeWelcome(allocator: std.mem.Allocator, welcome: types.Welcome) ![]u8 {
    // Use the serializeWelcome function we implemented
    return welcomes.serializeWelcome(allocator, welcome);
}

fn deserializeWelcome(allocator: std.mem.Allocator, data: []const u8) !types.Welcome {
    // Use the parseWelcome function we implemented
    return welcomes.parseWelcome(allocator, data);
}

test "event kind values" {
    try std.testing.expectEqual(@as(u32, 443), @intFromEnum(EventKind.key_package));
    try std.testing.expectEqual(@as(u32, 444), @intFromEnum(EventKind.welcome));
    try std.testing.expectEqual(@as(u32, 445), @intFromEnum(EventKind.group_message));
}

test "parse welcome event" {
    // Create a mock event
    const event = nostr.Event{
        .id = &[_]u8{0} ** 32,
        .pubkey = &[_]u8{1} ** 32,
        .created_at = 1234567890,
        .kind = 444,
        .tags = &[_][]const []const u8{
            &[_][]const u8{ "p", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" },
            &[_][]const u8{ "g", "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210" },
        },
        .content = "encrypted_content",
        .sig = &[_]u8{2} ** 64,
    };
    
    const welcome_event = try WelcomeEvent.parse(event);
    try std.testing.expect(welcome_event.recipient_pubkey != null);
    try std.testing.expect(welcome_event.group_id != null);
}

test "parse group message event" {
    const allocator = std.testing.allocator;
    
    // Create a mock event
    const event = nostr.Event{
        .id = &[_]u8{0} ** 32,
        .pubkey = &[_]u8{1} ** 32,
        .created_at = 1234567890,
        .kind = 445,
        .tags = &[_][]const []const u8{
            &[_][]const u8{ "g", "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210" },
            &[_][]const u8{ "epoch", "42" },
            &[_][]const u8{ "mls", "application" },
        },
        .content = "double_encrypted_content",
        .sig = &[_]u8{2} ** 64,
    };
    
    const msg_event = try GroupMessageEvent.parse(allocator, event);
    defer if (msg_event.message_type) |mt| allocator.free(mt);
    
    try std.testing.expect(msg_event.group_id != null);
    try std.testing.expectEqual(@as(types.Epoch, 42), msg_event.epoch.?);
    try std.testing.expectEqualStrings("application", msg_event.message_type.?);
}

test "KeyPackage discovery integration" {
    const allocator = std.testing.allocator;
    
    var discovery = KeyPackageDiscovery.init(allocator);
    defer discovery.deinit();
    
    // Test publishing relay list
    const private_key: [32]u8 = [_]u8{0xAB} ** 32;
    const relay_uris = [_][]const u8{
        "wss://relay1.example.com",
        "wss://relay2.example.com",
    };
    
    const relay_event = try discovery.publishKeyPackageRelays(
        private_key,
        &relay_uris,
        "My KeyPackage relays for testing",
    );
    defer relay_event.deinit(allocator);
    
    // Verify event was created correctly
    try std.testing.expectEqual(@as(u32, 10051), relay_event.event.kind);
    try std.testing.expectEqual(@as(usize, 2), relay_event.relay_uris.len);
    
    // Test stats
    const stats = discovery.getStats();
    try std.testing.expectEqual(@as(u32, 2), stats.current_relays_count);
    try std.testing.expectEqual(@as(u32, 0), stats.cached_users_count);
    
    // Test processing a relay list from another user
    const other_private_key: [32]u8 = [_]u8{0xCD} ** 32;
    const other_pubkey = try crypto.getPublicKey(other_private_key);
    
    const other_event = try keypackage_discovery.KeyPackageRelayListEvent.create(
        allocator,
        other_private_key,
        &[_][]const u8{"wss://other-relay.example.com"},
        null,
    );
    defer other_event.deinit(allocator);
    
    try discovery.processRelayListEvent(other_event.event);
    
    // Check if we can find the other user's relays
    const other_relays = discovery.findKeyPackageRelays(other_pubkey);
    try std.testing.expect(other_relays != null);
    try std.testing.expectEqual(@as(usize, 1), other_relays.?.len);
    try std.testing.expectEqualStrings("wss://other-relay.example.com", other_relays.?[0]);
}