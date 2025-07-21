const std = @import("std");
const nostr = @import("../nostr.zig");
const types = @import("types.zig");
const nip_ee = @import("nip_ee.zig");

/// NIP-EE Kind 10051: KeyPackage Relay List Events
/// These events enable discoverability of KeyPackages by advertising relay locations

/// Kind 10051 event for KeyPackage discovery
pub const KeyPackageRelayListEvent = struct {
    /// Standard Nostr event fields
    event: nostr.Event,
    
    /// List of relay URIs where KeyPackages can be found
    relay_uris: []const []const u8,
    
    /// Optional description from content field
    description: ?[]const u8,
    
    /// Create a new KeyPackage relay list event
    pub fn create(
        allocator: std.mem.Allocator,
        private_key: [32]u8,
        relay_uris: []const []const u8,
        description: ?[]const u8,
    ) !KeyPackageRelayListEvent {
        // Use proper event signing infrastructure (no more placeholders!)
        const event_signing = @import("event_signing.zig");
        const helper = event_signing.NipEEEventHelper.init(allocator, private_key);
        
        // Create properly signed KeyPackage relay list event
        const event = try helper.createKeyPackageRelayListEvent(relay_uris, description);
        
        // Deep copy the relay URIs to avoid double-free issues
        var relay_uris_copy = try allocator.alloc([]const u8, relay_uris.len);
        for (relay_uris, 0..) |uri, i| {
            relay_uris_copy[i] = try allocator.dupe(u8, uri);
        }
        
        return KeyPackageRelayListEvent{
            .event = event,
            .relay_uris = relay_uris_copy,
            .description = if (description) |desc| try allocator.dupe(u8, desc) else null,
        };
    }
    
    /// Parse a KeyPackage relay list event
    pub fn parse(allocator: std.mem.Allocator, event: nostr.Event) !KeyPackageRelayListEvent {
        if (event.kind != 10051) {
            return error.InvalidEventKind;
        }
        
        // Extract relay URIs from "r" tags
        var relay_list = std.ArrayList([]const u8).init(allocator);
        defer relay_list.deinit();
        
        for (event.tags) |tag| {
            if (tag.len >= 2 and std.mem.eql(u8, tag[0], "r")) {
                try relay_list.append(try allocator.dupe(u8, tag[1]));
            }
        }
        
        // Extract description from content
        const description = if (event.content.len > 0) 
            try allocator.dupe(u8, event.content) 
        else 
            null;
        
        // Deep copy the event to avoid use-after-free
        // We need to duplicate all the event fields since the original may be freed
        const event_copy = nostr.Event{
            .id = try allocator.dupe(u8, event.id),
            .pubkey = try allocator.dupe(u8, event.pubkey),
            .created_at = event.created_at,
            .kind = event.kind,
            .tags = blk: {
                const tags_copy = try allocator.alloc([]const []const u8, event.tags.len);
                for (event.tags, 0..) |tag, i| {
                    const tag_copy = try allocator.alloc([]const u8, tag.len);
                    for (tag, 0..) |item, j| {
                        tag_copy[j] = try allocator.dupe(u8, item);
                    }
                    tags_copy[i] = tag_copy;
                }
                break :blk tags_copy;
            },
            .content = try allocator.dupe(u8, event.content),
            .sig = try allocator.dupe(u8, event.sig),
        };
        
        return KeyPackageRelayListEvent{
            .event = event_copy,
            .relay_uris = try relay_list.toOwnedSlice(),
            .description = description,
        };
    }
    
    /// Free memory allocated for this event
    pub fn deinit(self: *const KeyPackageRelayListEvent, allocator: std.mem.Allocator) void {
        for (self.relay_uris) |uri| {
            allocator.free(uri);
        }
        allocator.free(self.relay_uris);
        
        if (self.description) |desc| {
            allocator.free(desc);
        }
        
        // Free the entire event (which includes tags and content)
        self.event.deinit(allocator);
    }
};

/// KeyPackage discovery service for managing relay advertisements
pub const KeyPackageDiscoveryService = struct {
    allocator: std.mem.Allocator,
    
    /// Current relay list for our KeyPackages
    current_relays: std.ArrayList([]const u8),
    
    /// Cached relay list events from other users
    relay_cache: std.AutoHashMap([32]u8, KeyPackageRelayListEvent), // pubkey -> relay list
    
    /// Cache expiry time in seconds
    cache_expiry: u64 = 3600, // 1 hour
    
    pub fn init(allocator: std.mem.Allocator) KeyPackageDiscoveryService {
        return .{
            .allocator = allocator,
            .current_relays = std.ArrayList([]const u8).init(allocator),
            .relay_cache = std.AutoHashMap([32]u8, KeyPackageRelayListEvent).init(allocator),
        };
    }
    
    pub fn deinit(self: *KeyPackageDiscoveryService) void {
        // Free current relays
        for (self.current_relays.items) |relay| {
            self.allocator.free(relay);
        }
        self.current_relays.deinit();
        
        // Free cached events
        var iterator = self.relay_cache.iterator();
        while (iterator.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.relay_cache.deinit();
    }
    
    /// Add a relay to our current relay list
    pub fn addRelay(self: *KeyPackageDiscoveryService, relay_uri: []const u8) !void {
        // Check if already exists
        for (self.current_relays.items) |existing| {
            if (std.mem.eql(u8, existing, relay_uri)) {
                return; // Already exists
            }
        }
        
        // Add new relay
        try self.current_relays.append(try self.allocator.dupe(u8, relay_uri));
    }
    
    /// Remove a relay from our current relay list
    pub fn removeRelay(self: *KeyPackageDiscoveryService, relay_uri: []const u8) void {
        var i: usize = 0;
        while (i < self.current_relays.items.len) {
            if (std.mem.eql(u8, self.current_relays.items[i], relay_uri)) {
                const removed = self.current_relays.orderedRemove(i);
                self.allocator.free(removed);
                return;
            } else {
                i += 1;
            }
        }
    }
    
    /// Create and publish our KeyPackage relay list event
    pub fn publishRelayList(
        self: *const KeyPackageDiscoveryService,
        private_key: [32]u8,
        description: ?[]const u8,
    ) !KeyPackageRelayListEvent {
        return try KeyPackageRelayListEvent.create(
            self.allocator,
            private_key,
            self.current_relays.items,
            description,
        );
    }
    
    /// Cache a relay list event from another user
    pub fn cacheRelayList(
        self: *KeyPackageDiscoveryService,
        pubkey: [32]u8,
        relay_event: KeyPackageRelayListEvent,
    ) !void {
        // Remove existing entry if it exists
        if (self.relay_cache.get(pubkey)) |existing| {
            existing.deinit(self.allocator);
        }
        
        // Add new entry
        try self.relay_cache.put(pubkey, relay_event);
    }
    
    /// Get relay list for a specific user
    pub fn getRelayListForUser(
        self: *const KeyPackageDiscoveryService,
        pubkey: [32]u8,
    ) ?[]const []const u8 {
        if (self.relay_cache.get(pubkey)) |relay_event| {
            // Check if event is not too old
            const current_time = std.time.timestamp();
            const event_age = @as(u64, @intCast(current_time - relay_event.event.created_at));
            
            if (event_age <= self.cache_expiry) {
                return relay_event.relay_uris;
            }
        }
        return null;
    }
    
    /// Find all known relays for KeyPackage discovery
    pub fn getAllKnownRelays(self: *const KeyPackageDiscoveryService) ![]const []const u8 {
        var all_relays = std.ArrayList([]const u8).init(self.allocator);
        defer all_relays.deinit();
        
        // Add our current relays
        for (self.current_relays.items) |relay| {
            try all_relays.append(relay);
        }
        
        // Add relays from cache
        var iterator = self.relay_cache.valueIterator();
        while (iterator.next()) |relay_event| {
            // Check if event is not too old
            const current_time = std.time.timestamp();
            const event_age = @as(u64, @intCast(current_time - relay_event.event.created_at));
            
            if (event_age <= self.cache_expiry) {
                for (relay_event.relay_uris) |relay| {
                    // Check for duplicates
                    var is_duplicate = false;
                    for (all_relays.items) |existing| {
                        if (std.mem.eql(u8, existing, relay)) {
                            is_duplicate = true;
                            break;
                        }
                    }
                    if (!is_duplicate) {
                        try all_relays.append(relay);
                    }
                }
            }
        }
        
        return try all_relays.toOwnedSlice();
    }
    
    /// Clean up expired entries from cache
    pub fn cleanupExpiredEntries(self: *KeyPackageDiscoveryService) !void {
        const current_time = std.time.timestamp();
        var to_remove = std.ArrayList([32]u8).init(self.allocator);
        defer to_remove.deinit();
        
        var iterator = self.relay_cache.iterator();
        while (iterator.next()) |entry| {
            const event_age = @as(u64, @intCast(current_time - entry.value_ptr.event.created_at));
            if (event_age > self.cache_expiry) {
                try to_remove.append(entry.key_ptr.*);
            }
        }
        
        // Remove expired entries
        for (to_remove.items) |pubkey| {
            if (self.relay_cache.get(pubkey)) |existing| {
                existing.deinit(self.allocator);
                _ = self.relay_cache.remove(pubkey);
            }
        }
    }
    
    /// Get statistics about the discovery service
    pub fn getStats(self: *const KeyPackageDiscoveryService) DiscoveryStats {
        return DiscoveryStats{
            .current_relays_count = @intCast(self.current_relays.items.len),
            .cached_users_count = @intCast(self.relay_cache.count()),
            .cache_expiry_seconds = self.cache_expiry,
        };
    }
};

/// Statistics for the discovery service
pub const DiscoveryStats = struct {
    current_relays_count: u32,
    cached_users_count: u32,
    cache_expiry_seconds: u64,
};

/// Validate a relay URI format
pub fn validateRelayUri(uri: []const u8) !void {
    // Basic validation for relay URIs
    if (uri.len == 0) {
        return error.EmptyUri;
    }
    
    // Check for websocket schemes
    if (std.mem.startsWith(u8, uri, "ws://") or std.mem.startsWith(u8, uri, "wss://")) {
        // Valid websocket URI
        return;
    }
    
    return error.InvalidUriScheme;
}

/// Helper to extract public key from hex string
pub fn parsePublicKey(hex_str: []const u8) ![32]u8 {
    if (hex_str.len != 64) {
        return error.InvalidPublicKeyLength;
    }
    
    var pubkey: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pubkey, hex_str);
    return pubkey;
}

// Tests

test "create and parse KeyPackage relay list event" {
    const allocator = std.testing.allocator;
    
    const private_key: [32]u8 = [_]u8{0xAB} ** 32;
    const relay_uris = [_][]const u8{
        "wss://relay1.example.com",
        "wss://relay2.example.com",
        "ws://localhost:7777",
    };
    const description = "My KeyPackage relays";
    
    // Create event
    const event = try KeyPackageRelayListEvent.create(
        allocator,
        private_key,
        &relay_uris,
        description,
    );
    defer event.deinit(allocator);
    
    // Verify basic properties
    try std.testing.expectEqual(@as(u32, 10051), event.event.kind);
    try std.testing.expectEqual(@as(usize, 3), event.relay_uris.len);
    try std.testing.expectEqualStrings(description, event.description.?);
    
    // Verify relay URIs
    try std.testing.expectEqualStrings("wss://relay1.example.com", event.relay_uris[0]);
    try std.testing.expectEqualStrings("wss://relay2.example.com", event.relay_uris[1]);
    try std.testing.expectEqualStrings("ws://localhost:7777", event.relay_uris[2]);
    
    // Verify tags
    try std.testing.expectEqual(@as(usize, 3), event.event.tags.len);
    for (event.event.tags, relay_uris) |tag, expected_uri| {
        try std.testing.expectEqual(@as(usize, 2), tag.len);
        try std.testing.expectEqualStrings("r", tag[0]);
        try std.testing.expectEqualStrings(expected_uri, tag[1]);
    }
}

test "KeyPackage discovery service basic operations" {
    const allocator = std.testing.allocator;
    
    var service = KeyPackageDiscoveryService.init(allocator);
    defer service.deinit();
    
    // Test adding relays
    try service.addRelay("wss://relay1.example.com");
    try service.addRelay("wss://relay2.example.com");
    
    // Check stats
    const stats = service.getStats();
    try std.testing.expectEqual(@as(u32, 2), stats.current_relays_count);
    try std.testing.expectEqual(@as(u32, 0), stats.cached_users_count);
    
    // Test removing relay
    service.removeRelay("wss://relay1.example.com");
    const stats2 = service.getStats();
    try std.testing.expectEqual(@as(u32, 1), stats2.current_relays_count);
    
    // Test duplicate addition (should be ignored)
    try service.addRelay("wss://relay2.example.com");
    const stats3 = service.getStats();
    try std.testing.expectEqual(@as(u32, 1), stats3.current_relays_count);
}

test "KeyPackage discovery caching" {
    const allocator = std.testing.allocator;
    
    var service = KeyPackageDiscoveryService.init(allocator);
    defer service.deinit();
    
    // Create a relay list event for another user
    const other_private_key: [32]u8 = [_]u8{0xCD} ** 32;
    const other_pubkey = try @import("../crypto.zig").getPublicKey(other_private_key);
    
    const relay_uris = [_][]const u8{
        "wss://other-relay.example.com",
    };
    
    const relay_event = try KeyPackageRelayListEvent.create(
        allocator,
        other_private_key,
        &relay_uris,
        "Other user's relays",
    );
    
    // Cache the event
    try service.cacheRelayList(other_pubkey, relay_event);
    
    // Verify it's cached
    const stats = service.getStats();
    try std.testing.expectEqual(@as(u32, 1), stats.cached_users_count);
    
    // Retrieve relay list for the user
    const cached_relays = service.getRelayListForUser(other_pubkey);
    try std.testing.expect(cached_relays != null);
    try std.testing.expectEqual(@as(usize, 1), cached_relays.?.len);
    try std.testing.expectEqualStrings("wss://other-relay.example.com", cached_relays.?[0]);
}

test "relay URI validation" {
    // Valid URIs
    try validateRelayUri("wss://relay.example.com");
    try validateRelayUri("ws://localhost:7777");
    try validateRelayUri("wss://relay.example.com/path");
    
    // Invalid URIs
    try std.testing.expectError(error.EmptyUri, validateRelayUri(""));
    try std.testing.expectError(error.InvalidUriScheme, validateRelayUri("https://example.com"));
    try std.testing.expectError(error.InvalidUriScheme, validateRelayUri("relay.example.com"));
}

test "parse public key from hex" {
    const valid_hex = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
    const pubkey = try parsePublicKey(valid_hex);
    try std.testing.expectEqual(@as(u8, 0xab), pubkey[0]);
    try std.testing.expectEqual(@as(u8, 0xcd), pubkey[31]);
    
    // Invalid lengths
    try std.testing.expectError(error.InvalidPublicKeyLength, parsePublicKey("short"));
    try std.testing.expectError(error.InvalidPublicKeyLength, parsePublicKey("abcd"));
}

test "get all known relays aggregation" {
    const allocator = std.testing.allocator;
    
    var service = KeyPackageDiscoveryService.init(allocator);
    defer service.deinit();
    
    // Add our relays
    try service.addRelay("wss://my-relay1.example.com");
    try service.addRelay("wss://my-relay2.example.com");
    
    // Add cached relays from another user
    const other_private_key: [32]u8 = [_]u8{0xEF} ** 32;
    const other_pubkey = try @import("../crypto.zig").getPublicKey(other_private_key);
    
    const other_relay_uris = [_][]const u8{
        "wss://other-relay.example.com",
        "wss://my-relay1.example.com", // Duplicate - should be filtered
    };
    
    const relay_event = try KeyPackageRelayListEvent.create(
        allocator,
        other_private_key,
        &other_relay_uris,
        null,
    );
    
    try service.cacheRelayList(other_pubkey, relay_event);
    
    // Get all known relays
    const all_relays = try service.getAllKnownRelays();
    defer allocator.free(all_relays);
    
    // Should have 3 unique relays (duplicate filtered out)
    try std.testing.expectEqual(@as(usize, 3), all_relays.len);
    
    // Verify specific relays are present (order may vary)
    var found_my1 = false;
    var found_my2 = false;
    var found_other = false;
    
    for (all_relays) |relay| {
        if (std.mem.eql(u8, relay, "wss://my-relay1.example.com")) found_my1 = true;
        if (std.mem.eql(u8, relay, "wss://my-relay2.example.com")) found_my2 = true;
        if (std.mem.eql(u8, relay, "wss://other-relay.example.com")) found_other = true;
    }
    
    try std.testing.expect(found_my1);
    try std.testing.expect(found_my2);
    try std.testing.expect(found_other);
}