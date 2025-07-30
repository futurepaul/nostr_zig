const std = @import("std");
const json = std.json;
const testing = std.testing;
const Allocator = std.mem.Allocator;

/// Nostr event kinds as defined in the protocol
pub const Kind = enum(u32) {
    metadata = 0,          // User metadata (profile)
    text_note = 1,         // Short text note
    recommend_relay = 2,   // Recommend a relay
    contacts = 3,          // Contact list
    encrypted_dm = 4,      // Encrypted direct message
    event_deletion = 5,    // Event deletion
    repost = 6,           // Repost/boost
    reaction = 7,         // Like/reaction
    badge_award = 8,      // Badge award
    
    // Add more kinds as needed
    _,                    // Allow unknown kinds

    pub fn fromInt(value: u32) Kind {
        return @enumFromInt(value);
    }

    pub fn toInt(self: Kind) u32 {
        return @intFromEnum(self);
    }
};

/// A Nostr tag is an array of strings
pub const Tag = [][]const u8;

/// Collection of tags
pub const Tags = []Tag;

/// Errors that can occur during event parsing and validation
pub const EventError = error{
    MissingField,
    InvalidFieldType,
    InvalidHexString,
    InvalidTimestamp,
    InvalidKind,
    InvalidSignature,
    InvalidEventId,
};

/// Represents a Nostr event with all required fields
pub const Event = struct {
    id: []const u8,           // 32-byte hex-encoded event ID
    pubkey: []const u8,       // 32-byte hex-encoded public key
    created_at: i64,          // Unix timestamp in seconds
    kind: u32,                // Event kind
    tags: []const []const []const u8,  // Array of tag arrays
    content: []const u8,      // Event content
    sig: []const u8,          // 64-byte hex-encoded signature

    const Self = @This();

    /// Parse a Nostr event from JSON
    pub fn fromJson(allocator: Allocator, json_str: []const u8) !Self {
        const parsed = try json.parseFromSlice(json.Value, allocator, json_str, .{});
        defer parsed.deinit();

        if (parsed.value != .object) {
            return EventError.InvalidFieldType;
        }

        return try fromJsonObject(allocator, parsed.value.object);
    }
    
    /// Parse a Nostr event from a JSON object map
    pub fn fromJsonObject(allocator: Allocator, obj: json.ObjectMap) !Self {
        // Extract required fields with proper error handling
        const id_value = obj.get("id") orelse return EventError.MissingField;
        if (id_value != .string) return EventError.InvalidFieldType;
        const id = try allocator.dupe(u8, id_value.string);
        
        const pubkey_value = obj.get("pubkey") orelse return EventError.MissingField;
        if (pubkey_value != .string) return EventError.InvalidFieldType;
        const pubkey = try allocator.dupe(u8, pubkey_value.string);
        
        const created_at_value = obj.get("created_at") orelse return EventError.MissingField;
        if (created_at_value != .integer) return EventError.InvalidFieldType;
        const created_at = @as(i64, @intCast(created_at_value.integer));
        
        const kind_value = obj.get("kind") orelse return EventError.MissingField;
        if (kind_value != .integer) return EventError.InvalidFieldType;
        const kind = @as(u32, @intCast(kind_value.integer));
        
        const content_value = obj.get("content") orelse return EventError.MissingField;
        if (content_value != .string) return EventError.InvalidFieldType;
        const content = try allocator.dupe(u8, content_value.string);
        
        const sig_value = obj.get("sig") orelse return EventError.MissingField;
        if (sig_value != .string) return EventError.InvalidFieldType;
        const sig = try allocator.dupe(u8, sig_value.string);

        // Parse tags array
        const tags_value = obj.get("tags") orelse return EventError.MissingField;
        if (tags_value != .array) return EventError.InvalidFieldType;
        const tags_array = tags_value.array;
        const tags = try allocator.alloc([]const []const u8, tags_array.items.len);
        
        for (tags_array.items, 0..) |tag_item, i| {
            if (tag_item != .array) return EventError.InvalidFieldType;
            const tag_array = tag_item.array;
            const tag = try allocator.alloc([]const u8, tag_array.items.len);
            
            for (tag_array.items, 0..) |tag_str, j| {
                if (tag_str != .string) return EventError.InvalidFieldType;
                tag[j] = try allocator.dupe(u8, tag_str.string);
            }
            
            tags[i] = tag;
        }

        return Self{
            .id = id,
            .pubkey = pubkey,
            .created_at = created_at,
            .kind = kind,
            .tags = tags,
            .content = content,
            .sig = sig,
        };
    }

    /// Serialize event to JSON string
    pub fn toJson(self: Self, allocator: Allocator) ![]u8 {
        // Create a temporary struct that matches JSON structure exactly
        const JsonEvent = struct {
            id: []const u8,
            pubkey: []const u8,
            created_at: i64,
            kind: u32,
            tags: []const []const []const u8,
            content: []const u8,
            sig: []const u8,
        };

        const json_event = JsonEvent{
            .id = self.id,
            .pubkey = self.pubkey,
            .created_at = self.created_at,
            .kind = self.kind,
            .tags = self.tags,
            .content = self.content,
            .sig = self.sig,
        };

        return try json.stringifyAlloc(allocator, json_event, .{});
    }

    /// Free all allocated memory for this event
    pub fn deinit(self: Self, allocator: Allocator) void {
        allocator.free(self.id);
        allocator.free(self.pubkey);
        allocator.free(self.content);
        allocator.free(self.sig);
        
        for (self.tags) |tag| {
            for (tag) |tag_str| {
                allocator.free(tag_str);
            }
            allocator.free(tag);
        }
        allocator.free(self.tags);
    }
    
    /// Create a deep copy of this event
    pub fn deepCopy(self: Self, allocator: Allocator) !Self {
        // Allocate copies of all strings
        const id = try allocator.dupe(u8, self.id);
        errdefer allocator.free(id);
        
        const pubkey = try allocator.dupe(u8, self.pubkey);
        errdefer allocator.free(pubkey);
        
        const content = try allocator.dupe(u8, self.content);
        errdefer allocator.free(content);
        
        const sig = try allocator.dupe(u8, self.sig);
        errdefer allocator.free(sig);
        
        // Deep copy tags
        const tags = try allocator.alloc([]const []const u8, self.tags.len);
        errdefer allocator.free(tags);
        
        for (self.tags, 0..) |tag, i| {
            const tag_copy = try allocator.alloc([]const u8, tag.len);
            errdefer allocator.free(tag_copy);
            
            for (tag, 0..) |tag_str, j| {
                tag_copy[j] = try allocator.dupe(u8, tag_str);
            }
            
            tags[i] = tag_copy;
        }
        
        return Self{
            .id = id,
            .pubkey = pubkey,
            .created_at = self.created_at,
            .kind = self.kind,
            .tags = tags,
            .content = content,
            .sig = sig,
        };
    }

    /// Calculate the event ID according to NIP-01
    pub fn calculateId(self: *Self, allocator: Allocator) !void {
        const crypto = @import("../crypto.zig");
        if (self.id.len > 0) {
            allocator.free(self.id);
        }
        self.id = try crypto.calculateEventId(
            allocator,
            self.pubkey,
            self.created_at,
            self.kind,
            self.tags,
            self.content,
        );
    }
    
    /// Sign the event with a private key
    pub fn sign(self: *Self, allocator: Allocator, private_key: [32]u8) !void {
        const crypto = @import("../crypto.zig");
        const wasm_time = @import("../wasm_time.zig");
        
        // Set public key if not already set
        if (self.pubkey.len == 0) {
            const public_key = try crypto.getPublicKey(private_key);
            self.pubkey = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(&public_key)});
        }
        
        // Set timestamp if not already set
        if (self.created_at == 0) {
            self.created_at = wasm_time.timestamp();
        }
        
        // Ensure ID is calculated
        if (self.id.len == 0) {
            try self.calculateId(allocator);
        }
        
        // Sign the event
        const sig_bytes = try crypto.signEvent(self.id, private_key);
        
        // Free old signature if exists
        if (self.sig.len > 0) {
            allocator.free(self.sig);
        }
        
        // Convert signature to hex
        self.sig = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(&sig_bytes)});
    }
    
    /// Verify the event signature
    pub fn verify(self: *const Self) !bool {
        const crypto = @import("../crypto.zig");
        
        // Parse public key from hex
        if (self.pubkey.len != 64) return error.InvalidPublicKey;
        var pubkey_bytes: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&pubkey_bytes, self.pubkey);
        
        // Parse signature from hex
        if (self.sig.len != 128) return error.InvalidSignature;
        var signature_bytes: [64]u8 = undefined;
        _ = try std.fmt.hexToBytes(&signature_bytes, self.sig);
        
        // Verify the signature
        return try crypto.verifySignature(self.id, signature_bytes, pubkey_bytes);
    }

    /// Validate event ID matches the computed hash
    pub fn validateId(self: Self, allocator: Allocator) !bool {
        const crypto = @import("../crypto.zig");
        
        // Calculate what the ID should be
        const calculated_id = try crypto.calculateEventId(
            allocator,
            self.pubkey,
            self.created_at,
            self.kind,
            self.tags,
            self.content,
        );
        defer allocator.free(calculated_id);
        
        // Compare with the actual ID
        return std.mem.eql(u8, self.id, calculated_id);
    }

    /// Validate signature (alias for verify for backward compatibility)
    pub fn validateSignature(self: *const Self) !bool {
        return try self.verify();
    }

    /// Initialize a new event with basic fields
    pub fn init(allocator: Allocator, kind: u32, content: []const u8, tags: []const []const []const u8) !Self {
        // Deep copy tags
        const tags_copy = try allocator.alloc([]const []const u8, tags.len);
        for (tags, 0..) |tag, i| {
            const tag_copy = try allocator.alloc([]const u8, tag.len);
            for (tag, 0..) |tag_item, j| {
                tag_copy[j] = try allocator.dupe(u8, tag_item);
            }
            tags_copy[i] = tag_copy;
        }
        
        return Self{
            .id = try allocator.dupe(u8, ""), // Will be calculated
            .pubkey = try allocator.dupe(u8, ""), // Will be set when signing
            .created_at = 0, // Will be set when signing
            .kind = kind,
            .tags = tags_copy,
            .content = try allocator.dupe(u8, content),
            .sig = try allocator.dupe(u8, ""), // Will be set when signing
        };
    }
    
    /// Initialize a new unsigned event (for NIP-59 rumors)
    pub fn initUnsigned(allocator: Allocator, private_key: [32]u8, kind: u32, content: []const u8, tags: []const []const []const u8, created_at: ?i64) !Self {
        const crypto = @import("../crypto.zig");
        const wasm_time = @import("../wasm_time.zig");
        
        // Get public key from private key
        const public_key = try crypto.getPublicKey(private_key);
        const pubkey_hex = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(&public_key)});
        
        // Use provided timestamp or current time
        const timestamp = created_at orelse wasm_time.timestamp();
        
        // Deep copy tags
        const tags_copy = try allocator.alloc([]const []const u8, tags.len);
        for (tags, 0..) |tag, i| {
            const tag_copy = try allocator.alloc([]const u8, tag.len);
            for (tag, 0..) |tag_item, j| {
                tag_copy[j] = try allocator.dupe(u8, tag_item);
            }
            tags_copy[i] = tag_copy;
        }
        
        var event = Self{
            .id = try allocator.dupe(u8, ""),
            .pubkey = pubkey_hex,
            .created_at = timestamp,
            .kind = kind,
            .tags = tags_copy,
            .content = try allocator.dupe(u8, content),
            .sig = try allocator.dupe(u8, ""), // Unsigned
        };
        
        // Calculate ID even for unsigned events
        try event.calculateId(allocator);
        
        return event;
    }

    /// Check if event is a text note
    pub fn isTextNote(self: Self) bool {
        return self.kind == 1;
    }

    /// Check if event is metadata
    pub fn isMetadata(self: Self) bool {
        return self.kind == 0;
    }
};

// Tests
test "parse text note event from JSON" {
    const allocator = testing.allocator;
    
    const json_str = 
        \\{
        \\  "id": "b7b1fb52ad8461a03e949820ae29a9ea07e35bcd79c95c4b59b0254944f62805",
        \\  "pubkey": "aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4",
        \\  "created_at": 1704644581,
        \\  "kind": 1,
        \\  "tags": [],
        \\  "content": "Text note",
        \\  "sig": "ed73a8a4e7c26cd797a7b875c634d9ecb6958c57733305fed23b978109d0411d21b3e182cb67c8ad750884e30ca383b509382ae6187b36e76ee76e6a142c4284"
        \\}
    ;
    
    const event = try Event.fromJson(allocator, json_str);
    defer event.deinit(allocator);
    
    // Verify all fields are correctly parsed
    try testing.expectEqualStrings("b7b1fb52ad8461a03e949820ae29a9ea07e35bcd79c95c4b59b0254944f62805", event.id);
    try testing.expectEqualStrings("aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4", event.pubkey);
    try testing.expectEqual(@as(i64, 1704644581), event.created_at);
    try testing.expectEqual(@as(u32, 1), event.kind);
    try testing.expectEqual(@as(usize, 0), event.tags.len);
    try testing.expectEqualStrings("Text note", event.content);
    try testing.expectEqualStrings("ed73a8a4e7c26cd797a7b875c634d9ecb6958c57733305fed23b978109d0411d21b3e182cb67c8ad750884e30ca383b509382ae6187b36e76ee76e6a142c4284", event.sig);
    
    // Test helper methods
    try testing.expect(event.isTextNote());
    try testing.expect(!event.isMetadata());
}

test "parse metadata event from JSON" {
    const allocator = testing.allocator;
    
    const json_str = 
        \\{
        \\  "id": "8b19ce08cc0b20fd6c30e73b102fd3092c4f95f1c2a23d44064f9634b4593da5",
        \\  "pubkey": "2f35aaff0c870f0510a8bed198e1f8c35e95c996148f2d0c0fb1825b05b8dd35",
        \\  "created_at": 1731251995,
        \\  "kind": 0,
        \\  "tags": [],
        \\  "content": "{\"name\":\"username\",\"display_name\":\"My Username\",\"about\":\"Description\"}",
        \\  "sig": "b26e4dfea18d4ecb072c665f9ed34b66d8dd9a45093790ea17cb618d85319587aa094f5c091efa3e237cd50976884e02c64c2f2b187c3ebdc4f773b2d74a61a4"
        \\}
    ;
    
    const event = try Event.fromJson(allocator, json_str);
    defer event.deinit(allocator);
    
    // Verify metadata-specific fields
    try testing.expectEqual(@as(u32, 0), event.kind);
    try testing.expect(event.isMetadata());
    try testing.expect(!event.isTextNote());
    
    // Content should be JSON string
    try testing.expect(std.mem.startsWith(u8, event.content, "{"));
    try testing.expect(std.mem.endsWith(u8, event.content, "}"));
}

test "parse event with tags" {
    const allocator = testing.allocator;
    
    const json_str = 
        \\{
        \\  "id": "test123",
        \\  "pubkey": "pubkey123",
        \\  "created_at": 1234567890,
        \\  "kind": 1,
        \\  "tags": [["e", "event_id"], ["p", "pubkey_id", "relay_url"]],
        \\  "content": "Hello with tags",
        \\  "sig": "sig123"
        \\}
    ;
    
    const event = try Event.fromJson(allocator, json_str);
    defer event.deinit(allocator);
    
    // Verify tags are parsed correctly
    try testing.expectEqual(@as(usize, 2), event.tags.len);
    
    // First tag: ["e", "event_id"]
    try testing.expectEqual(@as(usize, 2), event.tags[0].len);
    try testing.expectEqualStrings("e", event.tags[0][0]);
    try testing.expectEqualStrings("event_id", event.tags[0][1]);
    
    // Second tag: ["p", "pubkey_id", "relay_url"]
    try testing.expectEqual(@as(usize, 3), event.tags[1].len);
    try testing.expectEqualStrings("p", event.tags[1][0]);
    try testing.expectEqualStrings("pubkey_id", event.tags[1][1]);
    try testing.expectEqualStrings("relay_url", event.tags[1][2]);
}

test "serialize event to JSON" {
    const allocator = testing.allocator;
    
    // Create a simple event
    const tags = try allocator.alloc([]const []const u8, 0);
    defer allocator.free(tags);
    
    const event = Event{
        .id = "test_id",
        .pubkey = "test_pubkey",
        .created_at = 1234567890,
        .kind = 1,
        .tags = tags,
        .content = "Test content",
        .sig = "test_sig",
    };
    
    const json_str = try event.toJson(allocator);
    defer allocator.free(json_str);
    
    // Basic checks - should contain all required fields
    try testing.expect(std.mem.indexOf(u8, json_str, "\"id\":\"test_id\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"pubkey\":\"test_pubkey\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"created_at\":1234567890") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"kind\":1") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"content\":\"Test content\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"sig\":\"test_sig\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"tags\":[]") != null);
}

test "round-trip JSON parsing" {
    const allocator = testing.allocator;
    
    const original_json = 
        \\{
        \\  "id": "b7b1fb52ad8461a03e949820ae29a9ea07e35bcd79c95c4b59b0254944f62805",
        \\  "pubkey": "aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4",
        \\  "created_at": 1704644581,
        \\  "kind": 1,
        \\  "tags": [],
        \\  "content": "Text note",
        \\  "sig": "ed73a8a4e7c26cd797a7b875c634d9ecb6958c57733305fed23b978109d0411d21b3e182cb67c8ad750884e30ca383b509382ae6187b36e76ee76e6a142c4284"
        \\}
    ;
    
    // Parse JSON to Event
    const event1 = try Event.fromJson(allocator, original_json);
    defer event1.deinit(allocator);
    
    // Serialize Event to JSON
    const serialized_json = try event1.toJson(allocator);
    defer allocator.free(serialized_json);
    
    // Parse serialized JSON back to Event
    const event2 = try Event.fromJson(allocator, serialized_json);
    defer event2.deinit(allocator);
    
    // Verify both events are identical
    try testing.expectEqualStrings(event1.id, event2.id);
    try testing.expectEqualStrings(event1.pubkey, event2.pubkey);
    try testing.expectEqual(event1.created_at, event2.created_at);
    try testing.expectEqual(event1.kind, event2.kind);
    try testing.expectEqualStrings(event1.content, event2.content);
    try testing.expectEqualStrings(event1.sig, event2.sig);
    try testing.expectEqual(event1.tags.len, event2.tags.len);
}

test "basic validation checks" {
    const allocator = testing.allocator;
    
    const json_str = 
        \\{
        \\  "id": "b7b1fb52ad8461a03e949820ae29a9ea07e35bcd79c95c4b59b0254944f62805",
        \\  "pubkey": "aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4",
        \\  "created_at": 1704644581,
        \\  "kind": 1,
        \\  "tags": [],
        \\  "content": "Text note",
        \\  "sig": "ed73a8a4e7c26cd797a7b875c634d9ecb6958c57733305fed23b978109d0411d21b3e182cb67c8ad750884e30ca383b509382ae6187b36e76ee76e6a142c4284"
        \\}
    ;
    
    const event = try Event.fromJson(allocator, json_str);
    defer event.deinit(allocator);
    
    // Basic validation (validateId now requires allocator)
    try testing.expect(try event.validateId(allocator));
    try testing.expect(try event.validateSignature());
}

test "kind enum functionality" {
    try testing.expectEqual(@as(u32, 0), Kind.metadata.toInt());
    try testing.expectEqual(@as(u32, 1), Kind.text_note.toInt());
    try testing.expectEqual(@as(u32, 7), Kind.reaction.toInt());
    
    try testing.expectEqual(Kind.metadata, Kind.fromInt(0));
    try testing.expectEqual(Kind.text_note, Kind.fromInt(1));
    try testing.expectEqual(Kind.reaction, Kind.fromInt(7));
    
    // Test unknown kind
    const unknown_kind = Kind.fromInt(9999);
    try testing.expectEqual(@as(u32, 9999), unknown_kind.toInt());
}