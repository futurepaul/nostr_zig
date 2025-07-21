const std = @import("std");
const Event = @import("event.zig").Event;
const crypto = @import("../crypto.zig");
const wasm_time = @import("../wasm_time.zig");

/// Parameters for building an event
pub const EventParams = struct {
    kind: u32,
    content: []const u8,
    tags: []const []const []const u8 = &[_][]const []const u8{},
    created_at: ?i64 = null,
};

/// Builder for creating properly signed Nostr events
pub const EventBuilder = struct {
    allocator: std.mem.Allocator,
    private_key: ?[32]u8 = null,
    
    /// Initialize event builder
    pub fn init(allocator: std.mem.Allocator) EventBuilder {
        return EventBuilder{
            .allocator = allocator,
        };
    }
    
    /// Initialize event builder with a private key
    pub fn initWithKey(allocator: std.mem.Allocator, private_key: [32]u8) EventBuilder {
        return EventBuilder{
            .allocator = allocator,
            .private_key = private_key,
        };
    }
    
    /// Build and sign an event
    pub fn buildSigned(self: *const EventBuilder, private_key: [32]u8, params: EventParams) !Event {
        var event = try Event.init(self.allocator, params.kind, params.content, params.tags);
        
        // Set timestamp if provided
        if (params.created_at) |ts| {
            event.created_at = ts;
        }
        
        // Sign the event
        try event.sign(self.allocator, private_key);
        
        return event;
    }
    
    /// Build and sign an event using the builder's stored private key
    pub fn build(self: *const EventBuilder, params: EventParams) !Event {
        if (self.private_key) |key| {
            return try self.buildSigned(key, params);
        } else {
            return error.NoPrivateKey;
        }
    }
    
    /// Build an unsigned event (for NIP-59 rumors)
    pub fn buildUnsigned(self: *const EventBuilder, private_key: [32]u8, params: EventParams) !Event {
        return try Event.initUnsigned(
            self.allocator,
            private_key,
            params.kind,
            params.content,
            params.tags,
            params.created_at,
        );
    }
    
    /// Helper to create tags more easily
    pub fn tag(self: *const EventBuilder, comptime tag_name: []const u8, values: []const []const u8) ![]const []const u8 {
        const tag_array = try self.allocator.alloc([]const u8, values.len + 1);
        tag_array[0] = try self.allocator.dupe(u8, tag_name);
        for (values, 1..) |value, i| {
            tag_array[i] = try self.allocator.dupe(u8, value);
        }
        return tag_array;
    }
    
    /// Free a tag created by the tag() helper
    pub fn freeTag(self: *const EventBuilder, tag_array: []const []const u8) void {
        for (tag_array) |item| {
            self.allocator.free(item);
        }
        self.allocator.free(tag_array);
    }
};

/// Specialized builders for common event types
pub const TextNoteBuilder = struct {
    builder: EventBuilder,
    
    pub fn init(allocator: std.mem.Allocator, private_key: [32]u8) TextNoteBuilder {
        return .{ .builder = EventBuilder.initWithKey(allocator, private_key) };
    }
    
    pub fn build(self: *const TextNoteBuilder, content: []const u8, tags: []const []const []const u8) !Event {
        return try self.builder.build(.{
            .kind = 1,
            .content = content,
            .tags = tags,
        });
    }
};

pub const MetadataBuilder = struct {
    builder: EventBuilder,
    
    pub fn init(allocator: std.mem.Allocator, private_key: [32]u8) MetadataBuilder {
        return .{ .builder = EventBuilder.initWithKey(allocator, private_key) };
    }
    
    pub fn build(self: *const MetadataBuilder, metadata: struct {
        name: ?[]const u8 = null,
        about: ?[]const u8 = null,
        picture: ?[]const u8 = null,
        nip05: ?[]const u8 = null,
    }) !Event {
        // Build JSON content
        var content = std.ArrayList(u8).init(self.builder.allocator);
        defer content.deinit();
        
        try content.append('{');
        var first = true;
        
        if (metadata.name) |name| {
            try std.fmt.format(content.writer(), "\"name\":\"{s}\"", .{name});
            first = false;
        }
        
        if (metadata.about) |about| {
            if (!first) try content.append(',');
            try std.fmt.format(content.writer(), "\"about\":\"{s}\"", .{about});
            first = false;
        }
        
        if (metadata.picture) |picture| {
            if (!first) try content.append(',');
            try std.fmt.format(content.writer(), "\"picture\":\"{s}\"", .{picture});
            first = false;
        }
        
        if (metadata.nip05) |nip05| {
            if (!first) try content.append(',');
            try std.fmt.format(content.writer(), "\"nip05\":\"{s}\"", .{nip05});
        }
        
        try content.append('}');
        
        return try self.builder.build(.{
            .kind = 0,
            .content = content.items,
            .tags = &[_][]const []const u8{},
        });
    }
};

// Tests
test "build simple text note" {
    const allocator = std.testing.allocator;
    
    const private_key = try crypto.generatePrivateKey();
    const builder = EventBuilder.initWithKey(allocator, private_key);
    
    const event = try builder.build(.{
        .kind = 1,
        .content = "Hello, Nostr!",
        .tags = &[_][]const []const u8{},
    });
    defer event.deinit(allocator);
    
    // Verify event properties
    try std.testing.expectEqual(@as(u32, 1), event.kind);
    try std.testing.expectEqualStrings("Hello, Nostr!", event.content);
    try std.testing.expect(event.id.len == 64);
    try std.testing.expect(event.sig.len == 128);
    
    // Verify signature
    const is_valid = try event.verify();
    try std.testing.expect(is_valid);
}

test "build event with tags" {
    const allocator = std.testing.allocator;
    
    const private_key = try crypto.generatePrivateKey();
    const builder = EventBuilder.initWithKey(allocator, private_key);
    
    // Create tags using helper
    const e_tag = try builder.tag("e", &[_][]const u8{"event_id_123"});
    defer builder.freeTag(e_tag);
    
    const p_tag = try builder.tag("p", &[_][]const u8{ "pubkey_456", "relay_url" });
    defer builder.freeTag(p_tag);
    
    const tags = [_][]const []const u8{ e_tag, p_tag };
    
    const event = try builder.build(.{
        .kind = 1,
        .content = "Reply to event",
        .tags = &tags,
    });
    defer event.deinit(allocator);
    
    // Verify tags
    try std.testing.expectEqual(@as(usize, 2), event.tags.len);
    try std.testing.expectEqualStrings("e", event.tags[0][0]);
    try std.testing.expectEqualStrings("event_id_123", event.tags[0][1]);
    try std.testing.expectEqualStrings("p", event.tags[1][0]);
    try std.testing.expectEqualStrings("pubkey_456", event.tags[1][1]);
}

test "build unsigned event" {
    const allocator = std.testing.allocator;
    
    const private_key = try crypto.generatePrivateKey();
    const builder = EventBuilder.init(allocator);
    
    const event = try builder.buildUnsigned(private_key, .{
        .kind = 9,
        .content = "This is an unsigned rumor",
        .created_at = 1234567890,
    });
    defer event.deinit(allocator);
    
    // Verify event properties
    try std.testing.expectEqual(@as(u32, 9), event.kind);
    try std.testing.expectEqual(@as(i64, 1234567890), event.created_at);
    try std.testing.expectEqualStrings("", event.sig); // Unsigned
    try std.testing.expect(event.id.len == 64); // Still has ID
}

test "specialized text note builder" {
    const allocator = std.testing.allocator;
    
    const private_key = try crypto.generatePrivateKey();
    const text_builder = TextNoteBuilder.init(allocator, private_key);
    
    const event = try text_builder.build("My first note!", &[_][]const []const u8{});
    defer event.deinit(allocator);
    
    try std.testing.expectEqual(@as(u32, 1), event.kind);
    try std.testing.expectEqualStrings("My first note!", event.content);
}

test "specialized metadata builder" {
    const allocator = std.testing.allocator;
    
    const private_key = try crypto.generatePrivateKey();
    const metadata_builder = MetadataBuilder.init(allocator, private_key);
    
    const event = try metadata_builder.build(.{
        .name = "Alice",
        .about = "Nostr developer",
        .picture = "https://example.com/alice.jpg",
    });
    defer event.deinit(allocator);
    
    try std.testing.expectEqual(@as(u32, 0), event.kind);
    try std.testing.expect(std.mem.indexOf(u8, event.content, "\"name\":\"Alice\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, event.content, "\"about\":\"Nostr developer\"") != null);
}