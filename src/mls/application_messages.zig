const std = @import("std");
const nostr = @import("../nostr.zig");
const types = @import("types.zig");
const mls = @import("mls.zig");
const messages = @import("messages.zig");

/// Application message types supported within MLS group messages
/// These correspond to Nostr event kinds that can be sent as inner events
pub const InnerEventKind = enum(u32) {
    text_note = 1,      // Basic text message
    reaction = 7,       // Reaction/like to another event
    chat = 9,           // Chat message (extended text with more features)
    
    pub fn fromInt(value: u32) ?InnerEventKind {
        return switch (value) {
            1 => .text_note,
            7 => .reaction,
            9 => .chat,
            else => null,
        };
    }
    
    pub fn toInt(self: InnerEventKind) u32 {
        return @intFromEnum(self);
    }
};

/// An inner event that can be embedded within a group message
/// These events remain unsigned for security as per NIP-EE specification
pub const InnerEvent = struct {
    /// Event kind (1, 7, or 9)
    kind: InnerEventKind,
    /// Event content
    content: []const u8,
    /// Event tags
    tags: []const []const []const u8,
    /// Created timestamp
    created_at: i64,
    /// The pubkey of the sender (extracted from group member identity)
    pubkey: [32]u8,
    
    /// Serialize an inner event to JSON for embedding in MLS application message
    pub fn serialize(self: *const InnerEvent, allocator: std.mem.Allocator) ![]u8 {
        // Use a simple string building approach to avoid JSON library complexity
        var result = std.ArrayList(u8).init(allocator);
        defer result.deinit();
        
        // Start object
        try result.appendSlice("{");
        
        // Add kind
        try result.appendSlice("\"kind\":");
        try result.writer().print("{}", .{self.kind.toInt()});
        try result.appendSlice(",");
        
        // Add content (escape JSON)
        try result.appendSlice("\"content\":");
        try std.json.stringify(self.content, .{}, result.writer());
        try result.appendSlice(",");
        
        // Add created_at
        try result.appendSlice("\"created_at\":");
        try result.writer().print("{}", .{self.created_at});
        try result.appendSlice(",");
        
        // Add pubkey
        try result.appendSlice("\"pubkey\":\"");
        try result.writer().print("{s}", .{std.fmt.fmtSliceHexLower(&self.pubkey)});
        try result.appendSlice("\",");
        
        // Add tags
        try result.appendSlice("\"tags\":[");
        for (self.tags, 0..) |tag, i| {
            if (i > 0) try result.appendSlice(",");
            try result.appendSlice("[");
            for (tag, 0..) |tag_item, j| {
                if (j > 0) try result.appendSlice(",");
                try std.json.stringify(tag_item, .{}, result.writer());
            }
            try result.appendSlice("]");
        }
        try result.appendSlice("]");
        
        // End object
        try result.appendSlice("}");
        
        return try result.toOwnedSlice();
    }
    
    /// Parse an inner event from JSON
    pub fn parse(allocator: std.mem.Allocator, json_data: []const u8) !InnerEvent {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_data, .{});
        defer parsed.deinit();
        
        const obj = parsed.value.object;
        
        // Extract kind
        const kind_int = @as(u32, @intCast(obj.get("kind").?.integer));
        const kind = InnerEventKind.fromInt(kind_int) orelse return error.UnsupportedEventKind;
        
        // Extract content
        const content = try allocator.dupe(u8, obj.get("content").?.string);
        
        // Extract created_at
        const created_at = obj.get("created_at").?.integer;
        
        // Extract pubkey
        const pubkey_hex = obj.get("pubkey").?.string;
        if (pubkey_hex.len != 64) return error.InvalidPubkeyLength;
        var pubkey: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&pubkey, pubkey_hex);
        
        // Extract tags
        const tags_json = obj.get("tags").?.array;
        const tags = try allocator.alloc([]const []const u8, tags_json.items.len);
        
        for (tags_json.items, 0..) |tag_json, i| {
            const tag_array = tag_json.array;
            const tag = try allocator.alloc([]const u8, tag_array.items.len);
            
            for (tag_array.items, 0..) |tag_item_json, j| {
                // Handle both string and integer values in tags
                switch (tag_item_json) {
                    .string => |s| {
                        tag[j] = try allocator.dupe(u8, s);
                    },
                    .integer => |int_val| {
                        // Convert integer to string
                        tag[j] = try std.fmt.allocPrint(allocator, "{}", .{int_val});
                    },
                    else => return error.InvalidTagType,
                }
            }
            
            tags[i] = tag;
        }
        
        return InnerEvent{
            .kind = kind,
            .content = content,
            .tags = tags,
            .created_at = created_at,
            .pubkey = pubkey,
        };
    }
    
    /// Free memory allocated for an inner event
    pub fn deinit(self: *const InnerEvent, allocator: std.mem.Allocator) void {
        allocator.free(self.content);
        
        for (self.tags) |tag| {
            for (tag) |tag_item| {
                allocator.free(tag_item);
            }
            allocator.free(tag);
        }
        allocator.free(self.tags);
    }
};

/// Create a chat message (kind 9) inner event
pub fn createChatMessage(
    allocator: std.mem.Allocator,
    content: []const u8,
    sender_pubkey: [32]u8,
    created_at: i64,
) !InnerEvent {
    return InnerEvent{
        .kind = .chat,
        .content = try allocator.dupe(u8, content),
        .tags = &.{}, // No tags for basic chat
        .created_at = created_at,
        .pubkey = sender_pubkey,
    };
}

/// Create a reaction message (kind 7) inner event
pub fn createReactionMessage(
    allocator: std.mem.Allocator,
    reaction_content: []const u8, // e.g., "👍", "+", "-"
    target_event_id: [32]u8,
    sender_pubkey: [32]u8,
    created_at: i64,
) !InnerEvent {
    // Create e tag referencing the target event
    const e_tag = try allocator.alloc([]const u8, 2);
    e_tag[0] = try allocator.dupe(u8, "e");
    e_tag[1] = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(&target_event_id)});
    
    const tags = try allocator.alloc([]const []const u8, 1);
    tags[0] = e_tag;
    
    return InnerEvent{
        .kind = .reaction,
        .content = try allocator.dupe(u8, reaction_content),
        .tags = tags,
        .created_at = created_at,
        .pubkey = sender_pubkey,
    };
}

/// Create a text note message (kind 1) inner event
pub fn createTextNoteMessage(
    allocator: std.mem.Allocator,
    content: []const u8,
    sender_pubkey: [32]u8,
    created_at: i64,
    reply_to: ?[32]u8, // Optional event ID to reply to
) !InnerEvent {
    var tags_list = std.ArrayList([]const []const u8).init(allocator);
    defer tags_list.deinit();
    
    // Add reply tag if specified
    if (reply_to) |reply_id| {
        const e_tag = try allocator.alloc([]const u8, 2);
        e_tag[0] = try allocator.dupe(u8, "e");
        e_tag[1] = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(&reply_id)});
        try tags_list.append(e_tag);
    }
    
    return InnerEvent{
        .kind = .text_note,
        .content = try allocator.dupe(u8, content),
        .tags = try tags_list.toOwnedSlice(),
        .created_at = created_at,
        .pubkey = sender_pubkey,
    };
}

/// Validate that an inner event conforms to NIP-EE security requirements
pub fn validateInnerEvent(inner_event: *const InnerEvent) !void {
    // Check that the event kind is supported
    switch (inner_event.kind) {
        .text_note, .chat, .reaction => {},
        // Additional validation could be added here
    }
    
    // Validate content length (prevent abuse)
    if (inner_event.content.len > 65536) { // 64KB limit
        return error.ContentTooLong;
    }
    
    // Validate timestamp is reasonable (not too far in future/past)
    const current_time = std.time.timestamp();
    const time_diff = @abs(inner_event.created_at - current_time);
    if (time_diff > 86400) { // 24 hours tolerance
        return error.InvalidTimestamp;
    }
    
    // Validate pubkey format (should be 32 bytes)
    // This is enforced by the type system, but we could add additional checks
    
    // Validate tags don't exceed reasonable limits
    if (inner_event.tags.len > 100) { // Max 100 tags
        return error.TooManyTags;
    }
    
    for (inner_event.tags) |tag| {
        if (tag.len > 10) { // Max 10 items per tag
            return error.TagTooLong;
        }
        
        for (tag) |tag_item| {
            if (tag_item.len > 1000) { // Max 1KB per tag item
                return error.TagItemTooLong;
            }
        }
    }
}

/// Create an application message with inner event
/// DEPRECATED: Use createAuthenticatedApplicationMessage instead for security
pub fn createApplicationMessage(
    allocator: std.mem.Allocator,
    mls_provider: *@import("provider.zig").MlsProvider,
    group_state: *const mls.MlsGroupState,
    inner_event: InnerEvent,
    sender_private_key: [32]u8,
) !messages.EncryptedMessage {
    // Validate the inner event
    try validateInnerEvent(&inner_event);
    
    // Serialize the inner event
    const serialized_inner = try inner_event.serialize(allocator);
    defer allocator.free(serialized_inner);
    
    // Create the MLS application message with the serialized inner event
    return try messages.encryptGroupMessage(
        allocator,
        mls_provider,
        group_state,
        serialized_inner,
        sender_private_key,
        .{}, // default message params
    );
}

/// Create an authenticated application message with inner event
/// This function validates sender identity to prevent spoofing
pub fn createAuthenticatedApplicationMessage(
    allocator: std.mem.Allocator,
    mls_provider: *@import("provider.zig").MlsProvider,
    group_state: *const mls.MlsGroupState,
    inner_event: InnerEvent,
    sender_private_key: [32]u8,
) !messages.EncryptedMessage {
    const auth = @import("message_authentication.zig");
    return try auth.createAuthenticatedApplicationMessage(
        allocator,
        mls_provider,
        group_state,
        inner_event,
        sender_private_key,
    );
}

/// Decrypt and parse an application message to extract inner event
/// DEPRECATED: Use parseAuthenticatedApplicationMessage instead for security
pub fn parseApplicationMessage(
    allocator: std.mem.Allocator,
    mls_provider: *@import("provider.zig").MlsProvider,
    group_state: *const mls.MlsGroupState,
    encrypted_data: []const u8,
    epoch: types.Epoch,
    recipient_private_key: [32]u8,
) !InnerEvent {
    // Decrypt the group message
    const decrypted_msg = try messages.decryptGroupMessage(
        allocator,
        mls_provider,
        group_state,
        encrypted_data,
        epoch,
        recipient_private_key,
    );
    defer allocator.free(decrypted_msg.content);
    
    // Parse the inner event from the decrypted content
    return try InnerEvent.parse(allocator, decrypted_msg.content);
}

/// Decrypt and parse an authenticated application message to extract inner event
/// This function validates sender identity to prevent spoofing
pub fn parseAuthenticatedApplicationMessage(
    allocator: std.mem.Allocator,
    mls_provider: *@import("provider.zig").MlsProvider,
    group_state: *const mls.MlsGroupState,
    encrypted_data: []const u8,
    epoch: types.Epoch,
    recipient_private_key: [32]u8,
) !InnerEvent {
    const auth = @import("message_authentication.zig");
    return try auth.parseAuthenticatedApplicationMessage(
        allocator,
        mls_provider,
        group_state,
        encrypted_data,
        epoch,
        recipient_private_key,
    );
}

// Tests

test "create and serialize chat message" {
    const allocator = std.testing.allocator;
    
    const sender_pubkey: [32]u8 = [_]u8{0x11} ** 32;
    const created_at: i64 = 1234567890;
    const content = "Hello, group!";
    
    const chat_msg = try createChatMessage(allocator, content, sender_pubkey, created_at);
    defer chat_msg.deinit(allocator);
    
    try std.testing.expectEqual(InnerEventKind.chat, chat_msg.kind);
    try std.testing.expectEqualStrings(content, chat_msg.content);
    try std.testing.expectEqual(created_at, chat_msg.created_at);
    try std.testing.expectEqual(sender_pubkey, chat_msg.pubkey);
    
    // Test serialization
    const serialized = try chat_msg.serialize(allocator);
    defer allocator.free(serialized);
    
    // Should contain JSON with expected fields
    try std.testing.expect(std.mem.indexOf(u8, serialized, "\"kind\":9") != null);
    try std.testing.expect(std.mem.indexOf(u8, serialized, "Hello, group!") != null);
}

test "create and serialize reaction message" {
    const allocator = std.testing.allocator;
    
    const sender_pubkey: [32]u8 = [_]u8{0x22} ** 32;
    const target_event: [32]u8 = [_]u8{0x33} ** 32;
    const created_at: i64 = 1234567890;
    const reaction = "👍";
    
    const reaction_msg = try createReactionMessage(allocator, reaction, target_event, sender_pubkey, created_at);
    defer reaction_msg.deinit(allocator);
    
    try std.testing.expectEqual(InnerEventKind.reaction, reaction_msg.kind);
    try std.testing.expectEqualStrings(reaction, reaction_msg.content);
    try std.testing.expectEqual(created_at, reaction_msg.created_at);
    try std.testing.expectEqual(sender_pubkey, reaction_msg.pubkey);
    try std.testing.expectEqual(@as(usize, 1), reaction_msg.tags.len);
    
    // Check e tag
    const e_tag = reaction_msg.tags[0];
    try std.testing.expectEqual(@as(usize, 2), e_tag.len);
    try std.testing.expectEqualStrings("e", e_tag[0]);
    try std.testing.expectEqualStrings("3333333333333333333333333333333333333333333333333333333333333333", e_tag[1]);
}

test "parse inner event from JSON" {
    const allocator = std.testing.allocator;
    
    const json_data =
        \\{
        \\  "kind": 9,
        \\  "content": "Hello from JSON!",
        \\  "created_at": 1234567890,
        \\  "pubkey": "1111111111111111111111111111111111111111111111111111111111111111",
        \\  "tags": [["e", "2222222222222222222222222222222222222222222222222222222222222222"]]
        \\}
    ;
    
    const inner_event = try InnerEvent.parse(allocator, json_data);
    defer inner_event.deinit(allocator);
    
    try std.testing.expectEqual(InnerEventKind.chat, inner_event.kind);
    try std.testing.expectEqualStrings("Hello from JSON!", inner_event.content);
    try std.testing.expectEqual(@as(i64, 1234567890), inner_event.created_at);
    try std.testing.expectEqual([_]u8{0x11} ** 32, inner_event.pubkey);
    try std.testing.expectEqual(@as(usize, 1), inner_event.tags.len);
    
    const e_tag = inner_event.tags[0];
    try std.testing.expectEqual(@as(usize, 2), e_tag.len);
    try std.testing.expectEqualStrings("e", e_tag[0]);
    try std.testing.expectEqualStrings("2222222222222222222222222222222222222222222222222222222222222222", e_tag[1]);
}

test "validate inner event security requirements" {
    const allocator = std.testing.allocator;
    
    // Valid chat message
    const valid_chat = try createChatMessage(
        allocator,
        "Valid message",
        [_]u8{0x11} ** 32,
        std.time.timestamp(),
    );
    defer valid_chat.deinit(allocator);
    
    try validateInnerEvent(&valid_chat);
    
    // Test content too long
    const long_content = try allocator.alloc(u8, 70000); // > 64KB
    defer allocator.free(long_content);
    @memset(long_content, 'A');
    
    const invalid_long = InnerEvent{
        .kind = .chat,
        .content = long_content,
        .tags = &.{},
        .created_at = std.time.timestamp(),
        .pubkey = [_]u8{0x11} ** 32,
    };
    
    try std.testing.expectError(error.ContentTooLong, validateInnerEvent(&invalid_long));
    
    // Test invalid timestamp (too far in future)
    const invalid_time = InnerEvent{
        .kind = .chat,
        .content = "Valid message",
        .tags = &.{},
        .created_at = std.time.timestamp() + 100000, // Way in future
        .pubkey = [_]u8{0x11} ** 32,
    };
    
    try std.testing.expectError(error.InvalidTimestamp, validateInnerEvent(&invalid_time));
}

test "round-trip serialization" {
    const allocator = std.testing.allocator;
    
    const original = try createTextNoteMessage(
        allocator,
        "Round-trip test message",
        [_]u8{0xAB} ** 32,
        1234567890,
        [_]u8{0xCD} ** 32, // reply_to
    );
    defer original.deinit(allocator);
    
    // Serialize
    const serialized = try original.serialize(allocator);
    defer allocator.free(serialized);
    
    // Parse back
    const parsed = try InnerEvent.parse(allocator, serialized);
    defer parsed.deinit(allocator);
    
    // Verify round-trip
    try std.testing.expectEqual(original.kind, parsed.kind);
    try std.testing.expectEqualStrings(original.content, parsed.content);
    try std.testing.expectEqual(original.created_at, parsed.created_at);
    try std.testing.expectEqual(original.pubkey, parsed.pubkey);
    try std.testing.expectEqual(original.tags.len, parsed.tags.len);
    
    // Check tags match
    for (original.tags, parsed.tags) |orig_tag, parsed_tag| {
        try std.testing.expectEqual(orig_tag.len, parsed_tag.len);
        for (orig_tag, parsed_tag) |orig_item, parsed_item| {
            try std.testing.expectEqualStrings(orig_item, parsed_item);
        }
    }
}