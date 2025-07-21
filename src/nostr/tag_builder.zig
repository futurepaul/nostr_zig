const std = @import("std");
const Allocator = std.mem.Allocator;

/// A builder for creating Nostr event tags with safe memory management
/// Uses a single allocation strategy to minimize memory fragmentation and simplify cleanup
pub const TagBuilder = struct {
    allocator: Allocator,
    tags: std.ArrayList([]const []const u8),
    /// Owns all the string data for tags
    string_arena: std.heap.ArenaAllocator,
    
    pub fn init(allocator: Allocator) TagBuilder {
        return .{
            .allocator = allocator,
            .tags = std.ArrayList([]const []const u8).init(allocator),
            .string_arena = std.heap.ArenaAllocator.init(allocator),
        };
    }
    
    pub fn deinit(self: *TagBuilder) void {
        // Free the tag arrays
        for (self.tags.items) |tag| {
            self.allocator.free(tag);
        }
        self.tags.deinit();
        // Arena automatically frees all strings
        self.string_arena.deinit();
    }
    
    /// Add a tag with any number of values
    pub fn add(self: *TagBuilder, values: []const []const u8) !void {
        const arena = self.string_arena.allocator();
        
        // Allocate array for this tag
        const tag = try self.allocator.alloc([]const u8, values.len);
        errdefer self.allocator.free(tag);
        
        // Copy all values using arena allocator
        for (values, 0..) |value, i| {
            tag[i] = try arena.dupe(u8, value);
        }
        
        try self.tags.append(tag);
    }
    
    /// Convenience method for common 2-value tags
    pub fn addPair(self: *TagBuilder, key: []const u8, value: []const u8) !void {
        try self.add(&.{ key, value });
    }
    
    /// Convenience method for common 3-value tags
    pub fn addTriple(self: *TagBuilder, key: []const u8, value1: []const u8, value2: []const u8) !void {
        try self.add(&.{ key, value1, value2 });
    }
    
    /// Add an "e" (event) tag
    pub fn addEventTag(self: *TagBuilder, event_id: []const u8) !void {
        try self.addPair("e", event_id);
    }
    
    /// Add a "p" (pubkey) tag
    pub fn addPubkeyTag(self: *TagBuilder, pubkey: []const u8) !void {
        try self.addPair("p", pubkey);
    }
    
    /// Add an "r" (relay) tag
    pub fn addRelayTag(self: *TagBuilder, relay_url: []const u8) !void {
        try self.addPair("r", relay_url);
    }
    
    /// Add a "subject" tag
    pub fn addSubjectTag(self: *TagBuilder, subject: []const u8) !void {
        try self.addPair("subject", subject);
    }
    
    /// Build the final tag array, transferring ownership to the caller
    /// After calling this, the TagBuilder should not be used again
    pub fn build(self: *TagBuilder) ![]const []const []const u8 {
        return try self.tags.toOwnedSlice();
    }
    
    /// Build but also transfer string ownership
    /// Returns both the tags and the arena - caller must manage both
    pub fn buildWithArena(self: *TagBuilder) !struct {
        tags: []const []const []const u8,
        arena: std.heap.ArenaAllocator,
    } {
        return .{
            .tags = try self.tags.toOwnedSlice(),
            .arena = self.string_arena, // Transfer ownership
        };
    }
};

/// Alternative: Simple batch creator that consolidates allocations
pub fn createTagBatch(allocator: Allocator, tags_data: []const []const []const u8) ![]const []const []const u8 {
    // Create outer array
    const tags = try allocator.alloc([]const []const u8, tags_data.len);
    errdefer allocator.free(tags);
    
    // Use arena for all string allocations
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const arena_alloc = arena.allocator();
    
    // Copy each tag
    for (tags_data, 0..) |tag_data, i| {
        const tag = try allocator.alloc([]const u8, tag_data.len);
        errdefer allocator.free(tag);
        
        for (tag_data, 0..) |value, j| {
            tag[j] = try arena_alloc.dupe(u8, value);
        }
        tags[i] = tag;
    }
    
    // Transfer arena ownership by leaking it - caller must manage cleanup
    _ = arena.reset(.{ .retain_with_limit = 0 });
    
    return tags;
}

/// Free a tag batch created with createTagBatch
pub fn freeTagBatch(allocator: Allocator, tags: []const []const []const u8) void {
    // First free all the string data
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    
    // Free tag arrays
    for (tags) |tag| {
        allocator.free(tag);
    }
    allocator.free(tags);
}

test "TagBuilder basic usage" {
    const allocator = std.testing.allocator;
    
    var builder = TagBuilder.init(allocator);
    defer builder.deinit();
    
    try builder.addEventTag("event123");
    try builder.addPubkeyTag("pubkey456");
    try builder.addRelayTag("wss://relay.example.com");
    try builder.add(&.{ "custom", "tag", "with", "multiple", "values" });
    
    const tags = try builder.build();
    defer allocator.free(tags);
    
    try std.testing.expectEqual(@as(usize, 4), tags.len);
    try std.testing.expectEqualStrings("e", tags[0][0]);
    try std.testing.expectEqualStrings("event123", tags[0][1]);
    try std.testing.expectEqualStrings("p", tags[1][0]);
    try std.testing.expectEqualStrings("pubkey456", tags[1][1]);
}

test "createTagBatch" {
    const allocator = std.testing.allocator;
    
    const test_tags = [_][]const []const u8{
        &[_][]const u8{ "e", "event123" },
        &[_][]const u8{ "p", "pubkey456" },
        &[_][]const u8{ "r", "wss://relay.example.com" },
    };
    
    const tags = try createTagBatch(allocator, &test_tags);
    defer freeTagBatch(allocator, tags);
    
    try std.testing.expectEqual(@as(usize, 3), tags.len);
    try std.testing.expectEqualStrings("e", tags[0][0]);
    try std.testing.expectEqualStrings("event123", tags[0][1]);
}