const std = @import("std");
const Allocator = std.mem.Allocator;

/// A builder for creating Nostr event tags with arena-based memory management
/// Arena approach is more efficient and cleaner than individual allocations
pub const TagBuilder = struct {
    allocator: Allocator,
    tags: std.ArrayList([]const []const u8),
    /// Owns all the string data for tags (null if transferred)
    string_arena: ?std.heap.ArenaAllocator,
    
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
        // Arena automatically frees all strings (if not transferred)
        if (self.string_arena) |*arena| {
            arena.deinit();
        }
    }
    
    /// Add a tag with any number of values
    pub fn add(self: *TagBuilder, values: []const []const u8) !void {
        if (self.string_arena) |*arena| {
            const arena_alloc = arena.allocator();
            
            // Allocate array for this tag
            const tag = try self.allocator.alloc([]const u8, values.len);
            errdefer self.allocator.free(tag);
            
            // Copy all values using arena allocator
            for (values, 0..) |value, i| {
                tag[i] = try arena_alloc.dupe(u8, value);
            }
            
            try self.tags.append(tag);
        } else {
            return error.ArenaTransferred;
        }
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
    
    /// Build the final tag array, converting arena strings to individual allocations
    /// This is compatible with Event.deinit() which expects individual string ownership
    pub fn build(self: *TagBuilder) ![]const []const []const u8 {
        const tags = try self.tags.toOwnedSlice();
        
        // Convert arena-allocated strings to individually allocated strings
        for (tags) |tag| {
            const mutable_tag = @constCast(tag);
            for (tag, 0..) |arena_string, i| {
                // Duplicate the arena string with main allocator
                mutable_tag[i] = try self.allocator.dupe(u8, arena_string);
            }
        }
        
        return tags;
    }
    
    /// Build and transfer arena ownership to caller
    /// Returns both the tags and the arena - caller must manage both
    const BuildResult = struct {
        tags: []const []const []const u8,
        arena: std.heap.ArenaAllocator,
    };
    
    pub fn buildWithArena(self: *TagBuilder) !BuildResult {
        if (self.string_arena) |arena| {
            const result = BuildResult{
                .tags = try self.tags.toOwnedSlice(),
                .arena = arena, // Transfer ownership
            };
            self.string_arena = null; // Ownership transferred
            return result;
        } else {
            return error.ArenaAlreadyTransferred;
        }
    }
};

/// Alternative: Simple batch creator with arena for strings  
pub fn createTagBatch(allocator: Allocator, tags_data: []const []const []const u8) !struct {
    tags: []const []const []const u8,
    arena: std.heap.ArenaAllocator,
} {
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
    
    return .{
        .tags = tags,
        .arena = arena, // Transfer ownership
    };
}

/// Free tags created with TagBuilder.build() (individual allocations)
pub fn freeBuiltTags(allocator: Allocator, tags: []const []const []const u8) void {
    // Free individual strings and tag arrays
    for (tags) |tag| {
        for (tag) |tag_str| {
            allocator.free(tag_str);
        }
        allocator.free(tag);
    }
    allocator.free(tags);
}

/// Free a tag batch and arena created with createTagBatch
pub fn freeTagBatchWithArena(allocator: Allocator, tags: []const []const []const u8, arena: *std.heap.ArenaAllocator) void {
    // Free tag arrays
    for (tags) |tag| {
        allocator.free(tag);
    }
    allocator.free(tags);
    // Free arena (which contains all strings)
    arena.deinit();
}

test "TagBuilder basic usage" {
    const allocator = std.testing.allocator;
    
    var builder = TagBuilder.init(allocator);
    defer builder.deinit();
    
    try builder.addEventTag("event123");
    try builder.addPubkeyTag("pubkey456");
    try builder.addRelayTag("wss://relay.example.com");
    try builder.add(&.{ "custom", "tag", "with", "multiple", "values" });
    
    var result = try builder.buildWithArena();
    defer freeTagBatchWithArena(allocator, result.tags, &result.arena);
    
    try std.testing.expectEqual(@as(usize, 4), result.tags.len);
    try std.testing.expectEqualStrings("e", result.tags[0][0]);
    try std.testing.expectEqualStrings("event123", result.tags[0][1]);
    try std.testing.expectEqualStrings("p", result.tags[1][0]);
    try std.testing.expectEqualStrings("pubkey456", result.tags[1][1]);
}

test "createTagBatch" {
    const allocator = std.testing.allocator;
    
    const test_tags = [_][]const []const u8{
        &[_][]const u8{ "e", "event123" },
        &[_][]const u8{ "p", "pubkey456" },
        &[_][]const u8{ "r", "wss://relay.example.com" },
    };
    
    var result = try createTagBatch(allocator, &test_tags);
    defer freeTagBatchWithArena(allocator, result.tags, &result.arena);
    
    try std.testing.expectEqual(@as(usize, 3), result.tags.len);
    try std.testing.expectEqualStrings("e", result.tags[0][0]);
    try std.testing.expectEqualStrings("event123", result.tags[0][1]);
}