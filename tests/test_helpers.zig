const std = @import("std");

/// Simple arena-based test context for consistent memory management
pub const TestArena = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    
    pub fn init(allocator: std.mem.Allocator) TestArena {
        return .{
            .allocator = allocator,
            .arena = std.heap.ArenaAllocator.init(allocator),
        };
    }
    
    pub fn deinit(self: *TestArena) void {
        self.arena.deinit();
    }
    
    pub fn arenaAllocator(self: *TestArena) std.mem.Allocator {
        return self.arena.allocator();
    }
    
    pub fn reset(self: *TestArena) void {
        _ = self.arena.reset(.retain_capacity);
    }
};

/// Helper to create tags with arena allocation
pub fn createTags(arena: std.mem.Allocator, comptime N: usize) ![][]const []const u8 {
    return try arena.alloc([]const []const u8, N);
}

/// Helper to create a single tag
pub fn createTag(arena: std.mem.Allocator, values: []const []const u8) ![]const []const u8 {
    const tag = try arena.alloc([]const u8, values.len);
    for (values, 0..) |value, i| {
        tag[i] = try arena.dupe(u8, value);
    }
    return tag;
}