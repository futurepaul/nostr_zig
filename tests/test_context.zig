const std = @import("std");

/// Standardized test context for consistent memory management across all tests
/// This pattern consolidates allocations and uses arena allocators for temporary operations
pub const TestContext = struct {
    /// Main allocator for test-lifetime allocations
    allocator: std.mem.Allocator,
    
    /// Arena allocator for temporary allocations that get cleaned up together
    arena: std.heap.ArenaAllocator,
    
    /// Pre-allocated buffers for common operations
    hex_buffer: []u8,
    json_buffer: []u8,
    message_buffer: []u8,
    
    /// Configuration
    const HEX_BUFFER_SIZE = 4096;
    const JSON_BUFFER_SIZE = 16384;
    const MESSAGE_BUFFER_SIZE = 8192;
    
    pub fn init(allocator: std.mem.Allocator) !TestContext {
        var ctx = TestContext{
            .allocator = allocator,
            .arena = std.heap.ArenaAllocator.init(allocator),
            .hex_buffer = undefined,
            .json_buffer = undefined,
            .message_buffer = undefined,
        };
        
        // Pre-allocate common buffers
        ctx.hex_buffer = try allocator.alloc(u8, HEX_BUFFER_SIZE);
        ctx.json_buffer = try allocator.alloc(u8, JSON_BUFFER_SIZE);
        ctx.message_buffer = try allocator.alloc(u8, MESSAGE_BUFFER_SIZE);
        
        return ctx;
    }
    
    pub fn deinit(self: *TestContext) void {
        self.allocator.free(self.hex_buffer);
        self.allocator.free(self.json_buffer);
        self.allocator.free(self.message_buffer);
        self.arena.deinit();
    }
    
    /// Get the arena allocator for temporary allocations
    pub fn arenaAllocator(self: *TestContext) std.mem.Allocator {
        return self.arena.allocator();
    }
    
    /// Reset the arena allocator, freeing all temporary allocations
    pub fn resetArena(self: *TestContext) void {
        _ = self.arena.reset(.retain_capacity);
    }
    
    /// Create a tag array using arena allocation
    pub fn createTags(self: *TestContext, comptime N: usize) ![][]const []const u8 {
        const arena = self.arenaAllocator();
        const tags = try arena.alloc([]const []const u8, N);
        return tags;
    }
    
    /// Create a tag with arena allocation
    pub fn createTag(self: *TestContext, values: []const []const u8) ![]const []const u8 {
        const arena = self.arenaAllocator();
        const tag = try arena.alloc([]const u8, values.len);
        for (values, 0..) |value, i| {
            tag[i] = try arena.dupe(u8, value);
        }
        return tag;
    }
    
    /// Allocate string in arena
    pub fn dupeString(self: *TestContext, str: []const u8) ![]const u8 {
        return try self.arenaAllocator().dupe(u8, str);
    }
    
    /// Format and allocate string in arena
    pub fn formatString(self: *TestContext, comptime fmt: []const u8, args: anytype) ![]const u8 {
        return try std.fmt.allocPrint(self.arenaAllocator(), fmt, args);
    }
};

/// Helper for WebSocket operations with pooled buffers
pub const WebSocketContext = struct {
    ctx: *TestContext,
    read_buffer: []u8,
    write_buffer: []u8,
    
    const BUFFER_SIZE = 4096;
    
    pub fn init(ctx: *TestContext) !WebSocketContext {
        return WebSocketContext{
            .ctx = ctx,
            .read_buffer = try ctx.allocator.alloc(u8, BUFFER_SIZE),
            .write_buffer = try ctx.allocator.alloc(u8, BUFFER_SIZE),
        };
    }
    
    pub fn deinit(self: *WebSocketContext) void {
        self.ctx.allocator.free(self.read_buffer);
        self.ctx.allocator.free(self.write_buffer);
    }
};

/// Helper for MLS operations with arena allocation
pub const MLSContext = struct {
    ctx: *TestContext,
    mls_arena: std.heap.ArenaAllocator,
    
    pub fn init(ctx: *TestContext) MLSContext {
        return MLSContext{
            .ctx = ctx,
            .mls_arena = std.heap.ArenaAllocator.init(ctx.allocator),
        };
    }
    
    pub fn deinit(self: *MLSContext) void {
        self.mls_arena.deinit();
    }
    
    pub fn allocator(self: *MLSContext) std.mem.Allocator {
        return self.mls_arena.allocator();
    }
};

/// Test resource bundle for pre-allocating all test resources
pub const TestResources = struct {
    ctx: *TestContext,
    
    // Add specific resources based on test needs
    // This is a template that tests can extend
    
    pub fn init(ctx: *TestContext) !TestResources {
        return TestResources{
            .ctx = ctx,
        };
    }
    
    pub fn deinit(self: *TestResources) void {
        _ = self;
        // Cleanup any allocated resources
    }
};