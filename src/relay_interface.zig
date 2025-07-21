const std = @import("std");
const nostr = @import("nostr.zig");

/// Abstract interface for relay communication that can be implemented
/// differently for native vs WASM environments
pub const RelayInterface = struct {
    /// Function pointers for implementation
    const VTable = struct {
        publishEvent: *const fn (ctx: *anyopaque, event: nostr.Event, callback: ?EventCallback) anyerror!void,
        subscribe: *const fn (ctx: *anyopaque, id: []const u8, filters: []const Filter, callback: ?MessageCallback) anyerror!void,
        unsubscribe: *const fn (ctx: *anyopaque, id: []const u8) anyerror!void,
        connect: *const fn (ctx: *anyopaque, url: []const u8) anyerror!void,
        disconnect: *const fn (ctx: *anyopaque) void,
        isConnected: *const fn (ctx: *anyopaque) bool,
    };

    ctx: *anyopaque,
    vtable: *const VTable,
    allocator: std.mem.Allocator,

    /// Callback types
    pub const EventCallback = *const fn (ok: bool, message: ?[]const u8) void;
    pub const MessageCallback = *const fn (message: RelayMessage) void;

    /// Relay message types (same as client.zig but without websocket dependency)
    pub const RelayMessage = union(enum) {
        event: struct {
            subscription_id: []const u8,
            event: nostr.Event,
        },
        eose: struct {
            subscription_id: []const u8,
        },
        ok: struct {
            event_id: []const u8,
            accepted: bool,
            message: ?[]const u8,
        },
        notice: []const u8,
        auth: []const u8,
        count: struct {
            subscription_id: []const u8,
            count: u64,
        },
    };

    /// Filter structure (same as client.zig)
    pub const Filter = struct {
        ids: ?[]const []const u8 = null,
        authors: ?[]const []const u8 = null,
        kinds: ?[]const u32 = null,
        since: ?i64 = null,
        until: ?i64 = null,
        limit: ?u32 = null,
        tags: ?std.StringHashMap([]const []const u8) = null,
        e: ?[]const []const u8 = null,
        p: ?[]const []const u8 = null,
        a: ?[]const []const u8 = null,
        t: ?[]const []const u8 = null,
        r: ?[]const []const u8 = null,
    };

    /// Public interface methods
    pub fn publishEvent(self: RelayInterface, event: nostr.Event, callback: ?EventCallback) !void {
        return self.vtable.publishEvent(self.ctx, event, callback);
    }

    pub fn subscribe(self: RelayInterface, id: []const u8, filters: []const Filter, callback: ?MessageCallback) !void {
        return self.vtable.subscribe(self.ctx, id, filters, callback);
    }

    pub fn unsubscribe(self: RelayInterface, id: []const u8) !void {
        return self.vtable.unsubscribe(self.ctx, id);
    }

    pub fn connect(self: RelayInterface, url: []const u8) !void {
        return self.vtable.connect(self.ctx, url);
    }

    pub fn disconnect(self: RelayInterface) void {
        self.vtable.disconnect(self.ctx);
    }

    pub fn isConnected(self: RelayInterface) bool {
        return self.vtable.isConnected(self.ctx);
    }
};

/// WASM-specific relay interface that uses extern functions
pub const WasmRelayInterface = struct {
    allocator: std.mem.Allocator,
    connected: bool = false,
    relay_url: []const u8 = "",

    /// External functions that JavaScript must provide
    extern fn wasm_relay_connect(url_ptr: [*]const u8, url_len: usize) i32;
    extern fn wasm_relay_disconnect() void;
    extern fn wasm_relay_publish(event_json_ptr: [*]const u8, event_json_len: usize, callback_id: u32) i32;
    extern fn wasm_relay_subscribe(sub_id_ptr: [*]const u8, sub_id_len: usize, filters_json_ptr: [*]const u8, filters_json_len: usize, callback_id: u32) i32;
    extern fn wasm_relay_unsubscribe(sub_id_ptr: [*]const u8, sub_id_len: usize) i32;

    /// Callback registry for WASM
    var event_callbacks: std.AutoHashMap(u32, RelayInterface.EventCallback) = undefined;
    var message_callbacks: std.AutoHashMap(u32, RelayInterface.MessageCallback) = undefined;
    var callback_counter: u32 = 0;

    pub fn init(allocator: std.mem.Allocator) WasmRelayInterface {
        event_callbacks = std.AutoHashMap(u32, RelayInterface.EventCallback).init(allocator);
        message_callbacks = std.AutoHashMap(u32, RelayInterface.MessageCallback).init(allocator);
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *WasmRelayInterface) void {
        _ = self;
        event_callbacks.deinit();
        message_callbacks.deinit();
    }

    pub fn interface(self: *WasmRelayInterface) RelayInterface {
        return .{
            .ctx = self,
            .vtable = &.{
                .publishEvent = publishEvent,
                .subscribe = subscribe,
                .unsubscribe = unsubscribe,
                .connect = connect,
                .disconnect = disconnect,
                .isConnected = isConnected,
            },
            .allocator = self.allocator,
        };
    }

    fn publishEvent(ctx: *anyopaque, event: nostr.Event, callback: ?RelayInterface.EventCallback) !void {
        const self = @as(*WasmRelayInterface, @ptrCast(@alignCast(ctx)));
        
        // Serialize event to JSON
        const event_json = try event.toJson(self.allocator);
        defer self.allocator.free(event_json);

        // Register callback if provided
        var callback_id: u32 = 0;
        if (callback) |cb| {
            callback_counter += 1;
            callback_id = callback_counter;
            try event_callbacks.put(callback_id, cb);
        }

        // Call external function
        const result = wasm_relay_publish(event_json.ptr, event_json.len, callback_id);
        if (result != 0) {
            return error.PublishFailed;
        }
    }

    fn subscribe(ctx: *anyopaque, id: []const u8, filters: []const RelayInterface.Filter, callback: ?RelayInterface.MessageCallback) !void {
        const self = @as(*WasmRelayInterface, @ptrCast(@alignCast(ctx)));
        
        // Serialize filters to JSON
        var filters_json = std.ArrayList(u8).init(self.allocator);
        defer filters_json.deinit();
        try std.json.stringify(filters, .{}, filters_json.writer());

        // Register callback if provided
        var callback_id: u32 = 0;
        if (callback) |cb| {
            callback_counter += 1;
            callback_id = callback_counter;
            try message_callbacks.put(callback_id, cb);
        }

        // Call external function
        const result = wasm_relay_subscribe(id.ptr, id.len, filters_json.items.ptr, filters_json.items.len, callback_id);
        if (result != 0) {
            return error.SubscribeFailed;
        }
    }

    fn unsubscribe(ctx: *anyopaque, id: []const u8) !void {
        _ = ctx;
        const result = wasm_relay_unsubscribe(id.ptr, id.len);
        if (result != 0) {
            return error.UnsubscribeFailed;
        }
    }

    fn connect(ctx: *anyopaque, url: []const u8) !void {
        const self = @as(*WasmRelayInterface, @ptrCast(@alignCast(ctx)));
        const result = wasm_relay_connect(url.ptr, url.len);
        if (result != 0) {
            return error.ConnectFailed;
        }
        self.connected = true;
        self.relay_url = try self.allocator.dupe(u8, url);
    }

    fn disconnect(ctx: *anyopaque) void {
        const self = @as(*WasmRelayInterface, @ptrCast(@alignCast(ctx)));
        wasm_relay_disconnect();
        self.connected = false;
        if (self.relay_url.len > 0) {
            self.allocator.free(self.relay_url);
            self.relay_url = "";
        }
    }

    fn isConnected(ctx: *anyopaque) bool {
        const self = @as(*WasmRelayInterface, @ptrCast(@alignCast(ctx)));
        return self.connected;
    }

    /// Called from JavaScript when an event callback fires
    export fn wasm_relay_event_callback(callback_id: u32, ok: bool, message_ptr: ?[*]const u8, message_len: usize) void {
        if (event_callbacks.get(callback_id)) |callback| {
            const message = if (message_ptr) |ptr| ptr[0..message_len] else null;
            callback(ok, message);
            _ = event_callbacks.remove(callback_id);
        }
    }

    /// Called from JavaScript when a message callback fires
    export fn wasm_relay_message_callback(callback_id: u32, message_json_ptr: [*]const u8, message_json_len: usize) void {
        if (message_callbacks.get(callback_id)) |callback| {
            // Parse the message JSON and convert to RelayMessage
            // This is simplified - real implementation would parse properly
            _ = message_json_ptr;
            _ = message_json_len;
            // callback(parsed_message);
        }
    }
};

/// Native relay interface that wraps the existing client.zig
pub const NativeRelayInterface = struct {
    client: @import("client.zig").Client,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, relay_url: []const u8) NativeRelayInterface {
        return .{
            .client = @import("client.zig").Client.init(allocator, relay_url),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *NativeRelayInterface) void {
        self.client.deinit();
    }

    pub fn interface(self: *NativeRelayInterface) RelayInterface {
        return .{
            .ctx = self,
            .vtable = &.{
                .publishEvent = publishEvent,
                .subscribe = subscribe,
                .unsubscribe = unsubscribe,
                .connect = connect,
                .disconnect = disconnect,
                .isConnected = isConnected,
            },
            .allocator = self.allocator,
        };
    }

    fn publishEvent(ctx: *anyopaque, event: nostr.Event, callback: ?RelayInterface.EventCallback) !void {
        const self = @as(*NativeRelayInterface, @ptrCast(@alignCast(ctx)));
        try self.client.publish_event(event, callback);
    }

    fn subscribe(ctx: *anyopaque, id: []const u8, filters: []const RelayInterface.Filter, callback: ?RelayInterface.MessageCallback) !void {
        const self = @as(*NativeRelayInterface, @ptrCast(@alignCast(ctx)));
        // Convert RelayInterface.Filter to client.Filter
        var client_filters = try self.allocator.alloc(@import("client.zig").Filter, filters.len);
        defer self.allocator.free(client_filters);
        
        for (filters, 0..) |filter, i| {
            client_filters[i] = .{
                .ids = filter.ids,
                .authors = filter.authors,
                .kinds = filter.kinds,
                .since = filter.since,
                .until = filter.until,
                .limit = filter.limit,
                .tags = filter.tags,
                .e = filter.e,
                .p = filter.p,
                .a = filter.a,
                .t = filter.t,
                .r = filter.r,
            };
        }
        
        // Wrap callback to convert message types
        const wrapped_callback = if (callback) |cb| struct {
            fn call(msg: @import("client.zig").RelayMessage) void {
                // Convert client.RelayMessage to RelayInterface.RelayMessage
                const interface_msg = switch (msg) {
                    .event => |e| RelayInterface.RelayMessage{ .event = .{
                        .subscription_id = e.subscription_id,
                        .event = e.event,
                    } },
                    .eose => |e| RelayInterface.RelayMessage{ .eose = .{
                        .subscription_id = e.subscription_id,
                    } },
                    .ok => |o| RelayInterface.RelayMessage{ .ok = .{
                        .event_id = o.event_id,
                        .accepted = o.accepted,
                        .message = o.message,
                    } },
                    .notice => |n| RelayInterface.RelayMessage{ .notice = n },
                    .auth => |a| RelayInterface.RelayMessage{ .auth = a },
                    .count => |c| RelayInterface.RelayMessage{ .count = .{
                        .subscription_id = c.subscription_id,
                        .count = c.count,
                    } },
                };
                cb(interface_msg);
            }
        }.call else null;
        
        try self.client.subscribe(id, client_filters, wrapped_callback);
    }

    fn unsubscribe(ctx: *anyopaque, id: []const u8) !void {
        const self = @as(*NativeRelayInterface, @ptrCast(@alignCast(ctx)));
        try self.client.unsubscribe(id);
    }

    fn connect(ctx: *anyopaque, url: []const u8) !void {
        const self = @as(*NativeRelayInterface, @ptrCast(@alignCast(ctx)));
        _ = url; // Already set in init
        try self.client.connect();
    }

    fn disconnect(ctx: *anyopaque) void {
        const self = @as(*NativeRelayInterface, @ptrCast(@alignCast(ctx)));
        self.client.disconnect();
    }

    fn isConnected(ctx: *anyopaque) bool {
        const self = @as(*NativeRelayInterface, @ptrCast(@alignCast(ctx)));
        return self.client.connected;
    }
};

/// Factory function to create the appropriate relay interface
pub fn createRelayInterface(allocator: std.mem.Allocator, comptime is_wasm: bool) !RelayInterface {
    if (is_wasm) {
        var wasm_interface = WasmRelayInterface.init(allocator);
        return wasm_interface.interface();
    } else {
        // For native, we need the relay URL upfront
        // This is a limitation we'll need to work around
        return error.NativeRelayNeedsUrl;
    }
}