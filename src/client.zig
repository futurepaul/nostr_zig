const std = @import("std");
const websocket = @import("websocket");
const nostr = @import("nostr.zig");

const log = std.log.scoped(.nostr_client);

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

pub const Filter = struct {
    ids: ?[]const []const u8 = null,
    authors: ?[]const []const u8 = null,
    kinds: ?[]const u32 = null,
    since: ?i64 = null,
    until: ?i64 = null,
    limit: ?u32 = null,
    tags: ?std.StringHashMap([]const []const u8) = null,

    // Common tag filters
    e: ?[]const []const u8 = null, // event references
    p: ?[]const []const u8 = null, // pubkey references
    a: ?[]const []const u8 = null, // parameterized replaceable event references
    t: ?[]const []const u8 = null, // hashtags
    r: ?[]const []const u8 = null, // relay references
};

pub const Subscription = struct {
    id: []const u8,
    filters: []const Filter,
    callback: ?*const fn (message: RelayMessage) void = null,
};

pub const Client = struct {
    allocator: std.mem.Allocator,
    ws_client: ?websocket.Client = null,
    relay_url: []const u8,
    subscriptions: std.StringHashMap(Subscription),
    event_callbacks: std.StringHashMap(*const fn (ok: bool, message: ?[]const u8) void),
    connected: bool = false,

    pub fn init(allocator: std.mem.Allocator, relay_url: []const u8) Client {
        return .{
            .allocator = allocator,
            .relay_url = relay_url,
            .subscriptions = std.StringHashMap(Subscription).init(allocator),
            .event_callbacks = std.StringHashMap(*const fn (ok: bool, message: ?[]const u8) void).init(allocator),
        };
    }

    pub fn deinit(self: *Client) void {
        if (self.ws_client) |*client| {
            client.deinit();
        }
        self.subscriptions.deinit();
        self.event_callbacks.deinit();
    }

    pub fn connect(self: *Client) !void {
        log.info("Connecting to relay: {s}", .{self.relay_url});
        
        // Parse the relay URL to extract host and port
        const url = try std.Uri.parse(self.relay_url);
        const host = switch (url.host.?) {
            .raw => |h| h,
            .percent_encoded => |h| h,
        };
        const default_port: u16 = if (std.mem.eql(u8, url.scheme, "wss")) 443 else 80;
        const port = url.port orelse default_port;
        const path = switch (url.path) {
            .raw => |p| if (p.len == 0) "/" else p,
            .percent_encoded => |p| if (p.len == 0) "/" else p,
        };
        
        log.debug("Parsed URL - host: {s}, port: {}, path: {s}", .{ host, port, path });
        
        // Create websocket client
        self.ws_client = try websocket.Client.init(self.allocator, .{
            .host = host,
            .port = port,
            .tls = std.mem.eql(u8, url.scheme, "wss"),
        });
        
        // Perform websocket handshake with Host header
        var headers_buf: [256]u8 = undefined;
        const headers = try std.fmt.bufPrint(&headers_buf, "Host: {s}:{}\r\n", .{ host, port });
        try self.ws_client.?.handshake(path, .{ .headers = headers });
        
        self.connected = true;
        log.info("Connected to relay", .{});
    }

    pub fn disconnect(self: *Client) void {
        if (self.ws_client) |*client| {
            client.close(.{}) catch |err| {
                log.err("Error closing websocket: {}", .{err});
            };
            client.deinit();
            self.ws_client = null;
            self.connected = false;
        }
    }

    pub fn publish_event(self: *Client, event: nostr.Event, callback: ?*const fn (ok: bool, message: ?[]const u8) void) !void {
        if (!self.connected or self.ws_client == null) {
            return error.NotConnected;
        }

        // Serialize event
        var event_json = std.ArrayList(u8).init(self.allocator);
        defer event_json.deinit();
        try std.json.stringify(event, .{}, event_json.writer());

        // Create EVENT message: ["EVENT", <event>]
        var message = std.ArrayList(u8).init(self.allocator);
        defer message.deinit();
        
        try message.appendSlice("[\"EVENT\",");
        try message.appendSlice(event_json.items);
        try message.append(']');

        log.debug("Publishing event: {s}", .{message.items});

        // Store callback if provided
        if (callback) |cb| {
            try self.event_callbacks.put(event.id, cb);
        }

        // Send message
        try self.ws_client.?.writeText(message.items);
    }

    pub fn subscribe(self: *Client, subscription_id: []const u8, filters: []const Filter, callback: ?*const fn (message: RelayMessage) void) !void {
        if (!self.connected or self.ws_client == null) {
            return error.NotConnected;
        }

        // Create subscription
        const sub = Subscription{
            .id = subscription_id,
            .filters = filters,
            .callback = callback,
        };
        try self.subscriptions.put(subscription_id, sub);

        // Create REQ message: ["REQ", <subscription_id>, <filter1>, <filter2>, ...]
        var message = std.ArrayList(u8).init(self.allocator);
        defer message.deinit();
        
        try message.appendSlice("[\"REQ\",\"");
        try message.appendSlice(subscription_id);
        try message.append('"');

        for (filters) |filter| {
            try message.append(',');
            try self.serializeFilter(&message, filter);
        }
        
        try message.append(']');

        log.debug("Subscribing with: {s}", .{message.items});

        // Send message
        try self.ws_client.?.writeText(message.items);
    }

    pub fn unsubscribe(self: *Client, subscription_id: []const u8) !void {
        if (!self.connected or self.ws_client == null) {
            return error.NotConnected;
        }

        // Remove subscription
        _ = self.subscriptions.remove(subscription_id);

        // Create CLOSE message: ["CLOSE", <subscription_id>]
        var message = std.ArrayList(u8).init(self.allocator);
        defer message.deinit();
        
        try message.appendSlice("[\"CLOSE\",\"");
        try message.appendSlice(subscription_id);
        try message.appendSlice("\"]");

        log.debug("Unsubscribing: {s}", .{message.items});

        // Send message
        try self.ws_client.?.writeText(message.items);
    }

    pub fn process_messages(self: *Client) !void {
        if (!self.connected or self.ws_client == null) {
            return error.NotConnected;
        }

        const msg = try self.ws_client.?.read() orelse return error.WouldBlock;
        defer self.ws_client.?.done(msg);
        
        switch (msg.type) {
            .text => {
                try self.handleMessage(msg.data);
            },
            .binary => {
                log.warn("Received unexpected binary message", .{});
            },
            .close => {
                log.info("Relay closed connection", .{});
                self.connected = false;
            },
            else => {},
        }
    }

    fn handleMessage(self: *Client, data: []const u8) !void {
        log.debug("Received message: {s}", .{data});

        const parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, data, .{});
        defer parsed.deinit();

        const array = parsed.value.array;
        if (array.items.len < 2) {
            log.warn("Invalid message format", .{});
            return;
        }

        const msg_type = array.items[0].string;
        
        if (std.mem.eql(u8, msg_type, "EVENT")) {
            if (array.items.len < 3) return;
            
            const sub_id = array.items[1].string;
            // Parse event from array.items[2]
            // TODO: Implement event parsing
            
            if (self.subscriptions.get(sub_id)) |sub| {
                if (sub.callback) |_| {
                    // TODO: Parse event and call callback
                    // cb(RelayMessage{ .event = ... });
                }
            }
        } else if (std.mem.eql(u8, msg_type, "OK")) {
            if (array.items.len < 4) return;
            
            const event_id = array.items[1].string;
            const accepted = array.items[2].bool;
            const message = if (array.items.len > 3) array.items[3].string else null;
            
            if (self.event_callbacks.get(event_id)) |cb| {
                cb(accepted, message);
                _ = self.event_callbacks.remove(event_id);
            }
        } else if (std.mem.eql(u8, msg_type, "EOSE")) {
            if (array.items.len < 2) return;
            
            const sub_id = array.items[1].string;
            if (self.subscriptions.get(sub_id)) |sub| {
                if (sub.callback) |cb| {
                    cb(RelayMessage{ .eose = .{ .subscription_id = sub_id } });
                }
            }
        } else if (std.mem.eql(u8, msg_type, "NOTICE")) {
            if (array.items.len < 2) return;
            log.info("NOTICE from relay: {s}", .{array.items[1].string});
        }
    }

    fn serializeFilter(_: *Client, writer: *std.ArrayList(u8), filter: Filter) !void {
        try writer.append('{');
        
        var first = true;
        
        if (filter.ids) |ids| {
            try writer.appendSlice("\"ids\":[");
            for (ids, 0..) |id, i| {
                if (i > 0) try writer.append(',');
                try writer.append('"');
                try writer.appendSlice(id);
                try writer.append('"');
            }
            try writer.append(']');
            first = false;
        }
        
        if (filter.authors) |authors| {
            if (!first) try writer.append(',');
            try writer.appendSlice("\"authors\":[");
            for (authors, 0..) |author, i| {
                if (i > 0) try writer.append(',');
                try writer.append('"');
                try writer.appendSlice(author);
                try writer.append('"');
            }
            try writer.append(']');
            first = false;
        }
        
        if (filter.kinds) |kinds| {
            if (!first) try writer.append(',');
            try writer.appendSlice("\"kinds\":[");
            for (kinds, 0..) |kind, i| {
                if (i > 0) try writer.append(',');
                try std.fmt.format(writer.writer(), "{}", .{kind});
            }
            try writer.append(']');
            first = false;
        }
        
        if (filter.since) |since| {
            if (!first) try writer.append(',');
            try std.fmt.format(writer.writer(), "\"since\":{}", .{since});
            first = false;
        }
        
        if (filter.until) |until| {
            if (!first) try writer.append(',');
            try std.fmt.format(writer.writer(), "\"until\":{}", .{until});
            first = false;
        }
        
        if (filter.limit) |limit| {
            if (!first) try writer.append(',');
            try std.fmt.format(writer.writer(), "\"limit\":{}", .{limit});
            first = false;
        }
        
        // Tag filters
        if (filter.e) |e_tags| {
            if (!first) try writer.append(',');
            try writer.appendSlice("\"#e\":[");
            for (e_tags, 0..) |tag, i| {
                if (i > 0) try writer.append(',');
                try writer.append('"');
                try writer.appendSlice(tag);
                try writer.append('"');
            }
            try writer.append(']');
            first = false;
        }
        
        if (filter.p) |p_tags| {
            if (!first) try writer.append(',');
            try writer.appendSlice("\"#p\":[");
            for (p_tags, 0..) |tag, i| {
                if (i > 0) try writer.append(',');
                try writer.append('"');
                try writer.appendSlice(tag);
                try writer.append('"');
            }
            try writer.append(']');
            first = false;
        }
        
        try writer.append('}');
    }
};