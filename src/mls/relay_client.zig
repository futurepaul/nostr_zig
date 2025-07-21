const std = @import("std");
const nostr = @import("../nostr.zig");
const RelayInterface = @import("../relay_interface.zig").RelayInterface;

/// MLS-specific relay client that handles NIP-EE protocol requirements
pub const MLSRelayClient = struct {
    interface: RelayInterface,
    allocator: std.mem.Allocator,
    relay_urls: []const []const u8,
    connected: bool = false,

    /// Callbacks for various MLS operations
    keypackage_callbacks: std.StringHashMap(*const fn (event: nostr.Event) void),
    welcome_callbacks: std.StringHashMap(*const fn (event: nostr.Event) void),
    group_message_callbacks: std.StringHashMap(*const fn (event: nostr.Event) void),

    pub fn init(allocator: std.mem.Allocator, interface: RelayInterface, relay_urls: []const []const u8) MLSRelayClient {
        return .{
            .interface = interface,
            .allocator = allocator,
            .relay_urls = relay_urls,
            .keypackage_callbacks = std.StringHashMap(*const fn (event: nostr.Event) void).init(allocator),
            .welcome_callbacks = std.StringHashMap(*const fn (event: nostr.Event) void).init(allocator),
            .group_message_callbacks = std.StringHashMap(*const fn (event: nostr.Event) void).init(allocator),
        };
    }

    pub fn deinit(self: *MLSRelayClient) void {
        self.keypackage_callbacks.deinit();
        self.welcome_callbacks.deinit();
        self.group_message_callbacks.deinit();
        if (self.connected) {
            self.interface.disconnect();
        }
    }

    /// Connect to all configured relays
    pub fn connect(self: *MLSRelayClient) !void {
        // For now, connect to the first relay
        // TODO: Support multiple relays
        if (self.relay_urls.len > 0) {
            try self.interface.connect(self.relay_urls[0]);
            self.connected = true;
        }
    }

    /// Disconnect from all relays
    pub fn disconnect(self: *MLSRelayClient) void {
        self.interface.disconnect();
        self.connected = false;
    }

    /// Publish a KeyPackage event (kind 443)
    pub fn publishKeyPackage(self: *MLSRelayClient, event: nostr.Event, callback: ?*const fn (ok: bool, message: ?[]const u8) void) !void {
        if (!self.connected) {
            try self.connect();
        }
        
        // Verify it's a KeyPackage event
        if (event.kind != 443) {
            return error.InvalidEventKind;
        }
        
        try self.interface.publishEvent(event, callback);
    }

    /// Publish a KeyPackage relay list event (kind 10051)
    pub fn publishKeyPackageRelayList(self: *MLSRelayClient, event: nostr.Event, callback: ?*const fn (ok: bool, message: ?[]const u8) void) !void {
        if (!self.connected) {
            try self.connect();
        }
        
        // Verify it's a KeyPackage relay list event
        if (event.kind != 10051) {
            return error.InvalidEventKind;
        }
        
        try self.interface.publishEvent(event, callback);
    }

    /// Publish a Welcome event (kind 10050)
    pub fn publishWelcome(self: *MLSRelayClient, event: nostr.Event, callback: ?*const fn (ok: bool, message: ?[]const u8) void) !void {
        if (!self.connected) {
            try self.connect();
        }
        
        // Verify it's a Welcome event
        if (event.kind != 10050) {
            return error.InvalidEventKind;
        }
        
        try self.interface.publishEvent(event, callback);
    }

    /// Publish a Group Message event (kind 445)
    pub fn publishGroupMessage(self: *MLSRelayClient, event: nostr.Event, callback: ?*const fn (ok: bool, message: ?[]const u8) void) !void {
        if (!self.connected) {
            try self.connect();
        }
        
        // Verify it's a Group Message event
        if (event.kind != 445) {
            return error.InvalidEventKind;
        }
        
        try self.interface.publishEvent(event, callback);
    }

    /// Subscribe to KeyPackages for a specific public key
    pub fn subscribeToKeyPackages(self: *MLSRelayClient, pubkey: []const u8, callback: *const fn (event: nostr.Event) void) !void {
        if (!self.connected) {
            try self.connect();
        }
        
        const sub_id = try std.fmt.allocPrint(self.allocator, "kp_{s}", .{pubkey[0..8]});
        defer self.allocator.free(sub_id);
        
        // Store callback
        try self.keypackage_callbacks.put(sub_id, callback);
        
        // Create filter for KeyPackage events from this pubkey
        const filters = [_]RelayInterface.Filter{.{
            .authors = &[_][]const u8{pubkey},
            .kinds = &[_]u32{443}, // KeyPackage events
        }};
        
        // Subscribe with message handler
        try self.interface.subscribe(sub_id, &filters, struct {
            fn handleMessage(msg: RelayInterface.RelayMessage) void {
                switch (msg) {
                    .event => |e| {
                        // Find and call the callback
                        if (self.keypackage_callbacks.get(e.subscription_id)) |cb| {
                            cb(e.event);
                        }
                    },
                    else => {},
                }
            }
        }.handleMessage);
    }

    /// Subscribe to Welcome events for a specific public key
    pub fn subscribeToWelcomes(self: *MLSRelayClient, pubkey: []const u8, callback: *const fn (event: nostr.Event) void) !void {
        if (!self.connected) {
            try self.connect();
        }
        
        const sub_id = try std.fmt.allocPrint(self.allocator, "welcome_{s}", .{pubkey[0..8]});
        defer self.allocator.free(sub_id);
        
        // Store callback
        try self.welcome_callbacks.put(sub_id, callback);
        
        // Create filter for Welcome events to this pubkey
        const filters = [_]RelayInterface.Filter{.{
            .kinds = &[_]u32{10050}, // Welcome events
            .p = &[_][]const u8{pubkey}, // Tagged with this pubkey
        }};
        
        // Subscribe with message handler
        try self.interface.subscribe(sub_id, &filters, struct {
            fn handleMessage(msg: RelayInterface.RelayMessage) void {
                switch (msg) {
                    .event => |e| {
                        // Find and call the callback
                        if (self.welcome_callbacks.get(e.subscription_id)) |cb| {
                            cb(e.event);
                        }
                    },
                    else => {},
                }
            }
        }.handleMessage);
    }

    /// Subscribe to Group Messages for a specific group
    pub fn subscribeToGroupMessages(self: *MLSRelayClient, group_id: []const u8, callback: *const fn (event: nostr.Event) void) !void {
        if (!self.connected) {
            try self.connect();
        }
        
        const sub_id = try std.fmt.allocPrint(self.allocator, "gm_{s}", .{std.fmt.fmtSliceHexLower(group_id[0..8])});
        defer self.allocator.free(sub_id);
        
        // Store callback
        try self.group_message_callbacks.put(sub_id, callback);
        
        // Create filter for Group Message events with this group ID
        const filters = [_]RelayInterface.Filter{.{
            .kinds = &[_]u32{445}, // Group Message events
            // TODO: Add support for filtering by 'h' tag (group ID)
            // For now, we'll filter client-side
        }};
        
        // Subscribe with message handler
        try self.interface.subscribe(sub_id, &filters, struct {
            fn handleMessage(msg: RelayInterface.RelayMessage) void {
                switch (msg) {
                    .event => |e| {
                        // Check if event has the correct group ID in 'h' tag
                        for (e.event.tags) |tag| {
                            if (tag.len >= 2 and std.mem.eql(u8, tag[0], "h")) {
                                if (std.mem.eql(u8, tag[1], std.fmt.fmtSliceHexLower(group_id))) {
                                    // Find and call the callback
                                    if (self.group_message_callbacks.get(e.subscription_id)) |cb| {
                                        cb(e.event);
                                    }
                                }
                            }
                        }
                    },
                    else => {},
                }
            }
        }.handleMessage);
    }

    /// Wait for event confirmation with timeout
    pub fn waitForConfirmation(self: *MLSRelayClient, event_id: []const u8, timeout_ms: u64) !bool {
        _ = self;
        _ = event_id;
        _ = timeout_ms;
        // TODO: Implement proper confirmation waiting
        // For now, assume success
        return true;
    }

    /// Publish event to multiple relays and wait for confirmations
    pub fn publishToMultipleRelays(self: *MLSRelayClient, event: nostr.Event, min_confirmations: usize) !usize {
        var confirmations: usize = 0;
        var last_error: ?[]const u8 = null;
        
        // Callback to track confirmations
        const callback = struct {
            fn onResponse(ok: bool, message: ?[]const u8) void {
                if (ok) {
                    confirmations += 1;
                } else if (message) |msg| {
                    last_error = msg;
                }
            }
        }.onResponse;
        
        // Publish to all relays
        try self.interface.publishEvent(event, callback);
        
        // Wait for confirmations (simplified - real implementation would use proper async)
        // TODO: Implement proper async waiting
        
        if (confirmations < min_confirmations) {
            if (last_error) |err| {
                std.log.err("Relay error: {s}", .{err});
            }
            return error.InsufficientConfirmations;
        }
        
        return confirmations;
    }

    /// Fetch KeyPackages from discovery relays
    pub fn fetchKeyPackagesFromDiscovery(self: *MLSRelayClient, pubkey: []const u8) ![]nostr.Event {
        // First, fetch the KeyPackage relay list (kind 10051)
        const relay_list_filter = [_]RelayInterface.Filter{.{
            .authors = &[_][]const u8{pubkey},
            .kinds = &[_]u32{10051},
            .limit = 1,
        }};
        
        var relay_list_event: ?nostr.Event = null;
        
        try self.interface.subscribe("relay_list_temp", &relay_list_filter, struct {
            fn handleMessage(msg: RelayInterface.RelayMessage) void {
                switch (msg) {
                    .event => |e| {
                        relay_list_event = e.event;
                    },
                    else => {},
                }
            }
        }.handleMessage);
        
        // Wait for relay list (simplified - real implementation would use proper async)
        // TODO: Implement proper async waiting
        
        // Extract relay URIs from the event tags
        if (relay_list_event) |event| {
            var relay_uris = std.ArrayList([]const u8).init(self.allocator);
            defer relay_uris.deinit();
            
            for (event.tags) |tag| {
                if (tag.len >= 2 and std.mem.eql(u8, tag[0], "r")) {
                    try relay_uris.append(tag[1]);
                }
            }
            
            // TODO: Connect to discovered relays and fetch KeyPackages
            // For now, return empty array
            return &[_]nostr.Event{};
        }
        
        return &[_]nostr.Event{};
    }
};