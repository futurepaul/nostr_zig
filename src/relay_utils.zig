const std = @import("std");
const nostr = @import("nostr.zig"); 
const client = @import("client.zig");

const log = std.log.scoped(.relay_utils);

/// Result of fetching events from a relay
pub const FetchResult = struct {
    events: []nostr.Event,
    allocator: std.mem.Allocator,
    
    pub fn deinit(self: *FetchResult) void {
        for (self.events) |*event| {
            event.deinit(self.allocator);
        }
        self.allocator.free(self.events);
    }
};

/// Context for collecting events during subscription
pub const CollectorContext = struct {
    mutex: std.Thread.Mutex = .{},
    events: std.ArrayList(nostr.Event),
    allocator: std.mem.Allocator,
    eose_received: bool = false,
    filter: ?FilterMatch = null,
    
    pub const FilterMatch = struct {
        event_id: ?[]const u8 = null,
        author: ?[]const u8 = null,
        kind: ?u32 = null,
    };
    
    pub fn init(allocator: std.mem.Allocator) CollectorContext {
        return .{
            .events = std.ArrayList(nostr.Event).init(allocator),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *CollectorContext) void {
        // Note: We don't free the events here because ownership has been transferred
        // to FetchResult via toOwnedSlice(). Only deinit the ArrayList itself.
        self.events.deinit();
    }
    
    pub fn matches(self: *CollectorContext, event: *const nostr.Event) bool {
        if (self.filter == null) return true;
        
        const f = self.filter.?;
        if (f.event_id) |id| {
            if (!std.mem.eql(u8, event.id, id)) return false;
        }
        if (f.author) |author| {
            if (!std.mem.eql(u8, event.pubkey, author)) return false;
        }
        if (f.kind) |kind| {
            if (event.kind != kind) return false;
        }
        return true;
    }
};

// Global context for callbacks (Zig doesn't have closures)
var global_collector: *CollectorContext = undefined;

fn collector_callback(message: client.RelayMessage) void {
    global_collector.mutex.lock();
    defer global_collector.mutex.unlock();
    
    switch (message) {
        .event => |e| {
            // The client has already parsed the event and passed ownership to us
            // We must either take ownership or clean it up
            
            // Check if event matches our filter
            if (!global_collector.matches(&e.event)) {
                // Event doesn't match our filter, clean it up
                e.event.deinit(global_collector.allocator);
                return;
            }
            
            // Event matches, append it to our collection
            global_collector.events.append(e.event) catch {
                log.err("Failed to append event", .{});
                e.event.deinit(global_collector.allocator);
            };
        },
        .eose => {
            global_collector.eose_received = true;
        },
        else => {},
    }
}

/// Fetch events from a relay with the given filter
pub fn fetchEvents(
    allocator: std.mem.Allocator,
    relay_url: []const u8,
    filter: client.Filter,
    timeout_ms: u64,
) !FetchResult {
    // Create collector context
    var collector = CollectorContext.init(allocator);
    errdefer {
        // On error, clean up any collected events
        for (collector.events.items) |*event| {
            event.deinit(allocator);
        }
        collector.deinit();
    }
    
    // Set global context for callback
    global_collector = &collector;
    
    // Create client
    var relay_client = client.Client.init(allocator, relay_url);
    defer relay_client.deinit();
    
    // Connect to relay
    try relay_client.connect();
    defer relay_client.disconnect();
    
    // Subscribe
    const sub_id = "fetch";
    try relay_client.subscribe(sub_id, &[_]client.Filter{filter}, collector_callback);
    defer relay_client.unsubscribe(sub_id) catch {};
    
    // Wait for events
    const start_time = std.time.milliTimestamp();
    while (!collector.eose_received and 
           std.time.milliTimestamp() - start_time < timeout_ms) {
        relay_client.process_messages() catch |err| {
            if (err == error.WouldBlock) {
                std.time.sleep(10 * std.time.ns_per_ms);
                continue;
            }
            return err;
        };
    }
    
    // Transfer ownership of events to result
    const events = try collector.events.toOwnedSlice();
    // Always clean up the collector (events ownership already transferred)
    collector.deinit();
    
    return FetchResult{
        .events = events,
        .allocator = allocator,
    };
}

/// Publish an event to a relay and wait for OK response
pub fn publishEvent(
    allocator: std.mem.Allocator,
    relay_url: []const u8,
    event: nostr.Event,
    timeout_ms: u64,
) !bool {
    var relay_client = client.Client.init(allocator, relay_url);
    defer relay_client.deinit();
    
    // Connect to relay
    try relay_client.connect();
    defer relay_client.disconnect();
    
    // Publish state
    var ok_received = false;
    var ok_accepted = false;
    
    const publish_ctx = struct {
        var received: *bool = undefined;
        var accepted: *bool = undefined;
        
        fn callback(ok: bool, message: ?[]const u8) void {
            received.* = true;
            accepted.* = ok;
            if (!ok) {
                log.err("Event rejected: {s}", .{message orelse "no reason"});
            }
        }
    };
    
    publish_ctx.received = &ok_received;
    publish_ctx.accepted = &ok_accepted;
    
    // Publish the event
    try relay_client.publish_event(event, publish_ctx.callback);
    
    // Wait for OK response
    const start_time = std.time.milliTimestamp();
    while (!ok_received and 
           std.time.milliTimestamp() - start_time < timeout_ms) {
        relay_client.process_messages() catch |err| {
            if (err == error.WouldBlock) {
                std.time.sleep(10 * std.time.ns_per_ms);
                continue;
            }
            return err;
        };
    }
    
    return ok_accepted;
}

/// Convenience function to fetch a single KeyPackage by author
pub fn fetchKeyPackage(
    allocator: std.mem.Allocator,
    relay_url: []const u8,
    author_hex: []const u8,
    timeout_ms: u64,
) !?nostr.Event {
    const filter = client.Filter{
        .authors = &[_][]const u8{author_hex},
        .kinds = &[_]u32{443},
        .limit = 1,
    };
    
    var result = try fetchEvents(allocator, relay_url, filter, timeout_ms);
    defer {
        // If we're not returning an event, clean up all
        if (result.events.len == 0 or result.events.len > 1) {
            result.deinit();
        } else {
            // Clean up the array but not the first event
            allocator.free(result.events);
        }
    }
    
    if (result.events.len == 0) {
        return null;
    }
    
    // Return the first event (ownership transfers to caller)
    return result.events[0];
}