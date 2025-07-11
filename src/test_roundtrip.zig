const std = @import("std");
const nostr = @import("nostr.zig");
const client = @import("client.zig");
const test_events = @import("test_events.zig");

const log = std.log.scoped(.test_roundtrip);

// Test configuration
const TEST_RELAY_URL = "ws://localhost:10547";
const TEST_TIMEOUT_MS = 5000;

// Shared state for the test
const TestState = struct {
    mutex: std.Thread.Mutex = .{},
    received_events: std.ArrayList(nostr.Event),
    received_our_event: bool = false,
    test_event_id: ?[]const u8 = null,
    eose_received: bool = false,
    ok_received: bool = false,
    ok_accepted: bool = false,
    
    pub fn init(allocator: std.mem.Allocator) TestState {
        return .{
            .received_events = std.ArrayList(nostr.Event).init(allocator),
        };
    }
    
    pub fn deinit(self: *TestState) void {
        self.received_events.deinit();
    }
};

fn subscription_callback(state: *TestState) fn (message: client.RelayMessage) void {
    return struct {
        fn callback(message: client.RelayMessage) void {
            state.mutex.lock();
            defer state.mutex.unlock();
            
            switch (message) {
                .event => |e| {
                    log.info("Received event: {s}", .{e.event.id});
                    state.received_events.append(e.event) catch |err| {
                        log.err("Failed to append event: {}", .{err});
                    };
                    
                    if (state.test_event_id) |id| {
                        if (std.mem.eql(u8, e.event.id, id)) {
                            state.received_our_event = true;
                            log.info("Received our test event!", .{});
                        }
                    }
                },
                .eose => {
                    log.info("Received EOSE", .{});
                    state.eose_received = true;
                },
                else => {},
            }
        }
    }.callback;
}

fn publish_callback(state: *TestState) fn (ok: bool, message: ?[]const u8) void {
    return struct {
        fn callback(ok: bool, message: ?[]const u8) void {
            state.mutex.lock();
            defer state.mutex.unlock();
            
            state.ok_received = true;
            state.ok_accepted = ok;
            
            if (ok) {
                log.info("Event accepted by relay", .{});
            } else {
                log.err("Event rejected by relay: {s}", .{message orelse "no reason given"});
            }
        }
    }.callback;
}

// Publisher thread function
fn publisherThread(allocator: std.mem.Allocator, state: *TestState) !void {
    log.info("Publisher thread started", .{});
    
    // Give subscriber time to connect and subscribe
    std.time.sleep(500 * std.time.ns_per_ms);
    
    // Create a client
    var pub_client = client.Client.init(allocator, TEST_RELAY_URL);
    defer pub_client.deinit();
    
    // Connect to relay
    try pub_client.connect();
    defer pub_client.disconnect();
    
    // Create a test event
    const test_event = nostr.Event{
        .id = "0000000000000000000000000000000000000000000000000000000000000001",
        .pubkey = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        .created_at = @intCast(std.time.timestamp()),
        .kind = 1,
        .tags = &[_][]const []const u8{
            &[_][]const u8{ "test", "roundtrip" },
        },
        .content = "Hello from Zig Nostr client! This is a roundtrip test.",
        .sig = "0000000000000000000000000000000000000000000000000000000000000000" ++
              "0000000000000000000000000000000000000000000000000000000000000000",
    };
    
    // Store the event ID in shared state
    {
        state.mutex.lock();
        defer state.mutex.unlock();
        state.test_event_id = test_event.id;
    }
    
    log.info("Publishing test event...", .{});
    
    // Publish the event
    try pub_client.publish_event(test_event, publish_callback(state));
    
    // Process messages to receive OK response
    var attempts: u32 = 0;
    while (attempts < 50) : (attempts += 1) {
        pub_client.process_messages() catch |err| {
            if (err == error.WouldBlock) {
                std.time.sleep(100 * std.time.ns_per_ms);
                continue;
            }
            return err;
        };
        
        state.mutex.lock();
        const ok_received = state.ok_received;
        state.mutex.unlock();
        
        if (ok_received) break;
        
        std.time.sleep(100 * std.time.ns_per_ms);
    }
    
    log.info("Publisher thread finished", .{});
}

// Subscriber thread function
fn subscriberThread(allocator: std.mem.Allocator, state: *TestState) !void {
    log.info("Subscriber thread started", .{});
    
    // Create a client
    var sub_client = client.Client.init(allocator, TEST_RELAY_URL);
    defer sub_client.deinit();
    
    // Connect to relay
    try sub_client.connect();
    defer sub_client.disconnect();
    
    // Create subscription filter for kind 1 events
    const filters = [_]client.Filter{
        .{
            .kinds = &[_]u32{1},
            .limit = 10,
        },
    };
    
    log.info("Creating subscription...", .{});
    
    // Subscribe
    try sub_client.subscribe("test-sub-1", &filters, subscription_callback(state));
    defer sub_client.unsubscribe("test-sub-1") catch {};
    
    // Process messages
    const start_time = std.time.milliTimestamp();
    while (std.time.milliTimestamp() - start_time < TEST_TIMEOUT_MS) {
        sub_client.process_messages() catch |err| {
            if (err == error.WouldBlock) {
                std.time.sleep(100 * std.time.ns_per_ms);
                continue;
            }
            return err;
        };
        
        // Check if we received our event
        state.mutex.lock();
        const received = state.received_our_event;
        state.mutex.unlock();
        
        if (received) {
            log.info("Successfully received our published event!", .{});
            break;
        }
        
        std.time.sleep(100 * std.time.ns_per_ms);
    }
    
    log.info("Subscriber thread finished", .{});
}

test "roundtrip publish and subscribe" {
    const allocator = std.testing.allocator;
    
    log.info("Starting roundtrip test...", .{});
    log.info("Make sure nak relay is running: nak serve --verbose", .{});
    
    // Initialize shared state
    var state = TestState.init(allocator);
    defer state.deinit();
    
    // Start subscriber thread
    const sub_thread = try std.Thread.spawn(.{}, subscriberThread, .{ allocator, &state });
    
    // Start publisher thread
    const pub_thread = try std.Thread.spawn(.{}, publisherThread, .{ allocator, &state });
    
    // Wait for both threads to complete
    sub_thread.join();
    pub_thread.join();
    
    // Verify results
    state.mutex.lock();
    defer state.mutex.unlock();
    
    try std.testing.expect(state.ok_received);
    try std.testing.expect(state.ok_accepted);
    try std.testing.expect(state.received_our_event);
    try std.testing.expect(state.received_events.items.len > 0);
    
    log.info("Roundtrip test completed successfully!", .{});
    log.info("Total events received: {}", .{state.received_events.items.len});
}

test "multiple subscriptions" {
    const allocator = std.testing.allocator;
    
    var test_client = client.Client.init(allocator, TEST_RELAY_URL);
    defer test_client.deinit();
    
    try test_client.connect();
    defer test_client.disconnect();
    
    // Create multiple subscriptions with different filters
    const filters1 = [_]client.Filter{
        .{ .kinds = &[_]u32{1}, .limit = 5 },
    };
    const filters2 = [_]client.Filter{
        .{ .kinds = &[_]u32{0}, .limit = 5 },
    };
    const filters3 = [_]client.Filter{
        .{ .authors = &[_][]const u8{"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"} },
    };
    
    try test_client.subscribe("sub1", &filters1, null);
    try test_client.subscribe("sub2", &filters2, null);
    try test_client.subscribe("sub3", &filters3, null);
    
    // Process some messages
    var attempts: u32 = 0;
    while (attempts < 10) : (attempts += 1) {
        test_client.process_messages() catch |err| {
            if (err == error.WouldBlock) {
                std.time.sleep(100 * std.time.ns_per_ms);
                continue;
            }
            return err;
        };
    }
    
    // Unsubscribe from all
    try test_client.unsubscribe("sub1");
    try test_client.unsubscribe("sub2");
    try test_client.unsubscribe("sub3");
}

test "publish various event types" {
    const allocator = std.testing.allocator;
    
    var test_client = client.Client.init(allocator, TEST_RELAY_URL);
    defer test_client.deinit();
    
    try test_client.connect();
    defer test_client.disconnect();
    
    // Test publishing different event types from our test cases
    for (test_events.test_events[0..5]) |test_event| {
        if (!test_event.expected_valid) continue;
        
        const event = nostr.Event{
            .id = "0000000000000000000000000000000000000000000000000000000000000002",
            .pubkey = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            .created_at = @intCast(std.time.timestamp()),
            .kind = test_event.kind,
            .tags = test_event.tags,
            .content = test_event.content,
            .sig = "0000000000000000000000000000000000000000000000000000000000000000" ++
                  "0000000000000000000000000000000000000000000000000000000000000000",
        };
        
        log.info("Publishing {s} event...", .{test_event.name});
        try test_client.publish_event(event, null);
        
        // Small delay between publishes
        std.time.sleep(100 * std.time.ns_per_ms);
    }
}

// Run with: zig test src/test_roundtrip.zig --main-mod-path=.
// Make sure to start nak relay first: nak serve --verbose