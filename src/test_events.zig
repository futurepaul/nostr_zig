const std = @import("std");
const nostr = @import("nostr.zig");

// Test cases for various Nostr event types
// Based on NIPs from https://github.com/nostr-protocol/nips

pub const TestEvent = struct {
    name: []const u8,
    kind: u32,
    content: []const u8,
    tags: []const []const []const u8,
    expected_valid: bool,
};

pub const test_events = [_]TestEvent{
    // Kind 0: User Metadata
    .{
        .name = "user_metadata",
        .kind = 0,
        .content = 
        \\{"name":"alice","about":"Nostr enthusiast","picture":"https://example.com/alice.jpg","nip05":"alice@example.com"}
        ,
        .tags = &[_][]const []const u8{},
        .expected_valid = true,
    },
    .{
        .name = "user_metadata_minimal",
        .kind = 0,
        .content = 
        \\{"name":"bob"}
        ,
        .tags = &[_][]const []const u8{},
        .expected_valid = true,
    },

    // Kind 1: Short Text Note
    .{
        .name = "simple_text_note",
        .kind = 1,
        .content = "Hello, Nostr!",
        .tags = &[_][]const []const u8{},
        .expected_valid = true,
    },
    .{
        .name = "text_note_with_hashtag",
        .kind = 1,
        .content = "Building on Nostr is fun! #nostr #zig",
        .tags = &[_][]const []const u8{
            &[_][]const u8{ "t", "nostr" },
            &[_][]const u8{ "t", "zig" },
        },
        .expected_valid = true,
    },
    .{
        .name = "text_note_with_mention",
        .kind = 1,
        .content = "Hey nostr:npub1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsxlf9e3, check this out!",
        .tags = &[_][]const []const u8{
            &[_][]const u8{ "p", "000000000000000000000000000000000000000000000000000000000001d269", "wss://relay.example.com" },
        },
        .expected_valid = true,
    },
    .{
        .name = "reply_text_note",
        .kind = 1,
        .content = "I agree with this!",
        .tags = &[_][]const []const u8{
            &[_][]const u8{ "e", "5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36", "wss://relay.example.com", "root" },
            &[_][]const u8{ "e", "a3c5ce848013ff4d89c9be2afa0ca2b67c66a73a4179fcf0c45e8438195de69f", "wss://relay.example.com", "reply" },
            &[_][]const u8{ "p", "85672b1d7cd7fb35881e91ec5083dc4f8dc6b8d3f44b02bf99c172d67da70645" },
        },
        .expected_valid = true,
    },

    // Kind 3: Follows (Contact List)
    .{
        .name = "follow_list",
        .kind = 3,
        .content = "",
        .tags = &[_][]const []const u8{
            &[_][]const u8{ "p", "85672b1d7cd7fb35881e91ec5083dc4f8dc6b8d3f44b02bf99c172d67da70645", "wss://relay.damus.io", "alice" },
            &[_][]const u8{ "p", "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d", "wss://nos.lol", "bob" },
        },
        .expected_valid = true,
    },

    // Kind 4: Encrypted Direct Message (deprecated, but still common)
    .{
        .name = "encrypted_dm",
        .kind = 4,
        .content = "hH1HlQWY3dz7IzJlgnEgW1WNtA0KlvGgo2kquC2DOLkwAAAAAAAAAABhwx9BpFYJZhV+9wZfbVzBP0vYz5k55Lh5IyeVwrWqUQ==?iv=7/1uHitFVfKKVhFhXBYh3g==",
        .tags = &[_][]const []const u8{
            &[_][]const u8{ "p", "85672b1d7cd7fb35881e91ec5083dc4f8dc6b8d3f44b02bf99c172d67da70645" },
        },
        .expected_valid = true,
    },

    // Kind 5: Event Deletion Request
    .{
        .name = "delete_event",
        .kind = 5,
        .content = "Deleted by author",
        .tags = &[_][]const []const u8{
            &[_][]const u8{ "e", "5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36" },
            &[_][]const u8{ "e", "a3c5ce848013ff4d89c9be2afa0ca2b67c66a73a4179fcf0c45e8438195de69f" },
        },
        .expected_valid = true,
    },

    // Kind 6: Repost
    .{
        .name = "repost",
        .kind = 6,
        .content = "",
        .tags = &[_][]const []const u8{
            &[_][]const u8{ "e", "5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36", "wss://relay.example.com" },
            &[_][]const u8{ "p", "85672b1d7cd7fb35881e91ec5083dc4f8dc6b8d3f44b02bf99c172d67da70645" },
        },
        .expected_valid = true,
    },

    // Kind 7: Reaction
    .{
        .name = "reaction_like",
        .kind = 7,
        .content = "+",
        .tags = &[_][]const []const u8{
            &[_][]const u8{ "e", "5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36" },
            &[_][]const u8{ "p", "85672b1d7cd7fb35881e91ec5083dc4f8dc6b8d3f44b02bf99c172d67da70645" },
        },
        .expected_valid = true,
    },
    .{
        .name = "reaction_emoji",
        .kind = 7,
        .content = "🚀",
        .tags = &[_][]const []const u8{
            &[_][]const u8{ "e", "5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36" },
            &[_][]const u8{ "p", "85672b1d7cd7fb35881e91ec5083dc4f8dc6b8d3f44b02bf99c172d67da70645" },
        },
        .expected_valid = true,
    },

    // Kind 14: Direct Message (NIP-17)
    .{
        .name = "direct_message",
        .kind = 14,
        .content = "This is a private message",
        .tags = &[_][]const []const u8{
            &[_][]const u8{ "p", "85672b1d7cd7fb35881e91ec5083dc4f8dc6b8d3f44b02bf99c172d67da70645" },
            &[_][]const u8{ "subject", "Important update" },
        },
        .expected_valid = true,
    },

    // Kind 42: Channel Message
    .{
        .name = "channel_message",
        .kind = 42,
        .content = "Welcome to the Zig channel!",
        .tags = &[_][]const []const u8{
            &[_][]const u8{ "e", "5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36", "wss://relay.example.com", "root" },
        },
        .expected_valid = true,
    },

    // Kind 1063: File Metadata
    .{
        .name = "file_metadata",
        .kind = 1063,
        .content = "My vacation photo",
        .tags = &[_][]const []const u8{
            &[_][]const u8{ "url", "https://example.com/vacation.jpg" },
            &[_][]const u8{ "m", "image/jpeg" },
            &[_][]const u8{ "x", "7d7e4c29a8a8b7e8f19d7f2e8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b" },
            &[_][]const u8{ "size", "2048576" },
            &[_][]const u8{ "blurhash", "L6PZfRjD00ayoMayWBay00ay~qay" },
        },
        .expected_valid = true,
    },

    // Kind 1984: Reporting
    .{
        .name = "report_spam",
        .kind = 1984,
        .content = "spam",
        .tags = &[_][]const []const u8{
            &[_][]const u8{ "e", "5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36" },
            &[_][]const u8{ "p", "85672b1d7cd7fb35881e91ec5083dc4f8dc6b8d3f44b02bf99c172d67da70645" },
        },
        .expected_valid = true,
    },

    // Kind 9734: Zap Request
    .{
        .name = "zap_request",
        .kind = 9734,
        .content = "Great post! ⚡",
        .tags = &[_][]const []const u8{
            &[_][]const u8{ "e", "5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36" },
            &[_][]const u8{ "p", "85672b1d7cd7fb35881e91ec5083dc4f8dc6b8d3f44b02bf99c172d67da70645" },
            &[_][]const u8{ "amount", "1000" },
            &[_][]const u8{ "relays", "wss://relay.damus.io", "wss://nos.lol" },
        },
        .expected_valid = true,
    },

    // Kind 30023: Long-form Content
    .{
        .name = "long_form_article",
        .kind = 30023,
        .content = 
        \\# Building with Nostr and Zig
        \\
        \\This is a longer article about building Nostr clients with Zig.
        \\
        \\## Introduction
        \\
        \\Zig provides excellent performance and safety guarantees...
        ,
        .tags = &[_][]const []const u8{
            &[_][]const u8{ "d", "building-with-nostr-zig" },
            &[_][]const u8{ "title", "Building with Nostr and Zig" },
            &[_][]const u8{ "summary", "An introduction to building Nostr clients with Zig" },
            &[_][]const u8{ "published_at", "1720800000" },
            &[_][]const u8{ "t", "programming" },
            &[_][]const u8{ "t", "zig" },
            &[_][]const u8{ "t", "nostr" },
        },
        .expected_valid = true,
    },

    // Invalid event examples
    .{
        .name = "invalid_empty_content_metadata",
        .kind = 0,
        .content = "",
        .tags = &[_][]const []const u8{},
        .expected_valid = false,
    },
    .{
        .name = "invalid_malformed_json_metadata",
        .kind = 0,
        .content = "{not valid json",
        .tags = &[_][]const []const u8{},
        .expected_valid = false,
    },
};

test "create test events" {
    const allocator = std.testing.allocator;
    
    // Test creating events from our test cases
    for (test_events) |test_event| {
        std.debug.print("\nTesting event: {s}\n", .{test_event.name});
        
        // Here we would create actual Nostr events once we have the full implementation
        // For now, just validate the structure
        try std.testing.expect(test_event.kind >= 0);
        try std.testing.expect(test_event.content.len >= 0);
        
        // Validate JSON content for metadata events
        if (test_event.kind == 0 and test_event.expected_valid) {
            const parsed = std.json.parseFromSlice(std.json.Value, allocator, test_event.content, .{}) catch |err| {
                std.debug.print("Failed to parse JSON for {s}: {}\n", .{ test_event.name, err });
                return err;
            };
            defer parsed.deinit();
            
            // Metadata should have at least a name field
            try std.testing.expect(parsed.value.object.contains("name"));
        }
    }
}

test "event serialization" {
    // Test that we can properly serialize events to JSON
    // This will be implemented once we have the Event struct working
}

test "event signature verification" {
    // Test that we can verify event signatures
    // This will be implemented once we have crypto support
}

test "publish and subscribe event roundtrip" {
    const allocator = std.testing.allocator;
    
    // Import required modules
    const crypto = @import("crypto.zig");
    const client = @import("client.zig");
    
    std.debug.print("\n=== Testing Publish-Subscribe Roundtrip ===\n", .{});
    
    // 1. Create a test event to publish
    var rng = std.Random.DefaultPrng.init(@bitCast(std.time.timestamp()));
    const private_key = try crypto.generatePrivateKey(rng.random());
    const public_key = try crypto.getPublicKey(private_key);
    
    // Create test event content
    const test_content = "Test event for publish-subscribe validation";
    const current_time = @as(u32, @intCast(std.time.timestamp()));
    
    // Build the event
    var tags = std.ArrayList(nostr.Tag).init(allocator);
    defer tags.deinit();
    try tags.append(nostr.Tag{ .name = "test", .values = &[_][]const u8{ "roundtrip" } });
    
    var event = nostr.Event{
        .id = "",
        .pubkey = try allocator.dupe(u8, &public_key),
        .created_at = current_time,
        .kind = 1, // Text note
        .content = try allocator.dupe(u8, test_content),
        .tags = try tags.toOwnedSlice(),
        .sig = "",
    };
    defer {
        allocator.free(event.id);
        allocator.free(event.pubkey);
        allocator.free(event.content);
        for (event.tags) |tag| {
            allocator.free(tag.name);
            for (tag.values) |value| {
                allocator.free(value);
            }
            allocator.free(tag.values);
        }
        allocator.free(event.tags);
        allocator.free(event.sig);
    }
    
    // Calculate event ID and signature
    const event_id = try nostr.calculateEventId(allocator, event);
    defer allocator.free(event_id);
    event.id = try allocator.dupe(u8, event_id);
    
    const signature = try crypto.signSchnorr(private_key, event_id);
    event.sig = try allocator.dupe(u8, &signature);
    
    std.debug.print("Created test event ID: {s}\n", .{event.id});
    
    // 2. Set up relay client
    var relay_client = client.Client.init(allocator, "ws://localhost:10547");
    defer relay_client.deinit();
    
    // Connect to relay
    relay_client.connect() catch |err| switch (err) {
        error.ConnectionRefused => {
            std.debug.print("⚠️  Relay not available at ws://localhost:10547\n");
            std.debug.print("   To run this test, start a relay with: nak serve --verbose\n");
            return; // Skip test if relay is not available
        },
        else => return err,
    };
    defer relay_client.disconnect();
    
    // 3. Set up subscription state tracking
    var received_event: ?nostr.Event = null;
    var subscription_complete = false;
    var publish_confirmed = false;
    
    // Callback for publish confirmation
    const PublishContext = struct {
        confirmed: *bool,
        
        fn callback(self: @This(), ok: bool, message: ?[]const u8) void {
            _ = message;
            self.confirmed.* = ok;
            if (ok) {
                std.debug.print("✅ Event publish confirmed\n", .{});
            } else {
                std.debug.print("❌ Event publish failed\n", .{});
            }
        }
    };
    const publish_context = PublishContext{ .confirmed = &publish_confirmed };
    
    // Callback for subscription messages
    const SubContext = struct {
        target_event_id: []const u8,
        received: *?nostr.Event,
        complete: *bool,
        alloc: std.mem.Allocator,
        
        fn callback(self: @This(), message: client.RelayMessage) void {
            switch (message) {
                .event => |event_msg| {
                    std.debug.print("📨 Received event: {s}\n", .{event_msg.event.id});
                    
                    // Check if this is our target event
                    if (std.mem.eql(u8, event_msg.event.id, self.target_event_id)) {
                        std.debug.print("✅ Found our published event!\n", .{});
                        
                        // Clone the event for verification
                        const cloned_event = nostr.Event{
                            .id = self.alloc.dupe(u8, event_msg.event.id) catch return,
                            .pubkey = self.alloc.dupe(u8, event_msg.event.pubkey) catch return,
                            .created_at = event_msg.event.created_at,
                            .kind = event_msg.event.kind,
                            .content = self.alloc.dupe(u8, event_msg.event.content) catch return,
                            .tags = self.alloc.dupe(nostr.Tag, event_msg.event.tags) catch return,
                            .sig = self.alloc.dupe(u8, event_msg.event.sig) catch return,
                        };
                        
                        // Deep copy tags
                        for (cloned_event.tags, 0..) |*tag, i| {
                            tag.name = self.alloc.dupe(u8, event_msg.event.tags[i].name) catch return;
                            tag.values = self.alloc.dupe([]const u8, event_msg.event.tags[i].values) catch return;
                            for (tag.values, 0..) |*value, j| {
                                value.* = self.alloc.dupe(u8, event_msg.event.tags[i].values[j]) catch return;
                            }
                        }
                        
                        self.received.* = cloned_event;
                    }
                },
                .eose => |eose_msg| {
                    std.debug.print("📋 End of stored events for subscription: {s}\n", .{eose_msg.subscription_id});
                    self.complete.* = true;
                },
                .ok => |ok_msg| {
                    std.debug.print("📝 OK response: {s} -> {}\n", .{ ok_msg.event_id, ok_msg.accepted });
                },
                else => {},
            }
        }
    };
    const sub_context = SubContext{
        .target_event_id = event.id,
        .received = &received_event,
        .complete = &subscription_complete,
        .alloc = allocator,
    };
    
    // 4. Publish the event first
    std.debug.print("📤 Publishing test event...\n", .{});
    try relay_client.publish_event(event, publish_context.callback);
    
    // 5. Set up subscription to query for our event
    const subscription_id = "test-roundtrip-sub";
    var filters = [_]client.Filter{
        .{
            .ids = &[_][]const u8{event.id},
            .limit = 1,
        },
    };
    
    std.debug.print("📝 Setting up subscription for event ID: {s}\n", .{event.id});
    try relay_client.subscribe(subscription_id, &filters, sub_context.callback);
    
    // 6. Process messages with timeout
    const max_wait_time = 5 * 1000; // 5 seconds in milliseconds
    const start_time = std.time.milliTimestamp();
    var current_time_ms = start_time;
    
    std.debug.print("⏳ Waiting for messages (timeout: {}ms)...\n", .{max_wait_time});
    
    while (current_time_ms - start_time < max_wait_time) {
        relay_client.process_messages() catch |err| switch (err) {
            error.WouldBlock => {
                // No messages available, sleep briefly and continue
                std.time.sleep(10 * std.time.ns_per_ms); // 10ms
            },
            else => return err,
        };
        
        // Check if we're done
        if (publish_confirmed and subscription_complete and received_event != null) {
            break;
        }
        
        current_time_ms = std.time.milliTimestamp();
    }
    
    // 7. Clean up subscription
    try relay_client.unsubscribe(subscription_id);
    
    // 8. Validate results
    std.debug.print("\n=== Validation Results ===\n", .{});
    std.debug.print("Publish confirmed: {}\n", .{publish_confirmed});
    std.debug.print("Subscription complete: {}\n", .{subscription_complete});
    std.debug.print("Event received: {}\n", .{received_event != null});
    
    // Test assertions
    try std.testing.expect(publish_confirmed); // Publish should be confirmed
    
    if (received_event) |recv_event| {
        defer {
            allocator.free(recv_event.id);
            allocator.free(recv_event.pubkey);
            allocator.free(recv_event.content);
            for (recv_event.tags) |tag| {
                allocator.free(tag.name);
                for (tag.values) |value| {
                    allocator.free(value);
                }
                allocator.free(tag.values);
            }
            allocator.free(recv_event.tags);
            allocator.free(recv_event.sig);
        }
        
        // Verify the received event matches what we published
        try std.testing.expectEqualSlices(u8, event.id, recv_event.id);
        try std.testing.expectEqualSlices(u8, event.pubkey, recv_event.pubkey);
        try std.testing.expect(event.created_at == recv_event.created_at);
        try std.testing.expect(event.kind == recv_event.kind);
        try std.testing.expectEqualSlices(u8, event.content, recv_event.content);
        try std.testing.expectEqualSlices(u8, event.sig, recv_event.sig);
        
        // Verify tags match
        try std.testing.expect(event.tags.len == recv_event.tags.len);
        for (event.tags, recv_event.tags) |orig_tag, recv_tag| {
            try std.testing.expectEqualSlices(u8, orig_tag.name, recv_tag.name);
            try std.testing.expect(orig_tag.values.len == recv_tag.values.len);
            for (orig_tag.values, recv_tag.values) |orig_value, recv_value| {
                try std.testing.expectEqualSlices(u8, orig_value, recv_value);
            }
        }
        
        // Verify signature is valid
        const recv_event_id = try nostr.calculateEventId(allocator, recv_event);
        defer allocator.free(recv_event_id);
        
        try std.testing.expectEqualSlices(u8, recv_event.id, recv_event_id);
        
        const pubkey_bytes = try nostr.hexDecode(allocator, recv_event.pubkey);
        defer allocator.free(pubkey_bytes);
        
        const sig_bytes = try nostr.hexDecode(allocator, recv_event.sig);
        defer allocator.free(sig_bytes);
        
        const event_id_bytes = try nostr.hexDecode(allocator, recv_event_id);
        defer allocator.free(event_id_bytes);
        
        const is_valid = try crypto.verifySchnorr(pubkey_bytes[0..32].*, sig_bytes[0..64].*, event_id_bytes[0..32].*);
        try std.testing.expect(is_valid);
        
        std.debug.print("✅ All validations passed!\n", .{});
    } else {
        std.debug.print("❌ No event received within timeout period\n", .{});
        try std.testing.expect(false); // Fail if we didn't receive the event
    }
}