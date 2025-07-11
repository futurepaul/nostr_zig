const std = @import("std");
const nostr_zig = @import("nostr_zig");
const crypto = nostr_zig.crypto;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("=== Simple Roundtrip Test ===", .{});

    // Generate a real keypair
    const private_key = try crypto.generatePrivateKey();
    const public_key = try crypto.getPublicKey(private_key);
    const pubkey_hex = try crypto.bytesToHex(allocator, &public_key);
    defer allocator.free(pubkey_hex);
    std.log.info("Generated keypair. Pubkey: {s}...", .{pubkey_hex[0..16]});

    // Create event content
    const created_at = std.time.timestamp();
    const kind: u32 = 1;
    const tags = &[_][]const []const u8{
        &[_][]const u8{ "test", "simple-roundtrip" },
    };
    const content = "Simple roundtrip test with real signatures!";

    // Calculate real event ID
    const event_id = try crypto.calculateEventId(allocator, pubkey_hex, created_at, kind, tags, content);
    defer allocator.free(event_id);
    std.log.info("Event ID: {s}...", .{event_id[0..16]});

    // Create real signature
    const signature = try crypto.signEvent(event_id, private_key);
    const sig_hex = try crypto.bytesToHex(allocator, &signature);
    defer allocator.free(sig_hex);

    // Create the event
    const event = nostr_zig.Event{
        .id = event_id,
        .pubkey = pubkey_hex,
        .created_at = created_at,
        .kind = kind,
        .tags = tags,
        .content = content,
        .sig = sig_hex,
    };

    // Connect to relay
    const relay_url = "ws://localhost:10547";
    var client = nostr_zig.Client.init(allocator, relay_url);
    defer client.deinit();

    try client.connect();
    defer client.disconnect();
    std.log.info("Connected to {s}", .{relay_url});

    // First publish the event (like the realistic example)
    std.log.info("Publishing event...", .{});
    
    var event_published = false;
    var event_accepted = false;
    
    const PublishCallback = struct {
        var pub_flag: *bool = undefined;
        var acc_flag: *bool = undefined;
        
        fn init(p: *bool, a: *bool) void {
            pub_flag = p;
            acc_flag = a;
        }
        
        fn callback(ok: bool, message: ?[]const u8) void {
            pub_flag.* = true;
            if (ok) {
                std.log.info("Event accepted by relay!", .{});
                acc_flag.* = true;
            } else {
                std.log.err("Event rejected: {s}", .{message orelse "unknown"});
            }
        }
    };
    PublishCallback.init(&event_published, &event_accepted);
    
    try client.publish_event(event, PublishCallback.callback);

    // Wait for publish response
    var pub_attempts: u32 = 0;
    while (pub_attempts < 50 and !event_published) : (pub_attempts += 1) {
        client.process_messages() catch |err| switch (err) {
            error.WouldBlock => {},
            else => return err,
        };
        std.time.sleep(50 * std.time.ns_per_ms);
    }

    if (!event_accepted) {
        std.log.err("Event not accepted, aborting roundtrip test", .{});
        return;
    }

    // Now subscribe to see our own events
    std.log.info("Setting up subscription to receive our event back...", .{});
    
    var event_received = false;
    var events_count: u32 = 0;
    
    const SubscribeCallback = struct {
        var received_flag: *bool = undefined;
        var count: *u32 = undefined;
        var target_id: []const u8 = undefined;
        
        fn init(r: *bool, c: *u32, id: []const u8) void {
            received_flag = r;
            count = c;
            target_id = id;
        }
        
        fn callback(message: nostr_zig.client.RelayMessage) void {
            switch (message) {
                .event => |e| {
                    count.* += 1;
                    std.log.info("Received event #{}: {s}...", .{ count.*, e.event.id[0..16] });
                    if (std.mem.eql(u8, e.event.id, target_id)) {
                        std.log.info("🎉 Found our published event! Roundtrip complete!", .{});
                        received_flag.* = true;
                    }
                },
                .eose => {
                    std.log.info("End of stored events", .{});
                },
                else => {},
            }
        }
    };
    SubscribeCallback.init(&event_received, &events_count, event_id);
    
    try client.subscribe("test-sub", &[_]nostr_zig.Filter{
        .{
            .authors = &[_][]const u8{pubkey_hex},
            .kinds = &[_]u32{1},
            .limit = 5,
        },
    }, SubscribeCallback.callback);

    // Wait for our event to come back
    std.log.info("Waiting for our event to be received...", .{});
    var sub_attempts: u32 = 0;
    while (sub_attempts < 100 and !event_received) : (sub_attempts += 1) {
        client.process_messages() catch |err| switch (err) {
            error.WouldBlock => {},
            else => return err,
        };
        std.time.sleep(100 * std.time.ns_per_ms);
        
        if (sub_attempts % 20 == 0 and sub_attempts > 0) {
            std.log.info("Still waiting... (received {} events)", .{events_count});
        }
    }

    std.log.info("", .{});
    std.log.info("=== ROUNDTRIP RESULTS ===", .{});
    std.log.info("Event published: {}", .{event_published});
    std.log.info("Event accepted:  {}", .{event_accepted});
    std.log.info("Event received:  {}", .{event_received});
    std.log.info("Total events:    {}", .{events_count});

    if (event_received) {
        std.log.info("", .{});
        std.log.info("🎉🎉🎉 ROUNDTRIP SUCCESSFUL! 🎉🎉🎉", .{});
        std.log.info("✅ Published event with real BIP340 signatures", .{});
        std.log.info("✅ Relay accepted and validated the event", .{});
        std.log.info("✅ Event was successfully received back", .{});
        std.log.info("✅ Full Nostr protocol roundtrip completed!", .{});
    } else {
        std.log.warn("Roundtrip incomplete - event not received back", .{});
    }
}