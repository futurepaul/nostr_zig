const std = @import("std");
const nostr_zig = @import("nostr_zig");
const crypto = nostr_zig.crypto;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create a client connected to a local relay
    const relay_url = "ws://localhost:10547";
    var client = nostr_zig.Client.init(allocator, relay_url);
    defer client.deinit();

    // Connect to the relay
    client.connect() catch |err| {
        std.debug.print("Failed to connect: {}\n", .{err});
        std.debug.print("Make sure the relay is running with: nak serve --verbose\n", .{});
        return err;
    };
    defer client.disconnect();

    std.debug.print("Connected to {s}\n", .{relay_url});

    // Generate a private key and get public key
    const private_key = try crypto.generatePrivateKey();
    const public_key = try crypto.getPublicKey(private_key);
    const pubkey_hex = try crypto.bytesToHex(allocator, &public_key);
    defer allocator.free(pubkey_hex);

    // Create a properly formatted event
    const created_at = std.time.timestamp();
    const kind: u32 = 1;
    const tags = &[_][]const []const u8{};
    const content = "Hello from Zig Nostr client with proper event ID!";
    
    // Calculate event ID
    const event_id = try crypto.calculateEventId(allocator, pubkey_hex, created_at, kind, tags, content);
    defer allocator.free(event_id);
    
    // Sign the event
    const signature = try crypto.signEvent(event_id, private_key);
    const sig_hex = try crypto.bytesToHex(allocator, &signature);
    defer allocator.free(sig_hex);

    const event = nostr_zig.Event{
        .id = event_id,
        .pubkey = pubkey_hex,
        .created_at = created_at,
        .kind = kind,
        .tags = tags,
        .content = content,
        .sig = sig_hex,
    };

    // Publish the event with a callback
    std.debug.print("Publishing event with ID: {s}\n", .{event.id[0..16]});
    
    try client.publish_event(event, struct {
        fn cb(ok: bool, message: ?[]const u8) void {
            if (ok) {
                std.debug.print("Event accepted by relay!\n", .{});
            } else {
                std.debug.print("Event rejected: {s}\n", .{message orelse "unknown reason"});
            }
        }
    }.cb);

    // Create a subscription to see our own events
    const filters = [_]nostr_zig.Filter{
        .{
            .authors = &[_][]const u8{pubkey_hex},
            .kinds = &[_]u32{1},
            .limit = 10,
        },
    };

    std.debug.print("Subscribing to our own events...\n", .{});
    
    try client.subscribe("my-events", &filters, struct {
        fn cb(message: nostr_zig.RelayMessage) void {
            switch (message) {
                .event => |e| {
                    std.debug.print("Received event: {s}\n", .{e.event.content});
                },
                .eose => {
                    std.debug.print("End of stored events\n", .{});
                },
                else => {},
            }
        }
    }.cb);

    // Process messages for a few seconds
    const start_time = std.time.milliTimestamp();
    while (std.time.milliTimestamp() - start_time < 3000) {
        client.process_messages() catch |err| {
            if (err == error.WouldBlock) {
                std.time.sleep(100 * std.time.ns_per_ms);
                continue;
            }
            return err;
        };
    }

    // Unsubscribe before disconnecting
    try client.unsubscribe("my-events");
    std.debug.print("Done!\n", .{});
}