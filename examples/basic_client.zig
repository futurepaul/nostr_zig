const std = @import("std");
const nostr_zig = @import("nostr_zig");

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

    // Create a simple text note event
    const event = nostr_zig.Event{
        .id = "0000000000000000000000000000000000000000000000000000000000000001",
        .pubkey = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        .created_at = @intCast(std.time.timestamp()),
        .kind = 1,
        .tags = &[_][]const []const u8{},
        .content = "Hello from Zig Nostr client!",
        .sig = "0000000000000000000000000000000000000000000000000000000000000000" ++
              "0000000000000000000000000000000000000000000000000000000000000000",
    };

    // Publish the event
    std.debug.print("Publishing event...\n", .{});
    try client.publish_event(event, null);

    // Create a subscription to receive events
    const filters = [_]nostr_zig.Filter{
        .{
            .kinds = &[_]u32{1}, // Short text notes
            .limit = 10,
        },
    };

    std.debug.print("Subscribing to text notes...\n", .{});
    try client.subscribe("example-sub", &filters, null);

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
    try client.unsubscribe("example-sub");
    std.debug.print("Done!\n", .{});
}