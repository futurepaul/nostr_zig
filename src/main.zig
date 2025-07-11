const std = @import("std");

/// This imports the separate module containing `root.zig`. Take a look in `build.zig` for details.
const lib = @import("nostr_zig_lib");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const stdin = std.io.getStdIn().reader();
    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();

    // Read all input from stdin
    const input = try stdin.readAllAlloc(allocator, 1024 * 1024); // 1MB limit
    defer allocator.free(input);

    // Trim whitespace
    const trimmed_input = std.mem.trim(u8, input, " \t\n\r");
    
    if (trimmed_input.len == 0) {
        try stdout.print("Nostr Zig CLI - JSON event encoder/decoder\n", .{});
        try stdout.print("Usage: echo '{{\"id\":\"...\", ...}}' | zig build run\n", .{});
        try stdout.print("Or: zig build run < event.json\n", .{});
        try bw.flush();
        return;
    }

    // Try to parse as Nostr event
    parseAndDisplay(allocator, trimmed_input, stdout) catch |err| {
        try stdout.print("Error parsing Nostr event: {}\n", .{err});
        try stdout.print("Input was: {s}\n", .{trimmed_input});
    };

    try bw.flush();
}

fn parseAndDisplay(allocator: std.mem.Allocator, json_str: []const u8, writer: anytype) !void {
    // Parse the JSON as a Nostr event
    const event = try lib.Event.fromJson(allocator, json_str);
    defer event.deinit(allocator);

    // Display parsed event information
    try writer.print("=== Parsed Nostr Event ===\n", .{});
    try writer.print("ID: {s}\n", .{event.id});
    try writer.print("Public Key: {s}\n", .{event.pubkey});
    try writer.print("Created At: {} ({s})\n", .{ event.created_at, timestampToDate(event.created_at) });
    try writer.print("Kind: {} ({s})\n", .{ event.kind.toInt(), kindToString(event.kind) });
    try writer.print("Content: {s}\n", .{event.content});
    try writer.print("Tags: {} tags\n", .{event.tags.len});
    
    for (event.tags, 0..) |tag, i| {
        try writer.print("  Tag {}: [", .{i});
        for (tag, 0..) |tag_part, j| {
            if (j > 0) try writer.print(", ", .{});
            try writer.print("\"{s}\"", .{tag_part});
        }
        try writer.print("]\n", .{});
    }
    
    try writer.print("Signature: {s}\n", .{event.sig});
    
    // Basic validation
    try writer.print("\n=== Validation ===\n", .{});
    try writer.print("ID format: {s}\n", .{if (event.validateId()) "✓ Valid" else "✗ Invalid"});
    try writer.print("Signature format: {s}\n", .{if (event.validateSignature()) "✓ Valid" else "✗ Invalid"});
    
    // Serialize back to JSON
    try writer.print("\n=== Serialized JSON ===\n", .{});
    const serialized = try event.toJson(allocator);
    defer allocator.free(serialized);
    try writer.print("{s}\n", .{serialized});
}

fn kindToString(kind: lib.Kind) []const u8 {
    return switch (kind) {
        .metadata => "Metadata/Profile",
        .text_note => "Text Note",
        .recommend_relay => "Recommend Relay",
        .contacts => "Contact List",
        .encrypted_dm => "Encrypted DM",
        .event_deletion => "Event Deletion",
        .repost => "Repost",
        .reaction => "Reaction",
        .badge_award => "Badge Award",
        _ => "Unknown",
    };
}

fn timestampToDate(timestamp: i64) []const u8 {
    // Simple timestamp to date conversion (just show the timestamp for now)
    _ = timestamp;
    return "UTC";
}

test "can import nostr lib" {
    const Kind = lib.Kind;
    
    try std.testing.expectEqual(Kind.text_note, Kind.fromInt(1));
    try std.testing.expectEqual(Kind.metadata, Kind.fromInt(0));
}
