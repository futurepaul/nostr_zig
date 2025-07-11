const std = @import("std");
const nostr = @import("nostr.zig");

/// Generate a random 32-byte private key
pub fn generatePrivateKey() [32]u8 {
    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);
    return key;
}

/// Get public key from private key using secp256k1
pub fn getPublicKey(private_key: [32]u8) ![32]u8 {
    // For now, return a dummy public key
    // TODO: Implement secp256k1 public key derivation
    _ = private_key;
    var pubkey: [32]u8 = undefined;
    std.crypto.random.bytes(&pubkey);
    return pubkey;
}

/// Calculate event ID (SHA256 hash of serialized event)
pub fn calculateEventId(allocator: std.mem.Allocator, pubkey: []const u8, created_at: i64, kind: u32, tags: []const []const []const u8, content: []const u8) ![]u8 {
    // Create the serialized event array for hashing
    // [0, pubkey, created_at, kind, tags, content]
    var event_data = std.ArrayList(u8).init(allocator);
    defer event_data.deinit();
    
    try event_data.appendSlice("[0,\"");
    try event_data.appendSlice(pubkey);
    try event_data.appendSlice("\",");
    try std.fmt.format(event_data.writer(), "{}", .{created_at});
    try event_data.append(',');
    try std.fmt.format(event_data.writer(), "{}", .{kind});
    try event_data.append(',');
    
    // Serialize tags
    try event_data.append('[');
    for (tags, 0..) |tag, i| {
        if (i > 0) try event_data.append(',');
        try event_data.append('[');
        for (tag, 0..) |item, j| {
            if (j > 0) try event_data.append(',');
            try event_data.append('"');
            try event_data.appendSlice(item);
            try event_data.append('"');
        }
        try event_data.append(']');
    }
    try event_data.appendSlice("],\"");
    
    // Escape content for JSON
    for (content) |c| {
        switch (c) {
            '"' => try event_data.appendSlice("\\\""),
            '\\' => try event_data.appendSlice("\\\\"),
            '\n' => try event_data.appendSlice("\\n"),
            '\r' => try event_data.appendSlice("\\r"),
            '\t' => try event_data.appendSlice("\\t"),
            else => try event_data.append(c),
        }
    }
    try event_data.appendSlice("\"]");
    
    // Calculate SHA256
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(event_data.items, &hash, .{});
    
    // Convert to hex
    const hex_id = try allocator.alloc(u8, 64);
    const hex_chars = "0123456789abcdef";
    for (hash, 0..) |byte, i| {
        hex_id[i * 2] = hex_chars[byte >> 4];
        hex_id[i * 2 + 1] = hex_chars[byte & 0x0f];
    }
    
    return hex_id;
}

/// Sign an event (placeholder for now)
pub fn signEvent(event_id: []const u8, private_key: [32]u8) ![64]u8 {
    // TODO: Implement Schnorr signature
    _ = event_id;
    _ = private_key;
    var sig: [64]u8 = undefined;
    std.crypto.random.bytes(&sig);
    return sig;
}

/// Convert bytes to hex string
pub fn bytesToHex(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const hex = try allocator.alloc(u8, bytes.len * 2);
    const hex_chars = "0123456789abcdef";
    for (bytes, 0..) |byte, i| {
        hex[i * 2] = hex_chars[byte >> 4];
        hex[i * 2 + 1] = hex_chars[byte & 0x0f];
    }
    return hex;
}

test "calculate event id" {
    const allocator = std.testing.allocator;
    
    const pubkey = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const created_at: i64 = 1234567890;
    const kind: u32 = 1;
    const tags = &[_][]const []const u8{};
    const content = "Hello, Nostr!";
    
    const id = try calculateEventId(allocator, pubkey, created_at, kind, tags, content);
    defer allocator.free(id);
    
    // Should be a 64-character hex string
    try std.testing.expectEqual(@as(usize, 64), id.len);
    
    // Should only contain hex characters
    for (id) |c| {
        try std.testing.expect((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'));
    }
}