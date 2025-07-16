const std = @import("std");
const ephemeral = @import("src/mls/ephemeral.zig");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    
    std.debug.print("Testing ephemeral key generation...\n", .{});
    
    // Test single key generation
    const key1 = try ephemeral.EphemeralKeyPair.generate();
    std.debug.print("Generated ephemeral key pair:\n", .{});
    std.debug.print("  Private: {s}\n", .{std.fmt.fmtSliceHexLower(&key1.private_key)});
    std.debug.print("  Public:  {s}\n", .{std.fmt.fmtSliceHexLower(&key1.public_key)});
    
    // Test uniqueness
    const key2 = try ephemeral.EphemeralKeyPair.generate();
    const key3 = try ephemeral.EphemeralKeyPair.generate();
    
    if (std.mem.eql(u8, &key1.private_key, &key2.private_key) or
        std.mem.eql(u8, &key1.private_key, &key3.private_key) or
        std.mem.eql(u8, &key2.private_key, &key3.private_key)) {
        std.debug.print("ERROR: Key reuse detected!\n", .{});
    } else {
        std.debug.print("✓ Keys are unique\n", .{});
    }
    
    // Test batch generation
    const keys = try ephemeral.generateBatchEphemeralKeys(5, allocator);
    defer {
        ephemeral.clearBatchEphemeralKeys(keys);
        allocator.free(keys);
    }
    
    std.debug.print("\nGenerated {} ephemeral keys in batch\n", .{keys.len});
    
    // Test key cache
    var cache = ephemeral.EphemeralKeyCache.init(allocator);
    defer cache.deinit();
    
    const event_id: [32]u8 = [_]u8{1} ** 32;
    try cache.add(event_id, key1.public_key);
    
    if (cache.get(event_id)) |cached_key| {
        std.debug.print("✓ Key cache working\n", .{});
        _ = cached_key;
    } else {
        std.debug.print("ERROR: Key cache failed\n", .{});
    }
    
    std.debug.print("\nEphemeral key system ready for NIP-EE!\n", .{});
}