const std = @import("std");
const lib = @import("src/lib.zig");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    
    // Bob's hex pubkey
    const hex = "ab1ac1872a38a2f196bed5a6047f0da2c8130fe8de49fc4d5dfb201f7611d8e2";
    var pubkey: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pubkey, hex);
    
    const npub = try lib.bech32.encodeNpub1(allocator, pubkey);
    defer allocator.free(npub);
    
    std.debug.print("npub: {s}\n", .{npub});
}