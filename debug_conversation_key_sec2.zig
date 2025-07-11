const std = @import("std");
const nip44 = @import("src/nip44/mod.zig");

pub fn main() !void {
    
    // Test vector values
    const sec1_hex = "0000000000000000000000000000000000000000000000000000000000000001";
    const sec2_hex = "0000000000000000000000000000000000000000000000000000000000000002";
    
    // Convert hex to bytes
    var sec1: [32]u8 = undefined;
    var sec2: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&sec1, sec1_hex);
    _ = try std.fmt.hexToBytes(&sec2, sec2_hex);
    
    // Derive public key from sec2
    const pub2 = try nip44.derivePublicKey(sec2);
    
    std.debug.print("sec1: {x}\n", .{std.fmt.fmtSliceHexLower(&sec1)});
    std.debug.print("sec2: {x}\n", .{std.fmt.fmtSliceHexLower(&sec2)});
    std.debug.print("pub2 (derived): {x}\n", .{std.fmt.fmtSliceHexLower(&pub2)});
    
    // Test conversation key generation
    const v2 = @import("src/nip44/v2.zig");
    const conversation_key = try v2.ConversationKey.fromKeys(sec1, pub2);
    
    std.debug.print("Conversation key: {x}\n", .{std.fmt.fmtSliceHexLower(&conversation_key.key)});
    
    // Expected: c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d
    std.debug.print("Expected:         c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d\n", .{});
}