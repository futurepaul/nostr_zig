const std = @import("std");

pub fn main() !void {
    // Test vector secret key
    var sec2: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&sec2, "0000000000000000000000000000000000000000000000000000000000000002");
    
    std.debug.print("sec2: {s}\n", .{std.fmt.fmtSliceHexLower(&sec2)});
    
    // The expected public key for sec2 = 2 is:
    // Full compressed: 02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
    // X-only: c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
    std.debug.print("Expected pub2 (x-only): c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5\n", .{});
    
    // Now let's manually compute ECDH shared secret
    // sec1 = 1, pub2 = point for sec2
    // The shared secret should be the x-coordinate of sec1 * pub2
    // Which is the same as the x-coordinate of sec2 * pub1
    // Which is the x-coordinate of 1 * 2 * G = 2 * G
    
    // The expected conversation key is HKDF-Extract("nip44-v2", shared_secret)
    std.debug.print("\nExpected conversation key: c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d\n", .{});
}