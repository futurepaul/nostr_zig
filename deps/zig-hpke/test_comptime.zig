const std = @import("std");
const hpke = @import("src/main.zig");

test "comptime generic HPKE Suite basic functionality" {
    // Test 1: Create a Suite using comptime generics
    const SuiteType = hpke.Suite(.X25519HkdfSha256, .HkdfSha256, .Aes128Gcm);
    
    // Test 2: Generate key pairs with random function
    const RandomFn = struct {
        fn random(buffer: []u8) void {
            // Simple deterministic "random" for testing
            for (buffer, 0..) |*byte, i| {
                byte.* = @intCast(i % 256);
            }
        }
    }.random;
    
    const server_kp = try SuiteType.generateKeyPair(RandomFn);
    
    // Test 3: Create client context
    const info = "test info";
    const result = try SuiteType.createClientContext(
        server_kp.public_key.constSlice(),
        info,
        null, // no PSK
        null, // no seed
        RandomFn
    );
    
    // Test 4: Create server context  
    const server_ctx = try SuiteType.createServerContext(
        result.encapsulated_secret.encapsulated.constSlice(),
        server_kp,
        info,
        null // no PSK
    );
    
    // Test 5: Export secrets (should match)
    var client_secret: [32]u8 = undefined;
    var server_secret: [32]u8 = undefined;
    
    try result.client_ctx.exportSecret(&client_secret, "test export");
    try server_ctx.exportSecret(&server_secret, "test export");
    
    // Secrets should match
    try std.testing.expectEqualSlices(u8, &client_secret, &server_secret);
    
    std.debug.print("✅ Comptime generic HPKE Suite working correctly!\n", .{});
}

test "backwards compatibility with createSuite" {
    // Test the backwards compatibility function
    const SuiteType = try hpke.createSuite(0x0020, 0x0001, 0x0001);
    
    const RandomFn = struct {
        fn random(buffer: []u8) void {
            for (buffer, 0..) |*byte, i| {
                byte.* = @intCast((i * 37) % 256);
            }
        }
    }.random;
    
    const kp = try SuiteType.generateKeyPair(RandomFn);
    
    // Should be able to generate keys
    try std.testing.expect(kp.public_key.len > 0);
    try std.testing.expect(kp.secret_key.len > 0);
    
    std.debug.print("✅ Backwards compatibility working correctly!\n", .{});
}

test "ExportOnly AEAD mode" {
    const SuiteType = hpke.Suite(.X25519HkdfSha256, .HkdfSha256, .ExportOnly);
    
    const RandomFn = struct {
        fn random(buffer: []u8) void {
            for (buffer, 0..) |*byte, i| {
                byte.* = @intCast((i * 13) % 256);
            }
        }
    }.random;
    
    const server_kp = try SuiteType.generateKeyPair(RandomFn);
    
    const info = "export only test";
    const result = try SuiteType.createClientContext(
        server_kp.public_key.constSlice(),
        info,
        null,
        null,
        RandomFn
    );
    
    // Tag length should be 0 for ExportOnly mode
    try std.testing.expectEqual(@as(usize, 0), result.client_ctx.tagLength());
    
    std.debug.print("✅ ExportOnly AEAD mode working correctly!\n", .{});
}