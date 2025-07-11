const std = @import("std");
const nip44 = @import("src/nip44/mod.zig");
const v2 = @import("src/nip44/v2.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Test vector values
    var sec1: [32]u8 = undefined;
    var sec2: [32]u8 = undefined;
    
    _ = try std.fmt.hexToBytes(&sec1, "0000000000000000000000000000000000000000000000000000000000000001");
    _ = try std.fmt.hexToBytes(&sec2, "0000000000000000000000000000000000000000000000000000000000000002");
    
    std.debug.print("=== NIP-44 ECDH Flow Debug ===\n", .{});
    std.debug.print("sec1: {s}\n", .{std.fmt.fmtSliceHexLower(&sec1)});
    std.debug.print("sec2: {s}\n", .{std.fmt.fmtSliceHexLower(&sec2)});
    
    // Step 1: Derive public key from sec2
    const pub2 = try nip44.derivePublicKey(sec2);
    std.debug.print("\nDerived pub2 (x-only): {s}\n", .{std.fmt.fmtSliceHexLower(&pub2)});
    
    // Expected pub2 from test vector (for sec2 = 2)
    const expected_pub2 = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    std.debug.print("Expected pub2 (x-only): {s}\n", .{expected_pub2});
    
    // Step 2: Generate conversation key using sec1 and pub2
    const conversation_key = try nip44.getConversationKey(sec1, pub2);
    std.debug.print("\nConversation key: {s}\n", .{std.fmt.fmtSliceHexLower(&conversation_key.key)});
    
    // Expected conversation key from test vector
    const expected_conv_key = "c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d";
    std.debug.print("Expected conversation key: {s}\n", .{expected_conv_key});
    
    // Let's also try the decrypt flow to see what conversation key it generates
    const test_payload = "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABee0G5VSK0/9YypIObAtDKfYEAjD35uVkHyB0F4DwrcNaCXlCWZKaArsGrY6M9wnuTMxWfp1RTN9Xga8no+kF5Vsb";
    
    std.debug.print("\n=== Testing decrypt flow ===\n", .{});
    const decrypted = nip44.decrypt(allocator, sec1, sec2, test_payload) catch |err| {
        std.debug.print("Decrypt failed with error: {}\n", .{err});
        
        // Let's manually trace the decrypt flow
        std.debug.print("\n=== Manual decrypt trace ===\n", .{});
        
        // First, derivePublicKey is called on sec2
        const pub2_in_decrypt = try nip44.derivePublicKey(sec2);
        std.debug.print("pub2 derived in decrypt: {s}\n", .{std.fmt.fmtSliceHexLower(&pub2_in_decrypt)});
        
        // Then conversation key is generated
        const conv_key_in_decrypt = try v2.ConversationKey.fromKeys(sec1, pub2_in_decrypt);
        std.debug.print("Conversation key in decrypt: {s}\n", .{std.fmt.fmtSliceHexLower(&conv_key_in_decrypt.key)});
        
        return;
    };
    defer allocator.free(decrypted);
    
    std.debug.print("Decrypted successfully: {s}\n", .{decrypted});
}