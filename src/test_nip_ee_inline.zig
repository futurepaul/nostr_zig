const std = @import("std");
const nip_ee = @import("nip_ee.zig");
const crypto = @import("crypto.zig");

test "NIP-EE basic round trip" {
    const allocator = std.testing.allocator;
    
    // Test data
    const group_id: [32]u8 = [_]u8{0x42} ** 32;
    const epoch: u64 = 1;
    const sender_index: u32 = 0;
    const message = "Hello, NIP-EE!";
    const signature = [_]u8{0x00} ** 64;
    const exporter_secret: [32]u8 = [_]u8{0x42} ** 32;
    
    // Encrypt
    const encrypted = try nip_ee.createEncryptedGroupMessage(
        allocator,
        group_id,
        epoch,
        sender_index,
        message,
        &signature,
        exporter_secret,
    );
    defer allocator.free(encrypted);
    
    std.debug.print("\nEncrypted message size: {} bytes\n", .{encrypted.len});
    
    // Decrypt
    var decrypted = try nip_ee.decryptGroupMessage(
        allocator,
        encrypted,
        exporter_secret,
    );
    defer decrypted.deinit(allocator);
    
    // Verify
    try std.testing.expectEqual(epoch, decrypted.confirmed_transcript_hash.epoch);
    try std.testing.expectEqualSlices(u8, &group_id, &decrypted.confirmed_transcript_hash.group_id);
    
    std.debug.print("✅ NIP-EE round trip successful!\n", .{});
}