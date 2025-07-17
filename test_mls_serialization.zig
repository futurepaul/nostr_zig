const std = @import("std");

// Test basic MLS message enums and structures
test "Basic MLS message types" {
    // Wire format types as per MLS RFC 9420
    const WireFormat = enum(u16) {
        mls_plaintext = 0x0001,
        mls_ciphertext = 0x0002,
        mls_welcome = 0x0003,
        mls_group_info = 0x0004,
        mls_key_package = 0x0005,
    };
    
    // Content type for MLS messages
    const ContentType = enum(u8) {
        application = 0x01,
        proposal = 0x02,
        commit = 0x03,
    };
    
    // Sender type for MLS messages
    const Sender = union(enum) {
        member: u32,
        external: u32,
        new_member_proposal: void,
        new_member_commit: void,
    };
    
    // Test wire format enum
    const wire_format = WireFormat.mls_plaintext;
    try std.testing.expectEqual(@as(u16, 0x0001), @intFromEnum(wire_format));
    
    // Test content type enum
    const content_type = ContentType.application;
    try std.testing.expectEqual(@as(u8, 0x01), @intFromEnum(content_type));
    
    // Test sender creation
    const sender = Sender{ .member = 456 };
    try std.testing.expectEqual(@as(u32, 456), sender.member);
    
    std.debug.print("All basic MLS message tests passed!\n", .{});
}