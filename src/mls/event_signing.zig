const std = @import("std");
const nostr = @import("../nostr.zig");

/// NIP-EE specific event creation helpers
/// This module now uses the core Nostr event infrastructure instead of duplicating it

pub const NipEEEventHelper = struct {
    builder: nostr.EventBuilder,
    
    pub fn init(allocator: std.mem.Allocator, private_key: [32]u8) NipEEEventHelper {
        return NipEEEventHelper{
            .builder = nostr.EventBuilder.initWithKey(allocator, private_key),
        };
    }
    
    /// Create a KeyPackage event (kind 443)
    pub fn createKeyPackageEvent(
        self: *const NipEEEventHelper,
        key_package_data: []const u8,
        cipher_suite: u32,
        protocol_version: u32,
        extensions: []const u32,
    ) !nostr.Event {
        // Use TagBuilder for safe tag allocation
        var tag_builder = nostr.TagBuilder.init(self.builder.allocator);
        defer tag_builder.deinit();
        
        // Add cipher suite tag
        var cs_value_buf: [32]u8 = undefined;
        const cs_value = try std.fmt.bufPrint(&cs_value_buf, "{d}", .{cipher_suite});
        try tag_builder.addPair("cs", cs_value);
        
        // Add protocol version tag
        var pv_value_buf: [32]u8 = undefined;
        const pv_value = try std.fmt.bufPrint(&pv_value_buf, "{d}", .{protocol_version});
        try tag_builder.addPair("pv", pv_value);
        
        // Add extensions tag if provided
        if (extensions.len > 0) {
            // Build extension values
            var ext_values = try self.builder.allocator.alloc([]const u8, extensions.len + 1);
            defer self.builder.allocator.free(ext_values);
            
            ext_values[0] = "ext";
            var ext_bufs = try self.builder.allocator.alloc([32]u8, extensions.len);
            defer self.builder.allocator.free(ext_bufs);
            
            for (extensions, 0..) |ext, i| {
                ext_values[i + 1] = try std.fmt.bufPrint(&ext_bufs[i], "{d}", .{ext});
            }
            try tag_builder.add(ext_values);
        }
        
        // Build tags and ensure proper cleanup after Event makes its own copies
        const tags = try tag_builder.build();
        defer nostr.freeBuiltTags(self.builder.allocator, tags);
        
        return try self.builder.build(.{
            .kind = 443, // NIP-EE KeyPackage event
            .content = key_package_data,
            .tags = tags,
        });
    }
    
    /// Create a KeyPackage relay list event (kind 10051)
    pub fn createKeyPackageRelayListEvent(
        self: *const NipEEEventHelper,
        relay_uris: []const []const u8,
        description: ?[]const u8,
    ) !nostr.Event {
        // Use TagBuilder for safe tag allocation
        var tag_builder = nostr.TagBuilder.init(self.builder.allocator);
        defer tag_builder.deinit();
        
        // Add relay tags
        for (relay_uris) |relay_uri| {
            try tag_builder.addRelayTag(relay_uri);
        }
        
        // Content is the description
        const content = description orelse "";
        
        const tags = try tag_builder.build();
        defer nostr.freeBuiltTags(self.builder.allocator, tags);
        
        return try self.builder.build(.{
            .kind = 10051, // NIP-EE KeyPackage relay list
            .content = content,
            .tags = tags,
        });
    }
    
    /// Create a Group Message event (kind 445) with ephemeral key
    pub fn createGroupMessageEvent(
        self: *const NipEEEventHelper,
        ephemeral_private_key: [32]u8,
        group_id: []const u8,
        epoch: u64,
        message_type: []const u8,
        encrypted_content: []const u8,
    ) !nostr.Event {
        // Create builder with ephemeral key
        const ephemeral_builder = nostr.EventBuilder.initWithKey(self.builder.allocator, ephemeral_private_key);
        
        // Use TagBuilder for proper memory management
        var tag_builder = nostr.TagBuilder.init(self.builder.allocator);
        defer tag_builder.deinit();
        
        // Add group ID tag (h)
        const group_id_hex = try std.fmt.allocPrint(self.builder.allocator, "{s}", .{std.fmt.fmtSliceHexLower(group_id)});
        defer self.builder.allocator.free(group_id_hex);
        try tag_builder.addPair("h", group_id_hex);
        
        // Add epoch tag
        const epoch_str = try std.fmt.allocPrint(self.builder.allocator, "{d}", .{epoch});
        defer self.builder.allocator.free(epoch_str);
        try tag_builder.addPair("epoch", epoch_str);
        
        // Add message type tag
        try tag_builder.addPair("type", message_type);
        
        const tags = try tag_builder.build();
        defer nostr.freeBuiltTags(self.builder.allocator, tags);
        
        return try ephemeral_builder.build(.{
            .kind = 445, // NIP-EE Group Message event
            .content = encrypted_content,
            .tags = tags,
        });
    }
    
    /// Create an inner event for MLS application messages (unsigned rumor)
    pub fn createInnerEvent(
        self: *const NipEEEventHelper,
        private_key: [32]u8,
        kind: u32,
        content: []const u8,
        tags: []const []const []const u8,
        created_at: ?i64,
    ) !nostr.Event {
        return try self.builder.buildUnsigned(private_key, .{
            .kind = kind,
            .content = content,
            .tags = tags,
            .created_at = created_at,
        });
    }
};

// Tests

test "create and verify signed event using core infrastructure" {
    const allocator = std.testing.allocator;
    const crypto = @import("../crypto.zig");
    
    const private_key = try crypto.generatePrivateKey();
    const helper = NipEEEventHelper.init(allocator, private_key);
    
    // Create a simple event using the core builder
    const event = try helper.builder.build(.{
        .kind = 1,
        .content = "Hello, signed world!",
        .tags = &[_][]const []const u8{},
        .created_at = 1234567890,
    });
    defer event.deinit(allocator);
    
    // Verify the event structure
    try std.testing.expectEqual(@as(u32, 1), event.kind);
    try std.testing.expectEqualStrings("Hello, signed world!", event.content);
    try std.testing.expectEqual(@as(i64, 1234567890), event.created_at);
    try std.testing.expectEqual(@as(usize, 64), event.id.len);
    try std.testing.expectEqual(@as(usize, 64), event.pubkey.len);
    try std.testing.expectEqual(@as(usize, 128), event.sig.len);
    
    // Verify the signature using core method
    const is_valid = try event.verify();
    try std.testing.expect(is_valid);
}

test "create unsigned event (rumor) using core infrastructure" {
    const allocator = std.testing.allocator;
    const crypto = @import("../crypto.zig");
    
    const private_key = try crypto.generatePrivateKey();
    const helper = NipEEEventHelper.init(allocator, private_key);
    
    const rumor = try helper.createInnerEvent(
        private_key,
        9, // chat message
        "This is an unsigned event",
        &[_][]const []const u8{},
        1234567890,
    );
    defer rumor.deinit(allocator);
    
    // Verify the event structure
    try std.testing.expectEqual(@as(u32, 9), rumor.kind);
    try std.testing.expectEqualStrings("This is an unsigned event", rumor.content);
    try std.testing.expectEqual(@as(i64, 1234567890), rumor.created_at);
    try std.testing.expectEqual(@as(usize, 64), rumor.id.len);
    try std.testing.expectEqual(@as(usize, 64), rumor.pubkey.len);
    try std.testing.expectEqualStrings("", rumor.sig); // Empty signature
}

test "NIP-EE KeyPackage relay list event" {
    const allocator = std.testing.allocator;
    const crypto = @import("../crypto.zig");
    
    const private_key = try crypto.generatePrivateKey();
    const helper = NipEEEventHelper.init(allocator, private_key);
    
    const relay_uris = [_][]const u8{
        "wss://relay1.example.com",
        "wss://relay2.example.com",
    };
    const description = "My KeyPackage relays";
    
    const event = try helper.createKeyPackageRelayListEvent(&relay_uris, description);
    defer event.deinit(allocator);
    
    // Verify event structure
    try std.testing.expectEqual(@as(u32, 10051), event.kind);
    try std.testing.expectEqualStrings(description, event.content);
    try std.testing.expectEqual(@as(usize, 2), event.tags.len); // 2 "r" tags
    
    // Check tags
    try std.testing.expectEqualStrings("r", event.tags[0][0]);
    try std.testing.expectEqualStrings("wss://relay1.example.com", event.tags[0][1]);
    try std.testing.expectEqualStrings("r", event.tags[1][0]);
    try std.testing.expectEqualStrings("wss://relay2.example.com", event.tags[1][1]);
    
    // Verify the signature using core method
    const is_valid = try event.verify();
    try std.testing.expect(is_valid);
}

test "NIP-EE KeyPackage event with metadata" {
    const allocator = std.testing.allocator;
    const crypto = @import("../crypto.zig");
    
    const private_key = try crypto.generatePrivateKey();
    const helper = NipEEEventHelper.init(allocator, private_key);
    
    const key_package_data = "base64encodedkeypackagedata";
    const cipher_suite = 1; // MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
    const protocol_version = 1;
    const extensions = [_]u32{ 1, 2, 5 }; // Extension IDs
    
    const event = try helper.createKeyPackageEvent(
        key_package_data,
        cipher_suite,
        protocol_version,
        &extensions,
    );
    defer event.deinit(allocator);
    
    // Verify event structure
    try std.testing.expectEqual(@as(u32, 443), event.kind);
    try std.testing.expectEqualStrings(key_package_data, event.content);
    try std.testing.expectEqual(@as(usize, 3), event.tags.len); // cs, pv, ext tags
    
    // Verify the signature using core method
    const is_valid = try event.verify();
    try std.testing.expect(is_valid);
}

test "NIP-EE Group Message event with ephemeral key" {
    const allocator = std.testing.allocator;
    const crypto = @import("../crypto.zig");
    
    const private_key = try crypto.generatePrivateKey();
    const ephemeral_key = try crypto.generatePrivateKey();
    const helper = NipEEEventHelper.init(allocator, private_key);
    
    const group_id = [_]u8{0xAB} ** 32;
    const epoch: u64 = 42;
    const message_type = "application";
    const encrypted_content = "encryptedmessagecontent";
    
    const event = try helper.createGroupMessageEvent(
        ephemeral_key,
        &group_id,
        epoch,
        message_type,
        encrypted_content,
    );
    defer event.deinit(allocator);
    
    // Verify event structure
    try std.testing.expectEqual(@as(u32, 445), event.kind);
    try std.testing.expectEqualStrings(encrypted_content, event.content);
    try std.testing.expectEqual(@as(usize, 3), event.tags.len); // h, epoch, type tags
    
    // Verify the signature (should be signed with ephemeral key) using core method
    const is_valid = try event.verify();
    try std.testing.expect(is_valid);
    
    // Verify the ephemeral pubkey is different from the main private key
    const main_pubkey = try crypto.getPublicKey(private_key);
    const ephemeral_pubkey = try crypto.getPublicKey(ephemeral_key);
    try std.testing.expect(!std.mem.eql(u8, &main_pubkey, &ephemeral_pubkey));
}