const std = @import("std");
const nostr = @import("../nostr.zig");
const types = @import("types.zig");
const key_packages = @import("key_packages.zig");
const welcomes = @import("welcomes.zig");

/// NIP-EE event kinds
pub const EventKind = enum(u32) {
    key_package = 443,
    welcome = 444,
    group_message = 445,
};

/// Kind 443: MLS Key Package Event
/// Contains a user's key package for joining groups
pub const KeyPackageEvent = struct {
    /// Standard Nostr event fields
    event: nostr.Event,
    
    /// Parsed key package data
    key_package: ?types.KeyPackage,
    
    /// Create a new key package event
    pub fn create(
        allocator: std.mem.Allocator,
        private_key: [32]u8,
        key_package: types.KeyPackage,
    ) !KeyPackageEvent {
        // Serialize the key package
        const serialized = try serializeKeyPackage(allocator, key_package);
        defer allocator.free(serialized);
        
        // Base64 encode
        const encoded = try std.base64.standard.Encoder.calcSize(serialized.len);
        const content = try allocator.alloc(u8, encoded);
        _ = std.base64.standard.Encoder.encode(content, serialized);
        
        // Create the event
        var event = nostr.Event{
            .id = undefined,
            .pubkey = undefined,
            .created_at = @intCast(std.time.timestamp()),
            .kind = @intFromEnum(EventKind.key_package),
            .tags = &.{},
            .content = content,
            .sig = undefined,
        };
        
        // Set pubkey from private key
        event.pubkey = try crypto.getPublicKey(private_key);
        
        // Calculate event ID and sign
        try event.calculateId(allocator);
        try event.sign(allocator, private_key);
        
        return KeyPackageEvent{
            .event = event,
            .key_package = key_package,
        };
    }
    
    /// Parse a key package event
    pub fn parse(allocator: std.mem.Allocator, event: nostr.Event) !KeyPackageEvent {
        if (event.kind != @intFromEnum(EventKind.key_package)) {
            return error.InvalidEventKind;
        }
        
        // Base64 decode the content
        const decoded_size = try std.base64.standard.Decoder.calcSizeForSlice(event.content);
        const decoded = try allocator.alloc(u8, decoded_size);
        defer allocator.free(decoded);
        try std.base64.standard.Decoder.decode(decoded, event.content);
        
        // Parse the key package
        const key_package = try deserializeKeyPackage(allocator, decoded);
        
        return KeyPackageEvent{
            .event = event,
            .key_package = key_package,
        };
    }
};

/// Kind 444: MLS Welcome Event
/// Contains an encrypted welcome message for a specific recipient
pub const WelcomeEvent = struct {
    /// Standard Nostr event fields
    event: nostr.Event,
    
    /// Recipient public key (from p tag)
    recipient_pubkey: ?[32]u8,
    
    /// Group ID (from g tag)
    group_id: ?types.GroupId,
    
    /// Decrypted welcome data (only available after decryption)
    welcome: ?types.Welcome,
    
    /// Create a new welcome event
    pub fn create(
        allocator: std.mem.Allocator,
        sender_private_key: [32]u8,
        recipient_pubkey: [32]u8,
        group_id: types.GroupId,
        welcome: types.Welcome,
    ) !WelcomeEvent {
        // Serialize the welcome
        const serialized = try serializeWelcome(allocator, welcome);
        defer allocator.free(serialized);
        
        // Encrypt with NIP-44 to recipient
        const nip44 = @import("../nip44/mod.zig");
        const encrypted = try nip44.encrypt(allocator, serialized, sender_private_key, recipient_pubkey);
        defer allocator.free(encrypted);
        
        // Create tags
        var tags = std.ArrayList([]const []const u8).init(allocator);
        defer tags.deinit();
        
        // Add p tag for recipient
        const p_tag = try allocator.alloc([]const u8, 2);
        p_tag[0] = try allocator.dupe(u8, "p");
        p_tag[1] = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(&recipient_pubkey)});
        try tags.append(p_tag);
        
        // Add g tag for group ID
        const g_tag = try allocator.alloc([]const u8, 2);
        g_tag[0] = try allocator.dupe(u8, "g");
        g_tag[1] = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(&group_id)});
        try tags.append(g_tag);
        
        // Create the event
        var event = nostr.Event{
            .id = undefined,
            .pubkey = undefined,
            .created_at = @intCast(std.time.timestamp()),
            .kind = @intFromEnum(EventKind.welcome),
            .tags = try tags.toOwnedSlice(),
            .content = encrypted,
            .sig = undefined,
        };
        
        // Set pubkey from private key
        event.pubkey = try crypto.getPublicKey(sender_private_key);
        
        // Calculate event ID and sign
        try event.calculateId(allocator);
        try event.sign(allocator, sender_private_key);
        
        return WelcomeEvent{
            .event = event,
            .recipient_pubkey = recipient_pubkey,
            .group_id = group_id,
            .welcome = welcome,
        };
    }
    
    /// Parse a welcome event (without decryption)
    pub fn parse(event: nostr.Event) !WelcomeEvent {
        if (event.kind != @intFromEnum(EventKind.welcome)) {
            return error.InvalidEventKind;
        }
        
        var recipient_pubkey: ?[32]u8 = null;
        var group_id: ?types.GroupId = null;
        
        // Extract tags
        for (event.tags) |tag| {
            if (tag.len >= 2) {
                if (std.mem.eql(u8, tag[0], "p")) {
                    var pubkey: [32]u8 = undefined;
                    _ = try std.fmt.hexToBytes(&pubkey, tag[1]);
                    recipient_pubkey = pubkey;
                } else if (std.mem.eql(u8, tag[0], "g")) {
                    var gid: types.GroupId = undefined;
                    _ = try std.fmt.hexToBytes(&gid, tag[1]);
                    group_id = gid;
                }
            }
        }
        
        return WelcomeEvent{
            .event = event,
            .recipient_pubkey = recipient_pubkey,
            .group_id = group_id,
            .welcome = null,
        };
    }
    
    /// Decrypt the welcome message
    pub fn decrypt(
        self: *WelcomeEvent,
        allocator: std.mem.Allocator,
        recipient_private_key: [32]u8,
    ) !void {
        const nip44 = @import("../nip44/mod.zig");
        const decrypted = try nip44.decrypt(allocator, self.event.content, recipient_private_key, self.event.pubkey);
        defer allocator.free(decrypted);
        
        self.welcome = try deserializeWelcome(allocator, decrypted);
    }
};

/// Kind 445: MLS Group Message Event
/// Contains a double-encrypted group message
pub const GroupMessageEvent = struct {
    /// Standard Nostr event fields
    event: nostr.Event,
    
    /// Group ID (from g tag)
    group_id: ?types.GroupId,
    
    /// Epoch number (from epoch tag)
    epoch: ?types.Epoch,
    
    /// Message type (from mls tag)
    message_type: ?[]const u8,
    
    /// Create a new group message event
    pub fn create(
        allocator: std.mem.Allocator,
        ephemeral_private_key: [32]u8,
        group_id: types.GroupId,
        epoch: types.Epoch,
        message_type: []const u8,
        encrypted_content: []const u8,
    ) !GroupMessageEvent {
        // Create tags
        var tags = std.ArrayList([]const []const u8).init(allocator);
        defer tags.deinit();
        
        // Add g tag for group ID
        const g_tag = try allocator.alloc([]const u8, 2);
        g_tag[0] = try allocator.dupe(u8, "g");
        g_tag[1] = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(&group_id)});
        try tags.append(g_tag);
        
        // Add epoch tag
        const epoch_tag = try allocator.alloc([]const u8, 2);
        epoch_tag[0] = try allocator.dupe(u8, "epoch");
        epoch_tag[1] = try std.fmt.allocPrint(allocator, "{}", .{epoch});
        try tags.append(epoch_tag);
        
        // Add mls tag for message type
        const mls_tag = try allocator.alloc([]const u8, 2);
        mls_tag[0] = try allocator.dupe(u8, "mls");
        mls_tag[1] = try allocator.dupe(u8, message_type);
        try tags.append(mls_tag);
        
        // Create the event
        var event = nostr.Event{
            .id = undefined,
            .pubkey = undefined,
            .created_at = @intCast(std.time.timestamp()),
            .kind = @intFromEnum(EventKind.group_message),
            .tags = try tags.toOwnedSlice(),
            .content = try allocator.dupe(u8, encrypted_content),
            .sig = undefined,
        };
        
        // Set pubkey from ephemeral private key
        event.pubkey = try crypto.getPublicKey(ephemeral_private_key);
        
        // Calculate event ID and sign with ephemeral key
        try event.calculateId(allocator);
        try event.sign(allocator, ephemeral_private_key);
        
        return GroupMessageEvent{
            .event = event,
            .group_id = group_id,
            .epoch = epoch,
            .message_type = try allocator.dupe(u8, message_type),
        };
    }
    
    /// Parse a group message event
    pub fn parse(allocator: std.mem.Allocator, event: nostr.Event) !GroupMessageEvent {
        if (event.kind != @intFromEnum(EventKind.group_message)) {
            return error.InvalidEventKind;
        }
        
        var group_id: ?types.GroupId = null;
        var epoch: ?types.Epoch = null;
        var message_type: ?[]const u8 = null;
        
        // Extract tags
        for (event.tags) |tag| {
            if (tag.len >= 2) {
                if (std.mem.eql(u8, tag[0], "g")) {
                    var gid: types.GroupId = undefined;
                    _ = try std.fmt.hexToBytes(&gid, tag[1]);
                    group_id = gid;
                } else if (std.mem.eql(u8, tag[0], "epoch")) {
                    epoch = try std.fmt.parseInt(types.Epoch, tag[1], 10);
                } else if (std.mem.eql(u8, tag[0], "mls")) {
                    message_type = try allocator.dupe(u8, tag[1]);
                }
            }
        }
        
        return GroupMessageEvent{
            .event = event,
            .group_id = group_id,
            .epoch = epoch,
            .message_type = message_type,
        };
    }
};

const crypto = @import("../crypto.zig");

// Placeholder serialization functions - these would be implemented based on MLS wire format

fn serializeKeyPackage(allocator: std.mem.Allocator, key_package: types.KeyPackage) ![]u8 {
    _ = key_package;
    // TODO: Implement MLS wire format serialization
    return try allocator.dupe(u8, "serialized_key_package");
}

fn deserializeKeyPackage(allocator: std.mem.Allocator, data: []const u8) !types.KeyPackage {
    // Use the parseKeyPackage function we implemented
    return key_packages.parseKeyPackage(allocator, data);
}

fn serializeWelcome(allocator: std.mem.Allocator, welcome: types.Welcome) ![]u8 {
    // Use the serializeWelcome function we implemented
    return welcomes.serializeWelcome(allocator, welcome);
}

fn deserializeWelcome(allocator: std.mem.Allocator, data: []const u8) !types.Welcome {
    // Use the parseWelcome function we implemented
    return welcomes.parseWelcome(allocator, data);
}

test "event kind values" {
    try std.testing.expectEqual(@as(u32, 443), @intFromEnum(EventKind.key_package));
    try std.testing.expectEqual(@as(u32, 444), @intFromEnum(EventKind.welcome));
    try std.testing.expectEqual(@as(u32, 445), @intFromEnum(EventKind.group_message));
}

test "parse welcome event" {
    // Create a mock event
    const event = nostr.Event{
        .id = &[_]u8{0} ** 32,
        .pubkey = &[_]u8{1} ** 32,
        .created_at = 1234567890,
        .kind = 444,
        .tags = &[_][]const []const u8{
            &[_][]const u8{ "p", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" },
            &[_][]const u8{ "g", "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210" },
        },
        .content = "encrypted_content",
        .sig = &[_]u8{2} ** 64,
    };
    
    const welcome_event = try WelcomeEvent.parse(event);
    try std.testing.expect(welcome_event.recipient_pubkey != null);
    try std.testing.expect(welcome_event.group_id != null);
}

test "parse group message event" {
    const allocator = std.testing.allocator;
    
    // Create a mock event
    const event = nostr.Event{
        .id = &[_]u8{0} ** 32,
        .pubkey = &[_]u8{1} ** 32,
        .created_at = 1234567890,
        .kind = 445,
        .tags = &[_][]const []const u8{
            &[_][]const u8{ "g", "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210" },
            &[_][]const u8{ "epoch", "42" },
            &[_][]const u8{ "mls", "application" },
        },
        .content = "double_encrypted_content",
        .sig = &[_]u8{2} ** 64,
    };
    
    const msg_event = try GroupMessageEvent.parse(allocator, event);
    defer if (msg_event.message_type) |mt| allocator.free(mt);
    
    try std.testing.expect(msg_event.group_id != null);
    try std.testing.expectEqual(@as(types.Epoch, 42), msg_event.epoch.?);
    try std.testing.expectEqualStrings("application", msg_event.message_type.?);
}