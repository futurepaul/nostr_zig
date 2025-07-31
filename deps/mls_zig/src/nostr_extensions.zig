const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

const Extension = @import("key_package.zig").Extension;
const Extensions = @import("key_package.zig").Extensions;
const tls_encode = @import("tls_encode.zig");
const tls = std.crypto.tls;

/// NIP-EE specific extension types
/// These use the 0xFF00+ range for custom Nostr extensions as per MLS conventions
pub const NostrExtensionType = enum(u16) {
    /// Contains Nostr-specific group metadata and identity mappings
    nostr_group_data = 0xFF00,
    /// Prevents key package reuse for security
    last_resort = 0xFF01,
    /// Ratchet tree extension (standard MLS but critical for NIP-EE)
    ratchet_tree = 0x0002,
    
    pub fn serialize(self: NostrExtensionType, writer: anytype) !void {
        try writer.writeU16(@intFromEnum(self));
    }
    
    pub fn deserialize(reader: anytype) !NostrExtensionType {
        const value = try reader.readU16();
        return @enumFromInt(value);
    }
};

/// Nostr group data extension for linking MLS groups to Nostr identities
/// This extension contains Nostr-specific metadata for the group
pub const NostrGroupData = struct {
    /// Nostr group identifier (typically a hex-encoded public key)
    nostr_group_id: []u8,
    /// Nostr relay URLs for group coordination
    relay_urls: [][]u8,
    /// Group creator's Nostr public key
    creator_pubkey: []u8,
    /// Group metadata (name, description, etc.) as JSON
    metadata: []u8,
    
    allocator: Allocator,
    
    pub fn init(
        allocator: Allocator,
        nostr_group_id: []const u8,
        relay_urls: []const []const u8,
        creator_pubkey: []const u8,
        metadata: []const u8,
    ) !NostrGroupData {
        const group_id = try allocator.dupe(u8, nostr_group_id);
        errdefer allocator.free(group_id);
        
        const creator_pk = try allocator.dupe(u8, creator_pubkey);
        errdefer allocator.free(creator_pk);
        
        const meta = try allocator.dupe(u8, metadata);
        errdefer allocator.free(meta);
        
        // Create relay URL array
        const relays = try allocator.alloc([]u8, relay_urls.len);
        errdefer {
            for (relays[0..relay_urls.len]) |relay| {
                allocator.free(relay);
            }
            allocator.free(relays);
        }
        
        for (relay_urls, 0..) |url, i| {
            relays[i] = try allocator.dupe(u8, url);
        }
        
        return NostrGroupData{
            .nostr_group_id = group_id,
            .relay_urls = relays,
            .creator_pubkey = creator_pk,
            .metadata = meta,
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *NostrGroupData) void {
        self.allocator.free(self.nostr_group_id);
        for (self.relay_urls) |relay| {
            self.allocator.free(relay);
        }
        self.allocator.free(self.relay_urls);
        self.allocator.free(self.creator_pubkey);
        self.allocator.free(self.metadata);
    }
    
    pub fn serialize(self: NostrGroupData, list: *std.ArrayList(u8)) !void {
        try tls_encode.encodeVarBytes(list, u16, self.nostr_group_id);
        
        // Serialize relay URLs
        try tls_encode.encodeInt(list, u16, @intCast(self.relay_urls.len));
        for (self.relay_urls) |relay| {
            try tls_encode.encodeVarBytes(list, u16, relay);
        }
        
        try tls_encode.encodeVarBytes(list, u16, self.creator_pubkey);
        try tls_encode.encodeVarBytes(list, u32, self.metadata);
    }
    
    pub fn deserialize(allocator: Allocator, decoder: *tls.Decoder) !NostrGroupData {
        // Read group ID
        const group_id = try tls_encode.readVarBytes(decoder, u16, allocator);
        errdefer allocator.free(group_id);
        
        // Read relay URLs
        const relay_count = decoder.decode(u16);
        const relays = try allocator.alloc([]u8, relay_count);
        errdefer {
            for (relays[0..relay_count]) |relay| {
                allocator.free(relay);
            }
            allocator.free(relays);
        }
        
        for (relays) |*relay| {
            relay.* = try tls_encode.readVarBytes(decoder, u16, allocator);
        }
        
        // Read creator pubkey
        const creator_pk = try tls_encode.readVarBytes(decoder, u16, allocator);
        errdefer allocator.free(creator_pk);
        
        // Read metadata
        const metadata = try tls_encode.readVarBytes(decoder, u32, allocator);
        errdefer allocator.free(metadata);
        
        return NostrGroupData{
            .nostr_group_id = group_id,
            .relay_urls = relays,
            .creator_pubkey = creator_pk,
            .metadata = metadata,
            .allocator = allocator,
        };
    }
    
    /// Convert to a standard MLS Extension
    pub fn toExtension(self: *NostrGroupData) !Extension {
        // Serialize the NostrGroupData
        var data = std.ArrayList(u8).init(self.allocator);
        defer data.deinit();
        
        try self.serialize(&data);
        
        return Extension.init(
            self.allocator,
            @intFromEnum(NostrExtensionType.nostr_group_data),
            data.items
        );
    }
    
    /// Create from a standard MLS Extension
    pub fn fromExtension(allocator: Allocator, extension: *const Extension) !NostrGroupData {
        if (extension.extension_type != @intFromEnum(NostrExtensionType.nostr_group_data)) {
            return error.InvalidExtensionType;
        }
        
        var decoder = tls.Decoder.fromTheirSlice(extension.extension_data);
        
        return NostrGroupData.deserialize(allocator, &decoder);
    }
};

/// Last resort extension to prevent key package reuse
/// This is a security measure to ensure key packages are only used once
pub const LastResort = struct {
    /// Empty extension - presence indicates last resort
    
    pub fn init() LastResort {
        return LastResort{};
    }
    
    pub fn serialize(self: LastResort, writer: anytype) !void {
        _ = self;
        _ = writer;
        // Empty extension - no data to serialize
    }
    
    pub fn deserialize(reader: anytype) !LastResort {
        _ = reader;
        return LastResort{};
    }
    
    /// Convert to a standard MLS Extension
    pub fn toExtension(self: *LastResort, allocator: Allocator) !Extension {
        _ = self;
        return Extension.init(
            allocator,
            @intFromEnum(NostrExtensionType.last_resort),
            &[_]u8{} // Empty data
        );
    }
    
    /// Create from a standard MLS Extension
    pub fn fromExtension(extension: *const Extension) !LastResort {
        if (extension.extension_type != @intFromEnum(NostrExtensionType.last_resort)) {
            return error.InvalidExtensionType;
        }
        
        // Verify extension is empty
        if (extension.extension_data.len != 0) {
            return error.InvalidExtensionData;
        }
        
        return LastResort{};
    }
};

/// Helper functions for working with Nostr extensions in MLS

/// Add Nostr group data extension to an Extensions collection
pub fn addNostrGroupData(
    extensions: *Extensions,
    nostr_group_id: []const u8,
    relay_urls: []const []const u8,
    creator_pubkey: []const u8,
    metadata: []const u8,
) !void {
    var group_data = try NostrGroupData.init(
        extensions.allocator,
        nostr_group_id,
        relay_urls,
        creator_pubkey,
        metadata
    );
    defer group_data.deinit();
    
    const extension = try group_data.toExtension();
    try extensions.addExtension(extension);
}

/// Add last resort extension to an Extensions collection
pub fn addLastResort(extensions: *Extensions) !void {
    var last_resort = LastResort.init();
    const extension = try last_resort.toExtension(extensions.allocator);
    try extensions.addExtension(extension);
}

/// Find and parse Nostr group data from Extensions collection
pub fn findNostrGroupData(allocator: Allocator, extensions: *const Extensions) !?NostrGroupData {
    const ext = extensions.findExtension(@intFromEnum(NostrExtensionType.nostr_group_data)) orelse return null;
    const data = try NostrGroupData.fromExtension(allocator, ext);
    return data;
}

/// Check if Extensions collection has last resort extension
pub fn hasLastResort(extensions: *const Extensions) bool {
    return extensions.findExtension(@intFromEnum(NostrExtensionType.last_resort)) != null;
}

test "NostrGroupData serialization" {
    const allocator = testing.allocator;
    
    const group_id = "deadbeef1234567890abcdef";
    const relay_urls = [_][]const u8{
        "wss://relay1.example.com",
        "wss://relay2.example.com",
    };
    const creator_pubkey = "1234567890abcdef1234567890abcdef12345678";
    const metadata = "{\"name\":\"Test Group\",\"description\":\"A test group\"}";
    
    // Create NostrGroupData
    var group_data = try NostrGroupData.init(
        allocator,
        group_id,
        &relay_urls,
        creator_pubkey,
        metadata
    );
    defer group_data.deinit();
    
    // Test serialization
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    
    try group_data.serialize(&buffer);
    
    // Test deserialization
    var decoder = tls.Decoder.fromTheirSlice(buffer.items);
    
    var decoded = try NostrGroupData.deserialize(allocator, &decoder);
    defer decoded.deinit();
    
    // Verify data
    try testing.expectEqualSlices(u8, group_id, decoded.nostr_group_id);
    try testing.expectEqualSlices(u8, creator_pubkey, decoded.creator_pubkey);
    try testing.expectEqualSlices(u8, metadata, decoded.metadata);
    try testing.expectEqual(@as(usize, 2), decoded.relay_urls.len);
    try testing.expectEqualSlices(u8, relay_urls[0], decoded.relay_urls[0]);
    try testing.expectEqualSlices(u8, relay_urls[1], decoded.relay_urls[1]);
}

test "LastResort extension" {
    const allocator = testing.allocator;
    
    // Create LastResort extension
    var last_resort = LastResort.init();
    const extension = try last_resort.toExtension(allocator);
    defer {
        var mut_ext = extension;
        mut_ext.deinit();
    }
    
    // Verify extension properties
    try testing.expectEqual(@intFromEnum(NostrExtensionType.last_resort), extension.extension_type);
    try testing.expectEqual(@as(usize, 0), extension.extension_data.len);
    
    // Test round-trip
    const decoded = try LastResort.fromExtension(&extension);
    _ = decoded; // No data to verify
}

test "Extensions integration with Nostr data" {
    const allocator = testing.allocator;
    
    // Create Extensions collection
    var extensions = Extensions.init(allocator);
    defer extensions.deinit();
    
    // Add Nostr group data
    const group_id = "testgroup123";
    const relay_urls = [_][]const u8{"wss://test.relay"};
    const creator_pubkey = "creator123";
    const metadata = "{}";
    
    try addNostrGroupData(
        &extensions,
        group_id,
        &relay_urls,
        creator_pubkey,
        metadata
    );
    
    // Add last resort
    try addLastResort(&extensions);
    
    // Verify extensions were added
    try testing.expect(extensions.extensions.len == 2);
    try testing.expect(hasLastResort(&extensions));
    
    // Find and verify Nostr group data
    var found_data = try findNostrGroupData(allocator, &extensions);
    try testing.expect(found_data != null);
    defer if (found_data) |*data| data.deinit();
    
    if (found_data) |data| {
        try testing.expectEqualSlices(u8, group_id, data.nostr_group_id);
        try testing.expectEqualSlices(u8, creator_pubkey, data.creator_pubkey);
    }
}

test "NIP-EE extension compatibility" {
    // Test that our extension types don't conflict with standard MLS
    try testing.expect(@intFromEnum(NostrExtensionType.nostr_group_data) >= 0xFF00);
    try testing.expect(@intFromEnum(NostrExtensionType.last_resort) >= 0xFF00);
    
    // Ratchet tree is a standard MLS extension
    try testing.expect(@intFromEnum(NostrExtensionType.ratchet_tree) < 0x0010);
}