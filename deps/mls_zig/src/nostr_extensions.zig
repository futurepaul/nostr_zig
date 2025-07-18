const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

const Extension = @import("key_package.zig").Extension;
const Extensions = @import("key_package.zig").Extensions;
const VarBytes = @import("tls_codec.zig").VarBytes;
const TlsWriter = @import("tls_codec.zig").TlsWriter;
const TlsReader = @import("tls_codec.zig").TlsReader;

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
    nostr_group_id: VarBytes,
    /// Nostr relay URLs for group coordination
    relay_urls: []VarBytes,
    /// Group creator's Nostr public key
    creator_pubkey: VarBytes,
    /// Group metadata (name, description, etc.) as JSON
    metadata: VarBytes,
    
    allocator: Allocator,
    
    pub fn init(
        allocator: Allocator,
        nostr_group_id: []const u8,
        relay_urls: []const []const u8,
        creator_pubkey: []const u8,
        metadata: []const u8,
    ) !NostrGroupData {
        var group_id = try VarBytes.init(allocator, nostr_group_id);
        errdefer group_id.deinit();
        
        var creator_pk = try VarBytes.init(allocator, creator_pubkey);
        errdefer creator_pk.deinit();
        
        var meta = try VarBytes.init(allocator, metadata);
        errdefer meta.deinit();
        
        // Create relay URL array
        const relays = try allocator.alloc(VarBytes, relay_urls.len);
        errdefer {
            for (relays[0..relay_urls.len]) |*relay| {
                relay.deinit();
            }
            allocator.free(relays);
        }
        
        for (relay_urls, 0..) |url, i| {
            relays[i] = try VarBytes.init(allocator, url);
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
        self.nostr_group_id.deinit();
        for (self.relay_urls) |*relay| {
            relay.deinit();
        }
        self.allocator.free(self.relay_urls);
        self.creator_pubkey.deinit();
        self.metadata.deinit();
    }
    
    pub fn serialize(self: NostrGroupData, writer: anytype) !void {
        try writer.writeVarBytes(u16, self.nostr_group_id.asSlice());
        
        // Serialize relay URLs
        try writer.writeU16(@intCast(self.relay_urls.len));
        for (self.relay_urls) |relay| {
            try writer.writeVarBytes(u16, relay.asSlice());
        }
        
        try writer.writeVarBytes(u16, self.creator_pubkey.asSlice());
        try writer.writeVarBytes(u32, self.metadata.asSlice());
    }
    
    pub fn deserialize(allocator: Allocator, reader: anytype) !NostrGroupData {
        // Read group ID
        const group_id_data = try reader.readVarBytes(u16, allocator);
        defer allocator.free(group_id_data);
        var group_id = try VarBytes.init(allocator, group_id_data);
        errdefer group_id.deinit();
        
        // Read relay URLs
        const relay_count = try reader.readU16();
        const relays = try allocator.alloc(VarBytes, relay_count);
        errdefer {
            for (relays[0..relay_count]) |*relay| {
                relay.deinit();
            }
            allocator.free(relays);
        }
        
        for (relays) |*relay| {
            const relay_data = try reader.readVarBytes(u16, allocator);
            defer allocator.free(relay_data);
            relay.* = try VarBytes.init(allocator, relay_data);
        }
        
        // Read creator pubkey
        const creator_data = try reader.readVarBytes(u16, allocator);
        defer allocator.free(creator_data);
        var creator_pk = try VarBytes.init(allocator, creator_data);
        errdefer creator_pk.deinit();
        
        // Read metadata
        const metadata_data = try reader.readVarBytes(u32, allocator);
        defer allocator.free(metadata_data);
        const metadata = try VarBytes.init(allocator, metadata_data);
        
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
        
        var writer = TlsWriter(@TypeOf(data.writer())).init(data.writer());
        try self.serialize(&writer);
        
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
        
        var stream = std.io.fixedBufferStream(extension.extension_data);
        var reader = TlsReader(@TypeOf(stream.reader())).init(stream.reader());
        
        return NostrGroupData.deserialize(allocator, &reader);
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
    
    var writer = TlsWriter(@TypeOf(buffer.writer())).init(buffer.writer());
    try group_data.serialize(&writer);
    
    // Test deserialization
    var stream = std.io.fixedBufferStream(buffer.items);
    var reader = TlsReader(@TypeOf(stream.reader())).init(stream.reader());
    
    var decoded = try NostrGroupData.deserialize(allocator, &reader);
    defer decoded.deinit();
    
    // Verify data
    try testing.expectEqualSlices(u8, group_id, decoded.nostr_group_id.asSlice());
    try testing.expectEqualSlices(u8, creator_pubkey, decoded.creator_pubkey.asSlice());
    try testing.expectEqualSlices(u8, metadata, decoded.metadata.asSlice());
    try testing.expectEqual(@as(usize, 2), decoded.relay_urls.len);
    try testing.expectEqualSlices(u8, relay_urls[0], decoded.relay_urls[0].asSlice());
    try testing.expectEqualSlices(u8, relay_urls[1], decoded.relay_urls[1].asSlice());
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
        try testing.expectEqualSlices(u8, group_id, data.nostr_group_id.asSlice());
        try testing.expectEqualSlices(u8, creator_pubkey, data.creator_pubkey.asSlice());
    }
}

test "NIP-EE extension compatibility" {
    // Test that our extension types don't conflict with standard MLS
    try testing.expect(@intFromEnum(NostrExtensionType.nostr_group_data) >= 0xFF00);
    try testing.expect(@intFromEnum(NostrExtensionType.last_resort) >= 0xFF00);
    
    // Ratchet tree is a standard MLS extension
    try testing.expect(@intFromEnum(NostrExtensionType.ratchet_tree) < 0x0010);
}