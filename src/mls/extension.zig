const std = @import("std");
const types = @import("types.zig");

/// Nostr Group Data extension for MLS groups
pub const NostrGroupData = struct {
    /// Unique group ID
    group_id: types.GroupId,
    
    /// Human-readable group name
    name: []const u8,
    
    /// Group description
    description: []const u8,
    
    /// Admin public keys (Nostr hex format)
    admins: []const [32]u8,
    
    /// Relay URLs for this group
    relays: []const []const u8,
    
    /// Optional group image (base64 encoded)
    image: ?[]const u8,
    
    /// Create a new NostrGroupData
    pub fn init(
        group_id: types.GroupId,
        name: []const u8,
        description: []const u8,
        admins: []const [32]u8,
        relays: []const []const u8,
        image: ?[]const u8,
    ) NostrGroupData {
        return .{
            .group_id = group_id,
            .name = name,
            .description = description,
            .admins = admins,
            .relays = relays,
            .image = image,
        };
    }
    
    /// Check if a public key is an admin
    pub fn isAdmin(self: NostrGroupData, pubkey: [32]u8) bool {
        for (self.admins) |admin| {
            if (std.mem.eql(u8, &admin, &pubkey)) {
                return true;
            }
        }
        return false;
    }
};

/// Serialize NostrGroupData to MLS extension format
pub fn serializeNostrGroupData(
    allocator: std.mem.Allocator,
    data: NostrGroupData,
) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    
    // Version byte for future compatibility
    try buf.append(0x01);
    
    // Group ID (32 bytes)
    try buf.appendSlice(&data.group_id.data);
    
    // Name (length-prefixed)
    try writeString(&buf, data.name);
    
    // Description (length-prefixed)
    try writeString(&buf, data.description);
    
    // Number of admins
    try buf.append(@intCast(data.admins.len));
    
    // Admin public keys
    for (data.admins) |admin| {
        try buf.appendSlice(&admin);
    }
    
    // Number of relays
    try buf.append(@intCast(data.relays.len));
    
    // Relay URLs
    for (data.relays) |relay| {
        try writeString(&buf, relay);
    }
    
    // Image (optional)
    if (data.image) |img| {
        try buf.append(1); // Has image
        try writeString(&buf, img);
    } else {
        try buf.append(0); // No image
    }
    
    return try buf.toOwnedSlice();
}

/// Parse NostrGroupData from MLS extension format
pub fn parseNostrGroupData(
    allocator: std.mem.Allocator,
    data: []const u8,
) !NostrGroupData {
    if (data.len < 1) return error.InvalidExtension;
    
    var offset: usize = 0;
    
    // Check version
    const version = data[offset];
    offset += 1;
    if (version != 0x01) return error.UnsupportedVersion;
    
    // Group ID
    if (offset + 32 > data.len) return error.InvalidExtension;
    var group_id: types.GroupId = undefined;
    @memcpy(&group_id.data, data[offset..offset + 32]);
    offset += 32;
    
    // Name
    const name = try readString(allocator, data, &offset);
    
    // Description
    const description = try readString(allocator, data, &offset);
    
    // Admins
    if (offset >= data.len) return error.InvalidExtension;
    const admin_count = data[offset];
    offset += 1;
    
    var admins = try allocator.alloc([32]u8, admin_count);
    for (0..admin_count) |i| {
        if (offset + 32 > data.len) return error.InvalidExtension;
        @memcpy(&admins[i], data[offset..offset + 32]);
        offset += 32;
    }
    
    // Relays
    if (offset >= data.len) return error.InvalidExtension;
    const relay_count = data[offset];
    offset += 1;
    
    var relays = try allocator.alloc([]const u8, relay_count);
    for (0..relay_count) |i| {
        relays[i] = try readString(allocator, data, &offset);
    }
    
    // Image
    if (offset >= data.len) return error.InvalidExtension;
    const has_image = data[offset] != 0;
    offset += 1;
    
    const image = if (has_image)
        try readString(allocator, data, &offset)
    else
        null;
    
    return NostrGroupData{
        .group_id = group_id,
        .name = name,
        .description = description,
        .admins = admins,
        .relays = relays,
        .image = image,
    };
}

/// Create an MLS extension containing NostrGroupData
pub fn createNostrGroupDataExtension(
    allocator: std.mem.Allocator,
    data: NostrGroupData,
) !types.Extension {
    const serialized = try serializeNostrGroupData(allocator, data);
    return types.Extension{
        .extension_type = .nostr_group_data,
        .extension_data = serialized,
    };
}

/// Extract NostrGroupData from an MLS extension
pub fn extractNostrGroupData(
    allocator: std.mem.Allocator,
    extension: types.Extension,
) !NostrGroupData {
    if (extension.extension_type != .nostr_group_data) {
        return error.InvalidExtensionType;
    }
    return try parseNostrGroupData(allocator, extension.extension_data);
}

// Helper functions

fn writeString(buf: *std.ArrayList(u8), str: []const u8) !void {
    if (str.len > 255) return error.StringTooLong;
    try buf.append(@intCast(str.len));
    try buf.appendSlice(str);
}

fn readString(allocator: std.mem.Allocator, data: []const u8, offset: *usize) ![]const u8 {
    if (offset.* >= data.len) return error.InvalidExtension;
    
    const len = data[offset.*];
    offset.* += 1;
    
    if (offset.* + len > data.len) return error.InvalidExtension;
    
    const str = try allocator.alloc(u8, len);
    @memcpy(str, data[offset.*..offset.* + len]);
    offset.* += len;
    
    return str;
}

test "serialize and parse NostrGroupData" {
    const allocator = std.testing.allocator;
    
    const group_id = types.GroupId.init([_]u8{1} ** 32);
    const admin1: [32]u8 = [_]u8{2} ** 32;
    const admin2: [32]u8 = [_]u8{3} ** 32;
    
    const original = NostrGroupData{
        .group_id = group_id,
        .name = "Test Group",
        .description = "A test group for MLS",
        .admins = &[_][32]u8{ admin1, admin2 },
        .relays = &[_][]const u8{
            "wss://relay1.example.com",
            "wss://relay2.example.com",
        },
        .image = "base64encodedimage",
    };
    
    // Serialize
    const serialized = try serializeNostrGroupData(allocator, original);
    defer allocator.free(serialized);
    
    // Parse
    const parsed = try parseNostrGroupData(allocator, serialized);
    defer {
        allocator.free(parsed.name);
        allocator.free(parsed.description);
        allocator.free(parsed.admins);
        for (parsed.relays) |relay| {
            allocator.free(relay);
        }
        allocator.free(parsed.relays);
        if (parsed.image) |img| {
            allocator.free(img);
        }
    }
    
    // Verify
    try std.testing.expect(original.group_id.eql(parsed.group_id));
    try std.testing.expectEqualStrings(original.name, parsed.name);
    try std.testing.expectEqualStrings(original.description, parsed.description);
    try std.testing.expectEqual(original.admins.len, parsed.admins.len);
    try std.testing.expectEqualSlices(u8, &original.admins[0], &parsed.admins[0]);
    try std.testing.expectEqualSlices(u8, &original.admins[1], &parsed.admins[1]);
    try std.testing.expectEqual(original.relays.len, parsed.relays.len);
    try std.testing.expectEqualStrings(original.relays[0], parsed.relays[0]);
    try std.testing.expectEqualStrings(original.relays[1], parsed.relays[1]);
    try std.testing.expectEqualStrings(original.image.?, parsed.image.?);
}

test "isAdmin function" {
    const group_id = types.GroupId.init([_]u8{1} ** 32);
    const admin1: [32]u8 = [_]u8{2} ** 32;
    const admin2: [32]u8 = [_]u8{3} ** 32;
    const non_admin: [32]u8 = [_]u8{4} ** 32;
    
    const data = NostrGroupData{
        .group_id = group_id,
        .name = "Test",
        .description = "Test",
        .admins = &[_][32]u8{ admin1, admin2 },
        .relays = &.{},
        .image = null,
    };
    
    try std.testing.expect(data.isAdmin(admin1));
    try std.testing.expect(data.isAdmin(admin2));
    try std.testing.expect(!data.isAdmin(non_admin));
}

test "create and extract extension" {
    const allocator = std.testing.allocator;
    
    const group_id = types.GroupId.init([_]u8{5} ** 32);
    const data = NostrGroupData{
        .group_id = group_id,
        .name = "Extension Test",
        .description = "Testing extension creation",
        .admins = &[_][32]u8{[_]u8{6} ** 32},
        .relays = &[_][]const u8{"wss://test.relay"},
        .image = null,
    };
    
    // Create extension
    const extension = try createNostrGroupDataExtension(allocator, data);
    defer allocator.free(extension.extension_data);
    
    try std.testing.expectEqual(types.ExtensionType.nostr_group_data, extension.extension_type);
    
    // Extract data
    const extracted = try extractNostrGroupData(allocator, extension);
    defer {
        allocator.free(extracted.name);
        allocator.free(extracted.description);
        allocator.free(extracted.admins);
        for (extracted.relays) |relay| {
            allocator.free(relay);
        }
        allocator.free(extracted.relays);
    }
    
    try std.testing.expectEqualStrings(data.name, extracted.name);
    try std.testing.expectEqualStrings(data.description, extracted.description);
}