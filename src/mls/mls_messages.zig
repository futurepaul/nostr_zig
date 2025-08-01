const std = @import("std");
const tls = std.crypto.tls;
const mls_zig = @import("mls_zig");
const crypto = std.crypto;
const types = @import("types.zig");
const Allocator = std.mem.Allocator;

/// Wire format types as per MLS RFC 9420
pub const WireFormat = enum(u16) {
    mls_plaintext = 0x0001,
    mls_ciphertext = 0x0002,
    mls_welcome = 0x0003,
    mls_group_info = 0x0004,
    mls_key_package = 0x0005,
    
    pub fn tlsSerialize(self: WireFormat, writer: anytype) !void {
        try writer.writeU16(@intFromEnum(self));
    }
    
    pub fn tlsDeserialize(decoder: *tls.Decoder) !WireFormat {
        try decoder.ensure(2);
        const value = decoder.decode(u16);
        return switch (value) {
            0x0001 => .mls_plaintext,
            0x0002 => .mls_ciphertext,
            0x0003 => .mls_welcome,
            0x0004 => .mls_group_info,
            0x0005 => .mls_key_package,
            else => error.UnknownWireFormat,
        };
    }
};

/// Content type for MLS messages
pub const ContentType = enum(u8) {
    application = 0x01,
    proposal = 0x02,
    commit = 0x03,
    
    pub fn tlsSerialize(self: ContentType, writer: anytype) !void {
        try writer.writeU8(@intFromEnum(self));
    }
    
    pub fn tlsDeserialize(decoder: *tls.Decoder) !ContentType {
        try decoder.ensure(1);
        const value = decoder.decode(u8);
        return switch (value) {
            0x01 => .application,
            0x02 => .proposal,
            0x03 => .commit,
            else => error.UnknownContentType,
        };
    }
};

/// Sender type for MLS messages
pub const Sender = union(enum) {
    member: u32,
    external: u32,
    new_member_proposal: void,
    new_member_commit: void,
    
    pub fn tlsSerialize(self: Sender, writer: anytype) !void {
        switch (self) {
            .member => |index| {
                try writer.writeU8(1);
                try writer.writeU32(index);
            },
            .external => |index| {
                try writer.writeU8(2);
                try writer.writeU32(index);
            },
            .new_member_proposal => {
                try writer.writeU8(3);
            },
            .new_member_commit => {
                try writer.writeU8(4);
            },
        }
    }
    
    pub fn tlsDeserialize(decoder: *tls.Decoder) !Sender {
        try decoder.ensure(1);
        const sender_type = decoder.decode(u8);
        return switch (sender_type) {
            1 => blk: {
                try decoder.ensure(4);
                const bytes = decoder.slice(4);
                const index = std.mem.readInt(u32, bytes[0..4], .big);
                break :blk .{ .member = index };
            },
            2 => blk: {
                try decoder.ensure(4);
                const bytes = decoder.slice(4);
                const index = std.mem.readInt(u32, bytes[0..4], .big);
                break :blk .{ .external = index };
            },
            3 => .new_member_proposal,
            4 => .new_member_commit,
            else => error.UnknownSenderType,
        };
    }
};

/// Application data content for MLS messages
pub const ApplicationData = struct {
    data: []const u8,
    
    /// Create ApplicationData with owned memory
    pub fn init(allocator: Allocator, data: []const u8) !ApplicationData {
        const owned_data = try allocator.alloc(u8, data.len);
        @memcpy(owned_data, data);
        return ApplicationData{ .data = owned_data };
    }
    
    pub fn tlsSerialize(self: ApplicationData, writer: anytype) !void {
        try writer.writeVarBytes(u32, self.data);
    }
    
    pub fn tlsDeserialize(decoder: *tls.Decoder, allocator: Allocator) !ApplicationData {
        // Manual u32 var bytes decoding since readVarBytes doesn't support u32
        try decoder.ensure(4);
        const len_bytes = decoder.slice(4);
        const len = std.mem.readInt(u32, len_bytes[0..4], .big);
        try decoder.ensure(len);
        const data = try allocator.alloc(u8, len);
        @memcpy(data, decoder.slice(len));
        return ApplicationData{ .data = data };
    }
    
    pub fn deinit(self: ApplicationData, allocator: Allocator) void {
        allocator.free(self.data);
    }
};

/// Content union for different message types
pub const Content = union(ContentType) {
    application: ApplicationData,
    proposal: []const u8, // Simplified for now
    commit: []const u8,   // Simplified for now
    
    pub fn tlsSerialize(self: Content, writer: anytype) !void {
        const content_type = std.meta.activeTag(self);
        try content_type.tlsSerialize(writer);
        
        switch (self) {
            .application => |app_data| try app_data.tlsSerialize(writer),
            .proposal => |data| try writer.writeVarBytes(u32, data),
            .commit => |data| try writer.writeVarBytes(u32, data),
        }
    }
    
    pub fn tlsDeserialize(decoder: *tls.Decoder, allocator: Allocator) !Content {
        const content_type = try ContentType.tlsDeserialize(decoder);
        return switch (content_type) {
            .application => .{ .application = try ApplicationData.tlsDeserialize(decoder, allocator) },
            .proposal => blk: {
                // Manual u32 var bytes decoding
                try decoder.ensure(4);
                const len_bytes = decoder.slice(4);
                const len = std.mem.readInt(u32, len_bytes[0..4], .big);
                try decoder.ensure(len);
                const data = try allocator.alloc(u8, len);
                @memcpy(data, decoder.slice(len));
                break :blk .{ .proposal = data };
            },
            .commit => blk: {
                // Manual u32 var bytes decoding
                try decoder.ensure(4);
                const len_bytes = decoder.slice(4);
                const len = std.mem.readInt(u32, len_bytes[0..4], .big);
                try decoder.ensure(len);
                const data = try allocator.alloc(u8, len);
                @memcpy(data, decoder.slice(len));
                break :blk .{ .commit = data };
            },
        };
    }
    
    pub fn deinit(self: Content, allocator: Allocator) void {
        switch (self) {
            .application => |app_data| app_data.deinit(allocator),
            .proposal => |data| allocator.free(data),
            .commit => |data| allocator.free(data),
        }
    }
};

/// MLS Plaintext message structure per RFC 9420
pub const MLSPlaintext = struct {
    wire_format: WireFormat,
    group_id: [32]u8,
    epoch: u64,
    sender: Sender,
    authenticated_data: []const u8,
    content: Content,
    signature: []const u8,
    
    pub fn init(
        allocator: Allocator,
        group_id: [32]u8,
        epoch: u64,
        sender: Sender,
        authenticated_data: []const u8,
        content: Content,
        signature: []const u8,
    ) !MLSPlaintext {
        return MLSPlaintext{
            .wire_format = .mls_plaintext,
            .group_id = group_id,
            .epoch = epoch,
            .sender = sender,
            .authenticated_data = try allocator.dupe(u8, authenticated_data),
            .content = content,
            .signature = try allocator.dupe(u8, signature),
        };
    }
    
    pub fn deinit(self: *MLSPlaintext, allocator: Allocator) void {
        allocator.free(self.authenticated_data);
        self.content.deinit(allocator);
        allocator.free(self.signature);
    }
    
    /// Serialize to TLS wire format
    pub fn tlsSerialize(self: MLSPlaintext, writer: anytype) !void {
        // Wire format
        try self.wire_format.tlsSerialize(writer);
        
        // Group ID (32 bytes with length prefix)
        try writer.writeVarBytes(u8, &self.group_id);
        
        // Epoch
        try writer.writeU64(self.epoch);
        
        // Sender
        try self.sender.tlsSerialize(writer);
        
        // Authenticated data
        try writer.writeVarBytes(u32, self.authenticated_data);
        
        // Content
        try self.content.tlsSerialize(writer);
        
        // Signature
        try writer.writeVarBytes(u16, self.signature);
    }
    
    /// Deserialize from TLS wire format
    pub fn tlsDeserialize(decoder: *tls.Decoder, allocator: Allocator) !MLSPlaintext {
        const wire_format = try WireFormat.tlsDeserialize(decoder);
        if (wire_format != .mls_plaintext) return error.InvalidWireFormat;
        
        const group_id_bytes = try mls_zig.tls_encode.readVarBytes(decoder, u8, allocator);
        defer allocator.free(group_id_bytes);
        if (group_id_bytes.len != 32) return error.InvalidGroupIdLength;
        
        var group_id: [32]u8 = undefined;
        @memcpy(&group_id, group_id_bytes);
        
        // Manual u64 decoding since std.crypto.tls doesn't support it
        try decoder.ensure(8);
        const epoch_bytes = decoder.slice(8);
        const epoch = std.mem.readInt(u64, epoch_bytes[0..8], .big);
        const sender = try Sender.tlsDeserialize(decoder);
        // Manual u32 var bytes decoding since readVarBytes doesn't support u32
        try decoder.ensure(4);
        const auth_len_bytes = decoder.slice(4);
        const auth_len = std.mem.readInt(u32, auth_len_bytes[0..4], .big);
        try decoder.ensure(auth_len);
        const authenticated_data = try allocator.alloc(u8, auth_len);
        @memcpy(authenticated_data, decoder.slice(auth_len));
        const content = try Content.tlsDeserialize(decoder, allocator);
        const signature = try mls_zig.tls_encode.readVarBytes(decoder, u16, allocator);
        
        return MLSPlaintext{
            .wire_format = wire_format,
            .group_id = group_id,
            .epoch = epoch,
            .sender = sender,
            .authenticated_data = authenticated_data,
            .content = content,
            .signature = signature,
        };
    }
    
    /// Create the content that needs to be signed
    pub fn getSigningContent(self: MLSPlaintext, allocator: Allocator) ![]u8 {
        var content_buffer = std.ArrayList(u8).init(allocator);
        defer content_buffer.deinit();
        
        // Wire format (u16)
        try mls_zig.tls_encode.encodeInt(&content_buffer, u16, @intFromEnum(self.wire_format));
        
        // Group ID with length prefix (u8)
        try mls_zig.tls_encode.encodeVarBytes(&content_buffer, u8, &self.group_id);
        
        // Epoch (u64)
        try mls_zig.tls_encode.encodeInt(&content_buffer, u64, self.epoch);
        
        // Sender - use proper union serialization
        switch (self.sender) {
            .member => |index| {
                try mls_zig.tls_encode.encodeInt(&content_buffer, u8, 1);
                try mls_zig.tls_encode.encodeInt(&content_buffer, u32, index);
            },
            .external => |index| {
                try mls_zig.tls_encode.encodeInt(&content_buffer, u8, 2);
                try mls_zig.tls_encode.encodeInt(&content_buffer, u32, index);
            },
            .new_member_proposal => {
                try mls_zig.tls_encode.encodeInt(&content_buffer, u8, 3);
            },
            .new_member_commit => {
                try mls_zig.tls_encode.encodeInt(&content_buffer, u8, 4);
            },
        }
        
        // Authenticated data with length prefix (u32)
        try mls_zig.tls_encode.encodeVarBytes(&content_buffer, u32, self.authenticated_data);
        
        // Content type (u8)
        const content_type = switch (self.content) {
            .application => ContentType.application,
            .proposal => ContentType.proposal,
            .commit => ContentType.commit,
        };
        try mls_zig.tls_encode.encodeInt(&content_buffer, u8, @intFromEnum(content_type));
        
        // Content data based on type
        switch (self.content) {
            .application => |app_data| {
                // Application data with length prefix (u32)
                try mls_zig.tls_encode.encodeVarBytes(&content_buffer, u32, app_data.data);
            },
            .proposal => |data| {
                // For now, proposal content is raw bytes
                try mls_zig.tls_encode.encodeVarBytes(&content_buffer, u32, data);
            },
            .commit => |data| {
                // For now, commit content is raw bytes
                try mls_zig.tls_encode.encodeVarBytes(&content_buffer, u32, data);
            },
        }
        
        return try content_buffer.toOwnedSlice();
    }
};

/// Top-level MLS Message structure
pub const MLSMessage = struct {
    plaintext: MLSPlaintext,
    
    pub fn init(plaintext: MLSPlaintext) MLSMessage {
        return MLSMessage{ .plaintext = plaintext };
    }
    
    pub fn deinit(self: *MLSMessage, allocator: Allocator) void {
        self.plaintext.deinit(allocator);
    }
    
    /// Serialize to TLS wire format
    pub fn tlsSerialize(self: MLSMessage, writer: anytype) !void {
        try self.plaintext.tlsSerialize(writer);
    }
    
    /// Deserialize from TLS wire format
    pub fn tlsDeserialize(reader: anytype, allocator: Allocator) !MLSMessage {
        const plaintext = try MLSPlaintext.tlsDeserialize(reader, allocator);
        return MLSMessage{ .plaintext = plaintext };
    }
    
    /// Create an application message
    pub fn createApplicationMessage(
        allocator: Allocator,
        group_id: [32]u8,
        epoch: u64,
        sender_index: u32,
        application_data: []const u8,
        signature: []const u8,
    ) !MLSMessage {
        const sender = Sender{ .member = sender_index };
        const app_data = try ApplicationData.init(allocator, application_data);
        const content = Content{ .application = app_data };
        
        const plaintext = try MLSPlaintext.init(
            allocator,
            group_id,
            epoch,
            sender,
            &[_]u8{}, // Empty authenticated data
            content,
            signature,
        );
        
        return MLSMessage{ .plaintext = plaintext };
    }
};

/// Utility functions for Nostr integration

/// Create a properly formatted MLSMessage for a Group Event
pub fn createGroupEventMLSMessage(
    allocator: Allocator,
    group_id: [32]u8,
    epoch: u64,
    sender_index: u32,
    nostr_event_json: []const u8,
    mls_signature: []const u8,
) !MLSMessage {
    return try MLSMessage.createApplicationMessage(
        allocator,
        group_id,
        epoch,
        sender_index,
        nostr_event_json,
        mls_signature,
    );
}

/// Serialize MLSMessage to bytes for NIP-44 encryption
pub fn serializeMLSMessageForEncryption(allocator: Allocator, message: MLSMessage) ![]u8 {
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    
    const plaintext = message.plaintext;
    
    // Wire format (u16)
    try mls_zig.tls_encode.encodeInt(&buffer, u16, @intFromEnum(plaintext.wire_format));
    
    // Group ID with length prefix (u8)
    try mls_zig.tls_encode.encodeVarBytes(&buffer, u8, &plaintext.group_id);
    
    // Epoch (u64)
    try mls_zig.tls_encode.encodeInt(&buffer, u64, plaintext.epoch);
    
    // Sender - use proper union serialization
    switch (plaintext.sender) {
        .member => |index| {
            try mls_zig.tls_encode.encodeInt(&buffer, u8, 1);
            try mls_zig.tls_encode.encodeInt(&buffer, u32, index);
        },
        .external => |index| {
            try mls_zig.tls_encode.encodeInt(&buffer, u8, 2);
            try mls_zig.tls_encode.encodeInt(&buffer, u32, index);
        },
        .new_member_proposal => {
            try mls_zig.tls_encode.encodeInt(&buffer, u8, 3);
        },
        .new_member_commit => {
            try mls_zig.tls_encode.encodeInt(&buffer, u8, 4);
        },
    }
    
    // Authenticated data with length prefix (u32)
    try mls_zig.tls_encode.encodeVarBytes(&buffer, u32, plaintext.authenticated_data);
    
    // Content type (u8)
    const content_type = switch (plaintext.content) {
        .application => ContentType.application,
        .proposal => ContentType.proposal,
        .commit => ContentType.commit,
    };
    try mls_zig.tls_encode.encodeInt(&buffer, u8, @intFromEnum(content_type));
    
    // Content data
    switch (plaintext.content) {
        .application => |app_data| {
            // Application data with length prefix (u32)
            try mls_zig.tls_encode.encodeVarBytes(&buffer, u32, app_data.data);
        },
        .proposal => |data| {
            // For now, proposal content is raw bytes
            try mls_zig.tls_encode.encodeVarBytes(&buffer, u32, data);
        },
        .commit => |data| {
            // For now, commit content is raw bytes  
            try mls_zig.tls_encode.encodeVarBytes(&buffer, u32, data);
        },
    }
    
    // Signature with length prefix (u16)
    try mls_zig.tls_encode.encodeVarBytes(&buffer, u16, plaintext.signature);
    
    return try buffer.toOwnedSlice();
}

/// Deserialize MLSMessage from bytes after NIP-44 decryption
pub fn deserializeMLSMessageFromDecryption(allocator: Allocator, data: []const u8) !MLSMessage {
    var decoder = tls.Decoder.fromTheirSlice(@constCast(data));
    
    return try MLSMessage.tlsDeserialize(&decoder, allocator);
}

// Tests

test "MLSMessage TLS serialization roundtrip" {
    const allocator = std.testing.allocator;
    
    // Create test data
    const group_id: [32]u8 = [_]u8{0x42} ** 32;
    const epoch: u64 = 123;
    const sender_index: u32 = 456;
    const app_data = "test message content";
    const signature = [_]u8{0x01} ** 64;
    
    // Create MLSMessage
    var message = try createGroupEventMLSMessage(
        allocator,
        group_id,
        epoch,
        sender_index,
        app_data,
        &signature,
    );
    defer message.deinit(allocator);
    
    // Serialize
    const serialized = try serializeMLSMessageForEncryption(allocator, message);
    defer allocator.free(serialized);
    
    // Deserialize
    var deserialized = try deserializeMLSMessageFromDecryption(allocator, serialized);
    defer deserialized.deinit(allocator);
    
    // Verify
    try std.testing.expectEqual(group_id, deserialized.plaintext.group_id);
    try std.testing.expectEqual(epoch, deserialized.plaintext.epoch);
    try std.testing.expectEqual(sender_index, deserialized.plaintext.sender.member);
    try std.testing.expectEqualSlices(u8, app_data, deserialized.plaintext.content.application.data);
    try std.testing.expectEqualSlices(u8, &signature, deserialized.plaintext.signature);
}

test "WireFormat serialization" {
    var stream_buffer: [10]u8 = undefined;
    var stream = std.io.fixedBufferStream(&stream_buffer);
    
    const wire_format = WireFormat.mls_plaintext;
    var list_buffer = std.ArrayList(u8).init(std.testing.allocator);
    defer list_buffer.deinit();
    
    try mls_zig.tls_encode.encodeInt(&list_buffer, u16, @intFromEnum(wire_format));
    _ = try stream.write(list_buffer.items);
    
    // Reset stream for reading
    stream.reset();
    var decoder = tls.Decoder.fromTheirSlice(list_buffer.items);
    
    const deserialized = try WireFormat.tlsDeserialize(&decoder);
    try std.testing.expectEqual(WireFormat.mls_plaintext, deserialized);
}

test "ApplicationData serialization" {
    const allocator = std.testing.allocator;
    
    const test_data = "Hello, MLS!";
    const app_data = ApplicationData{ .data = test_data };
    
    var buffer: [100]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);
    
    var list_buffer = std.ArrayList(u8).init(allocator);
    defer list_buffer.deinit();
    
    try mls_zig.tls_encode.encodeVarBytes(&list_buffer, u32, app_data.data);
    _ = try stream.write(list_buffer.items);
    
    // Reset stream for reading
    stream.reset();
    var decoder = tls.Decoder.fromTheirSlice(list_buffer.items);
    
    var deserialized = try ApplicationData.tlsDeserialize(&decoder, allocator);
    defer deserialized.deinit(allocator);
    
    try std.testing.expectEqualSlices(u8, test_data, deserialized.data);
}