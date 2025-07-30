const std = @import("std");
const testing = std.testing;

/// Error types for TLS codec operations
pub const TlsCodecError = error{
    /// Buffer too small for operation
    BufferTooSmall,
    /// Invalid data format
    InvalidFormat,
    /// Value too large for encoding
    ValueTooLarge,
    /// Memory allocation failed
    OutOfMemory,
    /// End of stream reached unexpectedly
    EndOfStream,
    /// Write operation didn't write all bytes
    ShortWrite,
};

/// Helper functions for manual TLS serialization
/// Use these instead of the removed TlsWriter for ArrayList operations

/// Write a u8 to ArrayList
pub fn writeU8ToList(list: *std.ArrayList(u8), value: u8) !void {
    try list.append(value);
}

/// Write a u16 in big-endian to ArrayList
pub fn writeU16ToList(list: *std.ArrayList(u8), value: u16) !void {
    var buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &buf, value, .big);
    try list.appendSlice(&buf);
}

/// Write a u32 in big-endian to ArrayList
pub fn writeU32ToList(list: *std.ArrayList(u8), value: u32) !void {
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, value, .big);
    try list.appendSlice(&buf);
}

/// Write a u64 in big-endian to ArrayList
pub fn writeU64ToList(list: *std.ArrayList(u8), value: u64) !void {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, value, .big);
    try list.appendSlice(&buf);
}

/// Write raw bytes to ArrayList
pub fn writeBytesToList(list: *std.ArrayList(u8), bytes: []const u8) !void {
    try list.appendSlice(bytes);
}

/// Write variable-length bytes with length prefix to ArrayList
pub fn writeVarBytesToList(list: *std.ArrayList(u8), comptime LenType: type, bytes: []const u8) !void {
    if (bytes.len > std.math.maxInt(LenType)) {
        return TlsCodecError.ValueTooLarge;
    }
    
    switch (LenType) {
        u8 => try writeU8ToList(list, @intCast(bytes.len)),
        u16 => try writeU16ToList(list, @intCast(bytes.len)),
        u32 => try writeU32ToList(list, @intCast(bytes.len)),
        else => @compileError("Unsupported length type"),
    }
    
    try writeBytesToList(list, bytes);
}

/// Write TLS opaque<V> with proper variable-length encoding per RFC 8446
/// Uses single byte for lengths < 256, two bytes for larger values
pub fn writeTlsOpaqueToList(list: *std.ArrayList(u8), bytes: []const u8, max_len: u32) !void {
    if (bytes.len > max_len) {
        return TlsCodecError.ValueTooLarge;
    }
    
    // Determine encoding based on max_len
    if (max_len < 256) {
        // Use single byte length prefix
        try writeU8ToList(list, @intCast(bytes.len));
    } else if (max_len < 65536) {
        // Use two byte length prefix
        try writeU16ToList(list, @intCast(bytes.len));
    } else {
        // Use three byte length prefix (u24)
        const len: u32 = @intCast(bytes.len);
        try writeU8ToList(list, @intCast((len >> 16) & 0xFF));
        try writeU8ToList(list, @intCast((len >> 8) & 0xFF));
        try writeU8ToList(list, @intCast(len & 0xFF));
    }
    
    try writeBytesToList(list, bytes);
}

/// Reader interface for TLS deserialization
pub fn TlsReader(comptime ReaderType: type) type {
    return struct {
        const Self = @This();
        
        reader: ReaderType,
        bytes_read: usize,

        pub fn init(reader: ReaderType) Self {
            return .{
                .reader = reader,
                .bytes_read = 0,
            };
        }

        /// Read a u8
        pub fn readU8(self: *Self) !u8 {
            const byte = try self.reader.readByte();
            self.bytes_read += 1;
            return byte;
        }

        /// Read a u16 in big-endian
        pub fn readU16(self: *Self) !u16 {
            var buf: [2]u8 = undefined;
            _ = try self.reader.readAll(&buf);
            self.bytes_read += 2;
            return std.mem.readInt(u16, &buf, .big);
        }

        /// Read a u32 in big-endian
        pub fn readU32(self: *Self) !u32 {
            var buf: [4]u8 = undefined;
            _ = try self.reader.readAll(&buf);
            self.bytes_read += 4;
            return std.mem.readInt(u32, &buf, .big);
        }

        /// Read a u64 in big-endian
        pub fn readU64(self: *Self) !u64 {
            var buf: [8]u8 = undefined;
            _ = try self.reader.readAll(&buf);
            self.bytes_read += 8;
            return std.mem.readInt(u64, &buf, .big);
        }

        /// Read exact number of bytes
        pub fn readBytes(self: *Self, buf: []u8) !void {
            _ = try self.reader.readAll(buf);
            self.bytes_read += buf.len;
        }

        /// Read variable-length bytes with length prefix
        pub fn readVarBytes(self: *Self, comptime LenType: type, allocator: std.mem.Allocator) ![]u8 {
            const len = switch (LenType) {
                u8 => try self.readU8(),
                u16 => try self.readU16(),
                u32 => try self.readU32(),
                else => @compileError("Unsupported length type"),
            };
            
            const bytes = try allocator.alloc(u8, len);
            errdefer allocator.free(bytes);
            
            try self.readBytes(bytes);
            return bytes;
        }
        
        /// Read TLS opaque<V> with proper variable-length encoding per RFC 8446
        /// Determines encoding based on max_len parameter
        pub fn readTlsOpaque(self: *Self, allocator: std.mem.Allocator, max_len: u32) ![]u8 {
            const len = if (max_len < 256) blk: {
                // Single byte length
                break :blk @as(u32, try self.readU8());
            } else if (max_len < 65536) blk: {
                // Two byte length
                break :blk @as(u32, try self.readU16());
            } else blk: {
                // Three byte length (u24)
                const b1 = @as(u32, try self.readU8());
                const b2 = @as(u32, try self.readU8());
                const b3 = @as(u32, try self.readU8());
                break :blk (b1 << 16) | (b2 << 8) | b3;
            };
            
            if (len > max_len) {
                return TlsCodecError.ValueTooLarge;
            }
            
            const bytes = try allocator.alloc(u8, len);
            errdefer allocator.free(bytes);
            
            try self.readBytes(bytes);
            return bytes;
        }
    };
}

/// Variable-length bytes wrapper
/// Arena-based VarBytes - simple and WASM-friendly memory management
pub const VarBytes = struct {
    data: []const u8,
    allocator: std.mem.Allocator,
    
    /// Create VarBytes from data - data is owned by the caller's arena
    pub fn init(allocator: std.mem.Allocator, data: []const u8) !VarBytes {
        const owned_data = try allocator.dupe(u8, data);
        return VarBytes{
            .data = owned_data,
            .allocator = allocator,
        };
    }
    
    /// Create VarBytes that directly references external data (no copy)
    /// Use this when data is already managed by an arena
    pub fn fromSlice(allocator: std.mem.Allocator, data: []const u8) VarBytes {
        return VarBytes{
            .data = data,
            .allocator = allocator,
        };
    }

    /// No-op deinit - arena manages all memory
    /// Kept for API compatibility
    pub fn deinit(self: *VarBytes) void {
        _ = self;
    }

    pub fn asSlice(self: *const VarBytes) []const u8 {
        return self.data;
    }

    /// Get the length of the data
    pub fn len(self: *const VarBytes) usize {
        return self.data.len;
    }

    /// Create a copy of this VarBytes in a new arena
    pub fn clone(self: *const VarBytes, allocator: std.mem.Allocator) !VarBytes {
        return VarBytes.init(allocator, self.data);
    }
    
    /// Create a shared copy (no allocation needed with arena pattern)
    pub fn share(self: *const VarBytes) VarBytes {
        return VarBytes{
            .data = self.data,
            .allocator = self.allocator,
        };
    }
    
    /// No-op for arena pattern - always "owned" by arena
    pub fn makeOwned(self: *VarBytes, allocator: std.mem.Allocator) !void {
        _ = self;
        _ = allocator;
    }
};

/// Interface for types that can be TLS serialized
pub fn TlsSerializable(comptime T: type) type {
    return struct {
        pub fn tlsSerialize(self: *const T, writer: anytype) !void {
            return T.tlsSerialize(self, writer);
        }
        
        pub fn tlsSerializedLen(self: *const T) usize {
            return T.tlsSerializedLen(self);
        }
    };
}

/// Interface for types that can be TLS deserialized
pub fn TlsDeserializable(comptime T: type) type {
    return struct {
        pub fn tlsDeserialize(reader: anytype, allocator: std.mem.Allocator) !T {
            return T.tlsDeserialize(reader, allocator);
        }
    };
}

// Tests

test "TLS helper functions basic types" {
    var list = std.ArrayList(u8).init(testing.allocator);
    defer list.deinit();
    
    try writeU8ToList(&list, 0x42);
    try writeU16ToList(&list, 0x1234);
    try writeU32ToList(&list, 0x12345678);
    
    try testing.expectEqual(@as(usize, 7), list.items.len);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x42, 0x12, 0x34, 0x12, 0x34, 0x56, 0x78 }, list.items);
}

test "TLS reader basic types" {
    const data = [_]u8{ 0x42, 0x12, 0x34, 0x12, 0x34, 0x56, 0x78 };
    var stream = std.io.fixedBufferStream(&data);
    var reader = TlsReader(@TypeOf(stream.reader())).init(stream.reader());
    
    try testing.expectEqual(@as(u8, 0x42), try reader.readU8());
    try testing.expectEqual(@as(u16, 0x1234), try reader.readU16());
    try testing.expectEqual(@as(u32, 0x12345678), try reader.readU32());
    try testing.expectEqual(@as(usize, 7), reader.bytes_read);
}

test "TLS variable-length bytes" {
    const allocator = testing.allocator;
    
    // Test writing
    var list = std.ArrayList(u8).init(testing.allocator);
    defer list.deinit();
    
    const test_data = "Hello, TLS!";
    try writeVarBytesToList(&list, u8, test_data);
    
    // Should write: [length byte][data...]
    try testing.expectEqual(@as(u8, test_data.len), list.items[0]);
    try testing.expectEqualSlices(u8, test_data, list.items[1..1 + test_data.len]);
    
    // Test reading
    var stream = std.io.fixedBufferStream(list.items);
    var reader = TlsReader(@TypeOf(stream.reader())).init(stream.reader());
    
    const read_data = try reader.readVarBytes(u8, allocator);
    defer allocator.free(read_data);
    
    try testing.expectEqualSlices(u8, test_data, read_data);
}

test "TLS u16 length prefix" {
    const allocator = testing.allocator;
    
    var list = std.ArrayList(u8).init(testing.allocator);
    defer list.deinit();
    
    // Create data longer than 255 bytes
    const test_data = [_]u8{0x55} ** 300;
    try writeVarBytesToList(&list, u16, &test_data);
    
    // Check length encoding
    try testing.expectEqual(@as(u16, 300), std.mem.readInt(u16, list.items[0..2], .big));
    
    // Test reading
    var stream = std.io.fixedBufferStream(list.items);
    var reader = TlsReader(@TypeOf(stream.reader())).init(stream.reader());
    
    const read_data = try reader.readVarBytes(u16, allocator);
    defer allocator.free(read_data);
    
    try testing.expectEqual(@as(usize, 300), read_data.len);
    try testing.expectEqualSlices(u8, &test_data, read_data);
}