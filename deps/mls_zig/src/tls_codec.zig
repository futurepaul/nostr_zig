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
};

/// Writer interface for TLS serialization
pub fn TlsWriter(comptime WriterType: type) type {
    return struct {
        const Self = @This();
        
        writer: WriterType,
        bytes_written: usize,

        pub fn init(writer: WriterType) Self {
            return .{
                .writer = writer,
                .bytes_written = 0,
            };
        }

        /// Write a u8
        pub fn writeU8(self: *Self, value: u8) !void {
            try self.writer.writeByte(value);
            self.bytes_written += 1;
        }

        /// Write a u16 in big-endian
        pub fn writeU16(self: *Self, value: u16) !void {
            var buf: [2]u8 = undefined;
            std.mem.writeInt(u16, &buf, value, .big);
            try self.writer.writeAll(&buf);
            self.bytes_written += 2;
        }

        /// Write a u32 in big-endian
        pub fn writeU32(self: *Self, value: u32) !void {
            var buf: [4]u8 = undefined;
            std.mem.writeInt(u32, &buf, value, .big);
            try self.writer.writeAll(&buf);
            self.bytes_written += 4;
        }

        /// Write a u64 in big-endian
        pub fn writeU64(self: *Self, value: u64) !void {
            var buf: [8]u8 = undefined;
            std.mem.writeInt(u64, &buf, value, .big);
            try self.writer.writeAll(&buf);
            self.bytes_written += 8;
        }

        /// Write raw bytes
        pub fn writeBytes(self: *Self, bytes: []const u8) !void {
            try self.writer.writeAll(bytes);
            self.bytes_written += bytes.len;
        }

        /// Write variable-length bytes with length prefix
        pub fn writeVarBytes(self: *Self, comptime LenType: type, bytes: []const u8) !void {
            if (bytes.len > std.math.maxInt(LenType)) {
                return TlsCodecError.ValueTooLarge;
            }
            
            switch (LenType) {
                u8 => try self.writeU8(@intCast(bytes.len)),
                u16 => try self.writeU16(@intCast(bytes.len)),
                u32 => try self.writeU32(@intCast(bytes.len)),
                else => @compileError("Unsupported length type"),
            }
            
            try self.writeBytes(bytes);
        }
    };
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
    };
}

/// Variable-length bytes wrapper
pub const VarBytes = struct {
    data: []const u8,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, data: []const u8) !VarBytes {
        const owned_data = try allocator.dupe(u8, data);
        return VarBytes{
            .data = owned_data,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *VarBytes) void {
        self.allocator.free(self.data);
    }

    pub fn asSlice(self: *const VarBytes) []const u8 {
        return self.data;
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

test "TLS writer basic types" {
    var buf: [100]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    var writer = TlsWriter(@TypeOf(stream.writer())).init(stream.writer());
    
    try writer.writeU8(0x42);
    try writer.writeU16(0x1234);
    try writer.writeU32(0x12345678);
    
    try testing.expectEqual(@as(usize, 7), writer.bytes_written);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x42, 0x12, 0x34, 0x12, 0x34, 0x56, 0x78 }, buf[0..7]);
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
    var buf: [100]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    var writer = TlsWriter(@TypeOf(stream.writer())).init(stream.writer());
    
    const test_data = "Hello, TLS!";
    try writer.writeVarBytes(u8, test_data);
    
    // Should write: [length byte][data...]
    try testing.expectEqual(@as(u8, test_data.len), buf[0]);
    try testing.expectEqualSlices(u8, test_data, buf[1..1 + test_data.len]);
    
    // Test reading
    stream.reset();
    var reader = TlsReader(@TypeOf(stream.reader())).init(stream.reader());
    
    const read_data = try reader.readVarBytes(u8, allocator);
    defer allocator.free(read_data);
    
    try testing.expectEqualSlices(u8, test_data, read_data);
}

test "TLS u16 length prefix" {
    const allocator = testing.allocator;
    
    var buf: [1000]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    var writer = TlsWriter(@TypeOf(stream.writer())).init(stream.writer());
    
    // Create data longer than 255 bytes
    const test_data = [_]u8{0x55} ** 300;
    try writer.writeVarBytes(u16, &test_data);
    
    // Check length encoding
    try testing.expectEqual(@as(u16, 300), std.mem.readInt(u16, buf[0..2], .big));
    
    // Test reading
    stream.reset();
    var reader = TlsReader(@TypeOf(stream.reader())).init(stream.reader());
    
    const read_data = try reader.readVarBytes(u16, allocator);
    defer allocator.free(read_data);
    
    try testing.expectEqual(@as(usize, 300), read_data.len);
    try testing.expectEqualSlices(u8, &test_data, read_data);
}