const std = @import("std");
const tls = std.crypto.tls;

/// Helper functions for TLS wire format encoding using std.crypto.tls

/// Write a variable-length byte array with a length prefix
pub fn writeVarBytes(writer: anytype, comptime LenType: type, data: []const u8) !void {
    if (data.len > std.math.maxInt(LenType)) {
        return error.DataTooLarge;
    }
    if (LenType == u32) {
        // Manual u32 encoding since std.crypto.tls doesn't support it
        const len: u32 = @intCast(data.len);
        var buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &buf, len, .big);
        try writer.writeAll(&buf);
    } else {
        try writer.writeAll(&tls.int(LenType, @intCast(data.len)));
    }
    try writer.writeAll(data);
}

/// Encode variable-length bytes to an ArrayList
pub fn encodeVarBytes(list: *std.ArrayList(u8), comptime LenType: type, data: []const u8) !void {
    try writeVarBytes(list.writer(), LenType, data);
}

/// Write a fixed-size integer in network byte order
pub fn writeInt(writer: anytype, comptime T: type, value: T) !void {
    if (T == u32) {
        // Manual u32 encoding since std.crypto.tls doesn't support it
        var buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &buf, value, .big);
        try writer.writeAll(&buf);
    } else {
        try writer.writeAll(&tls.int(T, value));
    }
}

/// Encode an integer to an ArrayList
pub fn encodeInt(list: *std.ArrayList(u8), comptime T: type, value: T) !void {
    if (T == u32) {
        var buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &buf, value, .big);
        try list.appendSlice(&buf);
    } else {
        try list.appendSlice(&tls.int(T, value));
    }
}

/// Read variable-length bytes with a length prefix
/// Note: This function is primarily used for reading data that was encoded with writeVarBytes
/// For typical TLS decoding, use the reader-based version instead
pub fn readVarBytes(decoder: *tls.Decoder, comptime LenType: type, allocator: std.mem.Allocator) ![]u8 {
    // Ensure we have enough bytes for the length field
    try decoder.ensure(@sizeOf(LenType));
    const len = switch (LenType) {
        u8 => @as(usize, decoder.decode(u8)),
        u16 => @as(usize, decoder.decode(u16)),
        // u32 is not supported by std.crypto.tls.Decoder
        else => @compileError("Unsupported length type for TLS decoder: " ++ @typeName(LenType)),
    };
    // Ensure we have enough bytes for the data
    try decoder.ensure(len);
    const data = try allocator.alloc(u8, len);
    @memcpy(data, decoder.slice(len));
    return data;
}

/// Read variable-length bytes from a reader with manual length decoding
pub fn readVarBytesFromReader(reader: anytype, comptime LenType: type, allocator: std.mem.Allocator) ![]u8 {
    var len_buf: [@sizeOf(LenType)]u8 = undefined;
    _ = try reader.readAll(&len_buf);
    var decoder = tls.Decoder.fromTheirSlice(&len_buf);
    const len = switch (LenType) {
        u8 => @as(usize, decoder.decode(u8)),
        u16 => @as(usize, decoder.decode(u16)),
        u32 => blk: {
            // Manual u32 decoding since std.crypto.tls doesn't support it
            break :blk @as(usize, std.mem.readInt(u32, &len_buf, .big));
        },
        else => @compileError("Unsupported length type: " ++ @typeName(LenType)),
    };
    
    const data = try allocator.alloc(u8, len);
    _ = try reader.readAll(data);
    return data;
}

/// Read variable-length bytes into a pre-allocated buffer
pub fn readVarBytesInto(decoder: *tls.Decoder, comptime LenType: type, buffer: []u8) ![]u8 {
    const len = decoder.decode(LenType);
    if (len > buffer.len) return error.BufferTooSmall;
    @memcpy(buffer[0..len], decoder.slice(len));
    return buffer[0..len];
}

/// Write TLS opaque<V> with proper variable-length encoding per RFC 8446
/// Uses single byte for lengths < 256, two bytes for larger values
pub fn writeTlsOpaque(writer: anytype, bytes: []const u8, max_len: u32) !void {
    if (bytes.len > max_len) {
        return error.DataTooLarge;
    }
    
    // Determine encoding based on max_len
    if (max_len < 256) {
        // Use single byte length prefix
        try writeInt(writer, u8, @intCast(bytes.len));
    } else if (max_len < 65536) {
        // Use two byte length prefix
        try writeInt(writer, u16, @intCast(bytes.len));
    } else {
        // Use three byte length prefix (u24)
        const len: u32 = @intCast(bytes.len);
        try writeInt(writer, u8, @intCast((len >> 16) & 0xFF));
        try writeInt(writer, u8, @intCast((len >> 8) & 0xFF));
        try writeInt(writer, u8, @intCast(len & 0xFF));
    }
    
    try writer.writeAll(bytes);
}

/// Encode TLS opaque to an ArrayList
pub fn encodeTlsOpaque(list: *std.ArrayList(u8), bytes: []const u8, max_len: u32) !void {
    try writeTlsOpaque(list.writer(), bytes, max_len);
}

/// Read TLS opaque<V> with proper variable-length encoding per RFC 8446
/// Determines encoding based on max_len parameter
pub fn readTlsOpaque(decoder: *tls.Decoder, allocator: std.mem.Allocator, max_len: u32) ![]u8 {
    const len = if (max_len < 256) blk: {
        // Single byte length
        try decoder.ensure(1);
        break :blk @as(u32, decoder.decode(u8));
    } else if (max_len < 65536) blk: {
        // Two byte length
        try decoder.ensure(2);
        break :blk @as(u32, decoder.decode(u16));
    } else blk: {
        // Three byte length (u24)
        try decoder.ensure(3);
        const b1 = @as(u32, decoder.decode(u8));
        const b2 = @as(u32, decoder.decode(u8));
        const b3 = @as(u32, decoder.decode(u8));
        break :blk (b1 << 16) | (b2 << 8) | b3;
    };
    
    if (len > max_len) {
        return error.DataTooLarge;
    }
    
    try decoder.ensure(len);
    const bytes = try allocator.alloc(u8, len);
    @memcpy(bytes, decoder.slice(len));
    return bytes;
}

/// Read an integer from decoder, handling u32 manually
pub fn readInt(decoder: *tls.Decoder, comptime T: type) !T {
    try decoder.ensure(@sizeOf(T));
    if (T == u32) {
        // Manual u32 decoding since std.crypto.tls doesn't support it
        const bytes = decoder.slice(4);
        return std.mem.readInt(u32, bytes[0..4], .big);
    } else {
        return decoder.decode(T);
    }
}

// Tests
const testing = std.testing;

test "encode and decode integers" {
    var list = std.ArrayList(u8).init(testing.allocator);
    defer list.deinit();

    try encodeInt(&list, u8, 0x42);
    try encodeInt(&list, u16, 0x1234);

    // Debug the bytes written
    std.debug.print("\\nBytes written: ", .{});
    for (list.items) |byte| {
        std.debug.print("{x:02} ", .{byte});
    }
    std.debug.print("\\n", .{});
    
    var decoder = tls.Decoder.fromTheirSlice(list.items);
    try testing.expectEqual(@as(u8, 0x42), try readInt(&decoder, u8));
    try testing.expectEqual(@as(u16, 0x1234), try readInt(&decoder, u16));
}

test "encode and decode var bytes" {
    const allocator = testing.allocator;
    var list = std.ArrayList(u8).init(allocator);
    defer list.deinit();

    const data1 = "hello";
    const data2 = "world!";
    
    try encodeVarBytes(&list, u8, data1);
    try encodeVarBytes(&list, u16, data2);

    var decoder = tls.Decoder.fromTheirSlice(list.items);
    
    const read1 = try readVarBytes(&decoder, u8, allocator);
    defer allocator.free(read1);
    try testing.expectEqualSlices(u8, data1, read1);
    
    const read2 = try readVarBytes(&decoder, u16, allocator);
    defer allocator.free(read2);
    try testing.expectEqualSlices(u8, data2, read2);
}

test "encode and decode TLS opaque" {
    const allocator = testing.allocator;
    var list = std.ArrayList(u8).init(allocator);
    defer list.deinit();

    const data1 = "small";  // < 256 bytes, single byte length
    const data2 = [_]u8{0xAB} ** 300;  // > 256 bytes, two byte length
    
    try encodeTlsOpaque(&list, data1, 255);
    try encodeTlsOpaque(&list, &data2, 65535);

    var decoder = tls.Decoder.fromTheirSlice(list.items);
    
    const read1 = try readTlsOpaque(&decoder, allocator, 255);
    defer allocator.free(read1);
    try testing.expectEqualSlices(u8, data1, read1);
    
    const read2 = try readTlsOpaque(&decoder, allocator, 65535);
    defer allocator.free(read2);
    try testing.expectEqualSlices(u8, &data2, read2);
}