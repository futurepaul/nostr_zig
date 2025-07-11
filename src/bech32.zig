const std = @import("std");

// Import the C bech32 library
const c = @cImport({
    @cInclude("stdint.h");
    @cInclude("stddef.h");
    @cInclude("segwit_addr.h");
});

pub const Bech32Error = error{
    DecodeFailed,
    EncodeFailed,
    InvalidHrp,
    InvalidData,
    BufferTooSmall,
};

/// Decode a bech32 string into raw bytes
pub fn decode(allocator: std.mem.Allocator, expected_hrp: []const u8, bech32_str: []const u8) ![]u8 {
    var hrp_buf: [84]u8 = undefined; // Buffer for extracted HRP
    var data: [84]u8 = undefined; // Maximum bech32 data length
    var data_len: usize = 0;
    
    // Convert bech32 string to null-terminated C string
    const bech32_c = try allocator.dupeZ(u8, bech32_str);
    defer allocator.free(bech32_c);
    
    // Decode using the C library - this extracts HRP and 5-bit data
    const encoding = c.bech32_decode(&hrp_buf, &data, &data_len, bech32_c.ptr);
    
    if (encoding == c.BECH32_ENCODING_NONE) {
        return Bech32Error.DecodeFailed;
    }
    
    // Check if the HRP matches what we expect
    const hrp_len = std.mem.len(@as([*:0]u8, @ptrCast(&hrp_buf)));
    if (!std.mem.eql(u8, expected_hrp, hrp_buf[0..hrp_len])) {
        return Bech32Error.InvalidHrp;
    }
    
    // Convert 5-bit data to 8-bit bytes
    var result = std.ArrayList(u8).init(allocator);
    defer result.deinit();
    
    var acc: u32 = 0;
    var bits: u8 = 0;
    
    for (data[0..data_len]) |value| {
        if (value >= 32) {
            return Bech32Error.InvalidData;
        }
        
        acc = (acc << 5) | value;
        bits += 5;
        
        if (bits >= 8) {
            bits -= 8;
            const byte: u8 = @truncate((acc >> @intCast(bits)) & 0xFF);
            try result.append(byte);
        }
    }
    
    // Ensure there are no leftover bits (padding should be zero)
    if (bits >= 5 or ((acc << @intCast(8 - bits)) & 0xFF) != 0) {
        return Bech32Error.InvalidData;
    }
    
    return try result.toOwnedSlice();
}

/// Encode raw bytes into a bech32 string
pub fn encode(allocator: std.mem.Allocator, hrp: []const u8, data: []const u8) ![]u8 {
    var output: [84]u8 = undefined; // Maximum bech32 string length
    
    // Convert hrp to null-terminated C string
    const hrp_c = try allocator.dupeZ(u8, hrp);
    defer allocator.free(hrp_c);
    
    // Encode using the C library (version 0 for standard bech32)
    const result = c.segwit_addr_encode(&output, hrp_c.ptr, 0, data.ptr, data.len);
    
    if (result != 1) {
        return Bech32Error.EncodeFailed;
    }
    
    // Find the null terminator and copy to Zig string
    const len = std.mem.len(@as([*:0]u8, @ptrCast(&output)));
    return try allocator.dupe(u8, output[0..len]);
}

/// Decode nsec1 bech32 private key to 32-byte array
pub fn decodeNsec1(allocator: std.mem.Allocator, nsec1: []const u8) ![32]u8 {
    const decoded = try decode(allocator, "nsec", nsec1);
    defer allocator.free(decoded);
    
    if (decoded.len != 32) {
        return Bech32Error.InvalidData;
    }
    
    var result: [32]u8 = undefined;
    @memcpy(&result, decoded);
    return result;
}

/// Encode 32-byte private key to nsec1 bech32 format
pub fn encodeNsec1(allocator: std.mem.Allocator, private_key: [32]u8) ![]u8 {
    return encode(allocator, "nsec", &private_key);
}

/// Decode npub1 bech32 public key to 32-byte array  
pub fn decodeNpub1(allocator: std.mem.Allocator, npub1: []const u8) ![32]u8 {
    const decoded = try decode(allocator, "npub", npub1);
    defer allocator.free(decoded);
    
    if (decoded.len != 32) {
        return Bech32Error.InvalidData;
    }
    
    var result: [32]u8 = undefined;
    @memcpy(&result, decoded);
    return result;
}

/// Encode 32-byte public key to npub1 bech32 format
pub fn encodeNpub1(allocator: std.mem.Allocator, public_key: [32]u8) ![]u8 {
    return encode(allocator, "npub", &public_key);
}

// Test the functions
test "bech32 encode/decode" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test with some dummy data
    const test_data = [_]u8{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
    
    // Encode to nsec1
    const encoded = try encodeNsec1(allocator, test_data);
    defer allocator.free(encoded);
    
    try testing.expect(std.mem.startsWith(u8, encoded, "nsec1"));
    
    // Decode back
    const decoded = try decodeNsec1(allocator, encoded);
    
    try testing.expectEqualSlices(u8, &test_data, &decoded);
}