const std = @import("std");

/// Check if data looks like valid base64
pub fn isLikelyBase64(data: []const u8) bool {
    if (data.len == 0) return false;
    
    // Check for common binary bytes that wouldn't appear in base64
    for (data) |byte| {
        // Base64 uses A-Z, a-z, 0-9, +, /, =
        const is_base64_char = (byte >= 'A' and byte <= 'Z') or
                              (byte >= 'a' and byte <= 'z') or
                              (byte >= '0' and byte <= '9') or
                              byte == '+' or byte == '/' or byte == '=';
        
        // Also allow newlines and spaces (some base64 implementations add these)
        const is_whitespace = byte == '\n' or byte == '\r' or byte == ' ';
        
        if (!is_base64_char and !is_whitespace) {
            return false;
        }
    }
    
    // Check if length is reasonable for base64 (multiple of 4, with padding)
    const trimmed_len = if (data[data.len - 1] == '=') blk: {
        if (data.len > 1 and data[data.len - 2] == '=') {
            break :blk data.len - 2;
        } else {
            break :blk data.len - 1;
        }
    } else data.len;
    
    return (trimmed_len % 4) == 0 or data.len < 4;
}

/// Check if data contains non-printable characters (likely binary)
pub fn isLikelyBinary(data: []const u8) bool {
    if (data.len == 0) return false;
    
    var non_printable_count: usize = 0;
    for (data) |byte| {
        // Count non-printable, non-whitespace characters
        if (byte < 32 and byte != '\t' and byte != '\n' and byte != '\r') {
            non_printable_count += 1;
        }
    }
    
    // If more than 10% non-printable, it's likely binary
    return (non_printable_count * 10) > data.len;
}

/// Convert bytes to hex string for debugging
pub fn bytesToHex(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    var hex = try allocator.alloc(u8, bytes.len * 2);
    const hex_chars = "0123456789abcdef";
    
    for (bytes, 0..) |byte, i| {
        hex[i * 2] = hex_chars[byte >> 4];
        hex[i * 2 + 1] = hex_chars[byte & 0x0F];
    }
    
    return hex;
}

test "isLikelyBase64" {
    const testing = std.testing;
    
    // Valid base64
    try testing.expect(isLikelyBase64("SGVsbG8gV29ybGQ="));
    try testing.expect(isLikelyBase64("YWJjZGVmZ2hpams="));
    
    // Invalid base64 (binary data)
    try testing.expect(!isLikelyBase64(&[_]u8{0x00, 0x01, 0x02, 0x03}));
    try testing.expect(!isLikelyBase64(&[_]u8{0xFF, 0xFE, 0xFD, 0xFC}));
    
    // Text that's not base64
    try testing.expect(!isLikelyBase64("Hello, World!"));
}

test "isLikelyBinary" {
    const testing = std.testing;
    
    // Binary data
    try testing.expect(isLikelyBinary(&[_]u8{0x00, 0x01, 0x02, 0x03}));
    try testing.expect(isLikelyBinary(&[_]u8{0xFF, 0xFE, 0xFD, 0xFC}));
    
    // Text data
    try testing.expect(!isLikelyBinary("Hello, World!"));
    try testing.expect(!isLikelyBinary("SGVsbG8gV29ybGQ="));
}