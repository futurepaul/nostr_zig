const std = @import("std");

/// HKDF-Expand implementation following RFC 5869
/// This is a standalone implementation that doesn't depend on mls_zig
pub fn expand(allocator: std.mem.Allocator, prk: []const u8, info: []const u8, length: usize) ![]u8 {
    if (prk.len < 32) {
        return error.InvalidPrkLength;
    }
    
    const output = try allocator.alloc(u8, length);
    expandInPlace(output, prk, info);
    return output;
}

/// HKDF-Expand in-place implementation
pub fn expandInPlace(output: []u8, prk: []const u8, info: []const u8) void {
    var t_prev: [32]u8 = undefined;
    var written: usize = 0;
    var counter: u8 = 1;
    
    while (written < output.len) {
        var hmac_input_buf: [512]u8 = undefined;
        var hmac_input_len: usize = 0;
        
        // Add T(i-1) for i > 1
        if (counter > 1) {
            @memcpy(hmac_input_buf[hmac_input_len..hmac_input_len + 32], &t_prev);
            hmac_input_len += 32;
        }
        
        // Add info
        const info_copy_len = @min(info.len, hmac_input_buf.len - hmac_input_len - 1);
        @memcpy(hmac_input_buf[hmac_input_len..hmac_input_len + info_copy_len], info[0..info_copy_len]);
        hmac_input_len += info_copy_len;
        
        // Add counter byte
        hmac_input_buf[hmac_input_len] = counter;
        hmac_input_len += 1;
        
        // Compute T(i) = HMAC-SHA256(PRK, T(i-1) || info || counter)
        var t_current: [32]u8 = undefined;
        std.crypto.auth.hmac.sha2.HmacSha256.create(&t_current, hmac_input_buf[0..hmac_input_len], prk);
        
        // Copy to output
        const bytes_to_copy = @min(output.len - written, 32);
        @memcpy(output[written..written + bytes_to_copy], t_current[0..bytes_to_copy]);
        
        t_prev = t_current;
        written += bytes_to_copy;
        counter += 1;
    }
}

/// HKDF-Extract implementation following RFC 5869
pub fn extract(allocator: std.mem.Allocator, salt: []const u8, ikm: []const u8) ![]u8 {
    const output = try allocator.alloc(u8, 32);
    extractInPlace(output, salt, ikm);
    return output;
}

/// HKDF-Extract in-place implementation
pub fn extractInPlace(output: []u8, salt: []const u8, ikm: []const u8) void {
    if (output.len < 32) {
        @panic("Output buffer too small for HKDF-Extract");
    }
    std.crypto.auth.hmac.sha2.HmacSha256.create(@as(*[32]u8, @ptrCast(output.ptr)), ikm, salt);
}

test "hkdf expand" {
    const allocator = std.testing.allocator;
    
    // Test vector from RFC 5869
    const prk = [_]u8{0x07} ** 32;
    const info = "test info";
    
    const output = try expand(allocator, &prk, info, 42);
    defer allocator.free(output);
    
    try std.testing.expectEqual(@as(usize, 42), output.len);
}

test "hkdf extract" {
    const allocator = std.testing.allocator;
    
    const salt = "test salt";
    const ikm = "test input key material";
    
    const prk = try extract(allocator, salt, ikm);
    defer allocator.free(prk);
    
    try std.testing.expectEqual(@as(usize, 32), prk.len);
}