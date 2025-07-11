const std = @import("std");

// We'll just copy the Secret implementation from mls_zig since we can't import it easily
const crypto = std.crypto;
const Allocator = std.mem.Allocator;

pub const Secret = struct {
    data: []u8,
    allocator: Allocator,

    pub fn init(allocator: Allocator, length: usize) !Secret {
        const data = try allocator.alloc(u8, length);
        return Secret{
            .data = data,
            .allocator = allocator,
        };
    }

    pub fn initFromSlice(allocator: Allocator, bytes: []const u8) !Secret {
        const data = try allocator.dupe(u8, bytes);
        return Secret{
            .data = data,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Secret) void {
        crypto.secureZero(u8, self.data);
        self.allocator.free(self.data);
        self.data = &[_]u8{};
    }

    pub fn len(self: Secret) usize {
        return self.data.len;
    }

    pub fn asSlice(self: Secret) []const u8 {
        return self.data;
    }

    pub fn hkdfExpand(
        self: Secret,
        allocator: Allocator,
        comptime HashFunction: type,
        info: []const u8,
        length: usize,
    ) !Secret {
        const HkdfType = crypto.kdf.hkdf.Hkdf(crypto.auth.hmac.Hmac(HashFunction));
        const output_data = try allocator.alloc(u8, length);
        // Need to copy to fixed-size array for Zig HKDF API
        if (self.data.len != 32) return error.InvalidKeyLength;
        var prk: [32]u8 = undefined;
        @memcpy(&prk, self.data);
        HkdfType.expand(output_data, info, prk);
        return Secret{
            .data = output_data,
            .allocator = allocator,
        };
    }
};

fn hexToBytes(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    const bytes = try allocator.alloc(u8, hex.len / 2);
    for (0..bytes.len) |i| {
        const hex_byte = hex[i * 2..i * 2 + 2];
        bytes[i] = std.fmt.parseInt(u8, hex_byte, 16) catch return error.InvalidHex;
    }
    return bytes;
}

fn bytesToHex(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const hex = try allocator.alloc(u8, bytes.len * 2);
    for (bytes, 0..) |byte, i| {
        _ = std.fmt.bufPrint(hex[i * 2..i * 2 + 2], "{x:0>2}", .{byte}) catch unreachable;
    }
    return hex;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // Test inputs from test vector
    const conv_key_hex = "c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d";
    const nonce_hex = "0000000000000000000000000000000000000000000000000000000000000001";
    const expected_chacha_key_hex = "8c8b181c7bb23c1410ad0234d8ad35cbc7b6c6b827e5e0d2b3cf3d6e8c1de9e5";
    
    const conv_key_bytes = try hexToBytes(allocator, conv_key_hex);
    defer allocator.free(conv_key_bytes);
    const nonce_bytes = try hexToBytes(allocator, nonce_hex);
    defer allocator.free(nonce_bytes);
    
    std.debug.print("Testing mls_zig style HKDF...\n", .{});
    std.debug.print("Conversation key: {s}\n", .{conv_key_hex});
    std.debug.print("Nonce: {s}\n", .{nonce_hex});
    std.debug.print("Expected ChaCha key: {s}\n", .{expected_chacha_key_hex});
    std.debug.print("\n", .{});
    
    // Create Secret from conversation key
    var conv_key_secret = try Secret.initFromSlice(allocator, conv_key_bytes);
    defer conv_key_secret.deinit();
    
    // Use mls_zig style HKDF expand with SHA256
    var message_keys_secret = try conv_key_secret.hkdfExpand(
        allocator,
        crypto.hash.sha2.Sha256,
        nonce_bytes,
        76
    );
    defer message_keys_secret.deinit();
    
    const chacha_key_mls = message_keys_secret.asSlice()[0..32];
    
    const result_mls_hex = try bytesToHex(allocator, chacha_key_mls);
    defer allocator.free(result_mls_hex);
    
    std.debug.print("mls_zig style: {s}\n", .{result_mls_hex});
    std.debug.print("Expected:      {s}\n", .{expected_chacha_key_hex});
    std.debug.print("Match: {s}\n", .{if (std.mem.eql(u8, result_mls_hex, expected_chacha_key_hex)) "✅" else "❌"});
}