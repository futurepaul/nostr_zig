const std = @import("std");
const nip44 = @import("nip44");
const v2 = nip44.v2;

fn hexToBytes(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    const bytes = try allocator.alloc(u8, hex.len / 2);
    var i: usize = 0;
    while (i < hex.len) : (i += 2) {
        bytes[i / 2] = try std.fmt.parseInt(u8, hex[i..i + 2], 16);
    }
    return bytes;
}

fn bytesToHex(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const hex = try allocator.alloc(u8, bytes.len * 2);
    for (bytes, 0..) |byte, i| {
        _ = try std.fmt.bufPrint(hex[i * 2..i * 2 + 2], "{x:0>2}", .{byte});
    }
    return hex;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    
    if (args.len < 2) {
        std.debug.print("Usage: {s} <command> [args...]\n", .{args[0]});
        return;
    }
    
    const stdout = std.io.getStdOut().writer();
    const stdin = std.io.getStdIn().reader();
    
    const cmd = args[1];
    
    if (std.mem.eql(u8, cmd, "conversation_key")) {
        // Read input: sec1_hex pub2_hex
        const input = try stdin.readUntilDelimiterAlloc(allocator, '\n', 1024);
        defer allocator.free(input);
        
        var iter = std.mem.tokenizeAny(u8, input, " ");
        const sec1_hex = iter.next() orelse return error.MissingInput;
        const pub2_hex = iter.next() orelse return error.MissingInput;
        
        const sec1 = try hexToBytes(allocator, sec1_hex);
        defer allocator.free(sec1);
        const pub2 = try hexToBytes(allocator, pub2_hex);
        defer allocator.free(pub2);
        
        var sec1_array: [32]u8 = undefined;
        var pub2_array: [32]u8 = undefined;
        @memcpy(&sec1_array, sec1);
        
        // Handle both 32 and 33 byte public keys
        if (pub2.len == 33) {
            @memcpy(&pub2_array, pub2[1..]); // Skip compression byte
        } else {
            @memcpy(&pub2_array, pub2);
        }
        
        const conv_key = try v2.ConversationKey.fromKeys(sec1_array, pub2_array);
        const hex = try bytesToHex(allocator, &conv_key.key);
        defer allocator.free(hex);
        
        try stdout.print("{s}\n", .{hex});
    }
    else if (std.mem.eql(u8, cmd, "encrypt")) {
        // Read input: sec1_hex pub2_hex plaintext
        const input = try stdin.readUntilDelimiterAlloc(allocator, '\n', 10240);
        defer allocator.free(input);
        
        var iter = std.mem.tokenizeAny(u8, input, " ");
        const sec1_hex = iter.next() orelse return error.MissingInput;
        const pub2_hex = iter.next() orelse return error.MissingInput;
        const plaintext = iter.rest();
        
        const sec1 = try hexToBytes(allocator, sec1_hex);
        defer allocator.free(sec1);
        const pub2 = try hexToBytes(allocator, pub2_hex);
        defer allocator.free(pub2);
        
        var sec1_array: [32]u8 = undefined;
        var pub2_array: [32]u8 = undefined;
        @memcpy(&sec1_array, sec1);
        
        if (pub2.len == 33) {
            @memcpy(&pub2_array, pub2[1..]);
        } else {
            @memcpy(&pub2_array, pub2);
        }
        
        const ciphertext = try nip44.encrypt(allocator, sec1_array, pub2_array, plaintext);
        defer allocator.free(ciphertext);
        
        try stdout.print("{s}\n", .{ciphertext});
    }
    else if (std.mem.eql(u8, cmd, "decrypt")) {
        // Read input: sec1_hex pub2_hex payload
        const input = try stdin.readUntilDelimiterAlloc(allocator, '\n', 10240);
        defer allocator.free(input);
        
        var iter = std.mem.tokenizeAny(u8, input, " ");
        const sec1_hex = iter.next() orelse return error.MissingInput;
        const pub2_hex = iter.next() orelse return error.MissingInput;
        const payload = iter.rest();
        
        const sec1 = try hexToBytes(allocator, sec1_hex);
        defer allocator.free(sec1);
        const pub2 = try hexToBytes(allocator, pub2_hex);
        defer allocator.free(pub2);
        
        var sec1_array: [32]u8 = undefined;
        var pub2_array: [32]u8 = undefined;
        @memcpy(&sec1_array, sec1);
        
        if (pub2.len == 33) {
            @memcpy(&pub2_array, pub2[1..]);
        } else {
            @memcpy(&pub2_array, pub2);
        }
        
        const plaintext = try nip44.decrypt(allocator, sec1_array, pub2_array, payload);
        defer allocator.free(plaintext);
        
        try stdout.print("{s}\n", .{plaintext});
    }
    else if (std.mem.eql(u8, cmd, "message_keys")) {
        // Read input: conversation_key_hex nonce_hex
        const input = try stdin.readUntilDelimiterAlloc(allocator, '\n', 1024);
        defer allocator.free(input);
        
        var iter = std.mem.tokenizeAny(u8, input, " ");
        const conv_key_hex = iter.next() orelse return error.MissingInput;
        const nonce_hex = iter.next() orelse return error.MissingInput;
        
        const conv_key_bytes = try hexToBytes(allocator, conv_key_hex);
        defer allocator.free(conv_key_bytes);
        const nonce_bytes = try hexToBytes(allocator, nonce_hex);
        defer allocator.free(nonce_bytes);
        
        var conv_key_array: [32]u8 = undefined;
        var nonce_array: [32]u8 = undefined;
        @memcpy(&conv_key_array, conv_key_bytes);
        @memcpy(&nonce_array, nonce_bytes);
        
        const conv_key = v2.ConversationKey{ .key = conv_key_array };
        const message_keys = try conv_key.deriveMessageKeys(nonce_array);
        
        const chacha_key_hex = try bytesToHex(allocator, &message_keys.chacha_key);
        defer allocator.free(chacha_key_hex);
        const chacha_nonce_hex = try bytesToHex(allocator, &message_keys.chacha_nonce);
        defer allocator.free(chacha_nonce_hex);
        const hmac_key_hex = try bytesToHex(allocator, &message_keys.hmac_key);
        defer allocator.free(hmac_key_hex);
        
        try stdout.print("{s} {s} {s}\n", .{chacha_key_hex, chacha_nonce_hex, hmac_key_hex});
    }
    else if (std.mem.eql(u8, cmd, "calc_padded_len")) {
        // Read input: length
        const input = try stdin.readUntilDelimiterAlloc(allocator, '\n', 1024);
        defer allocator.free(input);
        
        const len = try std.fmt.parseInt(usize, std.mem.trim(u8, input, " \n"), 10);
        const padded = v2.calcPaddedLen(len);
        
        try stdout.print("{}\n", .{padded});
    }
    else {
        std.debug.print("Unknown command: {s}\n", .{cmd});
    }
}