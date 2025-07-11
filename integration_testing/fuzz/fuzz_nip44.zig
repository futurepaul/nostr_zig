const std = @import("std");
const nip44 = @import("nip44");
const v2 = nip44.v2;

// Zig's fuzzing infrastructure
const fuzz = std.testing.fuzz;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    std.debug.print("🔨 NIP-44 Fuzz Testing\n", .{});
    std.debug.print("====================\n\n", .{});
    
    // Run different fuzz test suites
    try fuzzConversationKeys(allocator);
    try fuzzMessageKeys(allocator);
    try fuzzPadding(allocator);
    try fuzzEncryptDecrypt(allocator);
    try fuzzMalformedInputs(allocator);
    
    std.debug.print("\n✅ Fuzz testing completed without crashes!\n", .{});
}

fn fuzzConversationKeys(allocator: std.mem.Allocator) !void {
    std.debug.print("Fuzzing conversation key generation...\n", .{});
    
    var prng = std.rand.DefaultPrng.init(0);
    const random = prng.random();
    
    const iterations = 10000;
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        // Generate random keys
        var sec1: [32]u8 = undefined;
        var pub2: [32]u8 = undefined;
        random.bytes(&sec1);
        random.bytes(&pub2);
        
        // Try to generate conversation key
        const result = v2.ConversationKey.fromKeys(sec1, pub2);
        if (result) |conv_key| {
            // Verify properties
            // 1. Should be deterministic
            const result2 = try v2.ConversationKey.fromKeys(sec1, pub2);
            if (!std.mem.eql(u8, &conv_key.key, &result2.key)) {
                std.debug.print("  ❌ Non-deterministic result at iteration {}\n", .{i});
                return error.NonDeterministic;
            }
            
            // 2. Should not be all zeros
            const all_zeros = std.mem.allEqual(u8, &conv_key.key, 0);
            if (all_zeros) {
                std.debug.print("  ⚠️  All-zero conversation key at iteration {}\n", .{i});
            }
        } else |_| {
            // Some keys may be invalid, that's OK
        }
        
        if (i % 1000 == 0) {
            std.debug.print("  Progress: {}/{}\r", .{ i, iterations });
        }
    }
    std.debug.print("  ✅ Completed {} iterations\n", .{iterations});
}

fn fuzzMessageKeys(allocator: std.mem.Allocator) !void {
    std.debug.print("\nFuzzing message key derivation...\n", .{});
    
    var prng = std.rand.DefaultPrng.init(1);
    const random = prng.random();
    
    const iterations = 10000;
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        // Generate random conversation key and nonce
        var conv_key_bytes: [32]u8 = undefined;
        var nonce: [32]u8 = undefined;
        random.bytes(&conv_key_bytes);
        random.bytes(&nonce);
        
        const conv_key = v2.ConversationKey{ .key = conv_key_bytes };
        const message_keys = try conv_key.deriveMessageKeys(nonce);
        
        // Verify properties
        // 1. Keys should be different from each other
        if (std.mem.eql(u8, &message_keys.chacha_key, &message_keys.hmac_key)) {
            std.debug.print("  ❌ ChaCha and HMAC keys are identical at iteration {}\n", .{i});
            return error.IdenticalKeys;
        }
        
        // 2. Should be deterministic
        const message_keys2 = try conv_key.deriveMessageKeys(nonce);
        if (!std.mem.eql(u8, &message_keys.chacha_key, &message_keys2.chacha_key) or
            !std.mem.eql(u8, &message_keys.chacha_nonce, &message_keys2.chacha_nonce) or
            !std.mem.eql(u8, &message_keys.hmac_key, &message_keys2.hmac_key)) {
            std.debug.print("  ❌ Non-deterministic message keys at iteration {}\n", .{i});
            return error.NonDeterministic;
        }
        
        if (i % 1000 == 0) {
            std.debug.print("  Progress: {}/{}\r", .{ i, iterations });
        }
    }
    std.debug.print("  ✅ Completed {} iterations\n", .{iterations});
}

fn fuzzPadding(allocator: std.mem.Allocator) !void {
    _ = allocator;
    std.debug.print("\nFuzzing padding algorithm...\n", .{});
    
    var prng = std.rand.DefaultPrng.init(2);
    const random = prng.random();
    
    const iterations = 100000;
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        // Generate random lengths
        const len = random.int(u32) % 1000000; // Test up to 1MB
        const padded = v2.calcPaddedLen(len);
        
        // Verify properties
        // 1. Padded length must be >= original length
        if (padded < len) {
            std.debug.print("  ❌ Padded length {} < original length {} at iteration {}\n", .{ padded, len, i });
            return error.InvalidPadding;
        }
        
        // 2. Padding should be consistent
        const padded2 = v2.calcPaddedLen(len);
        if (padded != padded2) {
            std.debug.print("  ❌ Non-deterministic padding at iteration {}\n", .{i});
            return error.NonDeterministic;
        }
        
        // 3. Monotonic: larger input should have larger or equal output
        if (len > 0) {
            const padded_prev = v2.calcPaddedLen(len - 1);
            if (padded < padded_prev) {
                std.debug.print("  ❌ Non-monotonic padding: {} -> {}, but {} -> {}\n", .{ 
                    len - 1, padded_prev, len, padded 
                });
                return error.NonMonotonic;
            }
        }
        
        if (i % 10000 == 0) {
            std.debug.print("  Progress: {}/{}\r", .{ i, iterations });
        }
    }
    std.debug.print("  ✅ Completed {} iterations\n", .{iterations});
}

fn fuzzEncryptDecrypt(allocator: std.mem.Allocator) !void {
    std.debug.print("\nFuzzing encrypt/decrypt roundtrip...\n", .{});
    
    var prng = std.rand.DefaultPrng.init(3);
    const random = prng.random();
    
    const iterations = 1000;
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        // Generate random keys
        var sec1: [32]u8 = undefined;
        var sec2: [32]u8 = undefined;
        random.bytes(&sec1);
        random.bytes(&sec2);
        
        // Derive public keys
        const pub1 = nip44.derivePublicKey(sec1) catch continue;
        const pub2 = nip44.derivePublicKey(sec2) catch continue;
        
        // Generate random message
        const msg_len = random.int(u16) % 1000;
        const message = try allocator.alloc(u8, msg_len);
        defer allocator.free(message);
        random.bytes(message);
        
        // Convert to string for testing
        const message_str = try std.fmt.allocPrint(allocator, "{}", .{std.fmt.fmtSliceHexLower(message)});
        defer allocator.free(message_str);
        
        // Encrypt
        const ciphertext = nip44.encrypt(allocator, sec1, pub2, message_str) catch |err| {
            std.debug.print("  ⚠️  Encryption failed at iteration {}: {}\n", .{ i, err });
            continue;
        };
        defer allocator.free(ciphertext);
        
        // Decrypt
        const plaintext = nip44.decrypt(allocator, sec2, pub1, ciphertext) catch |err| {
            std.debug.print("  ❌ Decryption failed at iteration {}: {}\n", .{ i, err });
            return err;
        };
        defer allocator.free(plaintext);
        
        // Verify roundtrip
        if (!std.mem.eql(u8, plaintext, message_str)) {
            std.debug.print("  ❌ Roundtrip mismatch at iteration {}\n", .{i});
            std.debug.print("    Original:  {} bytes\n", .{message_str.len});
            std.debug.print("    Decrypted: {} bytes\n", .{plaintext.len});
            return error.RoundtripMismatch;
        }
        
        if (i % 100 == 0) {
            std.debug.print("  Progress: {}/{}\r", .{ i, iterations });
        }
    }
    std.debug.print("  ✅ Completed {} iterations\n", .{iterations});
}

fn fuzzMalformedInputs(allocator: std.mem.Allocator) !void {
    std.debug.print("\nFuzzing malformed input handling...\n", .{});
    
    var prng = std.rand.DefaultPrng.init(4);
    const random = prng.random();
    
    // Generate valid keys for testing
    var sec1: [32]u8 = undefined;
    var pub2: [32]u8 = undefined;
    random.bytes(&sec1);
    random.bytes(&pub2);
    
    // Test various malformed payloads
    const test_cases = [_][]const u8{
        "",                                          // Empty
        "x",                                        // Too short
        "AgA",                                      // Valid base64 but too short
        "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // Valid length but likely invalid
    };
    
    for (test_cases, 0..) |payload, i| {
        const result = nip44.decrypt(allocator, sec1, pub2, payload);
        if (result) |plaintext| {
            allocator.free(plaintext);
            std.debug.print("  ⚠️  Malformed input {} accepted\n", .{i});
        } else |_| {
            // Expected to fail
        }
    }
    
    // Fuzz with random base64-like strings
    const iterations = 1000;
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        // Generate random base64-like payload
        const len = random.int(u16) % 500;
        const payload = try allocator.alloc(u8, len);
        defer allocator.free(payload);
        
        for (payload) |*byte| {
            const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
            byte.* = chars[random.int(u8) % chars.len];
        }
        
        // Try to decrypt
        const result = nip44.decrypt(allocator, sec1, pub2, payload);
        if (result) |plaintext| {
            allocator.free(plaintext);
            // Some random payloads might accidentally be valid
        } else |_| {
            // Expected to fail for most random inputs
        }
        
        if (i % 100 == 0) {
            std.debug.print("  Progress: {}/{}\r", .{ i, iterations });
        }
    }
    std.debug.print("  ✅ Completed {} malformed input tests\n", .{iterations + test_cases.len});
}

// Additional fuzz test using std.testing.fuzz if available
test "fuzz conversation keys with std.testing.fuzz" {
    const allocator = std.testing.allocator;
    
    try std.testing.fuzz(
        allocator,
        struct {
            sec1: [32]u8,
            pub2: [32]u8,
        },
        .{},
        fuzzConversationKeyInput,
    );
}

fn fuzzConversationKeyInput(input: anytype) void {
    const result = v2.ConversationKey.fromKeys(input.sec1, input.pub2);
    
    if (result) |conv_key| {
        // Should be deterministic
        const result2 = v2.ConversationKey.fromKeys(input.sec1, input.pub2) catch unreachable;
        std.testing.expectEqualSlices(u8, &conv_key.key, &result2.key) catch unreachable;
    } else |_| {
        // Invalid keys are OK
    }
}