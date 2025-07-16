const std = @import("std");
const secp256k1 = @import("secp256k1");
const wasm_random = @import("../wasm_random.zig");
const crypto = @import("../crypto.zig");

/// Ephemeral key pair for privacy-preserving group messages
pub const EphemeralKeyPair = struct {
    private_key: [32]u8,
    public_key: [32]u8,
    
    /// Generate a new ephemeral key pair using secp256k1
    pub fn generate() !EphemeralKeyPair {
        // Generate a cryptographically secure private key
        const private_key = try generateSecurePrivateKey();
        
        // Derive the public key using secp256k1 (x-only for Nostr)
        const public_key = try crypto.getPublicKey(private_key);
        
        return EphemeralKeyPair{
            .private_key = private_key,
            .public_key = public_key,
        };
    }
    
    /// Generate a secure private key that's valid for secp256k1
    fn generateSecurePrivateKey() ![32]u8 {
        const builtin = @import("builtin");
        const ctx = if (builtin.target.cpu.arch == .wasm32) blk: {
            // In WASM, use the static no-precomp context
            const wasm_ctx = @import("../wasm_secp_context.zig");
            break :blk wasm_ctx.getStaticContext();
        } else blk: {
            // On native platforms, create a context normally
            break :blk secp256k1.secp256k1_context_create(
                secp256k1.SECP256K1_CONTEXT_SIGN
            ) orelse return error.ContextCreationFailed;
        };
        defer if (builtin.target.cpu.arch != .wasm32) {
            secp256k1.secp256k1_context_destroy(ctx);
        };
        
        var key: [32]u8 = undefined;
        while (true) {
            // Use secure randomness that works in WASM
            wasm_random.secure_random.bytes(&key);
            
            // Verify the key is valid for secp256k1
            if (secp256k1.secp256k1_ec_seckey_verify(ctx, &key) == 1) {
                return key;
            }
            // If invalid (very rare), generate a new one
        }
    }
    
    /// Clear the private key from memory
    pub fn clear(self: *EphemeralKeyPair) void {
        std.crypto.utils.secureZero(u8, &self.private_key);
    }
};

/// Ephemeral key cache for temporary verification
/// Keys are kept only for the duration of message processing
pub const EphemeralKeyCache = struct {
    allocator: std.mem.Allocator,
    entries: std.AutoHashMap([32]u8, Entry),
    max_age_ms: u64 = 60_000, // 1 minute default
    
    const Entry = struct {
        timestamp_ms: u64,
        public_key: [32]u8,
    };
    
    pub fn init(allocator: std.mem.Allocator) EphemeralKeyCache {
        return .{
            .allocator = allocator,
            .entries = std.AutoHashMap([32]u8, Entry).init(allocator),
        };
    }
    
    pub fn deinit(self: *EphemeralKeyCache) void {
        self.entries.deinit();
    }
    
    /// Add an ephemeral public key to the cache
    pub fn add(self: *EphemeralKeyCache, event_id: [32]u8, public_key: [32]u8) !void {
        const entry = Entry{
            .timestamp_ms = @intCast(std.time.milliTimestamp()),
            .public_key = public_key,
        };
        try self.entries.put(event_id, entry);
        
        // Clean old entries
        try self.cleanOldEntries();
    }
    
    /// Get an ephemeral public key from the cache
    pub fn get(self: *EphemeralKeyCache, event_id: [32]u8) ?[32]u8 {
        if (self.entries.get(event_id)) |entry| {
            const now_ms: u64 = @intCast(std.time.milliTimestamp());
            const age_ms = now_ms - entry.timestamp_ms;
            if (age_ms <= self.max_age_ms) {
                return entry.public_key;
            }
        }
        return null;
    }
    
    /// Remove old entries from the cache
    fn cleanOldEntries(self: *EphemeralKeyCache) !void {
        const now_ms: u64 = @intCast(std.time.milliTimestamp());
        
        var to_remove = std.ArrayList([32]u8).init(self.allocator);
        defer to_remove.deinit();
        
        var iter = self.entries.iterator();
        while (iter.next()) |entry| {
            const age_ms = now_ms - entry.value_ptr.timestamp_ms;
            if (age_ms > self.max_age_ms) {
                try to_remove.append(entry.key_ptr.*);
            }
        }
        
        for (to_remove.items) |key| {
            _ = self.entries.remove(key);
        }
    }
};

/// Generate ephemeral keys for each message in a batch
pub fn generateBatchEphemeralKeys(count: usize, allocator: std.mem.Allocator) ![]EphemeralKeyPair {
    const keys = try allocator.alloc(EphemeralKeyPair, count);
    errdefer allocator.free(keys);
    
    for (keys) |*key| {
        key.* = try EphemeralKeyPair.generate();
    }
    
    return keys;
}

/// Securely clear a batch of ephemeral keys
pub fn clearBatchEphemeralKeys(keys: []EphemeralKeyPair) void {
    for (keys) |*key| {
        key.clear();
    }
}

test "generate ephemeral key pair" {
    const key_pair = try EphemeralKeyPair.generate();
    
    // Verify keys are different
    try std.testing.expect(!std.mem.eql(u8, &key_pair.private_key, &key_pair.public_key));
    
    // Verify keys are not zero
    var zero_key: [32]u8 = [_]u8{0} ** 32;
    try std.testing.expect(!std.mem.eql(u8, &key_pair.private_key, &zero_key));
    try std.testing.expect(!std.mem.eql(u8, &key_pair.public_key, &zero_key));
}

test "ephemeral key uniqueness" {
    // Generate multiple keys and verify they're unique
    const key1 = try EphemeralKeyPair.generate();
    const key2 = try EphemeralKeyPair.generate();
    const key3 = try EphemeralKeyPair.generate();
    
    try std.testing.expect(!std.mem.eql(u8, &key1.private_key, &key2.private_key));
    try std.testing.expect(!std.mem.eql(u8, &key1.private_key, &key3.private_key));
    try std.testing.expect(!std.mem.eql(u8, &key2.private_key, &key3.private_key));
    
    try std.testing.expect(!std.mem.eql(u8, &key1.public_key, &key2.public_key));
    try std.testing.expect(!std.mem.eql(u8, &key1.public_key, &key3.public_key));
    try std.testing.expect(!std.mem.eql(u8, &key2.public_key, &key3.public_key));
}

test "ephemeral key cache" {
    const allocator = std.testing.allocator;
    
    var cache = EphemeralKeyCache.init(allocator);
    defer cache.deinit();
    
    const event_id: [32]u8 = [_]u8{1} ** 32;
    const pub_key: [32]u8 = [_]u8{2} ** 32;
    
    // Add key
    try cache.add(event_id, pub_key);
    
    // Retrieve key
    const retrieved = cache.get(event_id);
    try std.testing.expect(retrieved != null);
    try std.testing.expectEqualSlices(u8, &pub_key, &retrieved.?);
    
    // Non-existent key
    const other_id: [32]u8 = [_]u8{3} ** 32;
    try std.testing.expect(cache.get(other_id) == null);
}

test "ephemeral key clear" {
    var key_pair = try EphemeralKeyPair.generate();
    const original_private = key_pair.private_key;
    
    // Clear the key
    key_pair.clear();
    
    // Verify private key is zeroed
    const zero_key: [32]u8 = [_]u8{0} ** 32;
    try std.testing.expectEqualSlices(u8, &zero_key, &key_pair.private_key);
    
    // Verify we had a non-zero key originally
    try std.testing.expect(!std.mem.eql(u8, &original_private, &zero_key));
}

test "batch ephemeral key generation" {
    const allocator = std.testing.allocator;
    
    const keys = try generateBatchEphemeralKeys(5, allocator);
    defer {
        clearBatchEphemeralKeys(keys);
        allocator.free(keys);
    }
    
    try std.testing.expectEqual(@as(usize, 5), keys.len);
    
    // Verify all keys are unique
    for (keys, 0..) |key1, i| {
        for (keys[i + 1 ..]) |key2| {
            try std.testing.expect(!std.mem.eql(u8, &key1.private_key, &key2.private_key));
            try std.testing.expect(!std.mem.eql(u8, &key1.public_key, &key2.public_key));
        }
    }
}