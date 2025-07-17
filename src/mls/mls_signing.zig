const std = @import("std");
const mls_zig = @import("mls_zig");
const crypto = std.crypto;
const Allocator = std.mem.Allocator;

/// MLS signing key pair for Group Events (separate from Nostr identity keys)
pub const MlsSigningKeyPair = struct {
    public_key: mls_zig.key_package.SignaturePublicKey,
    private_key: mls_zig.key_package.SignaturePrivateKey,
    cipher_suite: mls_zig.cipher_suite.CipherSuite,
    
    /// Generate a new MLS signing key pair using the specified cipher suite
    pub fn generate(allocator: Allocator, cs: mls_zig.cipher_suite.CipherSuite) !MlsSigningKeyPair {
        var key_pair = try mls_zig.key_package.generateSignatureKeyPair(allocator, cs);
        errdefer key_pair.deinit();
        
        var public_key = try mls_zig.key_package.SignaturePublicKey.init(allocator, key_pair.public_key);
        errdefer public_key.deinit();
        
        var private_key = try mls_zig.key_package.SignaturePrivateKey.init(allocator, key_pair.private_key);
        errdefer private_key.deinit();
        
        // Clean up the temporary key pair
        key_pair.deinit();
        
        return MlsSigningKeyPair{
            .public_key = public_key,
            .private_key = private_key,
            .cipher_suite = cs,
        };
    }
    
    /// Create from existing key material
    pub fn fromBytes(
        allocator: Allocator,
        cs: mls_zig.cipher_suite.CipherSuite,
        public_key_bytes: []const u8,
        private_key_bytes: []const u8,
    ) !MlsSigningKeyPair {
        var public_key = try mls_zig.key_package.SignaturePublicKey.init(allocator, public_key_bytes);
        errdefer public_key.deinit();
        
        var private_key = try mls_zig.key_package.SignaturePrivateKey.init(allocator, private_key_bytes);
        errdefer private_key.deinit();
        
        return MlsSigningKeyPair{
            .public_key = public_key,
            .private_key = private_key,
            .cipher_suite = cs,
        };
    }
    
    /// Sign data with this MLS signing key
    pub fn sign(self: *const MlsSigningKeyPair, allocator: Allocator, label: []const u8, content: []const u8) !mls_zig.key_package.Signature {
        return try mls_zig.key_package.signWithLabel(
            allocator,
            self.cipher_suite,
            self.private_key.asSlice(),
            label,
            content,
        );
    }
    
    /// Verify a signature with this public key
    pub fn verify(self: *const MlsSigningKeyPair, allocator: Allocator, signature: []const u8, label: []const u8, content: []const u8) !bool {
        return try mls_zig.key_package.verifyWithLabel(
            self.cipher_suite,
            self.public_key.asSlice(),
            signature,
            label,
            content,
            allocator,
        );
    }
    
    /// Get the public key bytes for Nostr events (ephemeral pubkey field)
    pub fn getNostrPublicKey(self: *const MlsSigningKeyPair) ![32]u8 {
        // For Nostr compatibility, we need to convert the MLS public key to a 32-byte format
        // This is a simplified approach - in production you might want a proper key derivation
        const pub_key_bytes = self.public_key.asSlice();
        
        var result: [32]u8 = undefined;
        if (pub_key_bytes.len >= 32) {
            // Take first 32 bytes for Ed25519 keys
            @memcpy(result[0..32], pub_key_bytes[0..32]);
        } else {
            // Pad shorter keys with zeros
            @memset(result[0..], 0);
            @memcpy(result[0..pub_key_bytes.len], pub_key_bytes);
        }
        
        return result;
    }
    
    /// Clear sensitive key material
    pub fn deinit(self: *MlsSigningKeyPair) void {
        self.private_key.deinit();
        self.public_key.deinit();
    }
};

/// Ephemeral MLS signing key manager for Group Events
/// Each Group Event MUST use a unique MLS signing key per NIP-EE spec
pub const EphemeralMlsSigningKeys = struct {
    allocator: Allocator,
    cipher_suite: mls_zig.cipher_suite.CipherSuite,
    used_keys: std.AutoHashMap([32]u8, void), // Track used public keys
    
    pub fn init(allocator: Allocator, cipher_suite: mls_zig.cipher_suite.CipherSuite) EphemeralMlsSigningKeys {
        return .{
            .allocator = allocator,
            .cipher_suite = cipher_suite,
            .used_keys = std.AutoHashMap([32]u8, void).init(allocator),
        };
    }
    
    pub fn deinit(self: *EphemeralMlsSigningKeys) void {
        self.used_keys.deinit();
    }
    
    /// Generate a new ephemeral MLS signing key for a Group Event
    pub fn generateEphemeralKey(self: *EphemeralMlsSigningKeys) !MlsSigningKeyPair {
        while (true) {
            var key_pair = try MlsSigningKeyPair.generate(self.allocator, self.cipher_suite);
            errdefer key_pair.deinit();
            
            const nostr_pubkey = try key_pair.getNostrPublicKey();
            
            // Ensure this key hasn't been used before
            if (!self.used_keys.contains(nostr_pubkey)) {
                try self.used_keys.put(nostr_pubkey, {});
                return key_pair;
            }
            
            // Extremely rare collision, generate another key
            key_pair.deinit();
        }
    }
    
    /// Generate multiple ephemeral keys for batch operations
    pub fn generateBatchEphemeralKeys(self: *EphemeralMlsSigningKeys, count: usize) ![]MlsSigningKeyPair {
        const keys = try self.allocator.alloc(MlsSigningKeyPair, count);
        errdefer self.allocator.free(keys);
        
        var generated: usize = 0;
        errdefer {
            // Clean up any keys we've generated so far
            for (keys[0..generated]) |*key| {
                key.deinit();
            }
        }
        
        for (keys) |*key| {
            key.* = try self.generateEphemeralKey();
            generated += 1;
        }
        
        return keys;
    }
    
    /// Clear batch of ephemeral keys
    pub fn clearBatchEphemeralKeys(keys: []MlsSigningKeyPair) void {
        for (keys) |*key| {
            key.deinit();
        }
    }
    
    /// Check if a public key has been used before
    pub fn isKeyUsed(self: *EphemeralMlsSigningKeys, nostr_pubkey: [32]u8) bool {
        return self.used_keys.contains(nostr_pubkey);
    }
    
    /// Get usage statistics
    pub fn getStats(self: *EphemeralMlsSigningKeys) struct { unique_keys_generated: u32 } {
        return .{ .unique_keys_generated = @intCast(self.used_keys.count()) };
    }
};

/// Convert MLS signing key to format suitable for Nostr Group Events
pub fn mlsKeyToNostrEvent(
    allocator: Allocator,
    mls_key: *const MlsSigningKeyPair,
    event_content: []const u8,
    group_id: [32]u8,
    created_at: u64,
) !struct {
    pubkey: [32]u8,
    signature: []u8,
    event_id: [32]u8,
} {
    // Get the Nostr-compatible public key
    const nostr_pubkey = try mls_key.getNostrPublicKey();
    
    // Create the event for signing (kind 445 Group Event format)
    var event_for_signing = std.ArrayList(u8).init(allocator);
    defer event_for_signing.deinit();
    
    // Construct the signable event content per Nostr spec
    // [0, pubkey, created_at, kind, tags, content]
    var writer = event_for_signing.writer();
    try writer.print("[0,\"{s}\",{},445,[[\"h\",\"{s}\"]],\"{s}\"]",
        .{ 
            std.fmt.fmtSliceHexLower(&nostr_pubkey), 
            created_at,
            std.fmt.fmtSliceHexLower(&group_id),
            std.fmt.fmtSliceHexLower(event_content)
        });
    
    // Sign with MLS key using "NostrGroupEvent" label
    var mls_signature = try mls_key.sign(allocator, "NostrGroupEvent", event_for_signing.items);
    defer mls_signature.deinit();
    
    // Create event ID (SHA-256 of the signable content)
    var event_id: [32]u8 = undefined;
    crypto.hash.sha2.Sha256.hash(event_for_signing.items, &event_id, .{});
    
    // Convert MLS signature to Nostr signature format (64 bytes hex)
    const signature_bytes = mls_signature.asSlice();
    var nostr_signature: [64]u8 = undefined;
    if (signature_bytes.len >= 64) {
        @memcpy(nostr_signature[0..64], signature_bytes[0..64]);
    } else {
        @memset(nostr_signature[0..], 0);
        @memcpy(nostr_signature[0..signature_bytes.len], signature_bytes);
    }
    
    const signature_hex = try allocator.alloc(u8, 128); // 64 bytes as hex
    _ = std.fmt.bufPrint(signature_hex, "{s}", .{std.fmt.fmtSliceHexLower(&nostr_signature)}) catch unreachable;
    
    return .{
        .pubkey = nostr_pubkey,
        .signature = signature_hex,
        .event_id = event_id,
    };
}

// Tests

test "MLS signing key generation and usage" {
    const allocator = std.testing.allocator;
    const cs = mls_zig.cipher_suite.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    
    var key_pair = try MlsSigningKeyPair.generate(allocator, cs);
    defer key_pair.deinit();
    
    // Test signing and verification
    const test_content = "test message";
    const test_label = "TestLabel";
    
    var signature = try key_pair.sign(allocator, test_label, test_content);
    defer signature.deinit();
    
    const is_valid = try key_pair.verify(allocator, signature.asSlice(), test_label, test_content);
    try std.testing.expect(is_valid);
    
    // Test Nostr public key conversion
    const nostr_pubkey = try key_pair.getNostrPublicKey();
    try std.testing.expect(!std.mem.allEqual(u8, nostr_pubkey, 0));
}

test "ephemeral MLS signing key uniqueness" {
    const allocator = std.testing.allocator;
    const cs = mls_zig.cipher_suite.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    
    var ephemeral_keys = EphemeralMlsSigningKeys.init(allocator, cs);
    defer ephemeral_keys.deinit();
    
    // Generate multiple keys and verify uniqueness
    var key1 = try ephemeral_keys.generateEphemeralKey();
    defer key1.deinit();
    
    var key2 = try ephemeral_keys.generateEphemeralKey();
    defer key2.deinit();
    
    const pubkey1 = try key1.getNostrPublicKey();
    const pubkey2 = try key2.getNostrPublicKey();
    
    try std.testing.expect(!std.mem.eql(u8, &pubkey1, &pubkey2));
    try std.testing.expect(ephemeral_keys.isKeyUsed(pubkey1));
    try std.testing.expect(ephemeral_keys.isKeyUsed(pubkey2));
    
    const stats = ephemeral_keys.getStats();
    try std.testing.expectEqual(@as(u32, 2), stats.unique_keys_generated);
}

test "batch ephemeral key generation" {
    const allocator = std.testing.allocator;
    const cs = mls_zig.cipher_suite.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    
    var ephemeral_keys = EphemeralMlsSigningKeys.init(allocator, cs);
    defer ephemeral_keys.deinit();
    
    const keys = try ephemeral_keys.generateBatchEphemeralKeys(3);
    defer {
        EphemeralMlsSigningKeys.clearBatchEphemeralKeys(keys);
        allocator.free(keys);
    }
    
    try std.testing.expectEqual(@as(usize, 3), keys.len);
    
    // Verify all keys are unique
    for (keys, 0..) |key1, i| {
        const pubkey1 = try key1.getNostrPublicKey();
        for (keys[i + 1 ..]) |key2| {
            const pubkey2 = try key2.getNostrPublicKey();
            try std.testing.expect(!std.mem.eql(u8, &pubkey1, &pubkey2));
        }
    }
}

test "MLS key to Nostr event conversion" {
    const allocator = std.testing.allocator;
    const cs = mls_zig.cipher_suite.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    
    var key_pair = try MlsSigningKeyPair.generate(allocator, cs);
    defer key_pair.deinit();
    
    const test_content = "encrypted message content";
    const group_id: [32]u8 = [_]u8{0x42} ** 32;
    const created_at: u64 = 1234567890;
    
    const nostr_event = try mlsKeyToNostrEvent(
        allocator,
        &key_pair,
        test_content,
        group_id,
        created_at,
    );
    defer allocator.free(nostr_event.signature);
    
    // Verify event structure
    try std.testing.expect(!std.mem.allEqual(u8, nostr_event.pubkey, 0));
    try std.testing.expect(!std.mem.allEqual(u8, nostr_event.event_id, 0));
    try std.testing.expectEqual(@as(usize, 128), nostr_event.signature.len); // 64 bytes as hex
}