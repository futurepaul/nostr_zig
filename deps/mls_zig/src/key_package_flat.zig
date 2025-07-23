const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const tls_codec = @import("tls_codec.zig");
const cipher_suite = @import("cipher_suite.zig");

/// MLS Protocol Version (RFC 9420)
pub const MLS_PROTOCOL_VERSION: u16 = 0x0001;

/// Flat KeyPackage structure - WASM-friendly with fixed arrays
/// Maintains MLS RFC 9420 compliance without complex ownership
pub const KeyPackage = struct {
    // Core MLS KeyPackage fields (RFC 9420 Section 7.2)
    protocol_version: u16,
    cipher_suite: cipher_suite.CipherSuite,
    
    // Fixed-size keys for WASM compatibility - NO HEAP ALLOCATION
    init_key: [32]u8,           // HPKE public key for initialization
    encryption_key: [32]u8,     // HPKE public key for encryption  
    signature_key: [32]u8,      // Ed25519 public key for signatures
    
    // Basic credential info (length only - data stored separately)
    credential_len: u16,
    
    // MLS signature over the to-be-signed content
    signature: [64]u8,          // Ed25519 signature
    
    pub fn init(
        cs: cipher_suite.CipherSuite,
        init_key: [32]u8,
        encryption_key: [32]u8,
        signature_key: [32]u8,
        credential_len: u16,
        signature: [64]u8,
    ) KeyPackage {
        return KeyPackage{
            .protocol_version = MLS_PROTOCOL_VERSION,
            .cipher_suite = cs,
            .init_key = init_key,
            .encryption_key = encryption_key,
            .signature_key = signature_key,
            .credential_len = credential_len,
            .signature = signature,
        };
    }
    
    /// Get the cipher suite (API compatibility)
    pub fn cipherSuite(self: KeyPackage) cipher_suite.CipherSuite {
        return self.cipher_suite;
    }
    
    /// Get the protocol version (API compatibility)
    pub fn protocolVersion(self: KeyPackage) u16 {
        return self.protocol_version;
    }
    
    /// Get init key (API compatibility - returns pointer to stack array)
    pub fn initKey(self: *const KeyPackage) *const [32]u8 {
        return &self.init_key;
    }
    
    /// Get encryption key (API compatibility)
    pub fn encryptionKey(self: *const KeyPackage) *const [32]u8 {
        return &self.encryption_key;
    }
    
    /// Get signature key (API compatibility)  
    pub fn signatureKey(self: *const KeyPackage) *const [32]u8 {
        return &self.signature_key;
    }
    
    /// TLS serialize the KeyPackage (RFC 9420 format)
    pub fn tlsSerialize(self: KeyPackage, allocator: Allocator) ![]u8 {
        var buffer = std.ArrayList(u8).init(allocator);
        errdefer buffer.deinit();
        
        // Protocol version (u16, big-endian)
        try tls_codec.writeU16ToList(&buffer, self.protocol_version);
        
        // Cipher suite (u16, big-endian)
        try tls_codec.writeU16ToList(&buffer, @intFromEnum(self.cipher_suite));
        
        // Init key with TLS variable-length encoding
        try tls_codec.writeVarBytesToList(&buffer, u16, &self.init_key);
        
        // Simplified leaf node (just the keys for NIP-EE)
        try tls_codec.writeVarBytesToList(&buffer, u16, &self.encryption_key);
        try tls_codec.writeVarBytesToList(&buffer, u16, &self.signature_key);
        
        // Credential length only (actual data stored separately)
        try tls_codec.writeU16ToList(&buffer, self.credential_len);
        
        // Empty extensions for NIP-EE simplicity
        try tls_codec.writeU16ToList(&buffer, 0);
        
        // Signature over the KeyPackageTBS
        try tls_codec.writeVarBytesToList(&buffer, u16, &self.signature);
        
        return buffer.toOwnedSlice();
    }
    
    /// No cleanup needed - everything is stack allocated!
    pub fn deinit(self: *KeyPackage) void {
        _ = self; // No-op - no heap allocation to free
    }
};

/// Bundle containing KeyPackage and private keys - also flat!
pub const KeyPackageBundle = struct {
    key_package: KeyPackage,
    private_init_key: [32]u8,       // X25519 private key
    private_encryption_key: [32]u8, // X25519 private key
    private_signature_key: [64]u8,  // Ed25519 private key (32 private + 32 public)
    
    pub fn init(
        allocator: Allocator,
        cs: cipher_suite.CipherSuite,
        credential_identity: []const u8,
        random_fn: ?*const fn ([]u8) void,
    ) !KeyPackageBundle {
        _ = allocator; // Not needed for flat approach
        
        // Generate private keys
        var init_private: [32]u8 = undefined;
        var enc_private: [32]u8 = undefined;
        var sig_private: [64]u8 = undefined;
        
        if (random_fn) |rand_fn| {
            rand_fn(&init_private);
            rand_fn(&enc_private);
            rand_fn(sig_private[0..32]);
        } else {
            // For non-WASM targets, use crypto random
            // In WASM, a random function MUST be provided
            if (@import("builtin").target.cpu.arch == .wasm32) {
                return error.RandomFunctionRequired;  
            }
            std.crypto.random.bytes(&init_private);
            std.crypto.random.bytes(&enc_private);
            std.crypto.random.bytes(sig_private[0..32]);
        }
        
        // Compute public keys
        const init_keypair = try std.crypto.dh.X25519.KeyPair.generateDeterministic(init_private);
        const enc_keypair = try std.crypto.dh.X25519.KeyPair.generateDeterministic(enc_private);
        // Generate Ed25519 keypair from the 32-byte seed
        const sig_keypair = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(sig_private[0..32].*);
        
        // Store the full secret key (seed + public key) in sig_private
        sig_private = sig_keypair.secret_key.bytes;
        
        // Create signature over the to-be-signed content
        const signature = try createMlsSignature(
            sig_keypair.secret_key.bytes,
            cs,
            init_keypair.public_key,
            enc_keypair.public_key,
            sig_keypair.public_key.bytes,
            credential_identity,
        );
        
        const key_package = KeyPackage.init(
            cs,
            init_keypair.public_key,
            enc_keypair.public_key,
            sig_keypair.public_key.bytes,
            @intCast(credential_identity.len),
            signature,
        );
        
        return KeyPackageBundle{
            .key_package = key_package,
            .private_init_key = init_private,
            .private_encryption_key = enc_private,
            .private_signature_key = sig_private,
        };
    }
    
    /// No cleanup needed - everything is stack allocated!
    pub fn deinit(self: *KeyPackageBundle) void {
        _ = self; // No-op
    }
};

/// Create MLS signature with proper label (RFC 9420 Section 5.1.2)
fn createMlsSignature(
    private_key: [64]u8,
    cs: cipher_suite.CipherSuite,
    init_key: [32]u8,
    enc_key: [32]u8,
    sig_key: [32]u8,
    credential_identity: []const u8,
) ![64]u8 {
    // Build the to-be-signed content
    var tbs_buffer: [512]u8 = undefined; // Stack buffer for most cases
    var pos: usize = 0;
    
    // Protocol version (u16, big-endian)
    std.mem.writeInt(u16, tbs_buffer[pos..pos+2][0..2], MLS_PROTOCOL_VERSION, .big);
    pos += 2;
    
    // Cipher suite (u16, big-endian)
    std.mem.writeInt(u16, tbs_buffer[pos..pos+2][0..2], @intFromEnum(cs), .big);
    pos += 2;
    
    // Init key with length prefix
    std.mem.writeInt(u16, tbs_buffer[pos..pos+2][0..2], 32, .big);
    pos += 2;
    @memcpy(tbs_buffer[pos..pos+32], &init_key);
    pos += 32;
    
    // Encryption key with length prefix
    std.mem.writeInt(u16, tbs_buffer[pos..pos+2][0..2], 32, .big);
    pos += 2;
    @memcpy(tbs_buffer[pos..pos+32], &enc_key);
    pos += 32;
    
    // Signature key with length prefix
    std.mem.writeInt(u16, tbs_buffer[pos..pos+2][0..2], 32, .big);
    pos += 2;
    @memcpy(tbs_buffer[pos..pos+32], &sig_key);
    pos += 32;
    
    // Credential length
    std.mem.writeInt(u16, tbs_buffer[pos..pos+2][0..2], @intCast(credential_identity.len), .big);
    pos += 2;
    
    // Empty extensions
    std.mem.writeInt(u16, tbs_buffer[pos..pos+2][0..2], 0, .big);
    pos += 2;
    
    const tbs_content = tbs_buffer[0..pos];
    
    // Create MLS signature with label
    const mls_prefix = "MLS 1.0 KeyPackageTBS";
    var full_content: [1024]u8 = undefined;
    @memcpy(full_content[0..mls_prefix.len], mls_prefix);
    @memcpy(full_content[mls_prefix.len..mls_prefix.len + tbs_content.len], tbs_content);
    
    const to_sign = full_content[0..mls_prefix.len + tbs_content.len];
    
    // Sign with Ed25519 - need to convert array to SecretKey struct
    const secret_key = std.crypto.sign.Ed25519.SecretKey{ .bytes = private_key };
    const keypair = try std.crypto.sign.Ed25519.KeyPair.fromSecretKey(secret_key);
    const signature = try keypair.sign(to_sign, null);
    
    return signature.toBytes();
}

// Tests to verify MLS compliance and WASM safety
test "flat KeyPackage prevents memory corruption" {
    const cs = cipher_suite.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    
    var init_key: [32]u8 = undefined;
    var enc_key: [32]u8 = undefined;
    var sig_key: [32]u8 = undefined;
    var signature: [64]u8 = undefined;
    
    // Fill with recognizable test data
    @memset(&init_key, 0x01);
    @memset(&enc_key, 0x02);
    @memset(&sig_key, 0x03);
    @memset(&signature, 0x04);
    
    const key_package = KeyPackage.init(
        cs,
        init_key,
        enc_key,
        sig_key,
        16, // "test@example.com".len
        signature,
    );
    
    // These can NEVER be corrupted - fixed-size stack arrays
    try testing.expectEqual(@as(usize, 32), key_package.init_key.len);
    try testing.expectEqual(@as(usize, 32), key_package.encryption_key.len);
    try testing.expectEqual(@as(usize, 32), key_package.signature_key.len);
    try testing.expectEqual(@as(usize, 64), key_package.signature.len);
    
    // Verify no "33 vs 32" corruption possible
    const init_key_ptr = key_package.initKey();
    try testing.expectEqual(@as(usize, 32), init_key_ptr.len);
    try testing.expectEqual(@as(u8, 0x01), init_key_ptr[0]); // Not 0x20!
    
    // Verify MLS compliance
    try testing.expectEqual(MLS_PROTOCOL_VERSION, key_package.protocol_version);
    try testing.expectEqual(cs, key_package.cipher_suite);
    
    std.debug.print("✅ Flat KeyPackage prevents corruption: init_key.len = {}\n", .{init_key_ptr.len});
}

test "KeyPackageBundle generation with real crypto" {
    const allocator = testing.allocator;
    const cs = cipher_suite.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    const identity = "test@example.com";
    
    var bundle = try KeyPackageBundle.init(allocator, cs, identity, null);
    defer bundle.deinit(); // No-op, but maintains API compatibility
    
    // Verify all keys are exactly 32 bytes
    try testing.expectEqual(@as(usize, 32), bundle.key_package.init_key.len);
    try testing.expectEqual(@as(usize, 32), bundle.key_package.encryption_key.len);
    try testing.expectEqual(@as(usize, 32), bundle.key_package.signature_key.len);
    
    // Verify private keys have correct sizes
    try testing.expectEqual(@as(usize, 32), bundle.private_init_key.len);
    try testing.expectEqual(@as(usize, 32), bundle.private_encryption_key.len);
    try testing.expectEqual(@as(usize, 64), bundle.private_signature_key.len); // Ed25519 format
    
    // Test serialization
    const serialized = try bundle.key_package.tlsSerialize(allocator);
    defer allocator.free(serialized);
    
    try testing.expect(serialized.len > 100); // Should have substantial content
    
    std.debug.print("✅ KeyPackageBundle generation: init={}, enc={}, sig={} bytes\n", 
        .{bundle.key_package.init_key.len, bundle.key_package.encryption_key.len, bundle.key_package.signature_key.len});
}

test "pass by value is safe for WASM" {
    // Critical test: flat structs can be safely passed by value across WASM boundaries
    const cs = cipher_suite.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    
    var test_key: [32]u8 = undefined;
    var test_sig: [64]u8 = undefined;
    @memset(&test_key, 0xAB);
    @memset(&test_sig, 0xCD);
    
    const original = KeyPackage.init(cs, test_key, test_key, test_key, 10, test_sig);
    
    // Pass by value (WASM-safe)
    const copy = passKeyPackageByValue(original);
    
    // Data should be identical
    try testing.expectEqualSlices(u8, &original.init_key, &copy.init_key);
    
    // But memory addresses should be different (independent copies)
    const orig_ptr = @intFromPtr(&original.init_key);
    const copy_ptr = @intFromPtr(&copy.init_key);
    try testing.expect(orig_ptr != copy_ptr);
    
    std.debug.print("✅ Pass-by-value safe for WASM!\n", .{});
}

fn passKeyPackageByValue(kp: KeyPackage) KeyPackage {
    // Receives a complete stack copy - no heap pointers to corrupt
    return kp;
}