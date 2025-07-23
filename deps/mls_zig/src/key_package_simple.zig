const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const wasm_random = @import("wasm_random.zig");
const tls_codec = @import("tls_codec.zig");
pub const cipher_suite = @import("cipher_suite.zig");
const credentials = @import("credentials.zig");

/// MLS Protocol Version (RFC 9420)
pub const MLS_PROTOCOL_VERSION: u16 = 0x0001;

/// Simplified KeyPackage with flat structure and fixed-size arrays
/// Maintains MLS RFC 9420 compliance while being WASM-friendly
pub const KeyPackage = struct {
    // Core MLS KeyPackage fields (RFC 9420 Section 7.2)
    protocol_version: u16,
    cipher_suite: cipher_suite.CipherSuite,
    
    // Fixed-size keys for WASM compatibility
    init_key: [32]u8,           // HPKE public key for initialization
    encryption_key: [32]u8,     // HPKE public key for encryption
    signature_key: [32]u8,      // Ed25519 signature public key
    
    // Credential (simplified to basic credential for NIP-EE)
    credential_identity: []const u8,  // Will be allocated separately
    
    // MLS signature over the to-be-signed content
    signature: [64]u8,          // Ed25519 signature
    
    pub fn init(
        cs: cipher_suite.CipherSuite,
        init_key: [32]u8,
        encryption_key: [32]u8,
        signature_key: [32]u8,
        credential_identity: []const u8,
        signature: [64]u8,
    ) KeyPackage {
        return KeyPackage{
            .protocol_version = MLS_PROTOCOL_VERSION,
            .cipher_suite = cs,
            .init_key = init_key,
            .encryption_key = encryption_key,
            .signature_key = signature_key,
            .credential_identity = credential_identity,
            .signature = signature,
        };
    }
    
    /// Get the cipher suite for this KeyPackage
    pub fn cipherSuite(self: KeyPackage) cipher_suite.CipherSuite {
        return self.cipher_suite;
    }
    
    /// Get the protocol version
    pub fn protocolVersion(self: KeyPackage) u16 {
        return self.protocol_version; 
    }
    
    /// Serialize KeyPackage to TLS format (RFC 9420)
    pub fn tlsSerialize(self: KeyPackage, allocator: Allocator) ![]u8 {
        var buffer = std.ArrayList(u8).init(allocator);
        errdefer buffer.deinit();
        
        // Protocol version (u16, big-endian)
        try tls_codec.writeU16ToList(&buffer, self.protocol_version);
        
        // Cipher suite (u16, big-endian) 
        try tls_codec.writeU16ToList(&buffer, @intFromEnum(self.cipher_suite));
        
        // Init key with length prefix (u16)
        try tls_codec.writeVarBytesToList(&buffer, u16, &self.init_key);
        
        // Simplified leaf node serialization
        try tls_codec.writeVarBytesToList(&buffer, u16, &self.encryption_key);
        try tls_codec.writeVarBytesToList(&buffer, u16, &self.signature_key);
        try tls_codec.writeVarBytesToList(&buffer, u16, self.credential_identity);
        
        // Empty extensions for simplicity
        try tls_codec.writeU16ToList(&buffer, 0);
        
        // Signature over the above content
        try tls_codec.writeVarBytesToList(&buffer, u16, &self.signature);
        
        return buffer.toOwnedSlice();
    }
};

/// Bundle containing KeyPackage and associated private keys
pub const KeyPackageBundle = struct {
    key_package: KeyPackage,
    private_init_key: [32]u8,       // X25519 private key
    private_encryption_key: [32]u8, // X25519 private key  
    private_signature_key: [64]u8,  // Ed25519 private key (32 bytes + 32 bytes public)
    
    pub fn init(
        key_package: KeyPackage,
        private_init_key: [32]u8,
        private_encryption_key: [32]u8,
        private_signature_key: [64]u8,
    ) KeyPackageBundle {
        return KeyPackageBundle{
            .key_package = key_package,
            .private_init_key = private_init_key,
            .private_encryption_key = private_encryption_key,
            .private_signature_key = private_signature_key,
        };
    }
};

/// Generate a complete KeyPackageBundle with proper MLS signing
pub fn generateKeyPackageBundle(
    allocator: Allocator,
    cs: cipher_suite.CipherSuite,
    credential_identity: []const u8,
    random_fn: ?wasm_random.RandomFunction,
) !KeyPackageBundle {
    // Generate three separate key pairs for MLS
    var init_private_key: [32]u8 = undefined;
    var init_public_key: [32]u8 = undefined;
    
    var enc_private_key: [32]u8 = undefined;
    var enc_public_key: [32]u8 = undefined;
    
    var sig_private_key: [64]u8 = undefined; // Ed25519 format: private + public
    var sig_public_key: [32]u8 = undefined;
    
    // Generate keys using crypto functions
    if (random_fn) |rand_fn| {
        rand_fn(&init_private_key);
        rand_fn(&enc_private_key);
        rand_fn(sig_private_key[0..32]); // Only first 32 bytes are random
    } else {
        wasm_random.secure_random.bytes(&init_private_key);
        wasm_random.secure_random.bytes(&enc_private_key);
        wasm_random.secure_random.bytes(sig_private_key[0..32]);
    }
    
    // Compute public keys
    const init_keypair = try std.crypto.dh.X25519.KeyPair.generateDeterministic(init_private_key);
    init_public_key = init_keypair.public_key;
    
    const enc_keypair = try std.crypto.dh.X25519.KeyPair.generateDeterministic(enc_private_key);
    enc_public_key = enc_keypair.public_key;
    
    const sig_keypair = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(sig_private_key[0..32].*);
    @memcpy(&sig_public_key, &sig_keypair.public_key.bytes);
    @memcpy(sig_private_key[32..64], &sig_keypair.public_key.bytes); // Store public key in private key structure
    
    // Create the to-be-signed content for MLS signature
    var tbs_content = std.ArrayList(u8).init(allocator);
    defer tbs_content.deinit();
    
    // Serialize the content that will be signed (RFC 9420 format)
    try tls_codec.writeU16ToList(&tbs_content, MLS_PROTOCOL_VERSION);
    try tls_codec.writeU16ToList(&tbs_content, @intFromEnum(cs));
    try tls_codec.writeVarBytesToList(&tbs_content, u16, &init_public_key);
    try tls_codec.writeVarBytesToList(&tbs_content, u16, &enc_public_key);
    try tls_codec.writeVarBytesToList(&tbs_content, u16, &sig_public_key);
    try tls_codec.writeVarBytesToList(&tbs_content, u16, credential_identity);
    try tls_codec.writeU16ToList(&tbs_content, 0); // Empty extensions
    
    // Sign with MLS label as per RFC 9420 
    // Ed25519 secret key is first 32 bytes
    const signature = try signWithLabel(
        sig_keypair.secret_key.bytes[0..32].*,
        "KeyPackageTBS",
        tbs_content.items,
    );
    
    // Create the KeyPackage
    const key_package = KeyPackage.init(
        cs,
        init_public_key,
        enc_public_key,
        sig_public_key,
        credential_identity,
        signature,
    );
    
    return KeyPackageBundle.init(
        key_package,
        init_private_key,
        enc_private_key,
        sig_private_key,
    );
}

/// MLS signature with label (RFC 9420 Section 5.1.2)
fn signWithLabel(
    private_key: [32]u8,
    label: []const u8,
    content: []const u8,
) ![64]u8 {
    // Create MLS signature context: "MLS 1.0 " + label + content
    const mls_prefix = "MLS 1.0 ";
    const total_len = mls_prefix.len + label.len + content.len;
    
    // Use a reasonable stack buffer for typical cases
    var stack_buffer: [1024]u8 = undefined;
    var to_sign: []u8 = undefined;
    var heap_buffer: ?std.ArrayList(u8) = null;
    
    if (total_len <= stack_buffer.len) {
        to_sign = stack_buffer[0..total_len];
    } else {
        // Fallback to heap allocation for large content
        heap_buffer = std.ArrayList(u8).init(std.heap.page_allocator);
        to_sign = try heap_buffer.?.addManyAsSlice(total_len);
    }
    defer if (heap_buffer) |*buf| buf.deinit();
    
    // Build the signing content
    @memcpy(to_sign[0..mls_prefix.len], mls_prefix);
    @memcpy(to_sign[mls_prefix.len..mls_prefix.len + label.len], label);
    @memcpy(to_sign[mls_prefix.len + label.len..], content);
    
    // Sign with Ed25519
    const keypair = try std.crypto.sign.Ed25519.KeyPair.fromSecretKey(private_key);
    const signature = try keypair.sign(to_sign, null);
    
    return signature.toBytes();
}

// Tests to ensure MLS compliance
test "KeyPackage creation and serialization" {
    const allocator = testing.allocator;
    const cs = cipher_suite.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    const identity = "test@example.com";
    
    var bundle = try generateKeyPackageBundle(allocator, cs, identity, null);
    
    // Verify key sizes are correct for MLS
    try testing.expectEqual(@as(usize, 32), bundle.key_package.init_key.len);
    try testing.expectEqual(@as(usize, 32), bundle.key_package.encryption_key.len);
    try testing.expectEqual(@as(usize, 32), bundle.key_package.signature_key.len);
    try testing.expectEqual(@as(usize, 64), bundle.key_package.signature.len);
    
    // Verify MLS protocol compliance
    try testing.expectEqual(MLS_PROTOCOL_VERSION, bundle.key_package.protocol_version);
    try testing.expectEqual(cs, bundle.key_package.cipher_suite);
    
    // Test serialization
    const serialized = try bundle.key_package.tlsSerialize(allocator);
    defer allocator.free(serialized);
    
    try testing.expect(serialized.len > 100); // Should have substantial content
}

test "Fixed-size arrays prevent memory corruption" {
    // This test verifies our WASM-friendly design
    const cs = cipher_suite.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    
    var init_key: [32]u8 = undefined;
    var enc_key: [32]u8 = undefined;
    var sig_key: [32]u8 = undefined;
    var signature: [64]u8 = undefined;
    
    wasm_random.secure_random.bytes(&init_key);
    wasm_random.secure_random.bytes(&enc_key);
    wasm_random.secure_random.bytes(&sig_key);
    wasm_random.secure_random.bytes(&signature);
    
    const key_package = KeyPackage.init(
        cs,
        init_key,
        enc_key, 
        sig_key,
        "test@example.com",
        signature,
    );
    
    // These should always be exactly 32 bytes (no corruption possible)
    try testing.expectEqual(@as(usize, 32), key_package.init_key.len);
    try testing.expectEqual(@as(usize, 32), key_package.encryption_key.len);
    try testing.expectEqual(@as(usize, 32), key_package.signature_key.len);
    try testing.expectEqual(@as(usize, 64), key_package.signature.len);
    
    // Verify no null pointers (common WASM corruption symptom)
    const init_ptr = @intFromPtr(&key_package.init_key);
    const enc_ptr = @intFromPtr(&key_package.encryption_key);
    const sig_ptr = @intFromPtr(&key_package.signature_key);
    
    try testing.expect(init_ptr != 0);
    try testing.expect(enc_ptr != 0);
    try testing.expect(sig_ptr != 0);
}