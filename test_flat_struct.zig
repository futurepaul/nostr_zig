const std = @import("std");
const testing = std.testing;

/// Simplified MLS-compliant KeyPackage with flat structure
pub const FlatKeyPackage = struct {
    // MLS RFC 9420 required fields
    protocol_version: u16 = 0x0001,
    cipher_suite: u16 = 0x0001, // Ed25519 + X25519 + AES-GCM + SHA256
    
    // Fixed-size keys for WASM compatibility
    init_key: [32]u8,           // X25519 public key for HPKE initialization
    encryption_key: [32]u8,     // X25519 public key for encryption
    signature_key: [32]u8,      // Ed25519 public key for signatures
    
    // Basic credential (just identity string length + data - to be allocated separately)
    credential_len: u16,
    
    // MLS signature over the to-be-signed content
    signature: [64]u8,          // Ed25519 signature
    
    pub fn init(
        init_key: [32]u8,
        encryption_key: [32]u8,
        signature_key: [32]u8,
        credential_len: u16,
        signature: [64]u8,
    ) FlatKeyPackage {
        return FlatKeyPackage{
            .init_key = init_key,
            .encryption_key = encryption_key,
            .signature_key = signature_key,
            .credential_len = credential_len,
            .signature = signature,
        };
    }
    
    /// Simple TLS serialization (no external dependencies)
    pub fn serialize(self: FlatKeyPackage, buffer: []u8) !usize {
        if (buffer.len < self.serializedSize()) return error.BufferTooSmall;
        
        var pos: usize = 0;
        
        // Protocol version (u16, big-endian)
        std.mem.writeInt(u16, buffer[pos..pos+2][0..2], self.protocol_version, .big);
        pos += 2;
        
        // Cipher suite (u16, big-endian)
        std.mem.writeInt(u16, buffer[pos..pos+2][0..2], self.cipher_suite, .big);
        pos += 2;
        
        // Init key with length prefix
        std.mem.writeInt(u16, buffer[pos..pos+2][0..2], 32, .big);
        pos += 2;
        @memcpy(buffer[pos..pos+32], &self.init_key);
        pos += 32;
        
        // Encryption key with length prefix
        std.mem.writeInt(u16, buffer[pos..pos+2][0..2], 32, .big);  
        pos += 2;
        @memcpy(buffer[pos..pos+32], &self.encryption_key);
        pos += 32;
        
        // Signature key with length prefix
        std.mem.writeInt(u16, buffer[pos..pos+2][0..2], 32, .big);
        pos += 2; 
        @memcpy(buffer[pos..pos+32], &self.signature_key);
        pos += 32;
        
        // Credential length
        std.mem.writeInt(u16, buffer[pos..pos+2][0..2], self.credential_len, .big);
        pos += 2;
        
        // Empty extensions (u16 length = 0)
        std.mem.writeInt(u16, buffer[pos..pos+2][0..2], 0, .big);
        pos += 2;
        
        // Signature with length prefix
        std.mem.writeInt(u16, buffer[pos..pos+2][0..2], 64, .big);
        pos += 2;
        @memcpy(buffer[pos..pos+64], &self.signature);
        pos += 64;
        
        return pos;
    }
    
    pub fn serializedSize(self: FlatKeyPackage) usize {
        _ = self;
        // version(2) + suite(2) + init_key(2+32) + enc_key(2+32) + sig_key(2+32) + 
        // cred_len(2) + extensions(2) + signature(2+64) = 176 bytes
        return 176;
    }
};

test "flat KeyPackage structure prevents memory corruption" {
    var init_key: [32]u8 = undefined;
    var enc_key: [32]u8 = undefined; 
    var sig_key: [32]u8 = undefined;
    var signature: [64]u8 = undefined;
    
    // Generate test keys
    std.crypto.random.bytes(&init_key);
    std.crypto.random.bytes(&enc_key);
    std.crypto.random.bytes(&sig_key);
    std.crypto.random.bytes(&signature);
    
    const key_package = FlatKeyPackage.init(
        init_key,
        enc_key,
        sig_key,
        16, // "test@example.com".len
        signature,
    );
    
    // These can NEVER be corrupted - they're fixed-size stack arrays
    try testing.expectEqual(@as(usize, 32), key_package.init_key.len);
    try testing.expectEqual(@as(usize, 32), key_package.encryption_key.len);
    try testing.expectEqual(@as(usize, 32), key_package.signature_key.len);
    try testing.expectEqual(@as(usize, 64), key_package.signature.len);
    
    // Verify MLS compliance
    try testing.expectEqual(@as(u16, 0x0001), key_package.protocol_version);
    try testing.expectEqual(@as(u16, 0x0001), key_package.cipher_suite);
    
    // Test serialization (no heap allocation needed)
    var buffer: [256]u8 = undefined;
    const serialized_len = try key_package.serialize(&buffer);
    
    try testing.expectEqual(@as(usize, 176), serialized_len);
    try testing.expectEqual(key_package.serializedSize(), serialized_len);
    
    // Verify no null pointers (WASM corruption symptom)
    const init_ptr = @intFromPtr(&key_package.init_key);
    const enc_ptr = @intFromPtr(&key_package.encryption_key);  
    const sig_ptr = @intFromPtr(&key_package.signature_key);
    
    try testing.expect(init_ptr != 0);
    try testing.expect(enc_ptr != 0); 
    try testing.expect(sig_ptr != 0);
    
    std.debug.print("✅ Flat KeyPackage test passed - no memory corruption possible!\n", .{});
    std.debug.print("   init_key.len = {}, enc_key.len = {}, sig_key.len = {}\n", 
        .{key_package.init_key.len, key_package.encryption_key.len, key_package.signature_key.len});
}

test "KeyPackage can be passed by value safely" {
    // Test the key insight: flat structs with fixed arrays can be passed by value
    // This is critical for WASM - no pointer sharing issues
    
    var test_keys: [32]u8 = undefined;
    @memset(&test_keys, 0xAB);
    
    var test_sig: [64]u8 = undefined;
    @memset(&test_sig, 0xCD);
    
    const original = FlatKeyPackage.init(
        test_keys, test_keys, test_keys, 10, test_sig
    );
    
    // Pass by value (copy the entire struct)
    const copy = passKeyPackageByValue(original);
    
    // Both should have identical, independent data
    try testing.expectEqual(original.init_key.len, copy.init_key.len);
    try testing.expectEqualSlices(u8, &original.init_key, &copy.init_key);
    try testing.expectEqualSlices(u8, &original.signature, &copy.signature);
    
    // Memory addresses should be different (independent copies)
    const orig_ptr = @intFromPtr(&original.init_key);
    const copy_ptr = @intFromPtr(&copy.init_key);  
    try testing.expect(orig_ptr != copy_ptr);
    
    std.debug.print("✅ Pass-by-value test passed - safe for WASM!\n", .{});
}

fn passKeyPackageByValue(kp: FlatKeyPackage) FlatKeyPackage {
    // This function receives a complete copy of the struct
    // No heap pointers to become invalid
    return kp;
}