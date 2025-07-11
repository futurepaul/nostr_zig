const std = @import("std");
const types = @import("types.zig");
const mls_zig = @import("mls_zig");

/// MLS Provider interface for cryptographic operations
pub const MlsProvider = struct {
    crypto: CryptoProvider,
    rand: RandomProvider,
    time: TimeProvider,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) MlsProvider {
        return .{
            .crypto = CryptoProvider.init(),
            .rand = RandomProvider.init(),
            .time = TimeProvider.init(),
            .allocator = allocator,
        };
    }
};

/// Cryptographic operations provider
pub const CryptoProvider = struct {
    /// Sign data with a private key
    signFn: *const fn (allocator: std.mem.Allocator, private_key: []const u8, data: []const u8) anyerror![]u8,
    
    /// Verify a signature
    verifyFn: *const fn (public_key: []const u8, data: []const u8, signature: []const u8) anyerror!bool,
    
    /// HPKE seal (encrypt)
    hpkeSealFn: *const fn (allocator: std.mem.Allocator, public_key: []const u8, info: []const u8, aad: []const u8, plaintext: []const u8) anyerror!HpkeCiphertext,
    
    /// HPKE open (decrypt)
    hpkeOpenFn: *const fn (allocator: std.mem.Allocator, private_key: []const u8, info: []const u8, aad: []const u8, ciphertext: HpkeCiphertext) anyerror![]u8,
    
    /// Generate HPKE key pair
    hpkeGenerateKeyPairFn: *const fn (allocator: std.mem.Allocator) anyerror!HpkeKeyPair,
    
    /// Derive key using HKDF
    hkdfExpandFn: *const fn (allocator: std.mem.Allocator, secret: []const u8, info: []const u8, length: usize) anyerror![]u8,
    
    /// Extract key using HKDF
    hkdfExtractFn: *const fn (allocator: std.mem.Allocator, salt: []const u8, ikm: []const u8) anyerror![]u8,
    
    /// Hash data
    hashFn: *const fn (allocator: std.mem.Allocator, data: []const u8) anyerror![32]u8,

    pub fn init() CryptoProvider {
        return .{
            .signFn = defaultSign,
            .verifyFn = defaultVerify,
            .hpkeSealFn = defaultHpkeSeal,
            .hpkeOpenFn = defaultHpkeOpen,
            .hpkeGenerateKeyPairFn = defaultHpkeGenerateKeyPair,
            .hkdfExpandFn = defaultHkdfExpand,
            .hkdfExtractFn = defaultHkdfExtract,
            .hashFn = defaultHash,
        };
    }
};

/// Random number generator provider
pub const RandomProvider = struct {
    /// Generate random bytes
    fillFn: *const fn (buffer: []u8) void,

    pub fn init() RandomProvider {
        return .{
            .fillFn = defaultRandomFill,
        };
    }

    pub fn fill(self: RandomProvider, buffer: []u8) void {
        self.fillFn(buffer);
    }
};

/// Time provider
pub const TimeProvider = struct {
    /// Get current Unix timestamp in seconds
    nowFn: *const fn () u64,

    pub fn init() TimeProvider {
        return .{
            .nowFn = defaultNow,
        };
    }

    pub fn now(self: TimeProvider) u64 {
        return self.nowFn();
    }
};

/// HPKE ciphertext structure
pub const HpkeCiphertext = struct {
    kem_output: []const u8,
    ciphertext: []const u8,
};

/// HPKE key pair
pub const HpkeKeyPair = struct {
    private_key: []const u8,
    public_key: []const u8,
};

// Default implementations using standard library and our crypto module

const crypto = @import("../crypto.zig");

fn defaultSign(allocator: std.mem.Allocator, private_key: []const u8, data: []const u8) anyerror![]u8 {
    // For now, use Zig's standard Ed25519 implementation
    // TODO: Integrate with mls_zig's signWithLabel once we understand the full API
    const Ed25519 = std.crypto.sign.Ed25519;
    
    // Ed25519 private keys should be 32 or 64 bytes
    var secret_key: Ed25519.SecretKey = undefined;
    
    if (private_key.len == 32) {
        // If we have a 32-byte seed, expand it to 64-byte secret key
        var full_key: [64]u8 = undefined;
        @memcpy(full_key[0..32], private_key);
        // Derive public key from seed
        const kp = Ed25519.KeyPair.create(private_key[0..32].*) catch return error.InvalidKeyLength;
        @memcpy(full_key[32..64], &kp.public_key.bytes);
        secret_key = Ed25519.SecretKey.fromBytes(full_key);
    } else if (private_key.len == 64) {
        // If we have a full 64-byte key, use it directly
        secret_key = Ed25519.SecretKey.fromBytes(private_key[0..64].*);
    } else {
        return error.InvalidKeyLength;
    }
    
    // Create KeyPair from secret key
    const kp = try Ed25519.KeyPair.fromSecretKey(secret_key);
    
    // Sign the data
    const signature = try kp.sign(data, null);
    
    // Return signature as allocated slice
    const result = try allocator.alloc(u8, signature.toBytes().len);
    @memcpy(result, &signature.toBytes());
    return result;
}

fn defaultVerify(public_key: []const u8, data: []const u8, signature: []const u8) anyerror!bool {
    // For now, use Zig's standard Ed25519 implementation
    // TODO: Integrate with mls_zig's verifyWithLabel once we understand the full API
    const Ed25519 = std.crypto.sign.Ed25519;
    
    // Ed25519 public keys should be 32 bytes
    if (public_key.len != 32) {
        return error.InvalidKeyLength;
    }
    
    // Ed25519 signatures should be 64 bytes
    if (signature.len != 64) {
        return error.InvalidSignatureLength;
    }
    
    // Create public key and signature from bytes
    const pub_key = Ed25519.PublicKey.fromBytes(public_key[0..32].*) catch return false;
    const sig = Ed25519.Signature.fromBytes(signature[0..64].*);
    
    // Verify the signature
    sig.verify(data, pub_key) catch return false;
    return true;
}

fn defaultHpkeSeal(allocator: std.mem.Allocator, public_key: []const u8, info: []const u8, aad: []const u8, plaintext: []const u8) anyerror!HpkeCiphertext {
    // Use the HPKE library for encryption - access through mls_zig
    const hpke = mls_zig.hpke;
    
    // Use X25519 HPKE mode - this matches the MLS cipher suite
    const suite = hpke.suite.X25519_SHA256_AES128GCM;
    
    // Validate public key length
    if (public_key.len != 32) {
        return error.InvalidKeyLength;
    }
    
    // Create HPKE context
    const context = try suite.setupSender(allocator, public_key[0..32].*, info);
    defer context.deinit();
    
    // Encrypt the plaintext
    const ciphertext = try context.seal(allocator, plaintext, aad);
    defer allocator.free(ciphertext);
    
    // Return the KEM output and ciphertext
    const kem_output = try allocator.dupe(u8, context.getKemOutput());
    const ct = try allocator.dupe(u8, ciphertext);
    
    return HpkeCiphertext{
        .kem_output = kem_output,
        .ciphertext = ct,
    };
}

fn defaultHpkeOpen(allocator: std.mem.Allocator, private_key: []const u8, info: []const u8, aad: []const u8, ciphertext: HpkeCiphertext) anyerror![]u8 {
    // Use the HPKE library for decryption - access through mls_zig
    const hpke = mls_zig.hpke;
    
    // Use X25519 HPKE mode - this matches the MLS cipher suite
    const suite = hpke.suite.X25519_SHA256_AES128GCM;
    
    // Validate private key length
    if (private_key.len != 32) {
        return error.InvalidKeyLength;
    }
    
    // Create HPKE context for receiver
    const context = try suite.setupReceiver(allocator, private_key[0..32].*, ciphertext.kem_output, info);
    defer context.deinit();
    
    // Decrypt the ciphertext
    const plaintext = try context.open(allocator, ciphertext.ciphertext, aad);
    
    return plaintext;
}

fn defaultHpkeGenerateKeyPair(allocator: std.mem.Allocator) anyerror!HpkeKeyPair {
    // Use the HPKE library for key generation - access through mls_zig
    const hpke = mls_zig.hpke;
    
    // Use X25519 HPKE mode - this matches the MLS cipher suite
    const suite = hpke.suite.X25519_SHA256_AES128GCM;
    
    // Generate a key pair
    const keypair = try suite.generateKeyPair(allocator);
    
    // Copy the keys to return them
    const private_key = try allocator.dupe(u8, keypair.private_key);
    const public_key = try allocator.dupe(u8, keypair.public_key);
    
    return HpkeKeyPair{
        .private_key = private_key,
        .public_key = public_key,
    };
}

fn defaultHkdfExpand(allocator: std.mem.Allocator, secret: []const u8, info: []const u8, length: usize) anyerror![]u8 {
    // Use mls_zig's cipher suite for HKDF operations
    const cs = mls_zig.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    var expanded = try cs.hkdfExpand(allocator, secret, info, length);
    defer expanded.deinit();
    
    // Copy the result to return it
    const output = try allocator.alloc(u8, expanded.data.len);
    @memcpy(output, expanded.data);
    return output;
}

fn defaultHkdfExtract(allocator: std.mem.Allocator, salt: []const u8, ikm: []const u8) anyerror![]u8 {
    // Use mls_zig's cipher suite for HKDF operations
    const cs = mls_zig.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    var secret = try cs.hkdfExtract(allocator, salt, ikm);
    defer secret.deinit();
    
    // Copy the result to return it
    const output = try allocator.alloc(u8, secret.data.len);
    @memcpy(output, secret.data);
    return output;
}

fn defaultHash(allocator: std.mem.Allocator, data: []const u8) anyerror![32]u8 {
    _ = allocator;
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &hash, .{});
    return hash;
}

fn defaultRandomFill(buffer: []u8) void {
    std.crypto.random.bytes(buffer);
}

fn defaultNow() u64 {
    return @intCast(std.time.timestamp());
}

test "provider initialization" {
    const allocator = std.testing.allocator;
    const provider = MlsProvider.init(allocator);
    
    // Test time provider
    const now = provider.time.now();
    try std.testing.expect(now > 0);
    
    // Test random provider
    var buffer: [32]u8 = undefined;
    provider.rand.fill(&buffer);
    // Check that buffer is not all zeros
    var all_zero = true;
    for (buffer) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
    
    // Test hash function
    const data = "test data";
    const hash = try provider.crypto.hashFn(allocator, data);
    try std.testing.expectEqual(@as(usize, 32), hash.len);
}

test "hkdf functions" {
    const allocator = std.testing.allocator;
    const provider = MlsProvider.init(allocator);
    
    // Test HKDF extract
    const salt = "salt";
    const ikm = "input key material";
    const prk = try provider.crypto.hkdfExtractFn(allocator, salt, ikm);
    defer allocator.free(prk);
    try std.testing.expectEqual(@as(usize, 32), prk.len);
    
    // Test HKDF expand
    const info = "info";
    const output = try provider.crypto.hkdfExpandFn(allocator, prk, info, 64);
    defer allocator.free(output);
    try std.testing.expectEqual(@as(usize, 64), output.len);
}