const std = @import("std");
const types = @import("types.zig");
const mls_zig = @import("mls_zig");
const wasm_random = @import("../wasm_random.zig");
const wasm_time = @import("../wasm_time.zig");

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
    // Use mls_zig's cipher suite for signing
    const cs = mls_zig.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    
    // For Ed25519, we need to handle the key properly
    if (private_key.len == 32) {
        // This is a seed, generate the full keypair from it
        const seed: [32]u8 = private_key[0..32].*;
        const keypair = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
        
        // Create the 64-byte private key format that mls_zig expects
        // Zig's Ed25519 already has 64-byte secret key
        var full_private_key: [64]u8 = keypair.secret_key.bytes;
        
        return cs.sign(allocator, &full_private_key, data);
    } else if (private_key.len == 64) {
        // Already in the correct format
        return cs.sign(allocator, private_key, data);
    } else {
        return error.InvalidPrivateKeyLength;
    }
}

fn defaultVerify(public_key: []const u8, data: []const u8, signature: []const u8) anyerror!bool {
    // Use mls_zig's cipher suite for verification
    const cs = mls_zig.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    return cs.verify(std.heap.page_allocator, public_key, data, signature);
}

fn defaultHpkeSeal(allocator: std.mem.Allocator, public_key: []const u8, info: []const u8, aad: []const u8, plaintext: []const u8) anyerror!HpkeCiphertext {
    // Use the HPKE library for encryption - access through mls_zig
    const hpke = mls_zig.hpke;
    
    // Create X25519 HPKE suite - this matches the MLS cipher suite
    const SuiteType = try hpke.createSuite(0x0020, 0x0001, 0x0001); // X25519, HKDF-SHA256, AES-128-GCM
    
    // Validate public key length
    if (public_key.len != 32) {
        return error.InvalidKeyLength;
    }
    
    // Create client context and get encapsulated secret
    const client_and_secret = try SuiteType.createClientContext(public_key, info, null, null, wasm_random.fillSecureRandom);
    var client_ctx = client_and_secret.client_ctx;
    
    // Calculate ciphertext length including tag
    const ciphertext_len = plaintext.len + client_ctx.tagLength();
    const ciphertext = try allocator.alloc(u8, ciphertext_len);
    
    // Encrypt the plaintext
    client_ctx.encryptToServer(ciphertext, plaintext, aad);
    
    // Return the KEM output and ciphertext
    const kem_output = try allocator.dupe(u8, client_and_secret.encapsulated_secret.encapsulated.constSlice());
    
    return HpkeCiphertext{
        .kem_output = kem_output,
        .ciphertext = ciphertext,
    };
}

fn defaultHpkeOpen(allocator: std.mem.Allocator, private_key: []const u8, info: []const u8, aad: []const u8, ciphertext: HpkeCiphertext) anyerror![]u8 {
    // Use the HPKE library for decryption - access through mls_zig
    const hpke = mls_zig.hpke;
    
    // Create X25519 HPKE suite - this matches the MLS cipher suite
    const SuiteType = try hpke.createSuite(0x0020, 0x0001, 0x0001); // X25519, HKDF-SHA256, AES-128-GCM
    
    // Validate private key length
    if (private_key.len != 32) {
        return error.InvalidKeyLength;
    }
    
    // Create server key pair from private key
    const server_kp = try SuiteType.deterministicKeyPair(private_key);
    
    // Create server context from encapsulated secret
    var server_ctx = try SuiteType.createServerContext(ciphertext.kem_output, server_kp, info, null);
    
    // Calculate plaintext length (ciphertext length minus tag)
    const plaintext_len = ciphertext.ciphertext.len - server_ctx.tagLength();
    const plaintext = try allocator.alloc(u8, plaintext_len);
    
    // Decrypt the ciphertext
    try server_ctx.decryptFromClient(plaintext, ciphertext.ciphertext, aad);
    
    return plaintext;
}

fn defaultHpkeGenerateKeyPair(allocator: std.mem.Allocator) anyerror!HpkeKeyPair {
    // Use the HPKE library for key generation - access through mls_zig
    const hpke = mls_zig.hpke;
    
    // Create X25519 HPKE suite - this matches the MLS cipher suite
    const SuiteType = try hpke.createSuite(0x0020, 0x0001, 0x0001); // X25519, HKDF-SHA256, AES-128-GCM
    
    // Generate deterministic seed using WASM-safe randomness
    var seed: [32]u8 = undefined;
    wasm_random.secure_random.bytes(&seed);
    
    // Generate a key pair deterministically from the seed
    const keypair = try SuiteType.deterministicKeyPair(&seed);
    
    // Copy the keys to return them
    const private_key = try allocator.dupe(u8, keypair.secret_key.constSlice());
    const public_key = try allocator.dupe(u8, keypair.public_key.constSlice());
    
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
    // Use WASM-safe randomness
    wasm_random.secure_random.bytes(buffer);
}

fn defaultNow() u64 {
    return @intCast(wasm_time.timestamp());
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