const std = @import("std");
const builtin = @import("builtin");
const crypto = std.crypto;
const ChaCha20IETF = std.crypto.stream.chacha.ChaCha20IETF;
const secp = @import("secp256k1");
const Nip44Error = @import("mod.zig").Nip44Error;
const wasm_random = @import("../wasm_random.zig");

/// NIP-44 v2 implementation
pub const VERSION = 0x02;

/// Conversation key derived from ECDH shared secret
pub const ConversationKey = struct {
    key: [32]u8,
    
    /// Create conversation key from ECDH shared secret
    pub fn fromSharedSecret(shared_secret: [32]u8) ConversationKey {
        // HKDF-Extract(salt="nip44-v2", ikm=shared_secret)
        const salt = "nip44-v2";
        const conversation_key = crypto.kdf.hkdf.HkdfSha256.extract(salt, &shared_secret);
        return ConversationKey{ .key = conversation_key };
    }
    
    /// Create conversation key directly from secret key and public key
    pub fn fromKeys(secret_key: [32]u8, public_key: [32]u8) Nip44Error!ConversationKey {
        const shared_secret = try generateSharedSecret(secret_key, public_key);
        return fromSharedSecret(shared_secret);
    }
    
    /// Derive message keys for encryption/decryption
    pub fn deriveMessageKeys(self: ConversationKey, nonce: [32]u8) Nip44Error!MessageKeys {
        // HKDF-Expand(conversation_key, nonce, 76 bytes)
        var expanded: [76]u8 = undefined;
        crypto.kdf.hkdf.HkdfSha256.expand(&expanded, &nonce, self.key);
        
        return MessageKeys.fromExpanded(expanded);
    }
};

/// Message-specific keys derived from conversation key and nonce
pub const MessageKeys = struct {
    chacha_key: [32]u8,
    chacha_nonce: [12]u8,
    hmac_key: [32]u8,
    
    pub fn fromExpanded(expanded: [76]u8) MessageKeys {
        var keys: MessageKeys = undefined;
        
        // Bytes 0-31: ChaCha20 key
        @memcpy(&keys.chacha_key, expanded[0..32]);
        
        // Bytes 32-43: ChaCha20 nonce (12 bytes)
        @memcpy(&keys.chacha_nonce, expanded[32..44]);
        
        // Bytes 44-75: HMAC key (32 bytes)
        @memcpy(&keys.hmac_key, expanded[44..76]);
        
        return keys;
    }
};

/// Calculate padded length according to NIP-44 spec (exact Rust reference implementation)
pub fn calcPaddedLen(content_len: usize) usize {
    if (content_len < 32) {
        return 32;
    }
    
    // Exact algorithm from Rust reference
    const log_val = log2RoundDown(content_len - 1) + 1;
    const shift_amount = @min(log_val, 31); // Clamp to u5 max value (31)
    const nextpower = @as(usize, 1) << @as(u5, @intCast(shift_amount));
    const chunk = if (nextpower <= 256) 32 else nextpower / 8;
    
    if (content_len <= 32) {
        return 32;
    } else {
        return chunk * (((content_len - 1) / chunk) + 1);
    }
}

/// Returns the base 2 logarithm of the number, rounded down.
fn log2RoundDown(x: usize) u32 {
    if (x == 0) {
        return 0;
    }
    // This is equivalent to floor(log2(x))
    return (@bitSizeOf(usize) - 1) - @clz(x);
}

/// Pad message according to NIP-44 spec
/// Returns [2_byte_length][message][zero_padding]
pub fn padMessage(allocator: std.mem.Allocator, content: []const u8) Nip44Error![]u8 {
    if (content.len > 65535) return Nip44Error.MessageTooLong;
    
    const padded_len = calcPaddedLen(content.len);
    const total_len = 2 + padded_len; // 2 bytes for length + padded content
    
    const padded = try allocator.alloc(u8, total_len);
    
    // Write length as big-endian 16-bit integer
    padded[0] = @intCast((content.len >> 8) & 0xFF);
    padded[1] = @intCast(content.len & 0xFF);
    
    // Copy content
    @memcpy(padded[2..2 + content.len], content);
    
    // Zero padding
    @memset(padded[2 + content.len..], 0);
    
    return padded;
}

/// Remove padding from message
pub fn unpadMessage(allocator: std.mem.Allocator, padded: []const u8) Nip44Error![]u8 {
    if (padded.len < 2) return Nip44Error.InvalidPadding;
    
    // Read length from first 2 bytes (big-endian)
    const content_len = (@as(u16, padded[0]) << 8) | @as(u16, padded[1]);
    
    if (content_len > padded.len - 2) return Nip44Error.InvalidPadding;
    
    // Empty messages (content_len == 0) are allowed
    const content = try allocator.alloc(u8, content_len);
    if (content_len > 0) {
        @memcpy(content, padded[2..2 + content_len]);
    }
    
    return content;
}

/// Custom ECDH hash function for NIP-44
/// This function copies the x-coordinate directly without hashing, as per NIP-44 spec
fn nip44EcdhHashFunction(
    output: [*c]u8,
    x32: [*c]const u8,
    y32: [*c]const u8,
    data: ?*anyopaque,
) callconv(.C) c_int {
    _ = y32; // y-coordinate is not used in NIP-44
    _ = data; // no additional data needed
    
    // Copy x-coordinate directly to output
    @memcpy(output[0..32], x32[0..32]);
    
    return 32; // Return number of bytes written
}

/// Generate ECDH shared secret using secp256k1
fn generateSharedSecret(secret_key: [32]u8, public_key: [32]u8) Nip44Error!([32]u8) {
    // Create secp256k1 context
    const ctx = secp.secp256k1_context_create(secp.SECP256K1_CONTEXT_SIGN) orelse return Nip44Error.CryptoError;
    defer secp.secp256k1_context_destroy(ctx);
    
    // Use existing secp256k1 integration for ECDH
    var shared_secret: [32]u8 = undefined;
    
    // Verify secret key
    if (secp.secp256k1_ec_seckey_verify(ctx, &secret_key) != 1) {
        return Nip44Error.InvalidSecretKey;
    }
    
    // For x-only public keys, we need to reconstruct the full point
    // Try using secp256k1_ecdh with xonly pubkey directly
    var xonly_pubkey: secp.secp256k1_xonly_pubkey = undefined;
    if (secp.secp256k1_xonly_pubkey_parse(ctx, &xonly_pubkey, &public_key) != 1) {
        // Debug: log the public key that failed
        if (builtin.target.cpu.arch == .wasm32) {
            std.debug.print("Failed to parse xonly pubkey. First 8 bytes: {x} {x} {x} {x} {x} {x} {x} {x}\n", .{
                public_key[0], public_key[1], public_key[2], public_key[3],
                public_key[4], public_key[5], public_key[6], public_key[7]
            });
        }
        return Nip44Error.InvalidPublicKey;
    }
    
    // Convert xonly to regular pubkey for ECDH
    // We need to create a full pubkey from the xonly pubkey
    // The secp256k1 library should choose the correct y-coordinate
    var full_pubkey_bytes: [33]u8 = undefined;
    
    // Create a pubkey structure that we can use for ECDH
    var pubkey: secp.secp256k1_pubkey = undefined;
    
    // NIP-44 standard: x-only public keys always use even y-coordinate (0x02)
    full_pubkey_bytes[0] = 0x02;
    @memcpy(full_pubkey_bytes[1..33], &public_key);
    if (secp.secp256k1_ec_pubkey_parse(ctx, &pubkey, &full_pubkey_bytes, 33) != 1) {
        return Nip44Error.InvalidPublicKey;
    }
    
    // Perform ECDH with custom hash function that returns x-coordinate only
    if (secp.secp256k1_ecdh(ctx, &shared_secret, &pubkey, &secret_key, nip44EcdhHashFunction, null) != 1) {
        return Nip44Error.CryptoError;
    }
    
    return shared_secret;
}

/// Encrypt content using NIP-44 v2 and return raw bytes (not base64)
/// This is the preferred function for WASM interop to avoid encoding confusion
pub fn encryptRaw(
    allocator: std.mem.Allocator,
    secret_key: [32]u8,
    public_key: [32]u8,
    content: []const u8,
) Nip44Error![]u8 {
    // Generate conversation key
    const conversation_key = try ConversationKey.fromKeys(secret_key, public_key);
    
    // Generate random nonce
    var nonce: [32]u8 = undefined;
    wasm_random.secure_random.bytes(&nonce);
    
    // Derive message keys
    const message_keys = try conversation_key.deriveMessageKeys(nonce);
    
    // Pad message - CRITICAL for privacy!
    const padded = try padMessage(allocator, content);
    defer allocator.free(padded);
    
    // Encrypt with ChaCha20
    const encrypted = try allocator.alloc(u8, padded.len);
    defer allocator.free(encrypted);
    
    // Use real ChaCha20IETF from Zig standard library
    // ChaCha20 encrypt/decrypt are the same operation (XOR)
    ChaCha20IETF.xor(encrypted, padded, 0, message_keys.chacha_key, message_keys.chacha_nonce);
    
    // Create payload: [version][nonce][encrypted][hmac]
    const payload_len = 1 + 32 + encrypted.len + 32;
    const payload = try allocator.alloc(u8, payload_len);
    // Note: no defer here, we return the payload
    
    // Version
    payload[0] = VERSION;
    
    // Nonce
    @memcpy(payload[1..33], &nonce);
    
    // Encrypted data
    @memcpy(payload[33..33 + encrypted.len], encrypted);
    
    // HMAC-SHA256 over nonce + ciphertext (matching NIP-44 spec)
    var hmac_ctx = crypto.auth.hmac.Hmac(crypto.hash.sha2.Sha256).init(&message_keys.hmac_key);
    hmac_ctx.update(&nonce); // 32 bytes of nonce
    hmac_ctx.update(encrypted); // ciphertext only
    var hmac: [32]u8 = undefined;
    hmac_ctx.final(&hmac);
    @memcpy(payload[33 + encrypted.len..], &hmac);
    
    return payload;
}

/// Encrypt content using NIP-44 v2 (returns base64 for text protocols)
pub fn encrypt(
    allocator: std.mem.Allocator,
    secret_key: [32]u8,
    public_key: [32]u8,
    content: []const u8,
) Nip44Error![]u8 {
    // Generate conversation key
    const conversation_key = try ConversationKey.fromKeys(secret_key, public_key);
    
    // Generate random nonce
    var nonce: [32]u8 = undefined;
    wasm_random.secure_random.bytes(&nonce);
    
    // Derive message keys
    const message_keys = try conversation_key.deriveMessageKeys(nonce);
    
    // Pad message
    const padded = try padMessage(allocator, content);
    defer allocator.free(padded);
    
    // Encrypt with ChaCha20
    const encrypted = try allocator.alloc(u8, padded.len);
    defer allocator.free(encrypted);
    
    // Use real ChaCha20IETF from Zig standard library
    // ChaCha20 encrypt/decrypt are the same operation (XOR)
    ChaCha20IETF.xor(encrypted, padded, 0, message_keys.chacha_key, message_keys.chacha_nonce);
    
    // Create payload: [version][nonce][encrypted][hmac]
    const payload_len = 1 + 32 + encrypted.len + 32;
    const payload = try allocator.alloc(u8, payload_len);
    defer allocator.free(payload);
    
    // Version
    payload[0] = VERSION;
    
    // Nonce
    @memcpy(payload[1..33], &nonce);
    
    // Encrypted data
    @memcpy(payload[33..33 + encrypted.len], encrypted);
    
    // HMAC-SHA256 over nonce + ciphertext (matching NIP-44 spec)
    var hmac_ctx = crypto.auth.hmac.Hmac(crypto.hash.sha2.Sha256).init(&message_keys.hmac_key);
    hmac_ctx.update(&nonce); // 32 bytes of nonce
    hmac_ctx.update(encrypted); // ciphertext only
    var hmac: [32]u8 = undefined;
    hmac_ctx.final(&hmac);
    @memcpy(payload[33 + encrypted.len..], &hmac);
    
    
    // Base64 encode result
    const encoded_len = std.base64.standard.Encoder.calcSize(payload.len);
    const encoded = try allocator.alloc(u8, encoded_len);
    _ = std.base64.standard.Encoder.encode(encoded, payload);
    
    return encoded;
}

/// Decrypt NIP-44 v2 payload (bytes, not base64)
pub fn decryptBytes(
    allocator: std.mem.Allocator,
    secret_key: [32]u8,
    public_key: [32]u8,
    payload: []const u8,
) Nip44Error![]u8 {
    
    if (payload.len < 65) return Nip44Error.InvalidLength; // 1 + 32 + 32 minimum
    if (payload[0] != VERSION) return Nip44Error.InvalidVersion;
    
    // Extract components
    const nonce = payload[1..33];
    const encrypted_len = payload.len - 65; // Total - version - nonce - hmac
    const encrypted = payload[33..33 + encrypted_len];
    const received_hmac = payload[payload.len - 32..];
    
    // Generate conversation key and message keys
    const conversation_key = try ConversationKey.fromKeys(secret_key, public_key);
    
    var nonce_array: [32]u8 = undefined;
    @memcpy(&nonce_array, nonce);
    const message_keys = try conversation_key.deriveMessageKeys(nonce_array);
    
    // Verify HMAC
    // HMAC should be calculated over nonce + ciphertext (not including version or HMAC itself)
    var hmac_ctx = crypto.auth.hmac.Hmac(crypto.hash.sha2.Sha256).init(&message_keys.hmac_key);
    hmac_ctx.update(nonce); // 32 bytes of nonce
    hmac_ctx.update(encrypted); // ciphertext only
    var computed_hmac: [32]u8 = undefined;
    hmac_ctx.final(&computed_hmac);
    
    
    if (!crypto.utils.timingSafeEql([32]u8, computed_hmac, received_hmac[0..32].*)) {
        return Nip44Error.InvalidHmac;
    }
    
    // Decrypt with ChaCha20
    const decrypted = try allocator.alloc(u8, encrypted.len);
    defer allocator.free(decrypted);
    
    // Use real ChaCha20IETF from Zig standard library
    // ChaCha20 encrypt/decrypt are the same operation (XOR)
    ChaCha20IETF.xor(decrypted, encrypted, 0, message_keys.chacha_key, message_keys.chacha_nonce);
    
    // Remove padding
    return unpadMessage(allocator, decrypted);
}

test "calc_padded_len" {
    // Test cases with correct values from Rust reference implementation
    const test_cases = [_]struct { len: usize, expected: usize }{
        .{ .len = 0, .expected = 32 },
        .{ .len = 1, .expected = 32 },
        .{ .len = 16, .expected = 32 },
        .{ .len = 32, .expected = 32 },
        .{ .len = 33, .expected = 64 },
        .{ .len = 64, .expected = 64 },
        .{ .len = 65, .expected = 96 },
        .{ .len = 100, .expected = 128 },
        .{ .len = 128, .expected = 128 },
        .{ .len = 129, .expected = 160 },
        .{ .len = 192, .expected = 192 },
        .{ .len = 193, .expected = 224 },
        .{ .len = 320, .expected = 320 },
        .{ .len = 384, .expected = 384 },
        .{ .len = 400, .expected = 448 },
        .{ .len = 500, .expected = 512 },
        .{ .len = 512, .expected = 512 },
        .{ .len = 1000, .expected = 1024 },
        .{ .len = 1024, .expected = 1024 },
        .{ .len = 65515, .expected = 65536 },
    };
    
    for (test_cases) |case| {
        const result = calcPaddedLen(case.len);
        std.testing.expect(result == case.expected) catch |err| {
            std.debug.print("calcPaddedLen({}) = {}, expected {}\n", .{ case.len, result, case.expected });
            return err;
        };
    }
}

test "padding roundtrip" {
    const allocator = std.testing.allocator;
    
    const test_messages = [_][]const u8{
        "",
        "a",
        "hello world",
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit",
    };
    
    for (test_messages) |message| {
        const padded = try padMessage(allocator, message);
        defer allocator.free(padded);
        
        const unpadded = try unpadMessage(allocator, padded);
        defer allocator.free(unpadded);
        
        try std.testing.expectEqualSlices(u8, message, unpadded);
    }
}

/// Encrypt a message with a specific nonce (for testing)
/// Returns raw bytes (not base64)
pub fn encryptWithNonce(
    allocator: std.mem.Allocator,
    conversation_key: ConversationKey,
    nonce: [32]u8,
    content: []const u8,
) Nip44Error![]u8 {
    // Derive message keys
    const message_keys = try conversation_key.deriveMessageKeys(nonce);
    
    // Pad message
    const padded = try padMessage(allocator, content);
    defer allocator.free(padded);
    
    // Encrypt with ChaCha20
    const encrypted = try allocator.alloc(u8, padded.len);
    defer allocator.free(encrypted);
    
    ChaCha20IETF.xor(encrypted, padded, 0, message_keys.chacha_key, message_keys.chacha_nonce);
    
    // Create payload: [version][nonce][encrypted][hmac]
    const payload_len = 1 + 32 + encrypted.len + 32;
    const payload = try allocator.alloc(u8, payload_len);
    
    // Version
    payload[0] = VERSION;
    
    // Nonce
    @memcpy(payload[1..33], &nonce);
    
    // Encrypted data
    @memcpy(payload[33..33 + encrypted.len], encrypted);
    
    // HMAC-SHA256 over nonce + ciphertext
    var hmac_ctx = crypto.auth.hmac.Hmac(crypto.hash.sha2.Sha256).init(&message_keys.hmac_key);
    hmac_ctx.update(&nonce);
    hmac_ctx.update(encrypted);
    var hmac: [32]u8 = undefined;
    hmac_ctx.final(&hmac);
    @memcpy(payload[33 + encrypted.len..], &hmac);
    
    return payload;
}

/// Decrypt with a conversation key (for testing invalid cases)
/// Accepts base64-encoded payload
pub fn decryptWithConversationKey(
    allocator: std.mem.Allocator,
    conversation_key: ConversationKey,
    payload: []const u8,
) Nip44Error![]u8 {
    // Decode base64 payload
    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(payload) catch return Nip44Error.Base64DecodeError;
    const payload_bytes = try allocator.alloc(u8, decoded_len);
    defer allocator.free(payload_bytes);
    
    _ = std.base64.standard.Decoder.decode(payload_bytes, payload) catch return Nip44Error.Base64DecodeError;
    
    if (payload_bytes.len < 1 + 32 + 32) return Nip44Error.InvalidLength;
    
    // Check version
    if (payload_bytes[0] != VERSION) return Nip44Error.InvalidVersion;
    
    // Extract components
    const nonce = payload_bytes[1..33];
    const encrypted = payload_bytes[33..payload_bytes.len - 32];
    const provided_hmac = payload_bytes[payload_bytes.len - 32..];
    
    // Derive message keys
    const message_keys = try conversation_key.deriveMessageKeys(nonce.*);
    
    // Verify HMAC
    var hmac_ctx = crypto.auth.hmac.Hmac(crypto.hash.sha2.Sha256).init(&message_keys.hmac_key);
    hmac_ctx.update(nonce);
    hmac_ctx.update(encrypted);
    var calculated_hmac: [32]u8 = undefined;
    hmac_ctx.final(&calculated_hmac);
    
    if (!std.mem.eql(u8, &calculated_hmac, provided_hmac)) {
        return Nip44Error.InvalidHmac;
    }
    
    // Decrypt
    const decrypted = try allocator.alloc(u8, encrypted.len);
    defer allocator.free(decrypted);
    ChaCha20IETF.xor(decrypted, encrypted, 0, message_keys.chacha_key, message_keys.chacha_nonce);
    
    // Unpad
    return unpadMessage(allocator, decrypted);
}

test {
    std.testing.refAllDecls(@This());
}