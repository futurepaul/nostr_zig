const std = @import("std");
const nostr = @import("nostr.zig");
const secp256k1 = @import("secp256k1");
const wasm_random = @import("wasm_random.zig");

/// Generate a cryptographically secure random 32-byte private key
pub fn generatePrivateKey() ![32]u8 {
    var key: [32]u8 = undefined;
    
    // Use WASM-safe randomness
    wasm_random.secure_random.bytes(&key);
    
    // Verify the generated key is valid for secp256k1
    const builtin = @import("builtin");
    const ctx = if (builtin.target.cpu.arch == .wasm32) blk: {
        // In WASM, use the static no-precomp context
        const wasm_ctx = @import("wasm_secp_context.zig");
        break :blk wasm_ctx.getStaticContext();
    } else blk: {
        // On native platforms, create a context normally
        break :blk secp256k1.secp256k1_context_create(secp256k1.SECP256K1_CONTEXT_SIGN) orelse return error.ContextCreationFailed;
    };
    defer if (builtin.target.cpu.arch != .wasm32) {
        secp256k1.secp256k1_context_destroy(ctx);
    };
    
    if (secp256k1.secp256k1_ec_seckey_verify(ctx, &key) != 1) {
        // If invalid, generate a new one (very rare case)
        return generatePrivateKey();
    }
    
    return key;
}

/// Generate cryptographically secure random bytes
pub fn generateRandomBytes(buffer: []u8) void {
    wasm_random.secure_random.bytes(buffer);
}

/// Convert bytes to hex string (fixed length)
pub fn bytesToHexFixed(bytes: []const u8) [64]u8 {
    var hex: [64]u8 = undefined;
    const charset = "0123456789abcdef";
    
    for (bytes, 0..) |b, i| {
        hex[i * 2] = charset[b >> 4];
        hex[i * 2 + 1] = charset[b & 0x0f];
    }
    
    return hex;
}

/// Sign a message with a private key using Schnorr signatures
pub fn sign(message: []const u8, private_key: [32]u8) ![64]u8 {
    const builtin = @import("builtin");
    const ctx = if (builtin.target.cpu.arch == .wasm32) blk: {
        const wasm_ctx = @import("wasm_secp_context.zig");
        break :blk wasm_ctx.getStaticContext();
    } else blk: {
        break :blk secp256k1.secp256k1_context_create(secp256k1.SECP256K1_CONTEXT_SIGN) orelse return error.ContextCreationFailed;
    };
    defer if (builtin.target.cpu.arch != .wasm32) {
        secp256k1.secp256k1_context_destroy(ctx);
    };
    
    // Hash the message
    var message_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(message, &message_hash, .{});
    
    // Create keypair
    var keypair: secp256k1.secp256k1_keypair = undefined;
    if (secp256k1.secp256k1_keypair_create(ctx, &keypair, &private_key) != 1) {
        return error.InvalidPrivateKey;
    }
    
    // Sign the message hash
    var signature: [64]u8 = undefined;
    var aux_rand: [32]u8 = undefined;
    generateRandomBytes(&aux_rand);
    
    if (secp256k1.secp256k1_schnorrsig_sign32(ctx, &signature, &message_hash, &keypair, &aux_rand) != 1) {
        return error.SigningFailed;
    }
    
    return signature;
}

/// Verify a Schnorr signature (message-based)
pub fn verifyMessageSignature(message: []const u8, signature: [64]u8, public_key: [32]u8) !bool {
    const builtin = @import("builtin");
    const ctx = if (builtin.target.cpu.arch == .wasm32) blk: {
        const wasm_ctx = @import("wasm_secp_context.zig");
        break :blk wasm_ctx.getStaticContext();
    } else blk: {
        break :blk secp256k1.secp256k1_context_create(secp256k1.SECP256K1_CONTEXT_VERIFY) orelse return error.ContextCreationFailed;
    };
    defer if (builtin.target.cpu.arch != .wasm32) {
        secp256k1.secp256k1_context_destroy(ctx);
    };
    
    // Hash the message
    var message_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(message, &message_hash, .{});
    
    // Parse the public key
    var xonly_pubkey: secp256k1.secp256k1_xonly_pubkey = undefined;
    if (secp256k1.secp256k1_xonly_pubkey_parse(ctx, &xonly_pubkey, &public_key) != 1) {
        return error.InvalidPublicKey;
    }
    
    // Verify the signature
    const result = secp256k1.secp256k1_schnorrsig_verify(ctx, &signature, &message_hash, 32, &xonly_pubkey);
    return result == 1;
}

/// Validate that a key is valid for secp256k1 without modifying it
pub fn validateSecp256k1Key(key: [32]u8) bool {
    const builtin = @import("builtin");
    const ctx = if (builtin.target.cpu.arch == .wasm32) blk: {
        // In WASM, use the static no-precomp context
        const wasm_ctx = @import("wasm_secp_context.zig");
        break :blk wasm_ctx.getStaticContext();
    } else blk: {
        // On native platforms, create a context normally
        break :blk secp256k1.secp256k1_context_create(secp256k1.SECP256K1_CONTEXT_SIGN) orelse return false;
    };
    defer if (builtin.target.cpu.arch != .wasm32) {
        secp256k1.secp256k1_context_destroy(ctx);
    };
    
    return secp256k1.secp256k1_ec_seckey_verify(ctx, &key) == 1;
}

/// Derive a valid secp256k1 private key from any 32-byte seed deterministically
/// WARNING: This ALWAYS modifies the input - it's a key derivation function, not validation!
/// Use validateSecp256k1Key() if you just want to check validity
pub fn deriveValidKeyFromSeed(seed: [32]u8) ![32]u8 {
    const builtin = @import("builtin");
    const ctx = if (builtin.target.cpu.arch == .wasm32) blk: {
        // In WASM, use the static no-precomp context
        const wasm_ctx = @import("wasm_secp_context.zig");
        break :blk wasm_ctx.getStaticContext();
    } else blk: {
        // On native platforms, create a context normally
        break :blk secp256k1.secp256k1_context_create(secp256k1.SECP256K1_CONTEXT_SIGN) orelse return error.ContextCreationFailed;
    };
    defer if (builtin.target.cpu.arch != .wasm32) {
        secp256k1.secp256k1_context_destroy(ctx);
    };
    
    // Try different deterministic derivations until we find a valid key
    var counter: u32 = 0;
    while (counter < 1000) : (counter += 1) {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update("secp256k1-key-v1");
        hasher.update(&seed);
        hasher.update(std.mem.asBytes(&counter));
        
        var derived_key: [32]u8 = undefined;
        hasher.final(&derived_key);
        
        // Test if this is a valid secp256k1 private key
        if (secp256k1.secp256k1_ec_seckey_verify(ctx, &derived_key) == 1) {
            return derived_key; // Success!
        }
        // Continue to next counter value if invalid
    }
    return error.CannotGenerateValidKey;
}

/// DEPRECATED: Use deriveValidKeyFromSeed instead
/// This is kept for compatibility while we update call sites
pub const generateValidSecp256k1Key = deriveValidKeyFromSeed;

/// Get public key from private key using secp256k1 (x-only for Nostr)
pub fn getPublicKey(private_key: [32]u8) ![32]u8 {
    // Use static context for WASM compatibility
    const builtin = @import("builtin");
    const ctx = if (builtin.target.cpu.arch == .wasm32) blk: {
        // In WASM, use the static no-precomp context
        const wasm_ctx = @import("wasm_secp_context.zig");
        break :blk wasm_ctx.getStaticContext();
    } else blk: {
        // On native platforms, create a context normally
        break :blk secp256k1.secp256k1_context_create(secp256k1.SECP256K1_CONTEXT_SIGN) orelse return error.ContextCreationFailed;
    };
    defer if (builtin.target.cpu.arch != .wasm32) {
        secp256k1.secp256k1_context_destroy(ctx);
    };
    
    // Verify the private key
    if (secp256k1.secp256k1_ec_seckey_verify(ctx, &private_key) != 1) {
        return error.InvalidPrivateKey;
    }
    
    // Create keypair for Schnorr operations
    var keypair: secp256k1.secp256k1_keypair = undefined;
    if (secp256k1.secp256k1_keypair_create(ctx, &keypair, &private_key) != 1) {
        return error.KeypairCreationFailed;
    }
    
    // Extract x-only public key (32 bytes, no parity byte)
    var xonly_pubkey: secp256k1.secp256k1_xonly_pubkey = undefined;
    var pk_parity: c_int = undefined;
    if (secp256k1.secp256k1_keypair_xonly_pub(ctx, &xonly_pubkey, &pk_parity, &keypair) != 1) {
        return error.XOnlyPubkeyExtractionFailed;
    }
    
    // Serialize x-only public key (32 bytes)
    var result: [32]u8 = undefined;
    if (secp256k1.secp256k1_xonly_pubkey_serialize(ctx, &result, &xonly_pubkey) != 1) {
        return error.XOnlyPubkeySerializationFailed;
    }
    
    return result;
}

/// Convert hex string to public key bytes
pub fn hexToPubkey(hex: []const u8) ![32]u8 {
    if (hex.len != 64) {
        return error.InvalidHexLength;
    }
    
    var pubkey: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pubkey, hex);
    return pubkey;
}

/// Convert public key bytes to hex string
pub fn pubkeyToHex(allocator: std.mem.Allocator, pubkey: [32]u8) ![]u8 {
    return try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(&pubkey)});
}

/// Get compressed public key from private key (33 bytes, used for NIP-44)
pub fn getPublicKeyCompressed(private_key: [32]u8) ![33]u8 {
    const builtin = @import("builtin");
    const ctx = if (builtin.target.cpu.arch == .wasm32) blk: {
        const wasm_ctx = @import("wasm_secp_context.zig");
        break :blk wasm_ctx.getStaticContext();
    } else blk: {
        break :blk secp256k1.secp256k1_context_create(secp256k1.SECP256K1_CONTEXT_SIGN) orelse return error.ContextCreationFailed;
    };
    defer if (builtin.target.cpu.arch != .wasm32) {
        secp256k1.secp256k1_context_destroy(ctx);
    };
    
    // Verify the private key
    if (secp256k1.secp256k1_ec_seckey_verify(ctx, &private_key) != 1) {
        return error.InvalidPrivateKey;
    }
    
    // Create public key
    var pubkey: secp256k1.secp256k1_pubkey = undefined;
    if (secp256k1.secp256k1_ec_pubkey_create(ctx, &pubkey, &private_key) != 1) {
        return error.PublicKeyCreationFailed;
    }
    
    // Serialize as compressed public key (33 bytes)
    var result: [33]u8 = undefined;
    var output_len: usize = 33;
    if (secp256k1.secp256k1_ec_pubkey_serialize(ctx, &result, &output_len, &pubkey, secp256k1.SECP256K1_EC_COMPRESSED) != 1) {
        return error.PublicKeySerializationFailed;
    }
    
    return result;
}

/// Get regular 32-byte public key for NIP-44 (x-only format)
pub fn getPublicKeyForNip44(private_key: [32]u8) ![32]u8 {
    // For NIP-44, we need to get the x-only public key just like we do for Nostr
    // This ensures it's in the correct format for secp256k1_xonly_pubkey_parse
    return getPublicKey(private_key);
}

/// Calculate event ID (SHA256 hash of serialized event)
pub fn calculateEventId(allocator: std.mem.Allocator, pubkey: []const u8, created_at: i64, kind: u32, tags: []const []const []const u8, content: []const u8) ![]u8 {
    // Create the serialized event array for hashing
    // [0, pubkey, created_at, kind, tags, content]
    var event_data = std.ArrayList(u8).init(allocator);
    defer event_data.deinit();
    
    try event_data.appendSlice("[0,\"");
    try event_data.appendSlice(pubkey);
    try event_data.appendSlice("\",");
    try std.fmt.format(event_data.writer(), "{}", .{created_at});
    try event_data.append(',');
    try std.fmt.format(event_data.writer(), "{}", .{kind});
    try event_data.append(',');
    
    // Serialize tags
    try event_data.append('[');
    for (tags, 0..) |tag, i| {
        if (i > 0) try event_data.append(',');
        try event_data.append('[');
        for (tag, 0..) |item, j| {
            if (j > 0) try event_data.append(',');
            try event_data.append('"');
            try event_data.appendSlice(item);
            try event_data.append('"');
        }
        try event_data.append(']');
    }
    try event_data.appendSlice("],\"");
    
    // Escape content for JSON
    for (content) |c| {
        switch (c) {
            '"' => try event_data.appendSlice("\\\""),
            '\\' => try event_data.appendSlice("\\\\"),
            '\n' => try event_data.appendSlice("\\n"),
            '\r' => try event_data.appendSlice("\\r"),
            '\t' => try event_data.appendSlice("\\t"),
            else => try event_data.append(c),
        }
    }
    try event_data.appendSlice("\"]");
    
    // Calculate SHA256
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(event_data.items, &hash, .{});
    
    // Convert to hex
    const hex_id = try allocator.alloc(u8, 64);
    const hex_chars = "0123456789abcdef";
    for (hash, 0..) |byte, i| {
        hex_id[i * 2] = hex_chars[byte >> 4];
        hex_id[i * 2 + 1] = hex_chars[byte & 0x0f];
    }
    
    return hex_id;
}

/// Sign an event using BIP340 Schnorr signature
pub fn signEvent(event_id: []const u8, private_key: [32]u8) ![64]u8 {
    // Create secp256k1 context
    const ctx = secp256k1.secp256k1_context_create(secp256k1.SECP256K1_CONTEXT_SIGN) orelse return error.ContextCreationFailed;
    defer secp256k1.secp256k1_context_destroy(ctx);
    
    // Verify the private key
    if (secp256k1.secp256k1_ec_seckey_verify(ctx, &private_key) != 1) {
        return error.InvalidPrivateKey;
    }
    
    // Create keypair for Schnorr signing
    var keypair: secp256k1.secp256k1_keypair = undefined;
    if (secp256k1.secp256k1_keypair_create(ctx, &keypair, &private_key) != 1) {
        return error.KeypairCreationFailed;
    }
    
    // Convert hex event ID to bytes (32 bytes)
    if (event_id.len != 64) {
        return error.InvalidEventIdLength;
    }
    
    var event_hash: [32]u8 = undefined;
    for (0..32) |i| {
        const hex_pair = event_id[i * 2 .. i * 2 + 2];
        event_hash[i] = std.fmt.parseInt(u8, hex_pair, 16) catch return error.InvalidEventIdHex;
    }
    
    // Create Schnorr signature (BIP340)
    var signature: [64]u8 = undefined;
    if (secp256k1.secp256k1_schnorrsig_sign32(ctx, &signature, &event_hash, &keypair, null) != 1) {
        return error.SchnorrSigningFailed;
    }
    
    return signature;
}

/// Verify a BIP340 Schnorr signature
pub fn verifySignature(event_id: []const u8, signature: [64]u8, pubkey: [32]u8) !bool {
    // Create secp256k1 context
    const ctx = secp256k1.secp256k1_context_create(secp256k1.SECP256K1_CONTEXT_VERIFY) orelse return error.ContextCreationFailed;
    defer secp256k1.secp256k1_context_destroy(ctx);
    
    // Convert hex event ID to bytes (32 bytes)
    if (event_id.len != 64) {
        return error.InvalidEventIdLength;
    }
    
    var event_hash: [32]u8 = undefined;
    for (0..32) |i| {
        const hex_pair = event_id[i * 2 .. i * 2 + 2];
        event_hash[i] = std.fmt.parseInt(u8, hex_pair, 16) catch return error.InvalidEventIdHex;
    }
    
    // Parse x-only public key
    var xonly_pubkey: secp256k1.secp256k1_xonly_pubkey = undefined;
    if (secp256k1.secp256k1_xonly_pubkey_parse(ctx, &xonly_pubkey, &pubkey) != 1) {
        return error.InvalidPublicKey;
    }
    
    // Verify Schnorr signature (BIP340)
    const result = secp256k1.secp256k1_schnorrsig_verify(ctx, &signature, &event_hash, 32, &xonly_pubkey);
    return result == 1;
}

/// Convert bytes to hex string
pub fn bytesToHex(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const hex = try allocator.alloc(u8, bytes.len * 2);
    const hex_chars = "0123456789abcdef";
    for (bytes, 0..) |byte, i| {
        hex[i * 2] = hex_chars[byte >> 4];
        hex[i * 2 + 1] = hex_chars[byte & 0x0f];
    }
    return hex;
}

test "key generation and public key derivation" {
    // Generate a private key
    const private_key = try generatePrivateKey();
    
    // Derive public key
    const public_key = try getPublicKey(private_key);
    
    // Public key should be 32 bytes (x-coordinate only for Nostr)
    try std.testing.expectEqual(@as(usize, 32), public_key.len);
    
    // Generate another key pair and verify they're different
    const private_key2 = try generatePrivateKey();
    const public_key2 = try getPublicKey(private_key2);
    
    try std.testing.expect(!std.mem.eql(u8, &private_key, &private_key2));
    try std.testing.expect(!std.mem.eql(u8, &public_key, &public_key2));
}

test "real Schnorr signature and verification" {
    const allocator = std.testing.allocator;
    
    const private_key = try generatePrivateKey();
    const public_key = try getPublicKey(private_key);
    
    // Create a real event ID by calculating it
    const pubkey_hex = try bytesToHex(allocator, &public_key);
    defer allocator.free(pubkey_hex);
    
    const created_at: i64 = 1234567890;
    const kind: u32 = 1;
    const tags = &[_][]const []const u8{};
    const content = "Hello, Nostr with real signatures!";
    
    const event_id = try calculateEventId(allocator, pubkey_hex, created_at, kind, tags, content);
    defer allocator.free(event_id);
    
    // Create real Schnorr signature
    const signature = try signEvent(event_id, private_key);
    
    // Signature should not be all zeros (it's a real signature now)
    var all_zeros = true;
    for (signature) |byte| {
        if (byte != 0) {
            all_zeros = false;
            break;
        }
    }
    try std.testing.expect(!all_zeros);
    
    // Verify the real signature
    const is_valid = try verifySignature(event_id, signature, public_key);
    try std.testing.expect(is_valid);
    
    // Test that an invalid signature fails verification
    var invalid_signature = signature;
    invalid_signature[0] = invalid_signature[0] ^ 0xFF; // Flip some bits
    const is_invalid = try verifySignature(event_id, invalid_signature, public_key);
    try std.testing.expect(!is_invalid);
}

test "calculate event id" {
    const allocator = std.testing.allocator;
    
    const pubkey = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const created_at: i64 = 1234567890;
    const kind: u32 = 1;
    const tags = &[_][]const []const u8{};
    const content = "Hello, Nostr!";
    
    const id = try calculateEventId(allocator, pubkey, created_at, kind, tags, content);
    defer allocator.free(id);
    
    // Should be a 64-character hex string
    try std.testing.expectEqual(@as(usize, 64), id.len);
    
    // Should only contain hex characters
    for (id) |c| {
        try std.testing.expect((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'));
    }
}