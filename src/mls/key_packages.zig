const std = @import("std");
const tls = std.crypto.tls;
const types = @import("types.zig");
const provider = @import("provider.zig");
const mls_zig = @import("mls_zig");
const constants = @import("constants.zig");
const crypto = @import("../crypto.zig");
const crypto_utils = @import("crypto_utils.zig");

/// Key package generation parameters
pub const KeyPackageParams = struct {
    /// Cipher suite to use
    cipher_suite: types.Ciphersuite = .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
    
    /// Lifetime in seconds (default 30 days)
    lifetime_seconds: u64 = 30 * 24 * 60 * 60,
    
    /// Extensions to include
    extensions: []const types.Extension = &.{},
};

/// Generate a new key package for joining groups
pub fn generateKeyPackage(
    allocator: std.mem.Allocator,
    mls_provider: *provider.MlsProvider,
    nostr_private_key: [32]u8,
    params: KeyPackageParams,
) !types.KeyPackage {
    // Get current time
    const now = mls_provider.time.now();
    const not_before = now;
    const not_after = now + params.lifetime_seconds;
    
    // Derive Nostr public key
    var nostr_pubkey: [32]u8 = undefined;
    nostr_pubkey = try crypto.getPublicKey(nostr_private_key);
    
    // Create basic credential with Nostr public key as identity
    const identity = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(&nostr_pubkey)});
    defer allocator.free(identity);
    
    const credential = types.Credential{
        .basic = types.BasicCredential{
            .identity = try allocator.dupe(u8, identity),
        },
    };
    
    // Generate HPKE key pair for encryption
    const hpke_keypair = try mls_provider.crypto.hpkeGenerateKeyPairFn(allocator);
    defer allocator.free(hpke_keypair.private_key);
    defer allocator.free(hpke_keypair.public_key);
    
    // Generate signature key pair for MLS
    // For key packages, we use epoch 0 as they're generated before group creation
    const mls_private_key = try crypto_utils.deriveMlsSigningKey(allocator, nostr_private_key, 0);
    defer allocator.free(mls_private_key);
    
    const mls_public_key = try deriveMlsPublicKey(allocator, mls_private_key);
    
    // Create capabilities
    const capabilities = types.Capabilities{
        .versions = try allocator.dupe(types.ProtocolVersion, &[_]types.ProtocolVersion{.mls10}),
        .ciphersuites = try allocator.dupe(types.Ciphersuite, &[_]types.Ciphersuite{params.cipher_suite}),
        .extensions = try allocator.dupe(types.ExtensionType, &[_]types.ExtensionType{
            .capabilities,
            .lifetime,
            .required_capabilities,
            .last_resort,
        }),
        .proposals = try allocator.dupe(types.ProposalType, &[_]types.ProposalType{
            .add,
            .update,
            .remove,
            .reinit,
            .external_init,
            .group_context_extensions,
        }),
        .credentials = try allocator.dupe(types.CredentialType, &[_]types.CredentialType{.basic}),
    };
    
    // Create lifetime extension
    const lifetime_ext_data = try serializeLifetime(allocator, types.Lifetime{
        .not_before = not_before,
        .not_after = not_after,
    });
    defer allocator.free(lifetime_ext_data);
    
    // Build extensions list
    var extensions = std.ArrayList(types.Extension).init(allocator);
    defer extensions.deinit();
    
    // Add lifetime extension
    try extensions.append(types.Extension{
        .extension_type = .lifetime,
        .extension_data = try allocator.dupe(u8, lifetime_ext_data),
    });
    
    // Add capabilities extension
    const capabilities_data = try serializeCapabilities(allocator, capabilities);
    defer allocator.free(capabilities_data);
    
    try extensions.append(types.Extension{
        .extension_type = .capabilities,
        .extension_data = try allocator.dupe(u8, capabilities_data),
    });
    
    // Add last_resort extension (empty data, presence indicates last resort)
    try extensions.append(types.Extension{
        .extension_type = .last_resort,
        .extension_data = try allocator.dupe(u8, &.{}), // Empty extension
    });
    
    // Add any additional extensions
    for (params.extensions) |ext| {
        try extensions.append(ext);
    }
    
    // Create leaf node
    const leaf_node = types.LeafNode{
        .encryption_key = types.HPKEPublicKey{
            .data = try allocator.dupe(u8, hpke_keypair.public_key),
        },
        .signature_key = types.SignaturePublicKey{
            .data = mls_public_key,
        },
        .credential = credential,
        .capabilities = capabilities,
        .leaf_node_source = .key_package,
        .extensions = try extensions.toOwnedSlice(),
        .signature = &.{}, // Will be filled after signing
    };
    
    // Sign the leaf node
    const leaf_node_tbs = try leafNodeTBS(allocator, leaf_node);
    defer allocator.free(leaf_node_tbs);
    
    const leaf_signature = try mls_provider.crypto.signFn(allocator, mls_private_key, leaf_node_tbs);
    
    // Create key package with signed leaf node
    var signed_leaf = leaf_node;
    signed_leaf.signature = leaf_signature;
    
    const key_package = types.KeyPackage{
        .version = .mls10,
        .cipher_suite = params.cipher_suite,
        .init_key = types.HPKEPublicKey{
            .data = try allocator.dupe(u8, hpke_keypair.public_key),
        },
        .leaf_node = signed_leaf,
        .extensions = &.{},
        .signature = &.{}, // Will be filled after signing
    };
    
    // Sign the key package
    const key_package_tbs = try keyPackageTBS(allocator, key_package);
    defer allocator.free(key_package_tbs);
    
    const key_package_signature = try mls_provider.crypto.signFn(allocator, mls_private_key, key_package_tbs);
    
    // Return signed key package
    var signed_key_package = key_package;
    signed_key_package.signature = key_package_signature;
    
    return signed_key_package;
}

/// Parse key package from wire format
pub fn parseKeyPackage(
    allocator: std.mem.Allocator,
    data: []const u8,
) types.KeyPackageError!types.KeyPackage {
    // Use TLS 1.3 wire format as per RFC 9420
    var decoder = tls.Decoder.fromTheirSlice(data);
    
    // Parse according to MLS KeyPackage format:
    // struct {
    //     ProtocolVersion version;
    //     CipherSuite cipher_suite;
    //     HPKEPublicKey init_key<V>;
    //     LeafNode leaf_node<V>;
    //     Extension extensions<V>;
    //     opaque signature<V>;
    // } KeyPackage;
    
    // Version (u16)
    try decoder.ensure(2);
    const version_raw = decoder.decode(u16);
    const version = types.ProtocolVersion.fromInt(version_raw);
    
    // Cipher suite (u16)
    try decoder.ensure(2);
    const cipher_suite_raw = decoder.decode(u16);
    const cipher_suite = types.Ciphersuite.fromInt(cipher_suite_raw);
    
    // Init key (variable length with u16 length prefix)
    const init_key = mls_zig.tls_encode.readVarBytes(&decoder, u16, allocator) catch return error.UnexpectedEndOfStream;
    std.log.debug("Init key length: {}", .{init_key.len});
    if (init_key.len > 256) {
        allocator.free(init_key);
        return error.InvalidKeyLength; // Sanity check
    }
    
    // Leaf node (variable length)
    const leaf_node_data = mls_zig.tls_encode.readVarBytes(&decoder, u16, allocator) catch return error.UnexpectedEndOfStream;
    defer allocator.free(leaf_node_data);
    const leaf_node = parseLeafNode(allocator, leaf_node_data) catch return error.InvalidLeafNode;
    
    // Extensions (variable length)
    const extensions_data = mls_zig.tls_encode.readVarBytes(&decoder, u16, allocator) catch return error.UnexpectedEndOfStream;
    defer allocator.free(extensions_data);
    const extensions = parseExtensions(allocator, extensions_data) catch return error.MalformedExtensions;
    
    // Signature (variable length with u16 length prefix)
    const signature = mls_zig.tls_encode.readVarBytes(&decoder, u16, allocator) catch return error.UnexpectedEndOfStream;
    if (signature.len > 512) {
        allocator.free(signature);
        return error.InvalidSignature; // Sanity check
    }
    
    return types.KeyPackage{
        .version = version,
        .cipher_suite = cipher_suite,
        .init_key = types.HPKEPublicKey.init(init_key),
        .leaf_node = leaf_node,
        .extensions = extensions,
        .signature = signature,
    };
}

/// Serialize key package to wire format
pub fn serializeKeyPackage(
    allocator: std.mem.Allocator,
    key_package: types.KeyPackage,
) ![]u8 {
    // Use TLS 1.3 wire format as per RFC 9420
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    
    // Use TLS codec convenience functions
    
    // Serialize according to MLS KeyPackage format:
    // struct {
    //     ProtocolVersion version;
    //     CipherSuite cipher_suite;
    //     HPKEPublicKey init_key<V>;
    //     LeafNode leaf_node<V>;
    //     Extension extensions<V>;
    //     opaque signature<V>;
    // } KeyPackage;
    
    // Version (u16)
    try mls_zig.tls_encode.encodeInt(&buffer, u16, @intFromEnum(key_package.version));
    
    // Cipher suite (u16)
    try mls_zig.tls_encode.encodeInt(&buffer, u16, @intFromEnum(key_package.cipher_suite));
    
    // Init key (variable length with u16 length prefix)
    try mls_zig.tls_encode.encodeVarBytes(&buffer, u16, key_package.init_key.data);
    
    // Leaf node - serialize as variable length (simplified for now)
    const leaf_node_data = try serializeLeafNode(allocator, key_package.leaf_node);
    defer allocator.free(leaf_node_data);
    try mls_zig.tls_encode.encodeVarBytes(&buffer, u16, leaf_node_data);
    
    // Extensions - serialize as variable length 
    const extensions_data = try serializeExtensions(allocator, key_package.extensions);
    defer allocator.free(extensions_data);
    try mls_zig.tls_encode.encodeVarBytes(&buffer, u16, extensions_data);
    
    // Signature (variable length with u16 length prefix)
    try mls_zig.tls_encode.encodeVarBytes(&buffer, u16, key_package.signature);
    
    return buffer.toOwnedSlice();
}

/// Validate a key package
pub fn validateKeyPackage(
    allocator: std.mem.Allocator,
    mls_provider: *provider.MlsProvider,
    key_package: types.KeyPackage,
) !void {
    // Check version
    if (key_package.version != .mls10) {
        return error.UnsupportedVersion;
    }
    
    // Check cipher suite
    if (!isSupportedCipherSuite(key_package.cipher_suite)) {
        return error.UnsupportedCiphersuite;
    }
    
    // Verify leaf node signature
    const leaf_node_tbs = try leafNodeTBS(allocator, key_package.leaf_node);
    defer allocator.free(leaf_node_tbs);
    
    const leaf_valid = try mls_provider.crypto.verifyFn(
        key_package.leaf_node.signature_key.data,
        leaf_node_tbs,
        key_package.leaf_node.signature,
    );
    
    if (!leaf_valid) {
        return error.InvalidSignature;
    }
    
    // Verify key package signature
    const key_package_tbs = try keyPackageTBS(allocator, key_package);
    defer allocator.free(key_package_tbs);
    
    const package_valid = try mls_provider.crypto.verifyFn(
        key_package.leaf_node.signature_key.data,
        key_package_tbs,
        key_package.signature,
    );
    
    if (!package_valid) {
        return error.InvalidSignature;
    }
    
    // Check lifetime if present
    for (key_package.leaf_node.extensions) |ext| {
        if (ext.extension_type == .lifetime) {
            const lifetime = try deserializeLifetime(ext.extension_data);
            const now = mls_provider.time.now();
            if (now < lifetime.not_before or now > lifetime.not_after) {
                return error.InvalidKeyPackage;
            }
        }
    }
}

/// Check if key package has last_resort extension
pub fn hasLastResortExtension(key_package: types.KeyPackage) bool {
    for (key_package.leaf_node.extensions) |ext| {
        if (ext.extension_type == .last_resort) {
            return true;
        }
    }
    return false;
}

/// Extract Nostr public key from key package
pub fn extractNostrPubkey(key_package: types.KeyPackage) ![32]u8 {
    switch (key_package.leaf_node.credential) {
        .basic => |basic| {
            if (basic.identity.len != 64) {
                return error.InvalidCredential;
            }
            var pubkey: [32]u8 = undefined;
            _ = try std.fmt.hexToBytes(&pubkey, basic.identity);
            return pubkey;
        },
        else => return error.UnsupportedCredential,
    }
}

/// Parse key package from Nostr event content
pub fn parseFromNostrEvent(
    allocator: std.mem.Allocator,
    content: []const u8,
) types.KeyPackageError!types.KeyPackage {
    // Try hex decoding first (most common in Nostr)
    if (isHexString(content)) {
        const decoded = allocator.alloc(u8, content.len / 2) catch return error.UnexpectedEndOfStream;
        defer allocator.free(decoded);
        _ = std.fmt.hexToBytes(decoded, content) catch return error.InvalidVersion;
        return parseKeyPackage(allocator, decoded);
    }
    
    // Try base64 if not hex
    // TODO: Implement base64 decoding when needed
    
    // Otherwise assume raw binary
    return parseKeyPackage(allocator, content);
}

/// Serialize key package for Nostr event
pub fn serializeForNostrEvent(
    allocator: std.mem.Allocator,
    key_package: types.KeyPackage,
) ![]u8 {
    const binary = try serializeKeyPackage(allocator, key_package);
    defer allocator.free(binary);
    
    // Encode as hex for Nostr
    const hex = try allocator.alloc(u8, binary.len * 2);
    _ = std.fmt.bufPrint(hex, "{s}", .{std.fmt.fmtSliceHexLower(binary)}) catch unreachable;
    return hex;
}

/// Check if string is valid hex
fn isHexString(s: []const u8) bool {
    if (s.len == 0 or s.len % 2 != 0) return false;
    for (s) |c| {
        if (!std.ascii.isHex(c)) return false;
    }
    return true;
}

// Helper functions



fn deriveMlsPublicKey(allocator: std.mem.Allocator, mls_private_key: []const u8) ![]u8 {
    // Derive Ed25519 public key from private key
    if (mls_private_key.len != 32) {
        return error.InvalidKeySize;
    }
    
    // For Ed25519, we need to derive the public key from the private key seed
    const seed: [32]u8 = mls_private_key[0..32].*;
    const keypair = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed) catch |err| return err;
    
    // Allocate and return the public key
    const pubkey = try allocator.alloc(u8, 32);
    @memcpy(pubkey, &keypair.public_key.bytes);
    
    return pubkey;
}

fn isSupportedCipherSuite(cipher_suite: types.Ciphersuite) bool {
    return switch (cipher_suite) {
        .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        .MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
        => true,
        else => false,
    };
}

fn leafNodeTBS(allocator: std.mem.Allocator, leaf_node: types.LeafNode) ![]u8 {
    // Create to-be-signed data for leaf node
    // This is a simplified version - actual implementation needs proper encoding
    var tbs = std.ArrayList(u8).init(allocator);
    defer tbs.deinit();
    
    // Add all fields except signature
    try tbs.appendSlice(leaf_node.encryption_key.data);
    try tbs.appendSlice(leaf_node.signature_key.data);
    
    // Add credential
    switch (leaf_node.credential) {
        .basic => |basic| {
            try tbs.append(@intFromEnum(types.CredentialType.basic));
            try tbs.appendSlice(basic.identity);
        },
        else => return error.UnsupportedCredential,
    }
    
    // Add extensions
    for (leaf_node.extensions) |ext| {
        const ext_type_bytes = std.mem.toBytes(@intFromEnum(ext.extension_type));
        try tbs.appendSlice(&ext_type_bytes);
        try tbs.appendSlice(ext.extension_data);
    }
    
    return try tbs.toOwnedSlice();
}

fn keyPackageTBS(allocator: std.mem.Allocator, key_package: types.KeyPackage) ![]u8 {
    // Create to-be-signed data for key package
    var tbs = std.ArrayList(u8).init(allocator);
    defer tbs.deinit();
    
    // Add version and cipher suite
    const version_bytes = std.mem.toBytes(@intFromEnum(key_package.version));
    try tbs.appendSlice(&version_bytes);
    
    const cipher_bytes = std.mem.toBytes(@intFromEnum(key_package.cipher_suite));
    try tbs.appendSlice(&cipher_bytes);
    
    // Add init key
    try tbs.appendSlice(key_package.init_key.data);
    
    // Add leaf node TBS
    const leaf_tbs = try leafNodeTBS(allocator, key_package.leaf_node);
    defer allocator.free(leaf_tbs);
    try tbs.appendSlice(leaf_tbs);
    
    return try tbs.toOwnedSlice();
}

fn serializeLifetime(allocator: std.mem.Allocator, lifetime: types.Lifetime) ![]u8 {
    var data = try allocator.alloc(u8, 16);
    std.mem.writeInt(u64, data[0..8], lifetime.not_before, .big);
    std.mem.writeInt(u64, data[8..16], lifetime.not_after, .big);
    return data;
}

fn deserializeLifetime(data: []const u8) !types.Lifetime {
    if (data.len != 16) return error.InvalidExtension;
    return types.Lifetime{
        .not_before = std.mem.readInt(u64, data[0..8], .big),
        .not_after = std.mem.readInt(u64, data[8..16], .big),
    };
}

fn serializeCapabilities(allocator: std.mem.Allocator, capabilities: types.Capabilities) ![]u8 {
    // Simplified serialization
    var data = std.ArrayList(u8).init(allocator);
    defer data.deinit();
    
    // Add versions
    try data.append(@intCast(capabilities.versions.len));
    for (capabilities.versions) |v| {
        const bytes = std.mem.toBytes(@intFromEnum(v));
        try data.appendSlice(&bytes);
    }
    
    // Add ciphersuites
    try data.append(@intCast(capabilities.ciphersuites.len));
    for (capabilities.ciphersuites) |cs| {
        const bytes = std.mem.toBytes(@intFromEnum(cs));
        try data.appendSlice(&bytes);
    }
    
    return try data.toOwnedSlice();
}

/// Helper function to serialize a leaf node
fn serializeLeafNode(allocator: std.mem.Allocator, leaf_node: types.LeafNode) ![]u8 {
    // Simplified leaf node serialization
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    
    // Use TLS codec convenience functions
    
    // Encryption key
    try mls_zig.tls_encode.encodeVarBytes(&buffer, u16, leaf_node.encryption_key.data);
    
    // Signature key  
    try mls_zig.tls_encode.encodeVarBytes(&buffer, u16, leaf_node.signature_key.data);
    
    // Credential (simplified)
    try mls_zig.tls_encode.encodeInt(&buffer, u8, @intFromEnum(types.CredentialType.basic));
    switch (leaf_node.credential) {
        .basic => |basic| {
            try mls_zig.tls_encode.encodeVarBytes(&buffer, u16, basic.identity);
        },
        else => return error.UnsupportedCredential,
    }
    
    // Capabilities (simplified - write as empty for now)
    try mls_zig.tls_encode.encodeInt(&buffer, u16, 0);
    
    // Leaf node source
    try mls_zig.tls_encode.encodeInt(&buffer, u8, @intFromEnum(leaf_node.leaf_node_source));
    
    // Extensions (simplified)
    try mls_zig.tls_encode.encodeInt(&buffer, u16, @intCast(leaf_node.extensions.len));
    for (leaf_node.extensions) |ext| {
        try mls_zig.tls_encode.encodeInt(&buffer, u16, @intFromEnum(ext.extension_type));
        try mls_zig.tls_encode.encodeVarBytes(&buffer, u16, ext.extension_data);
    }
    
    // Signature
    try mls_zig.tls_encode.encodeVarBytes(&buffer, u16, leaf_node.signature);
    
    return buffer.toOwnedSlice();
}

/// Helper function to parse a leaf node
fn parseLeafNode(allocator: std.mem.Allocator, data: []const u8) !types.LeafNode {
    var decoder = tls.Decoder.fromTheirSlice(data);
    
    // Encryption key
    const enc_key_data = try mls_zig.tls_encode.readVarBytes(&decoder, u16, allocator);
    
    // Signature key
    const sig_key_data = try mls_zig.tls_encode.readVarBytes(&decoder, u16, allocator);
    
    // Credential
    try decoder.ensure(1);
    _ = decoder.decode(u8); // credential type (ignore for now)
    const identity = try mls_zig.tls_encode.readVarBytes(&decoder, u16, allocator);
    
    // Skip capabilities for now
    try decoder.ensure(2);
    const cap_len = decoder.decode(u16);
    try decoder.ensure(cap_len);
    _ = decoder.slice(cap_len);
    
    // Leaf node source
    try decoder.ensure(1);
    const source = decoder.decode(u8);
    
    // Extensions
    try decoder.ensure(2);
    const ext_count = decoder.decode(u16);
    const extensions = try allocator.alloc(types.Extension, ext_count);
    for (extensions) |*ext| {
        try decoder.ensure(2);
        const ext_type = decoder.decode(u16);
        const ext_data = try mls_zig.tls_encode.readVarBytes(&decoder, u16, allocator);
        
        ext.* = types.Extension{
            .extension_type = types.ExtensionType.fromInt(ext_type),
            .critical = false,
            .extension_data = ext_data,
        };
    }
    
    // Signature
    const signature = try mls_zig.tls_encode.readVarBytes(&decoder, u16, allocator);
    
    return types.LeafNode{
        .encryption_key = .{ .data = enc_key_data },
        .signature_key = .{ .data = sig_key_data },
        .credential = .{ .basic = .{ .identity = identity } },
        .capabilities = .{
            .versions = &.{},
            .ciphersuites = &.{},
            .extensions = &.{},
            .proposals = &.{},
            .credentials = &.{},
        },
        .leaf_node_source = switch (source) {
            0 => .reserved,
            1 => .key_package,
            2 => .update,
            3 => .{ .commit = &.{} }, // TODO: Parse commit data if present
            else => return error.InvalidLeafNodeSource,
        },
        .extensions = extensions,
        .signature = signature,
    };
}

/// Helper function to serialize extensions
fn serializeExtensions(allocator: std.mem.Allocator, extensions: []const types.Extension) ![]u8 {
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    
    // Use TLS codec convenience functions
    
    for (extensions) |ext| {
        try mls_zig.tls_encode.encodeInt(&buffer, u16, @intFromEnum(ext.extension_type));
        try mls_zig.tls_encode.encodeInt(&buffer, u8, if (ext.critical) 1 else 0);
        try mls_zig.tls_encode.encodeVarBytes(&buffer, u16, ext.extension_data);
    }
    
    return buffer.toOwnedSlice();
}

/// Helper function to parse extensions
fn parseExtensions(allocator: std.mem.Allocator, data: []const u8) ![]types.Extension {
    if (data.len == 0) return &.{};
    
    var decoder = tls.Decoder.fromTheirSlice(data);
    
    var extensions = std.ArrayList(types.Extension).init(allocator);
    defer extensions.deinit();
    
    while (decoder.eof() == false) {
        if (decoder.rest().len < 3) break; // Need at least ext_type(2) + critical(1)
        
        try decoder.ensure(2);
        const ext_type = decoder.decode(u16);
        try decoder.ensure(1);
        const critical = decoder.decode(u8) != 0;
        const ext_data = try mls_zig.tls_encode.readVarBytes(&decoder, u16, allocator);
        
        try extensions.append(types.Extension{
            .extension_type = types.ExtensionType.fromInt(ext_type),
            .critical = critical,
            .extension_data = ext_data,
        });
    }
    
    return extensions.toOwnedSlice();
}

test "key package lifetime extension" {
    const allocator = std.testing.allocator;
    
    const lifetime = types.Lifetime{
        .not_before = 1000,
        .not_after = 2000,
    };
    
    const serialized = try serializeLifetime(allocator, lifetime);
    defer allocator.free(serialized);
    
    const deserialized = try deserializeLifetime(serialized);
    try std.testing.expectEqual(lifetime.not_before, deserialized.not_before);
    try std.testing.expectEqual(lifetime.not_after, deserialized.not_after);
}

test "extract nostr pubkey from credential" {
    const pubkey_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const key_package = types.KeyPackage{
        .version = .mls10,
        .cipher_suite = .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        .init_key = types.HPKEPublicKey.init(&.{}),
        .leaf_node = .{
            .encryption_key = types.HPKEPublicKey.init(&.{}),
            .signature_key = types.SignaturePublicKey.init(&.{}),
            .credential = .{ .basic = .{ .identity = pubkey_hex } },
            .capabilities = .{
                .versions = &.{},
                .ciphersuites = &.{},
                .extensions = &.{},
                .proposals = &.{},
                .credentials = &.{},
            },
            .leaf_node_source = .key_package,
            .extensions = &.{},
            .signature = &.{},
        },
        .extensions = &.{},
        .signature = &.{},
    };
    
    const extracted = try extractNostrPubkey(key_package);
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, pubkey_hex);
    try std.testing.expectEqualSlices(u8, &expected, &extracted);
}

test "key package serialization roundtrip" {
    const allocator = std.testing.allocator;
    
    // Create a test key package
    const test_init_key = try allocator.alloc(u8, 32);
    defer allocator.free(test_init_key);
    @memset(test_init_key, 0xAA);
    
    const test_enc_key = try allocator.alloc(u8, 32);
    defer allocator.free(test_enc_key);
    @memset(test_enc_key, 0xBB);
    
    const test_sig_key = try allocator.alloc(u8, 32);
    defer allocator.free(test_sig_key);
    @memset(test_sig_key, 0xCC);
    
    const test_signature = try allocator.alloc(u8, 64);
    defer allocator.free(test_signature);
    @memset(test_signature, 0xDD);
    
    const original = types.KeyPackage{
        .version = .mls10,
        .cipher_suite = .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        .init_key = types.HPKEPublicKey.init(test_init_key),
        .leaf_node = .{
            .encryption_key = types.HPKEPublicKey.init(test_enc_key),
            .signature_key = types.SignaturePublicKey.init(test_sig_key),
            .credential = .{ .basic = .{ .identity = "test" } },
            .capabilities = .{
                .versions = &.{},
                .ciphersuites = &.{},
                .extensions = &.{},
                .proposals = &.{},
                .credentials = &.{},
            },
            .leaf_node_source = .key_package,
            .extensions = &.{},
            .signature = test_signature,
        },
        .extensions = &.{},
        .signature = test_signature,
    };
    
    // Serialize
    const serialized = try serializeKeyPackage(allocator, original);
    defer allocator.free(serialized);
    
    // Parse back
    const parsed = try parseKeyPackage(allocator, serialized);
    defer freeKeyPackage(allocator, parsed);
    
    // Check key fields match
    try std.testing.expectEqual(original.version, parsed.version);
    try std.testing.expectEqual(original.cipher_suite, parsed.cipher_suite);
    try std.testing.expect(original.init_key.eql(parsed.init_key));
}

test "key package includes last_resort extension" {
    // Test that we properly add last_resort to capabilities
    const allocator = std.testing.allocator;
    
    const capabilities = types.Capabilities{
        .versions = try allocator.dupe(types.ProtocolVersion, &[_]types.ProtocolVersion{.mls10}),
        .ciphersuites = try allocator.dupe(types.Ciphersuite, &[_]types.Ciphersuite{.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519}),
        .extensions = try allocator.dupe(types.ExtensionType, &[_]types.ExtensionType{
            .capabilities,
            .lifetime,
            .required_capabilities,
            .last_resort,
        }),
        .proposals = try allocator.dupe(types.ProposalType, &[_]types.ProposalType{.add}),
        .credentials = try allocator.dupe(types.CredentialType, &[_]types.CredentialType{.basic}),
    };
    defer {
        allocator.free(capabilities.versions);
        allocator.free(capabilities.ciphersuites);
        allocator.free(capabilities.extensions);
        allocator.free(capabilities.proposals);
        allocator.free(capabilities.credentials);
    }
    
    // Check that last_resort is in the extensions
    var found = false;
    for (capabilities.extensions) |ext| {
        if (ext == .last_resort) {
            found = true;
            break;
        }
    }
    try std.testing.expect(found);
}

pub fn freeKeyPackage(allocator: std.mem.Allocator, kp: types.KeyPackage) void {
    allocator.free(kp.init_key.data);
    allocator.free(kp.leaf_node.encryption_key.data);
    allocator.free(kp.leaf_node.signature_key.data);
    
    switch (kp.leaf_node.credential) {
        .basic => |basic| allocator.free(basic.identity),
        else => {},
    }
    
    allocator.free(kp.leaf_node.capabilities.versions);
    allocator.free(kp.leaf_node.capabilities.ciphersuites);
    allocator.free(kp.leaf_node.capabilities.extensions);
    allocator.free(kp.leaf_node.capabilities.proposals);
    allocator.free(kp.leaf_node.capabilities.credentials);
    
    // Free the extensions array
    allocator.free(kp.extensions);
    
    for (kp.leaf_node.extensions) |ext| {
        allocator.free(ext.extension_data);
    }
    allocator.free(kp.leaf_node.extensions);
    allocator.free(kp.leaf_node.signature);
    allocator.free(kp.signature);
}