const std = @import("std");
const types = @import("types.zig");
const provider = @import("provider.zig");
const extension = @import("extension.zig");
const mls = @import("mls.zig");
const groups = @import("groups.zig");
const key_packages = @import("key_packages.zig");
const mls_zig = @import("mls_zig");

/// Welcome processing result
pub const WelcomeProcessingResult = struct {
    /// Group preview information
    preview: mls.GroupPreview,
    
    /// Encrypted group secrets (to be decrypted when joining)
    encrypted_secrets: []const u8,
    
    /// Serialized group info
    group_info_data: []const u8,
};

/// Preview a welcome message before joining
pub fn previewWelcome(
    allocator: std.mem.Allocator,
    welcome_data: []const u8,
    recipient_private_key: [32]u8,
) !mls.GroupPreview {
    // Parse the welcome message
    const welcome = try parseWelcome(allocator, welcome_data);
    defer freeWelcome(allocator, welcome);
    
    // Find our encrypted secrets
    const our_secrets = try findOurSecrets(allocator, welcome, recipient_private_key);
    if (our_secrets == null) {
        return error.SecretsNotFound;
    }
    
    // Decrypt group info (but not the actual group secrets yet)
    const group_info = try decryptGroupInfo(allocator, welcome.encrypted_group_info, our_secrets.?);
    defer freeGroupInfo(allocator, group_info);
    
    // Extract group metadata from extensions
    var group_data: ?extension.NostrGroupData = null;
    for (group_info.group_context.extensions) |ext| {
        if (ext.extension_type == .nostr_group_data) {
            group_data = try extension.extractNostrGroupData(allocator, ext);
            break;
        }
    }
    
    if (group_data == null) {
        return error.NoGroupDataFound;
    }
    defer {
        if (group_data) |gd| {
            allocator.free(gd.name);
            allocator.free(gd.description);
            allocator.free(gd.admins);
            for (gd.relays) |relay| {
                allocator.free(relay);
            }
            allocator.free(gd.relays);
            if (gd.image) |img| {
                allocator.free(img);
            }
        }
    }
    
    return mls.GroupPreview{
        .group_id = group_info.group_context.group_id,
        .metadata = mls.GroupMetadata{
            .name = try allocator.dupe(u8, group_data.?.name),
            .description = try allocator.dupe(u8, group_data.?.description),
            .admins = try allocator.dupe([32]u8, group_data.?.admins),
            .relays = try duplicateStringArray(allocator, group_data.?.relays),
            .image = if (group_data.?.image) |img| try allocator.dupe(u8, img) else null,
        },
        .epoch = group_info.group_context.epoch,
        .member_count = group_info.members.len,
        .cipher_suite = group_info.group_context.cipher_suite,
    };
}

/// Join a group from a welcome message
pub fn joinFromWelcome(
    allocator: std.mem.Allocator,
    mls_provider: *provider.MlsProvider,
    welcome_data: []const u8,
    private_key: [32]u8,
) !mls.JoinResult {
    // Parse the welcome message
    const welcome = try parseWelcome(allocator, welcome_data);
    defer freeWelcome(allocator, welcome);
    
    // Find and decrypt our secrets
    const our_secrets = try findOurSecrets(allocator, welcome, private_key);
    if (our_secrets == null) {
        return error.SecretsNotFound;
    }
    
    const decrypted_secrets = try decryptSecrets(allocator, mls_provider, our_secrets.?, private_key);
    defer allocator.free(decrypted_secrets);
    
    // Decrypt and parse group info
    const group_info = try decryptGroupInfo(allocator, welcome.encrypted_group_info, our_secrets.?);
    defer freeGroupInfo(allocator, group_info);
    
    // Extract group data
    var group_data: ?extension.NostrGroupData = null;
    for (group_info.group_context.extensions) |ext| {
        if (ext.extension_type == .nostr_group_data) {
            group_data = try extension.extractNostrGroupData(allocator, ext);
            break;
        }
    }
    
    if (group_data == null) {
        return error.NoGroupDataFound;
    }
    
    // Reconstruct epoch secrets from decrypted data
    const epoch_secrets = try reconstructEpochSecrets(allocator, decrypted_secrets);
    
    // Build initial group state
    const state = mls.MlsGroupState{
        .group_id = group_info.group_context.group_id,
        .epoch = group_info.group_context.epoch,
        .cipher_suite = group_info.group_context.cipher_suite,
        .group_context = group_info.group_context,
        .tree_hash = group_info.group_context.tree_hash,
        .confirmed_transcript_hash = group_info.group_context.confirmed_transcript_hash,
        .members = try allocator.dupe(types.MemberInfo, group_info.members),
        .ratchet_tree = try allocator.dupe(u8, group_info.ratchet_tree),
        .interim_transcript_hash = [_]u8{0} ** 32, // Will be updated
        .epoch_secrets = epoch_secrets,
    };
    
    const metadata = mls.GroupMetadata{
        .name = try allocator.dupe(u8, group_data.?.name),
        .description = try allocator.dupe(u8, group_data.?.description),
        .admins = try allocator.dupe([32]u8, group_data.?.admins),
        .relays = try duplicateStringArray(allocator, group_data.?.relays),
        .image = if (group_data.?.image) |img| try allocator.dupe(u8, img) else null,
    };
    
    // Clean up group data
    allocator.free(group_data.?.name);
    allocator.free(group_data.?.description);
    allocator.free(group_data.?.admins);
    for (group_data.?.relays) |relay| {
        allocator.free(relay);
    }
    allocator.free(group_data.?.relays);
    if (group_data.?.image) |img| {
        allocator.free(img);
    }
    
    return mls.JoinResult{
        .state = state,
        .metadata = metadata,
    };
}

/// Create a welcome message for a new member
pub fn createWelcome(
    allocator: std.mem.Allocator,
    mls_provider: *provider.MlsProvider,
    group_state: *const mls.MlsGroupState,
    recipient_key_package: types.KeyPackage,
    sender_private_key: [32]u8,
) !types.Welcome {
    _ = sender_private_key;
    
    // Extract recipient's HPKE public key
    const recipient_hpke_key = recipient_key_package.init_key.data;
    
    // Create group secrets to encrypt
    const group_secrets = try createGroupSecrets(allocator, group_state);
    defer allocator.free(group_secrets);
    
    // Encrypt secrets to recipient using HPKE
    const info = "MLS 1.0 Welcome";
    const aad = &group_state.group_id;
    
    const encrypted = try mls_provider.crypto.hpkeSealFn(
        allocator,
        recipient_hpke_key,
        info,
        aad,
        group_secrets,
    );
    defer {
        allocator.free(encrypted.kem_output);
        allocator.free(encrypted.ciphertext);
    }
    
    // Create encrypted group secrets entry
    const encrypted_secrets = types.EncryptedGroupSecrets{
        .new_member = try allocator.dupe(u8, recipient_hpke_key),
        .encrypted_group_secrets = try std.fmt.allocPrint(
            allocator,
            "{s}{s}",
            .{ encrypted.kem_output, encrypted.ciphertext },
        ),
    };
    
    // Create group info
    const group_info = types.GroupInfo{
        .group_context = group_state.group_context,
        .members = group_state.members,
        .ratchet_tree = group_state.ratchet_tree,
    };
    
    // Serialize and encrypt group info
    const group_info_data = try serializeGroupInfo(allocator, group_info);
    defer allocator.free(group_info_data);
    
    // For simplicity, we'll use the same encryption key
    // In real MLS, this would use a different key derivation
    const encrypted_group_info = try mls_provider.crypto.hpkeSealFn(
        allocator,
        recipient_hpke_key,
        "MLS 1.0 GroupInfo",
        aad,
        group_info_data,
    );
    
    const encrypted_info_bytes = try std.fmt.allocPrint(
        allocator,
        "{s}{s}",
        .{ encrypted_group_info.kem_output, encrypted_group_info.ciphertext },
    );
    defer {
        allocator.free(encrypted_group_info.kem_output);
        allocator.free(encrypted_group_info.ciphertext);
    }
    
    return types.Welcome{
        .cipher_suite = group_state.cipher_suite,
        .secrets = try allocator.dupe(
            types.EncryptedGroupSecrets,
            &[_]types.EncryptedGroupSecrets{encrypted_secrets},
        ),
        .encrypted_group_info = encrypted_info_bytes,
    };
}

/// Parse a serialized welcome message
pub fn parseWelcome(allocator: std.mem.Allocator, data: []const u8) !types.Welcome {
    // Use TLS 1.3 wire format as per RFC 9420
    var stream = std.io.fixedBufferStream(data);
    var reader = mls_zig.tls_codec.TlsReader(@TypeOf(stream.reader())).init(stream.reader());
    
    // Welcome message format:
    // struct {
    //     CipherSuite cipher_suite;
    //     EncryptedGroupSecrets secrets<V>;
    //     opaque encrypted_group_info<V>;
    // } Welcome;
    
    // Cipher suite (u16)
    const cipher_suite_raw = try reader.readU16();
    const cipher_suite: types.Ciphersuite = @enumFromInt(cipher_suite_raw);
    
    // Secrets array (variable length with u16 count prefix)
    const secrets_count = try reader.readU16();
    const secrets = try allocator.alloc(types.EncryptedGroupSecrets, secrets_count);
    
    for (secrets) |*secret| {
        // new_member (variable length with u16 length prefix)
        const new_member_len = try reader.readU16();
        const new_member = try allocator.alloc(u8, new_member_len);
        try reader.reader.readNoEof(new_member);
        
        // encrypted_group_secrets (variable length with u16 length prefix)
        const encrypted_secrets_len = try reader.readU16();
        const encrypted_secrets = try allocator.alloc(u8, encrypted_secrets_len);
        try reader.reader.readNoEof(encrypted_secrets);
        
        secret.* = types.EncryptedGroupSecrets{
            .new_member = new_member,
            .encrypted_group_secrets = encrypted_secrets,
        };
    }
    
    // Encrypted group info (variable length with u16 length prefix)
    const group_info_len = try reader.readU16();
    const encrypted_group_info = try allocator.alloc(u8, group_info_len);
    try reader.reader.readNoEof(encrypted_group_info);
    
    return types.Welcome{
        .cipher_suite = cipher_suite,
        .secrets = secrets,
        .encrypted_group_info = encrypted_group_info,
    };
}

/// Serialize a welcome message
pub fn serializeWelcome(allocator: std.mem.Allocator, welcome: types.Welcome) ![]u8 {
    // Use TLS 1.3 wire format as per RFC 9420
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    
    // Manual serialization instead of TlsWriter
    
    // Welcome message format:
    // struct {
    //     CipherSuite cipher_suite;
    //     EncryptedGroupSecrets secrets<V>;
    //     opaque encrypted_group_info<V>;
    // } Welcome;
    
    // Cipher suite (u16)
    try mls_zig.tls_codec.writeU16ToList(&buffer, @intFromEnum(welcome.cipher_suite));
    
    // Secrets array (variable length with u16 count prefix)
    try mls_zig.tls_codec.writeU16ToList(&buffer, @intCast(welcome.secrets.len));
    for (welcome.secrets) |secret| {
        // new_member (variable length with u16 length prefix)
        try mls_zig.tls_codec.writeU16ToList(&buffer, @intCast(secret.new_member.len));
        try buffer.appendSlice(secret.new_member);
        
        // encrypted_group_secrets (variable length with u16 length prefix)
        try mls_zig.tls_codec.writeU16ToList(&buffer, @intCast(secret.encrypted_group_secrets.len));
        try buffer.appendSlice(secret.encrypted_group_secrets);
    }
    
    // Encrypted group info (variable length with u16 length prefix)
    try mls_zig.tls_codec.writeU16ToList(&buffer, @intCast(welcome.encrypted_group_info.len));
    try buffer.appendSlice(welcome.encrypted_group_info);
    
    return buffer.toOwnedSlice();
}

// Helper functions

fn findOurSecrets(
    allocator: std.mem.Allocator,
    welcome: types.Welcome,
    private_key: [32]u8,
) !?types.EncryptedGroupSecrets {
    _ = allocator;
    _ = private_key;
    
    // Find the encrypted secrets for our key
    for (welcome.secrets) |secrets| {
        // In real implementation, we'd match against the HPKE public key
        // derived from the private key
        // For now, we'll just return the first one
        return secrets;
    }
    
    return null;
}

fn decryptSecrets(
    allocator: std.mem.Allocator,
    mls_provider: *provider.MlsProvider,
    encrypted_secrets: types.EncryptedGroupSecrets,
    private_key: [32]u8,
) ![]u8 {
    // The encrypted_group_secrets field contains KEM output + ciphertext concatenated
    // We need to parse it to extract both parts
    const encrypted_data = encrypted_secrets.encrypted_group_secrets;
    
    // For X25519, KEM output is 32 bytes
    const kem_output_size = 32;
    if (encrypted_data.len <= kem_output_size) {
        return error.InvalidEncryptedData;
    }
    
    // Split the data into KEM output and ciphertext
    const kem_output = encrypted_data[0..kem_output_size];
    const ciphertext = encrypted_data[kem_output_size..];
    
    // Create HpkeCiphertext structure
    const hpke_ciphertext = provider.HpkeCiphertext{
        .kem_output = kem_output,
        .ciphertext = ciphertext,
    };
    
    // Prepare the info field for HPKE - MLS uses "mls 1.0 group_secrets" as the info
    const info = "mls 1.0 group_secrets";
    
    // AAD (additional authenticated data) is typically empty for group secrets
    const aad = "";
    
    // Use the MLS provider's HPKE open function to decrypt
    return mls_provider.crypto.hpkeOpenFn(
        allocator,
        &private_key,
        info,
        aad,
        hpke_ciphertext,
    );
}

fn decryptGroupInfo(
    allocator: std.mem.Allocator,
    encrypted_data: []const u8,
    secrets: types.EncryptedGroupSecrets,
) !types.GroupInfo {
    _ = secrets; // The decrypted secrets from the previous step would be used here
    
    // In MLS, the GroupInfo is encrypted using a key derived from the joiner_secret
    // For now, we need to parse the encrypted data which should have been decrypted
    // using the group_info_key derived from the joiner_secret
    
    // The encrypted_data should contain:
    // - KEM output (for HPKE encryption)
    // - Ciphertext (the actual encrypted GroupInfo)
    
    // For X25519, KEM output is 32 bytes
    const kem_output_size = 32;
    if (encrypted_data.len <= kem_output_size) {
        return error.InvalidEncryptedGroupInfo;
    }
    
    // Note: In a full implementation, we would:
    // 1. Derive group_info_key from joiner_secret using expandWithLabel
    // 2. Use HPKE to decrypt the ciphertext using the group_info_key
    // 3. Parse the decrypted data as a GroupInfo structure
    
    // For now, return a minimal valid GroupInfo structure
    // This will be replaced when we have the full MLS key schedule implementation
    return types.GroupInfo{
        .group_context = types.GroupContext{
            .version = .mls10,
            .cipher_suite = .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            .group_id = types.GroupId.init([_]u8{0} ** 32),
            .epoch = 0,
            .tree_hash = [_]u8{0} ** 32,
            .confirmed_transcript_hash = [_]u8{0} ** 32,
            .extensions = try allocator.alloc(types.Extension, 0),
        },
        .members = try allocator.alloc(types.MemberInfo, 0),
        .ratchet_tree = try allocator.alloc(u8, 0),
    };
}

pub fn freeWelcome(allocator: std.mem.Allocator, welcome: types.Welcome) void {
    for (welcome.secrets) |secrets| {
        allocator.free(secrets.new_member);
        allocator.free(secrets.encrypted_group_secrets);
    }
    allocator.free(welcome.secrets);
    allocator.free(welcome.encrypted_group_info);
}

fn freeGroupInfo(allocator: std.mem.Allocator, group_info: types.GroupInfo) void {
    for (group_info.group_context.extensions) |ext| {
        allocator.free(ext.extension_data);
    }
    allocator.free(group_info.group_context.extensions);
    
    for (group_info.members) |member| {
        switch (member.credential) {
            .basic => |basic| allocator.free(basic.identity),
            else => {},
        }
    }
    allocator.free(group_info.members);
    allocator.free(group_info.ratchet_tree);
}

fn createGroupSecrets(allocator: std.mem.Allocator, group_state: *const mls.MlsGroupState) ![]u8 {
    // Package the epoch secrets and other necessary data
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    
    // Add epoch secrets
    try buf.appendSlice(&group_state.epoch_secrets.init_secret);
    try buf.appendSlice(&group_state.epoch_secrets.sender_data_secret);
    try buf.appendSlice(&group_state.epoch_secrets.encryption_secret);
    try buf.appendSlice(&group_state.epoch_secrets.exporter_secret);
    try buf.appendSlice(&group_state.epoch_secrets.epoch_authenticator);
    try buf.appendSlice(&group_state.epoch_secrets.external_secret);
    try buf.appendSlice(&group_state.epoch_secrets.confirmation_key);
    try buf.appendSlice(&group_state.epoch_secrets.membership_key);
    try buf.appendSlice(&group_state.epoch_secrets.resumption_psk);
    
    return try buf.toOwnedSlice();
}

fn reconstructEpochSecrets(allocator: std.mem.Allocator, data: []const u8) !mls.EpochSecrets {
    _ = allocator;
    
    if (data.len < 32 * 9) {
        return error.InvalidSecrets;
    }
    
    var secrets: mls.EpochSecrets = undefined;
    var offset: usize = 0;
    
    @memcpy(&secrets.init_secret, data[offset..offset + 32]);
    offset += 32;
    @memcpy(&secrets.sender_data_secret, data[offset..offset + 32]);
    offset += 32;
    @memcpy(&secrets.encryption_secret, data[offset..offset + 32]);
    offset += 32;
    @memcpy(&secrets.exporter_secret, data[offset..offset + 32]);
    offset += 32;
    @memcpy(&secrets.epoch_authenticator, data[offset..offset + 32]);
    offset += 32;
    @memcpy(&secrets.external_secret, data[offset..offset + 32]);
    offset += 32;
    @memcpy(&secrets.confirmation_key, data[offset..offset + 32]);
    offset += 32;
    @memcpy(&secrets.membership_key, data[offset..offset + 32]);
    offset += 32;
    @memcpy(&secrets.resumption_psk, data[offset..offset + 32]);
    
    return secrets;
}

fn serializeGroupInfo(allocator: std.mem.Allocator, group_info: types.GroupInfo) ![]u8 {
    // Our types.GroupInfo is a simplified version that only contains:
    // - group_context
    // - members 
    // - ratchet_tree
    //
    // For the Welcome message context, we need to serialize this in a format
    // that can be parsed later. Since we don't have the full MLS GroupInfo
    // structure with confirmation_tag and signature, we'll serialize what we have.
    
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    
    // Serialize GroupContext
    // Protocol version (u16)
    try mls_zig.tls_codec.writeU16ToList(&buffer, @intFromEnum(group_info.group_context.version));
    
    // Cipher suite (u16)
    try mls_zig.tls_codec.writeU16ToList(&buffer, @intFromEnum(group_info.group_context.cipher_suite));
    
    // Group ID (variable length with u8 length prefix)
    try mls_zig.tls_codec.writeU8ToList(&buffer, @intCast(group_info.group_context.group_id.len));
    try buffer.appendSlice(&group_info.group_context.group_id);
    
    // Epoch (u64)
    try mls_zig.tls_codec.writeU64ToList(&buffer, group_info.group_context.epoch);
    
    // Tree hash (variable length with u8 length prefix)
    try mls_zig.tls_codec.writeU8ToList(&buffer, @intCast(group_info.group_context.tree_hash.len));
    try buffer.appendSlice(&group_info.group_context.tree_hash);
    
    // Confirmed transcript hash (variable length with u8 length prefix)
    try mls_zig.tls_codec.writeU8ToList(&buffer, @intCast(group_info.group_context.confirmed_transcript_hash.len));
    try buffer.appendSlice(&group_info.group_context.confirmed_transcript_hash);
    
    // Extensions (variable length with u32 length prefix)
    try mls_zig.tls_codec.writeU32ToList(&buffer, @intCast(group_info.group_context.extensions.len));
    for (group_info.group_context.extensions) |ext| {
        // Extension type (u16)
        try mls_zig.tls_codec.writeU16ToList(&buffer, @intFromEnum(ext.extension_type));
        // Extension data (variable length with u16 length prefix)
        try mls_zig.tls_codec.writeU16ToList(&buffer, @intCast(ext.extension_data.len));
        try buffer.appendSlice(ext.extension_data);
    }
    
    // Members (variable length with u32 length prefix)
    try mls_zig.tls_codec.writeU32ToList(&buffer, @intCast(group_info.members.len));
    for (group_info.members) |member| {
        // For now, serialize member index as u32
        try mls_zig.tls_codec.writeU32ToList(&buffer, member.index);
        // Add credential data length and data
        try mls_zig.tls_codec.writeU16ToList(&buffer, @intCast(member.credential.identity.len));
        try buffer.appendSlice(member.credential.identity);
    }
    
    // Ratchet tree (variable length with u32 length prefix)
    try mls_zig.tls_codec.writeU32ToList(&buffer, @intCast(group_info.ratchet_tree.len));
    try buffer.appendSlice(group_info.ratchet_tree);
    
    return buffer.toOwnedSlice();
}

fn duplicateStringArray(allocator: std.mem.Allocator, strings: []const []const u8) ![]const []const u8 {
    const result = try allocator.alloc([]const u8, strings.len);
    for (strings, 0..) |str, i| {
        result[i] = try allocator.dupe(u8, str);
    }
    return result;
}

test "create group secrets" {
    const allocator = std.testing.allocator;
    
    const state = mls.MlsGroupState{
        .group_id = types.GroupId.init([_]u8{1} ** 32),
        .epoch = 0,
        .cipher_suite = .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        .group_context = undefined,
        .tree_hash = [_]u8{0} ** 32,
        .confirmed_transcript_hash = [_]u8{0} ** 32,
        .members = &.{},
        .ratchet_tree = &.{},
        .interim_transcript_hash = [_]u8{0} ** 32,
        .epoch_secrets = mls.EpochSecrets{
            .joiner_secret = [_]u8{0} ** 32,
            .member_secret = [_]u8{0} ** 32,
            .welcome_secret = [_]u8{0} ** 32,
            .epoch_secret = [_]u8{0} ** 32,
            .sender_data_secret = [_]u8{1} ** 32,
            .encryption_secret = [_]u8{2} ** 32,
            .exporter_secret = [_]u8{3} ** 32,
            .epoch_authenticator = [_]u8{4} ** 32,
            .external_secret = [_]u8{5} ** 32,
            .confirmation_key = [_]u8{6} ** 32,
            .membership_key = [_]u8{7} ** 32,
            .resumption_psk = [_]u8{8} ** 32,
            .init_secret = [_]u8{9} ** 32,
        },
    };
    
    const secrets = try createGroupSecrets(allocator, &state);
    defer allocator.free(secrets);
    
    try std.testing.expect(secrets.len >= 32 * 9);
    
    // Test reconstruction
    const reconstructed = try reconstructEpochSecrets(allocator, secrets);
    try std.testing.expectEqualSlices(u8, &state.epoch_secrets.init_secret, &reconstructed.init_secret);
    try std.testing.expectEqualSlices(u8, &state.epoch_secrets.exporter_secret, &reconstructed.exporter_secret);
}

test "duplicate string array" {
    const allocator = std.testing.allocator;
    
    const original = &[_][]const u8{
        "string1",
        "string2",
        "string3",
    };
    
    const duplicated = try duplicateStringArray(allocator, original);
    defer {
        for (duplicated) |str| {
            allocator.free(str);
        }
        allocator.free(duplicated);
    }
    
    try std.testing.expectEqual(original.len, duplicated.len);
    for (original, duplicated) |orig, dup| {
        try std.testing.expectEqualStrings(orig, dup);
        // Ensure they're different allocations
        try std.testing.expect(orig.ptr != dup.ptr);
    }
}