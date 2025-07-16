const std = @import("std");
const types = @import("types.zig");
const provider = @import("provider.zig");
const mls = @import("mls.zig");
const nip44 = @import("../nip44/mod.zig");
const crypto = @import("../crypto.zig");
const nip_ee = @import("nip_ee.zig");
const mls_zig = @import("mls_zig");
const ephemeral = @import("ephemeral.zig");
const constants = @import("constants.zig");

/// Message encryption parameters
pub const MessageParams = struct {
    /// Additional authenticated data
    authenticated_data: []const u8 = &.{},
    
    /// Whether to include membership tag
    include_membership_tag: bool = false,
};

/// Encrypt a message for the group (double-layer encryption)
pub fn encryptGroupMessage(
    allocator: std.mem.Allocator,
    mls_provider: *provider.MlsProvider,
    group_state: *const mls.MlsGroupState,
    content: []const u8,
    sender_private_key: [32]u8,
    params: MessageParams,
) !mls.EncryptedMessage {
    // Determine sender index from private key
    var sender_pubkey: [32]u8 = undefined;
    sender_pubkey = try crypto.getPublicKey(sender_private_key);
    
    const sender_index = try findMemberIndex(group_state, sender_pubkey);
    
    // Create MLS application message
    const mls_content = types.Content{
        .application = content,
    };
    
    // Create framed content
    const framed_content = types.FramedContent{
        .group_id = group_state.group_id,
        .epoch = group_state.epoch,
        .sender = types.Sender{ .member = sender_index },
        .authenticated_data = params.authenticated_data,
        .content_type = .application,
        .content = mls_content,
    };
    
    // Serialize framed content for signing
    const framed_tbs = try serializeFramedContentTBS(allocator, framed_content);
    defer allocator.free(framed_tbs);
    
    // Sign with sender's MLS signing key
    const mls_private_key = try deriveMlsSigningKey(allocator, sender_private_key);
    defer allocator.free(mls_private_key);
    
    const signature = try mls_provider.crypto.signFn(allocator, mls_private_key, framed_tbs);
    defer allocator.free(signature);
    
    // Create MLS plaintext
    const mls_plaintext = types.MLSPlaintext{
        .group_id = framed_content.group_id,
        .epoch = framed_content.epoch,
        .sender = framed_content.sender,
        .authenticated_data = framed_content.authenticated_data,
        .content_type = framed_content.content_type,
        .content = framed_content.content,
        .signature = signature,
        .confirmation_tag = null, // For application messages
        .membership_tag = if (params.include_membership_tag) 
            try computeMembershipTag(allocator, mls_provider, group_state, framed_content)
        else 
            null,
    };
    
    // Encrypt to MLS ciphertext
    const mls_ciphertext = try encryptMLSPlaintext(allocator, mls_provider, group_state, mls_plaintext);
    defer allocator.free(mls_ciphertext.encrypted_sender_data);
    defer allocator.free(mls_ciphertext.ciphertext);
    
    // Serialize MLS ciphertext
    const serialized_mls = try serializeMLSCiphertext(allocator, mls_ciphertext);
    defer allocator.free(serialized_mls);
    
    // Apply NIP-44 encryption using exporter secret
    // Create a deterministic "recipient" key from exporter secret for NIP-44
    var nip44_recipient_key: [32]u8 = undefined;
    @memcpy(&nip44_recipient_key, &group_state.epoch_secrets.exporter_secret);
    
    const nip44_encrypted = try nip44.encrypt(
        allocator,
        serialized_mls,
        sender_private_key,
        nip44_recipient_key,
    );
    
    return mls.EncryptedMessage{
        .mls_ciphertext = serialized_mls,
        .nip44_ciphertext = nip44_encrypted,
        .epoch = group_state.epoch,
        .message_type = "application",
    };
}

/// Decrypt a received group message (double-layer decryption)
pub fn decryptGroupMessage(
    allocator: std.mem.Allocator,
    mls_provider: *provider.MlsProvider,
    group_state: *const mls.MlsGroupState,
    encrypted_data: []const u8,
    epoch: types.Epoch,
    recipient_private_key: [32]u8,
) !mls.DecryptedMessage {
    // First, decrypt NIP-44 layer using exporter secret from the specified epoch
    var exporter_secret: [32]u8 = undefined;
    
    // Handle epoch mismatch - try current and previous epochs
    if (epoch == group_state.epoch) {
        @memcpy(&exporter_secret, &group_state.epoch_secrets.exporter_secret);
    } else if (epoch == group_state.epoch - 1) {
        // In real implementation, we'd need to store previous epoch secrets
        // For now, we'll use the current one
        @memcpy(&exporter_secret, &group_state.epoch_secrets.exporter_secret);
    } else {
        return error.InvalidEpoch;
    }
    
    // Use exporter secret as the "sender" key for NIP-44 decryption
    const nip44_decrypted = try nip44.decrypt(
        allocator,
        encrypted_data,
        recipient_private_key,
        exporter_secret,
    );
    defer allocator.free(nip44_decrypted);
    
    // Parse MLS ciphertext
    const mls_ciphertext = try parseMLSCiphertext(allocator, nip44_decrypted);
    defer {
        allocator.free(mls_ciphertext.authenticated_data);
        allocator.free(mls_ciphertext.encrypted_sender_data);
        allocator.free(mls_ciphertext.ciphertext);
    }
    
    // Decrypt MLS ciphertext
    const mls_plaintext = try decryptMLSCiphertext(allocator, mls_provider, group_state, mls_ciphertext);
    defer freeMLSPlaintext(allocator, mls_plaintext);
    
    // Verify signature
    const framed_content = types.FramedContent{
        .group_id = mls_plaintext.group_id,
        .epoch = mls_plaintext.epoch,
        .sender = mls_plaintext.sender,
        .authenticated_data = mls_plaintext.authenticated_data,
        .content_type = mls_plaintext.content_type,
        .content = mls_plaintext.content,
    };
    
    const framed_tbs = try serializeFramedContentTBS(allocator, framed_content);
    defer allocator.free(framed_tbs);
    
    // Get sender's public key
    const sender_pubkey = try getSenderPublicKey(group_state, mls_plaintext.sender);
    const sender_mls_pubkey = try deriveMlsPublicKey(allocator, sender_pubkey);
    defer allocator.free(sender_mls_pubkey);
    
    const valid = try mls_provider.crypto.verifyFn(
        sender_mls_pubkey,
        framed_tbs,
        mls_plaintext.signature,
    );
    
    if (!valid) {
        return error.InvalidSignature;
    }
    
    // Extract content based on type
    var decrypted_content: []const u8 = undefined;
    var state_updated = false;
    const new_state: ?mls.MlsGroupState = null;
    
    switch (mls_plaintext.content) {
        .application => |app_data| {
            decrypted_content = try allocator.dupe(u8, app_data);
        },
        .proposal => {
            // Handle proposal
            decrypted_content = try allocator.dupe(u8, "proposal");
            // Proposals don't immediately update state
        },
        .commit => {
            // Handle commit - this updates the group state
            decrypted_content = try allocator.dupe(u8, "commit");
            state_updated = true;
            // TODO: Process commit and create new state
        },
        else => return error.UnexpectedContentType,
    }
    
    return mls.DecryptedMessage{
        .content = decrypted_content,
        .sender = mls_plaintext.sender,
        .state_updated = state_updated,
        .new_state = new_state,
    };
}

/// Create a group message event from encrypted message with ephemeral keys
pub fn createGroupMessageEvent(
    allocator: std.mem.Allocator,
    encrypted: mls.EncryptedMessage,
    group_id: types.GroupId,
) !nip_ee.GroupMessageEvent {
    // Generate a new ephemeral key pair for this message
    const ephemeral_key = try ephemeral.EphemeralKeyPair.generate();
    defer ephemeral_key.clear();
    
    return try nip_ee.GroupMessageEvent.create(
        allocator,
        ephemeral_key.private_key,
        group_id,
        encrypted.epoch,
        encrypted.message_type,
        encrypted.nip44_ciphertext,
    );
}

/// Create a group message event with a provided ephemeral key (for testing)
pub fn createGroupMessageEventWithKey(
    allocator: std.mem.Allocator,
    encrypted: mls.EncryptedMessage,
    group_id: types.GroupId,
    ephemeral_private_key: [32]u8,
) !nip_ee.GroupMessageEvent {
    return try nip_ee.GroupMessageEvent.create(
        allocator,
        ephemeral_private_key,
        group_id,
        encrypted.epoch,
        encrypted.message_type,
        encrypted.nip44_ciphertext,
    );
}

// Helper functions

fn findMemberIndex(group_state: *const mls.MlsGroupState, pubkey: [32]u8) !u32 {
    const pubkey_hex = try std.fmt.allocPrint(
        std.heap.page_allocator,
        "{s}",
        .{std.fmt.fmtSliceHexLower(&pubkey)},
    );
    defer std.heap.page_allocator.free(pubkey_hex);
    
    for (group_state.members, 0..) |member, i| {
        switch (member.credential) {
            .basic => |basic| {
                if (std.mem.eql(u8, basic.identity, pubkey_hex)) {
                    return @intCast(i);
                }
            },
            else => {},
        }
    }
    return error.MemberNotFound;
}

fn getSenderPublicKey(group_state: *const mls.MlsGroupState, sender: types.Sender) ![32]u8 {
    switch (sender) {
        .member => |index| {
            if (index >= group_state.members.len) {
                return error.InvalidSender;
            }
            const member = group_state.members[index];
            switch (member.credential) {
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
        },
        else => return error.UnsupportedSenderType,
    }
}

fn deriveMlsSigningKey(allocator: std.mem.Allocator, nostr_private_key: [32]u8) ![]u8 {
    // Derive MLS signing key from Nostr private key using HKDF
    const hkdf = std.crypto.kdf.hkdf.Hkdf(std.crypto.hash.sha2.Sha256);
    var prk: [32]u8 = undefined;
    
    // HKDF-extract: extract(output, salt, ikm)
    // Uses domain separation to ensure MLS keys are cryptographically isolated from Nostr keys
    hkdf.extract(&prk, constants.HKDF_SALT.NOSTR_TO_MLS_SIGNING, &nostr_private_key);
    
    // HKDF-expand: expand(output, context, prk)
    // Further domain separation for the specific use as a signing key
    const key = try allocator.alloc(u8, constants.KEY_SIZES.HKDF_OUTPUT);
    hkdf.expand(key, constants.HKDF_INFO.MLS_SIGNING_KEY, &prk);
    return key;
}

fn deriveMlsPublicKey(allocator: std.mem.Allocator, nostr_pubkey: [32]u8) ![]u8 {
    // Note: This function derives a deterministic identifier from a Nostr public key.
    // It does NOT produce a valid Ed25519 public key (that's mathematically impossible).
    // This is used only as a deterministic identifier in contexts where the actual
    // Ed25519 public key would be derived from the corresponding MLS private key.
    
    // Use HKDF to derive a deterministic identifier
    const hkdf = std.crypto.kdf.hkdf.Hkdf(std.crypto.hash.sha2.Sha256);
    var prk: [32]u8 = undefined;
    
    // HKDF-extract: extract(output, salt, ikm)
    // Domain separation for deriving identifiers (not keys) from Nostr public keys
    hkdf.extract(&prk, constants.HKDF_SALT.NOSTR_TO_MLS_ID, &nostr_pubkey);
    
    // HKDF-expand: expand(output, context, prk)
    // Creates a deterministic 32-byte identifier
    const identifier = try allocator.alloc(u8, constants.KEY_SIZES.HKDF_OUTPUT);
    hkdf.expand(identifier, constants.HKDF_INFO.MLS_IDENTIFIER, &prk);
    
    return identifier;
}

fn serializeFramedContentTBS(allocator: std.mem.Allocator, content: types.FramedContent) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    
    // Wire format version
    try buf.append(@intFromEnum(types.WireFormat.mls_plaintext));
    
    // Group ID
    try buf.appendSlice(&content.group_id);
    
    // Epoch
    const epoch_bytes = std.mem.toBytes(content.epoch);
    try buf.appendSlice(&epoch_bytes);
    
    // Sender
    try buf.append(@intFromEnum(content.sender));
    switch (content.sender) {
        .member => |idx| {
            const idx_bytes = std.mem.toBytes(idx);
            try buf.appendSlice(&idx_bytes);
        },
        else => {},
    }
    
    // Authenticated data length and data
    const aad_len = std.mem.toBytes(@as(u32, @intCast(content.authenticated_data.len)));
    try buf.appendSlice(&aad_len);
    try buf.appendSlice(content.authenticated_data);
    
    // Content type
    try buf.append(@intFromEnum(content.content_type));
    
    // Content
    switch (content.content) {
        .application => |data| {
            const len = std.mem.toBytes(@as(u32, @intCast(data.len)));
            try buf.appendSlice(&len);
            try buf.appendSlice(data);
        },
        else => return error.UnsupportedContentType,
    }
    
    return try buf.toOwnedSlice();
}

fn computeMembershipTag(
    allocator: std.mem.Allocator,
    mls_provider: *provider.MlsProvider,
    group_state: *const mls.MlsGroupState,
    content: types.FramedContent,
) ![]u8 {
    _ = content;
    
    // Compute membership tag using membership key
    const tag_input = "membership tag";
    const Sha256 = std.crypto.hash.sha2.Sha256;
    const mac = std.crypto.auth.hmac.Hmac(Sha256);
    var tag: [mac.mac_length]u8 = undefined;
    mac.create(&tag, tag_input, &group_state.epoch_secrets.membership_key);
    
    _ = mls_provider;
    
    return try allocator.dupe(u8, &tag);
}

fn encryptMLSPlaintext(
    allocator: std.mem.Allocator,
    mls_provider: *provider.MlsProvider,
    group_state: *const mls.MlsGroupState,
    plaintext: types.MLSPlaintext,
) !types.MLSCiphertext {
    _ = mls_provider;
    
    // Serialize plaintext content
    const content_data = try serializeMLSPlaintextContent(allocator, plaintext);
    defer allocator.free(content_data);
    
    // Create sender data
    const sender_data = try createSenderData(allocator, plaintext.sender);
    defer allocator.free(sender_data);
    
    // Encrypt sender data with sender data secret
    const encrypted_sender = try encryptWithSecret(
        allocator,
        sender_data,
        group_state.epoch_secrets.sender_data_secret,
    );
    
    // Encrypt content with encryption secret
    const encrypted_content = try encryptWithSecret(
        allocator,
        content_data,
        group_state.epoch_secrets.encryption_secret,
    );
    
    return types.MLSCiphertext{
        .group_id = plaintext.group_id,
        .epoch = plaintext.epoch,
        .content_type = plaintext.content_type,
        .authenticated_data = try allocator.dupe(u8, plaintext.authenticated_data),
        .encrypted_sender_data = encrypted_sender,
        .ciphertext = encrypted_content,
    };
}

fn decryptMLSCiphertext(
    allocator: std.mem.Allocator,
    mls_provider: *provider.MlsProvider,
    group_state: *const mls.MlsGroupState,
    ciphertext: types.MLSCiphertext,
) !types.MLSPlaintext {
    _ = mls_provider;
    
    // Decrypt sender data
    const sender_data = try decryptWithSecret(
        allocator,
        ciphertext.encrypted_sender_data,
        group_state.epoch_secrets.sender_data_secret,
    );
    defer allocator.free(sender_data);
    
    // Parse sender
    const sender = try parseSenderData(sender_data);
    
    // Decrypt content
    const content_data = try decryptWithSecret(
        allocator,
        ciphertext.ciphertext,
        group_state.epoch_secrets.encryption_secret,
    );
    defer allocator.free(content_data);
    
    // Parse content based on content type
    const content = switch (ciphertext.content_type) {
        .application => types.Content{ .application = try allocator.dupe(u8, content_data) },
        else => return error.UnsupportedContentType,
    };
    
    return types.MLSPlaintext{
        .group_id = ciphertext.group_id,
        .epoch = ciphertext.epoch,
        .sender = sender,
        .authenticated_data = try allocator.dupe(u8, ciphertext.authenticated_data),
        .content_type = ciphertext.content_type,
        .content = content,
        .signature = try allocator.alloc(u8, 64), // Placeholder
        .confirmation_tag = null,
        .membership_tag = null,
    };
}

fn serializeMLSCiphertext(allocator: std.mem.Allocator, ciphertext: types.MLSCiphertext) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    
    // Wire format
    try buf.append(@intFromEnum(types.WireFormat.mls_ciphertext));
    
    // Group ID
    try buf.appendSlice(&ciphertext.group_id);
    
    // Epoch
    const epoch_bytes = std.mem.toBytes(ciphertext.epoch);
    try buf.appendSlice(&epoch_bytes);
    
    // Content type
    try buf.append(@intFromEnum(ciphertext.content_type));
    
    // Authenticated data
    const aad_len = std.mem.toBytes(@as(u32, @intCast(ciphertext.authenticated_data.len)));
    try buf.appendSlice(&aad_len);
    try buf.appendSlice(ciphertext.authenticated_data);
    
    // Encrypted sender data
    const sender_len = std.mem.toBytes(@as(u32, @intCast(ciphertext.encrypted_sender_data.len)));
    try buf.appendSlice(&sender_len);
    try buf.appendSlice(ciphertext.encrypted_sender_data);
    
    // Ciphertext
    const ct_len = std.mem.toBytes(@as(u32, @intCast(ciphertext.ciphertext.len)));
    try buf.appendSlice(&ct_len);
    try buf.appendSlice(ciphertext.ciphertext);
    
    return try buf.toOwnedSlice();
}

fn parseMLSCiphertext(allocator: std.mem.Allocator, data: []const u8) !types.MLSCiphertext {
    // Use TLS 1.3 wire format as per RFC 9420
    var stream = std.io.fixedBufferStream(data);
    var reader = mls_zig.tls_codec.TlsReader(@TypeOf(stream.reader())).init(stream.reader());
    
    // MLSCiphertext format:
    // struct {
    //     opaque group_id<V>;
    //     uint64 epoch;
    //     ContentType content_type;
    //     opaque authenticated_data<V>;
    //     opaque encrypted_sender_data<V>;
    //     opaque ciphertext<V>;
    // } MLSCiphertext;
    
    // Group ID (variable length with u16 length prefix)
    const group_id_len = try reader.readU16();
    const group_id_data = try allocator.alloc(u8, group_id_len);
    try reader.reader.readNoEof(group_id_data);
    
    // Epoch (u64)
    const epoch = try reader.readU64();
    
    // Content type (u8)
    const content_type_raw = try reader.readU8();
    const content_type: types.ContentType = @enumFromInt(content_type_raw);
    
    // Authenticated data (variable length with u16 length prefix)
    const auth_data_len = try reader.readU16();
    const authenticated_data = try allocator.alloc(u8, auth_data_len);
    try reader.reader.readNoEof(authenticated_data);
    
    // Encrypted sender data (variable length with u16 length prefix)
    const sender_data_len = try reader.readU16();
    const encrypted_sender_data = try allocator.alloc(u8, sender_data_len);
    try reader.reader.readNoEof(encrypted_sender_data);
    
    // Ciphertext (variable length with u16 length prefix)
    const ciphertext_len = try reader.readU16();
    const ciphertext = try allocator.alloc(u8, ciphertext_len);
    try reader.reader.readNoEof(ciphertext);
    
    return types.MLSCiphertext{
        .group_id = .{ .data = group_id_data },
        .epoch = epoch,
        .content_type = content_type,
        .authenticated_data = authenticated_data,
        .encrypted_sender_data = encrypted_sender_data,
        .ciphertext = ciphertext,
    };
}

fn serializeMLSPlaintextContent(allocator: std.mem.Allocator, plaintext: types.MLSPlaintext) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    
    // Content
    switch (plaintext.content) {
        .application => |app_data| {
            try buf.appendSlice(app_data);
        },
        else => return error.UnsupportedContentType,
    }
    
    // Signature
    try buf.appendSlice(plaintext.signature);
    
    // Optional tags
    if (plaintext.confirmation_tag) |tag| {
        try buf.appendSlice(tag);
    }
    if (plaintext.membership_tag) |tag| {
        try buf.appendSlice(tag);
    }
    
    return try buf.toOwnedSlice();
}

fn createSenderData(allocator: std.mem.Allocator, sender: types.Sender) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    
    try buf.append(@intFromEnum(sender));
    switch (sender) {
        .member => |idx| {
            const idx_bytes = std.mem.toBytes(idx);
            try buf.appendSlice(&idx_bytes);
        },
        else => {},
    }
    
    return try buf.toOwnedSlice();
}

fn parseSenderData(data: []const u8) !types.Sender {
    if (data.len < 1) return error.InvalidSenderData;
    
    const sender_type = @as(types.SenderType, @enumFromInt(data[0]));
    return switch (sender_type) {
        .member => blk: {
            if (data.len < 5) return error.InvalidSenderData;
            const idx = std.mem.readInt(u32, data[1..5], .big);
            break :blk types.Sender{ .member = idx };
        },
        else => error.UnsupportedSenderType,
    };
}

fn encryptWithSecret(allocator: std.mem.Allocator, data: []const u8, secret: [32]u8) ![]u8 {
    // Simple XOR encryption for demonstration
    // Real implementation would use AES-GCM or similar
    const encrypted = try allocator.alloc(u8, data.len);
    for (data, 0..) |byte, i| {
        encrypted[i] = byte ^ secret[i % secret.len];
    }
    return encrypted;
}

fn decryptWithSecret(allocator: std.mem.Allocator, data: []const u8, secret: [32]u8) ![]u8 {
    // XOR is symmetric
    return try encryptWithSecret(allocator, data, secret);
}

fn freeMLSPlaintext(allocator: std.mem.Allocator, plaintext: types.MLSPlaintext) void {
    switch (plaintext.content) {
        .application => |data| allocator.free(data),
        else => {},
    }
    allocator.free(plaintext.authenticated_data);
    allocator.free(plaintext.signature);
    if (plaintext.confirmation_tag) |tag| allocator.free(tag);
    if (plaintext.membership_tag) |tag| allocator.free(tag);
}

test "find member index" {
    
    const pubkey1: [32]u8 = [_]u8{1} ** 32;
    const pubkey2: [32]u8 = [_]u8{2} ** 32;
    
    const members = [_]types.MemberInfo{
        .{
            .index = 0,
            .credential = .{
                .basic = .{
                    .identity = "0101010101010101010101010101010101010101010101010101010101010101",
                },
            },
            .role = .member,
            .joined_at_epoch = 0,
        },
        .{
            .index = 1,
            .credential = .{
                .basic = .{
                    .identity = "0202020202020202020202020202020202020202020202020202020202020202",
                },
            },
            .role = .admin,
            .joined_at_epoch = 0,
        },
    };
    
    const state = mls.MlsGroupState{
        .group_id = types.GroupId.init([_]u8{0} ** 32),
        .epoch = 0,
        .cipher_suite = .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        .group_context = undefined,
        .tree_hash = [_]u8{0} ** 32,
        .confirmed_transcript_hash = [_]u8{0} ** 32,
        .members = &members,
        .ratchet_tree = &.{},
        .interim_transcript_hash = [_]u8{0} ** 32,
        .epoch_secrets = undefined,
    };
    
    const idx1 = try findMemberIndex(&state, pubkey1);
    try std.testing.expectEqual(@as(u32, 0), idx1);
    
    const idx2 = try findMemberIndex(&state, pubkey2);
    try std.testing.expectEqual(@as(u32, 1), idx2);
}

test "sender data serialization" {
    const allocator = std.testing.allocator;
    
    const sender = types.Sender{ .member = 42 };
    const data = try createSenderData(allocator, sender);
    defer allocator.free(data);
    
    const parsed = try parseSenderData(data);
    try std.testing.expectEqual(types.Sender{ .member = 42 }, parsed);
}

test "symmetric encryption" {
    const allocator = std.testing.allocator;
    
    const secret: [32]u8 = [_]u8{0xAB} ** 32;
    const plaintext = "Hello, MLS!";
    
    const encrypted = try encryptWithSecret(allocator, plaintext, secret);
    defer allocator.free(encrypted);
    
    const decrypted = try decryptWithSecret(allocator, encrypted, secret);
    defer allocator.free(decrypted);
    
    try std.testing.expectEqualStrings(plaintext, decrypted);
}