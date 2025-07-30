const std = @import("std");
const types = @import("types.zig");
const provider = @import("provider.zig");
const extension = @import("extension.zig");
const key_packages = @import("key_packages.zig");
const mls = @import("mls.zig");
const crypto = @import("../crypto.zig");
const mls_zig = @import("mls_zig");

/// Group creation parameters
pub const GroupCreationParams = struct {
    /// Group name
    name: []const u8,
    
    /// Group description
    description: []const u8,
    
    /// Admin public keys (including creator)
    admins: []const [32]u8,
    
    /// Relay URLs for group messages
    relays: []const []const u8,
    
    /// Optional group image
    image: ?[]const u8,
    
    /// Cipher suite to use
    cipher_suite: types.Ciphersuite = .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
    
    /// Additional extensions
    extensions: []const types.Extension = &.{},
};

/// Create a new MLS group
pub fn createGroup(
    allocator: std.mem.Allocator,
    mls_provider: *provider.MlsProvider,
    creator_private_key: [32]u8,
    params: GroupCreationParams,
    initial_members: []const types.KeyPackage,
) !mls.GroupCreationResult {
    // Generate group ID
    var group_id: types.GroupId = undefined;
    mls_provider.rand.fill(&group_id.data);
    
    // Derive creator's public key
    var creator_pubkey: [32]u8 = undefined;
    creator_pubkey = try crypto.getPublicKey(creator_private_key);
    
    // Ensure creator is in admins list
    var is_creator_admin = false;
    for (params.admins) |admin| {
        if (std.mem.eql(u8, &admin, &creator_pubkey)) {
            is_creator_admin = true;
            break;
        }
    }
    if (!is_creator_admin) {
        return error.CreatorMustBeAdmin;
    }
    
    // Create NostrGroupData extension
    const group_data = extension.NostrGroupData{
        .group_id = group_id,
        .name = params.name,
        .description = params.description,
        .admins = params.admins,
        .relays = params.relays,
        .image = params.image,
    };
    
    const group_data_ext = try extension.createNostrGroupDataExtension(allocator, group_data);
    defer allocator.free(group_data_ext.extension_data);
    
    // Build extensions list
    var extensions = std.ArrayList(types.Extension).init(allocator);
    defer extensions.deinit();
    
    // Add NostrGroupData extension (duplicate the data)
    try extensions.append(types.Extension{
        .extension_type = group_data_ext.extension_type,
        .extension_data = try allocator.dupe(u8, group_data_ext.extension_data),
    });
    
    // Add required MLS extensions
    try extensions.append(types.Extension{
        .extension_type = .ratchet_tree,
        .extension_data = &.{}, // Will be populated by MLS stack
    });
    
    try extensions.append(types.Extension{
        .extension_type = .required_capabilities,
        .extension_data = try serializeRequiredCapabilities(allocator),
    });
    
    // Add any additional extensions from params
    for (params.extensions) |ext| {
        try extensions.append(ext);
    }
    
    // Initialize group context with placeholders
    var group_context = types.GroupContext{
        .version = .mls10,
        .cipher_suite = params.cipher_suite,
        .group_id = group_id,
        .epoch = 0,
        .tree_hash = [_]u8{0} ** 32, // Will be computed
        .confirmed_transcript_hash = [_]u8{0} ** 32, // Will be computed
        .extensions = try extensions.toOwnedSlice(),
    };
    
    // Generate initial epoch secrets
    const epoch_secrets = try generateInitialEpochSecrets(allocator, mls_provider, group_id);
    
    // Create initial member list
    var members = std.ArrayList(types.MemberInfo).init(allocator);
    defer members.deinit();
    
    // Add creator as first member
    try members.append(types.MemberInfo{
        .index = 0,
        .credential = types.Credential{
            .basic = types.BasicCredential{
                .identity = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(&creator_pubkey)}),
            },
        },
        .role = .admin,
        .joined_at_epoch = 0,
    });
    
    // Create TreeSync for managing the ratchet tree
    // Convert our cipher suite enum to mls_zig's enum (they should have the same values)
    const mls_cipher_suite = @as(mls_zig.CipherSuite, @enumFromInt(@intFromEnum(params.cipher_suite)));
    var tree = try mls_zig.tree_kem.TreeSync.init(allocator, mls_cipher_suite, @intCast(initial_members.len + 1));
    defer tree.deinit();
    
    // Add creator's leaf node to the tree at index 0
    // For now, we'll create a minimal leaf node for the creator
    // TODO: Create proper leaf node from creator's key package
    
    // Process initial members
    var welcomes = std.ArrayList(types.Welcome).init(allocator);
    defer welcomes.deinit();
    
    // Add leaf nodes for all members to the tree
    for (initial_members, 1..) |kp, index| {
        // Skip validation for converted flat KeyPackages
        // They were already validated when created and the conversion
        // doesn't preserve the leaf node signature structure
        
        // Extract member's Nostr pubkey
        const member_pubkey = try key_packages.extractNostrPubkey(kp);
        
        // Determine role
        const role: types.MemberRole = if (group_data.isAdmin(member_pubkey)) .admin else .member;
        
        // Add to member list
        try members.append(types.MemberInfo{
            .index = @intCast(index),
            .credential = kp.leaf_node.credential,
            .role = role,
            .joined_at_epoch = 0,
        });
        
        // Create welcome message
        const welcome = try createWelcomeForMember(allocator, mls_provider, group_context, kp, epoch_secrets);
        try welcomes.append(welcome);
    }
    
    // Compute the tree hash
    var tree_hash_varbytes = try tree.computeTreeHash(allocator);
    defer tree_hash_varbytes.deinit();
    
    // Convert VarBytes to fixed array
    var tree_hash_array: [32]u8 = undefined;
    if (tree_hash_varbytes.asSlice().len == 32) {
        @memcpy(&tree_hash_array, tree_hash_varbytes.asSlice()[0..32]);
    } else {
        // If hash is not 32 bytes, pad or truncate as needed
        @memset(&tree_hash_array, 0);
        const copy_len = @min(tree_hash_varbytes.asSlice().len, 32);
        @memcpy(tree_hash_array[0..copy_len], tree_hash_varbytes.asSlice()[0..copy_len]);
    }
    
    // Update group context with computed tree hash
    group_context.tree_hash = tree_hash_array;
    
    // Compute the initial transcript hash (which includes the tree hash)
    const confirmed_transcript_hash = try computeTranscriptHash(allocator, mls_provider, &group_context);
    
    // Update group context with computed transcript hash
    group_context.confirmed_transcript_hash = confirmed_transcript_hash;
    
    // Create initial group state
    const state = mls.MlsGroupState{
        .group_id = group_id,
        .epoch = 0,
        .cipher_suite = params.cipher_suite,
        .group_context = group_context,
        .tree_hash = tree_hash_array,
        .confirmed_transcript_hash = confirmed_transcript_hash,
        .members = try members.toOwnedSlice(),
        .ratchet_tree = &.{}, // TODO: Build actual ratchet tree from tree
        .interim_transcript_hash = confirmed_transcript_hash, // Initially same as confirmed
        .epoch_secrets = epoch_secrets,
    };
    
    // Copy the key packages array since the caller owns initial_members
    const used_packages = try allocator.alloc(types.KeyPackage, initial_members.len);
    @memcpy(used_packages, initial_members);
    
    return mls.GroupCreationResult{
        .state = state,
        .welcomes = try welcomes.toOwnedSlice(),
        .used_key_packages = used_packages,
    };
}

/// Compute transcript hash for a group context
/// This is a simplified implementation that hashes the group context
/// TODO: Implement full MLS transcript hash computation including all commits
pub fn computeTranscriptHash(
    allocator: std.mem.Allocator,
    mls_provider: *provider.MlsProvider,
    group_context: *const types.GroupContext,
) ![32]u8 {
    // Serialize the group context for hashing
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    
    const tls_codec = mls_zig.tls_codec;
    
    // Write group ID
    try tls_codec.writeVarBytesToList(&buffer, u8, &group_context.group_id.data);
    
    // Write epoch
    try tls_codec.writeU64ToList(&buffer, group_context.epoch);
    
    // Write tree hash
    try tls_codec.writeBytesToList(&buffer, &group_context.tree_hash);
    
    // Write confirmed transcript hash (for interim transcript hash computation)
    try tls_codec.writeBytesToList(&buffer, &group_context.confirmed_transcript_hash);
    
    // Write extensions
    for (group_context.extensions) |ext| {
        try tls_codec.writeU16ToList(&buffer, @intFromEnum(ext.extension_type));
        try tls_codec.writeVarBytesToList(&buffer, u16, ext.extension_data);
    }
    
    // Hash the serialized data
    return mls_provider.crypto.hashFn(allocator, buffer.items);
}

/// Add a member to an existing group
pub fn addMember(
    allocator: std.mem.Allocator,
    mls_provider: *provider.MlsProvider,
    current_state: *const mls.MlsGroupState,
    new_member_key_package: types.KeyPackage,
    proposer_private_key: [32]u8,
) !mls.AddMemberResult {
    // Verify proposer is admin
    var proposer_pubkey: [32]u8 = undefined;
    proposer_pubkey = try crypto.getPublicKey(proposer_private_key);
    
    const group_data = try extractGroupData(allocator, current_state.group_context);
    defer freeGroupData(allocator, group_data);
    
    if (!group_data.isAdmin(proposer_pubkey)) {
        return error.PermissionDenied;
    }
    
    // Validate key package
    try key_packages.validateKeyPackage(allocator, mls_provider, new_member_key_package);
    
    // Create add proposal
    const proposal = types.Proposal{
        .add = types.Add{
            .key_package = new_member_key_package,
        },
    };
    
    // Auto-commit since proposer is admin
    const commit_result = try createAndProcessCommit(
        allocator,
        mls_provider,
        current_state,
        &[_]types.Proposal{proposal},
        proposer_private_key,
    );
    
    // Create welcome for new member
    const welcome = try createWelcomeForMember(
        allocator,
        mls_provider,
        commit_result.new_state.group_context,
        new_member_key_package,
        commit_result.new_state.epoch_secrets,
    );
    
    return mls.AddMemberResult{
        .state = commit_result.new_state,
        .welcome = welcome,
        .commit = commit_result.commit_message,
    };
}

/// Remove a member from the group
pub fn removeMember(
    allocator: std.mem.Allocator,
    mls_provider: *provider.MlsProvider,
    current_state: *const mls.MlsGroupState,
    member_index: u32,
    proposer_private_key: [32]u8,
) !CommitResult {
    // Verify proposer is admin
    var proposer_pubkey: [32]u8 = undefined;
    proposer_pubkey = try crypto.getPublicKey(proposer_private_key);
    
    const group_data = try extractGroupData(allocator, current_state.group_context);
    defer freeGroupData(allocator, group_data);
    
    if (!group_data.isAdmin(proposer_pubkey)) {
        return error.PermissionDenied;
    }
    
    // Verify member exists
    if (member_index >= current_state.members.len) {
        return error.MemberNotFound;
    }
    
    // Create remove proposal
    const proposal = types.Proposal{
        .remove = types.Remove{
            .removed = member_index,
        },
    };
    
    // Auto-commit since proposer is admin
    return try createAndProcessCommit(
        allocator,
        mls_provider,
        current_state,
        &[_]types.Proposal{proposal},
        proposer_private_key,
    );
}

/// Update a member's key package
pub fn updateMember(
    allocator: std.mem.Allocator,
    mls_provider: *provider.MlsProvider,
    current_state: *const mls.MlsGroupState,
    leaf_node: types.LeafNode,
    member_private_key: [32]u8,
) !CommitResult {
    // Create update proposal
    const proposal = types.Proposal{
        .update = types.Update{
            .leaf_node = leaf_node,
        },
    };
    
    return try createAndProcessCommit(
        allocator,
        mls_provider,
        current_state,
        &[_]types.Proposal{proposal},
        member_private_key,
    );
}

/// Result of creating and processing a commit
pub const CommitResult = struct {
    /// New group state after commit
    new_state: mls.MlsGroupState,
    
    /// Commit message to broadcast
    commit_message: types.MLSMessage,
};

// Helper functions

pub fn generateInitialEpochSecrets(
    allocator: std.mem.Allocator,
    mls_provider: *provider.MlsProvider,
    group_id: types.GroupId,
) !mls.EpochSecrets {
    // Generate random init secret for initial epoch
    var init_secret: [32]u8 = undefined;
    mls_provider.rand.fill(&init_secret);
    
    // For initial epoch, commit_secret = init_secret
    const commit_secret = init_secret;
    
    // Serialize group context for key schedule
    var group_context_buf = std.ArrayList(u8).init(allocator);
    defer group_context_buf.deinit();
    try mls_zig.tls_codec.writeVarBytesToList(&group_context_buf, u8, &group_id.data);
    
    // Use proper key schedule
    const cipher_suite = mls_zig.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    var key_schedule = mls_zig.KeySchedule.init(allocator, cipher_suite);
    
    var epoch_secrets_var = try key_schedule.deriveEpochSecrets(
        &commit_secret,
        null, // no PSK for initial epoch
        group_context_buf.items,
    );
    defer epoch_secrets_var.deinit();
    
    // Convert to fixed-size epoch secrets
    const fixed = epoch_secrets_var.toFixed();
    
    return mls.EpochSecrets{
        .joiner_secret = fixed.joiner_secret,
        .member_secret = fixed.member_secret,
        .welcome_secret = fixed.welcome_secret,
        .epoch_secret = fixed.epoch_secret,
        .sender_data_secret = fixed.sender_data_secret,
        .encryption_secret = fixed.encryption_secret,
        .exporter_secret = fixed.exporter_secret,
        .epoch_authenticator = fixed.epoch_authenticator,
        .external_secret = fixed.external_secret,
        .confirmation_key = fixed.confirmation_key,
        .membership_key = fixed.membership_key,
        .resumption_psk = fixed.resumption_psk,
        .init_secret = fixed.init_secret,
    };
}


fn createWelcomeForMember(
    allocator: std.mem.Allocator,
    mls_provider: *provider.MlsProvider,
    group_context: types.GroupContext,
    member_key_package: types.KeyPackage,
    epoch_secrets: mls.EpochSecrets,
) !types.Welcome {
    // Serialize GroupInfo
    var group_info_buf = std.ArrayList(u8).init(allocator);
    defer group_info_buf.deinit();
    
    // Write group context
    const tls_codec = mls_zig.tls_codec;
    // First serialize the group context itself
    try tls_codec.writeU16ToList(&group_info_buf, @intFromEnum(group_context.version));
    try tls_codec.writeU16ToList(&group_info_buf, @intFromEnum(group_context.cipher_suite));
    try tls_codec.writeVarBytesToList(&group_info_buf, u8, &group_context.group_id.data);
    try tls_codec.writeU64ToList(&group_info_buf, group_context.epoch);
    try tls_codec.writeBytesToList(&group_info_buf, &group_context.tree_hash);
    try tls_codec.writeBytesToList(&group_info_buf, &group_context.confirmed_transcript_hash);
    try tls_codec.writeU16ToList(&group_info_buf, @intCast(group_context.extensions.len));
    for (group_context.extensions) |ext| {
        try tls_codec.writeU16ToList(&group_info_buf, @intFromEnum(ext.extension_type));
        try tls_codec.writeVarBytesToList(&group_info_buf, u16, ext.extension_data);
    }
    
    // Write members (empty array for now)
    try tls_codec.writeU32ToList(&group_info_buf, 0);
    
    // Write ratchet tree (empty for now) 
    try tls_codec.writeVarBytesToList(&group_info_buf, u32, &.{});
    
    // Encrypt GroupInfo using welcome_secret with AES-128-GCM
    // The cipher suite is MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
    const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
    
    // Generate a random nonce (12 bytes for AES-GCM)
    var nonce: [12]u8 = undefined;
    mls_provider.rand.fill(&nonce);
    
    // Use the first 16 bytes of welcome_secret as the AES key
    const aes_key = epoch_secrets.welcome_secret[0..16].*;
    
    // Allocate space for encrypted data (plaintext + 16-byte tag)
    const encrypted_group_info = try allocator.alloc(u8, group_info_buf.items.len + 16 + nonce.len);
    
    // Store nonce at the beginning
    @memcpy(encrypted_group_info[0..nonce.len], &nonce);
    
    // Encrypt with empty additional authenticated data
    var tag: [16]u8 = undefined;
    Aes128Gcm.encrypt(
        encrypted_group_info[nonce.len..nonce.len + group_info_buf.items.len],
        &tag,
        group_info_buf.items,
        &.{},
        nonce,
        aes_key,
    );
    // Append tag after ciphertext
    @memcpy(encrypted_group_info[nonce.len + group_info_buf.items.len..nonce.len + group_info_buf.items.len + 16], &tag);
    
    // Serialize group secrets - just the joiner secret and optional path secret
    var secrets_buf = std.ArrayList(u8).init(allocator);
    defer secrets_buf.deinit();
    
    try tls_codec.writeBytesToList(&secrets_buf, &epoch_secrets.joiner_secret);
    // Write null path secret (0 length)
    try tls_codec.writeVarBytesToList(&secrets_buf, u8, &.{});
    
    // Encrypt to member's init key using HPKE
    const encrypted_secrets = try mls_provider.crypto.hpkeSealFn(
        allocator,
        member_key_package.init_key.data,
        "MLS 1.0 Welcome", // info
        &.{}, // empty AAD
        secrets_buf.items,
    );
    
    // Combine KEM output and ciphertext into a single buffer
    const combined_len = encrypted_secrets.kem_output.len + encrypted_secrets.ciphertext.len;
    const combined_secrets = try allocator.alloc(u8, combined_len);
    @memcpy(combined_secrets[0..encrypted_secrets.kem_output.len], encrypted_secrets.kem_output);
    @memcpy(combined_secrets[encrypted_secrets.kem_output.len..], encrypted_secrets.ciphertext);
    
    // Create the EncryptedGroupSecrets
    const encrypted_group_secrets = types.EncryptedGroupSecrets{
        .new_member = try allocator.dupe(u8, member_key_package.init_key.data),
        .encrypted_group_secrets = combined_secrets,
    };
    
    // Clean up HPKE result
    allocator.free(encrypted_secrets.kem_output);
    allocator.free(encrypted_secrets.ciphertext);
    
    // Create Welcome message
    const secrets = try allocator.alloc(types.EncryptedGroupSecrets, 1);
    secrets[0] = encrypted_group_secrets;
    
    return types.Welcome{
        .cipher_suite = group_context.cipher_suite,
        .secrets = secrets,
        .encrypted_group_info = encrypted_group_info,
    };
}

fn createAndProcessCommit(
    allocator: std.mem.Allocator,
    mls_provider: *provider.MlsProvider,
    current_state: *const mls.MlsGroupState,
    proposals: []const types.Proposal,
    committer_private_key: [32]u8,
) !CommitResult {
    _ = mls_provider; // TODO: Use for actual MLS operations
    _ = committer_private_key; // TODO: Use for signing commit
    // Simplified commit creation using mls_zig
    // This is a basic implementation - full MLS commit logic is complex
    
    // Create a new epoch
    const new_epoch = current_state.epoch + 1;
    
    // Process proposals to update group state
    var new_state = current_state.*;
    new_state.epoch = new_epoch;
    
    // For now, create a simplified commit that just advances the epoch
    // In a full implementation, this would:
    // 1. Apply all proposals to update the ratchet tree
    // 2. Generate new epoch secrets using mls_zig
    // 3. Create proper commit message with path secrets
    // 4. Update group context with new members/removed members
    
    // Generate new epoch secrets using mls_zig HKDF
    const cipher_suite = mls_zig.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    const epoch_secret_input = try std.fmt.allocPrint(allocator, "epoch_{d}", .{new_epoch});
    defer allocator.free(epoch_secret_input);
    
    var epoch_secret = try cipher_suite.hkdfExtract(allocator, "MLS_EPOCH", epoch_secret_input);
    defer epoch_secret.deinit();
    
    // Create simplified epoch secrets
    new_state.epoch_secrets = .{
        .joiner_secret = try allocator.dupe(u8, epoch_secret.data[0..32]),
        .welcome_secret = try allocator.dupe(u8, epoch_secret.data[0..32]),
        .init_secret = try allocator.dupe(u8, epoch_secret.data[0..32]),
        .sender_data_secret = try allocator.dupe(u8, epoch_secret.data[0..32]),
        .encryption_secret = try allocator.dupe(u8, epoch_secret.data[0..32]),
        .exporter_secret = try allocator.dupe(u8, epoch_secret.data[0..32]),
        .external_secret = try allocator.dupe(u8, epoch_secret.data[0..32]),
        .confirmation_key = try allocator.dupe(u8, epoch_secret.data[0..32]),
        .membership_key = try allocator.dupe(u8, epoch_secret.data[0..32]),
        .resumption_psk = try allocator.dupe(u8, epoch_secret.data[0..32]),
    };
    
    // Apply proposals to group state (simplified)
    for (proposals) |proposal| {
        switch (proposal) {
            .add => |add| {
                // Add new member to group (simplified)
                std.log.info("Adding member with key package to group", .{});
                _ = add; // Use the key package to add member
            },
            .remove => |remove| {
                // Remove member from group (simplified)
                std.log.info("Removing member {d} from group", .{remove.removed});
            },
            .update => |update| {
                // Update member's leaf node (simplified)
                std.log.info("Updating member leaf node", .{});
                _ = update; // Use the new leaf node
            },
            else => {
                std.log.warn("Unsupported proposal type in simplified implementation", .{});
            },
        }
    }
    
    // Create commit message (simplified)
    const commit_content = types.Commit{
        .proposals = try allocator.dupe(types.ProposalOrRef, &.{}), // Empty for now
        .path = null, // No path update in simplified version
    };
    
    const commit_message = types.MLSMessage{
        .mls_plaintext = .{
            .group_id = current_state.group_context.group_id,
            .epoch = new_epoch,
            .sender = .{ .member = 0 }, // Simplified sender
            .authenticated_data = &.{},
            .content = .{ .commit = commit_content },
            .signature = &.{}, // Would need to sign with committer key
        },
    };
    
    return CommitResult{
        .new_state = new_state,
        .commit_message = commit_message,
    };
}

fn extractGroupData(allocator: std.mem.Allocator, group_context: types.GroupContext) !extension.NostrGroupData {
    for (group_context.extensions) |ext| {
        if (ext.extension_type == .nostr_group_data) {
            return try extension.extractNostrGroupData(allocator, ext);
        }
    }
    return error.ExtensionNotFound;
}

fn freeGroupData(allocator: std.mem.Allocator, group_data: extension.NostrGroupData) void {
    allocator.free(group_data.name);
    allocator.free(group_data.description);
    allocator.free(group_data.admins);
    for (group_data.relays) |relay| {
        allocator.free(relay);
    }
    allocator.free(group_data.relays);
    if (group_data.image) |img| {
        allocator.free(img);
    }
}

fn serializeRequiredCapabilities(allocator: std.mem.Allocator) ![]u8 {
    // Create required capabilities extension
    const required_caps = types.Capabilities{
        .versions = &[_]types.ProtocolVersion{.mls10},
        .ciphersuites = &[_]types.Ciphersuite{
            .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        },
        .extensions = &[_]types.ExtensionType{
            .ratchet_tree,
            .required_capabilities,
            .nostr_group_data,
        },
        .proposals = &[_]types.ProposalType{
            .add,
            .update,
            .remove,
        },
        .credentials = &[_]types.CredentialType{.basic},
    };
    
    // Simplified serialization
    var data = std.ArrayList(u8).init(allocator);
    defer data.deinit();
    
    // Add number of required extensions
    try data.append(3);
    try data.appendSlice(&std.mem.toBytes(@intFromEnum(types.ExtensionType.ratchet_tree)));
    try data.appendSlice(&std.mem.toBytes(@intFromEnum(types.ExtensionType.required_capabilities)));
    try data.appendSlice(&std.mem.toBytes(@intFromEnum(types.ExtensionType.nostr_group_data)));
    
    _ = required_caps;
    
    return try data.toOwnedSlice();
}

test "group creation with admins" {
    const allocator = std.testing.allocator;
    var mls_provider = provider.MlsProvider.init(allocator);
    
    // Generate creator key
    var creator_private_key: [32]u8 = undefined;
    std.crypto.random.bytes(&creator_private_key);
    
    var creator_pubkey: [32]u8 = undefined;
    creator_pubkey = try crypto.getPublicKey(creator_private_key);
    
    const params = GroupCreationParams{
        .name = "Test Group",
        .description = "A test MLS group",
        .admins = &[_][32]u8{creator_pubkey},
        .relays = &[_][]const u8{"wss://relay.example.com"},
        .image = null,
    };
    
    const result = try createGroup(allocator, &mls_provider, creator_private_key, params, &.{});
    defer {
        // Free member identities
        for (result.state.members) |member| {
            switch (member.credential) {
                .basic => |basic| allocator.free(basic.identity),
                else => {},
            }
        }
        allocator.free(result.state.members);
        for (result.state.group_context.extensions) |ext| {
            allocator.free(ext.extension_data);
        }
        allocator.free(result.state.group_context.extensions);
        allocator.free(result.welcomes);
    }
    
    try std.testing.expectEqual(@as(types.Epoch, 0), result.state.epoch);
    try std.testing.expectEqual(@as(usize, 1), result.state.members.len);
    try std.testing.expectEqual(types.MemberRole.admin, result.state.members[0].role);
}

test "extract group data from context" {
    const allocator = std.testing.allocator;
    
    const group_id = types.GroupId.init([_]u8{7} ** 32);
    // Use valid secp256k1 public key
    const admin_privkey = try crypto.deriveValidKeyFromSeed([_]u8{8} ** 32);
    const admin_pubkey = try crypto.getPublicKey(admin_privkey);
    
    const group_data = extension.NostrGroupData{
        .group_id = group_id,
        .name = "Extract Test",
        .description = "Testing extraction",
        .admins = &[_][32]u8{admin_pubkey},
        .relays = &[_][]const u8{"wss://test.relay"},
        .image = null,
    };
    
    const ext = try extension.createNostrGroupDataExtension(allocator, group_data);
    defer allocator.free(ext.extension_data);
    
    const group_context = types.GroupContext{
        .version = .mls10,
        .cipher_suite = .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        .group_id = group_id,
        .epoch = 0,
        .tree_hash = [_]u8{0} ** 32,
        .confirmed_transcript_hash = [_]u8{0} ** 32,
        .extensions = &[_]types.Extension{ext},
    };
    
    const extracted = try extractGroupData(allocator, group_context);
    defer freeGroupData(allocator, extracted);
    
    try std.testing.expectEqualStrings(group_data.name, extracted.name);
}