const std = @import("std");
const types = @import("types.zig");
const provider = @import("provider.zig");
const extension = @import("extension.zig");
const key_packages = @import("key_packages.zig");
const mls = @import("mls.zig");
const crypto = @import("../crypto.zig");

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
    mls_provider.rand.fill(&group_id);
    
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
    
    // Initialize group context
    const group_context = types.GroupContext{
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
    
    // Process initial members
    var welcomes = std.ArrayList(types.Welcome).init(allocator);
    defer welcomes.deinit();
    
    for (initial_members, 1..) |kp, index| {
        // Validate key package
        try key_packages.validateKeyPackage(allocator, mls_provider, kp);
        
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
    
    // Create initial group state
    const state = mls.MlsGroupState{
        .group_id = group_id,
        .epoch = 0,
        .cipher_suite = params.cipher_suite,
        .group_context = group_context,
        .tree_hash = [_]u8{0} ** 32, // TODO: Compute actual tree hash
        .confirmed_transcript_hash = [_]u8{0} ** 32, // TODO: Compute actual transcript hash
        .members = try members.toOwnedSlice(),
        .ratchet_tree = &.{}, // TODO: Build actual ratchet tree
        .interim_transcript_hash = [_]u8{0} ** 32,
        .epoch_secrets = epoch_secrets,
    };
    
    return mls.GroupCreationResult{
        .state = state,
        .welcomes = try welcomes.toOwnedSlice(),
        .used_key_packages = initial_members,
    };
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

fn generateInitialEpochSecrets(
    allocator: std.mem.Allocator,
    mls_provider: *provider.MlsProvider,
    group_id: types.GroupId,
) !mls.EpochSecrets {
    _ = allocator;
    
    // Generate random init secret
    var init_secret: [32]u8 = undefined;
    mls_provider.rand.fill(&init_secret);
    
    // Derive epoch secrets from init secret
    return deriveEpochSecrets(mls_provider, init_secret, group_id);
}

fn deriveEpochSecrets(
    mls_provider: *provider.MlsProvider,
    init_secret: [32]u8,
    group_id: types.GroupId,
) !mls.EpochSecrets {
    const allocator = mls_provider.allocator;
    
    // Use HKDF to derive all secrets
    const sender_data_secret = try deriveSecret(allocator, mls_provider, init_secret, "sender data", group_id);
    defer allocator.free(sender_data_secret);
    
    const encryption_secret = try deriveSecret(allocator, mls_provider, init_secret, "encryption", group_id);
    defer allocator.free(encryption_secret);
    
    const exporter_secret = try deriveSecret(allocator, mls_provider, init_secret, "exporter", group_id);
    defer allocator.free(exporter_secret);
    
    const authentication_secret = try deriveSecret(allocator, mls_provider, init_secret, "authentication", group_id);
    defer allocator.free(authentication_secret);
    
    const external_secret = try deriveSecret(allocator, mls_provider, init_secret, "external", group_id);
    defer allocator.free(external_secret);
    
    const confirmation_key = try deriveSecret(allocator, mls_provider, init_secret, "confirm", group_id);
    defer allocator.free(confirmation_key);
    
    const membership_key = try deriveSecret(allocator, mls_provider, init_secret, "membership", group_id);
    defer allocator.free(membership_key);
    
    const resumption_psk = try deriveSecret(allocator, mls_provider, init_secret, "resumption", group_id);
    defer allocator.free(resumption_psk);
    
    var epoch_secrets: mls.EpochSecrets = undefined;
    @memcpy(&epoch_secrets.sender_data_secret, sender_data_secret[0..32]);
    @memcpy(&epoch_secrets.encryption_secret, encryption_secret[0..32]);
    @memcpy(&epoch_secrets.exporter_secret, exporter_secret[0..32]);
    @memcpy(&epoch_secrets.authentication_secret, authentication_secret[0..32]);
    @memcpy(&epoch_secrets.external_secret, external_secret[0..32]);
    @memcpy(&epoch_secrets.confirmation_key, confirmation_key[0..32]);
    @memcpy(&epoch_secrets.membership_key, membership_key[0..32]);
    @memcpy(&epoch_secrets.resumption_psk, resumption_psk[0..32]);
    @memcpy(&epoch_secrets.init_secret, &init_secret);
    
    return epoch_secrets;
}

fn deriveSecret(
    allocator: std.mem.Allocator,
    mls_provider: *provider.MlsProvider,
    secret: [32]u8,
    label: []const u8,
    context: types.GroupId,
) ![]u8 {
    // Build info string
    const info = try std.fmt.allocPrint(allocator, "MLS 1.0 {s}{s}", .{ label, std.fmt.fmtSliceHexLower(&context) });
    defer allocator.free(info);
    
    return try mls_provider.crypto.hkdfExpandFn(allocator, &secret, info, 32);
}

fn createWelcomeForMember(
    allocator: std.mem.Allocator,
    mls_provider: *provider.MlsProvider,
    group_context: types.GroupContext,
    member_key_package: types.KeyPackage,
    epoch_secrets: mls.EpochSecrets,
) !types.Welcome {
    _ = allocator;
    _ = mls_provider;
    _ = member_key_package;
    _ = epoch_secrets;
    
    // TODO: Implement actual welcome creation
    // This requires encrypting group secrets to the member's init key
    return types.Welcome{
        .cipher_suite = group_context.cipher_suite,
        .secrets = &.{},
        .encrypted_group_info = &.{},
    };
}

fn createAndProcessCommit(
    allocator: std.mem.Allocator,
    mls_provider: *provider.MlsProvider,
    current_state: *const mls.MlsGroupState,
    proposals: []const types.Proposal,
    committer_private_key: [32]u8,
) !CommitResult {
    _ = allocator;
    _ = mls_provider;
    _ = current_state;
    _ = proposals;
    _ = committer_private_key;
    
    // TODO: Implement actual commit creation and processing
    return error.NotImplemented;
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
    
    const group_id: types.GroupId = [_]u8{7} ** 32;
    const group_data = extension.NostrGroupData{
        .group_id = group_id,
        .name = "Extract Test",
        .description = "Testing extraction",
        .admins = &[_][32]u8{[_]u8{8} ** 32},
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