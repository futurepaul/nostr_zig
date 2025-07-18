const std = @import("std");
const mls = @import("mls/mls.zig");
const crypto = @import("crypto.zig");
const wasm_exports = @import("wasm_exports.zig");

/// WASM wrapper for MLS state machine operations
/// Following DEVELOPMENT.md best practices - thin wrappers only

/// Initialize a new group
export fn wasm_state_machine_init_group(
    group_id: [*]const u8, // 32 bytes
    _: [*]const u8, // 32 bytes - creator_identity_pubkey (unused)
    creator_signing_key: [*]const u8, // 32 bytes
    out_state: [*]u8, // Serialized state output
    out_state_len: *u32,
) bool {
    const allocator = wasm_exports.getAllocator();
    
    // Create MLS provider with WASM-safe abstractions
    var mls_provider = mls.provider.MlsProvider.init(allocator);
    
    // Convert signing key to private key
    const creator_privkey = creator_signing_key[0..32].*;
    
    // Create key package params
    const kp_params = mls.key_packages.KeyPackageParams{
        .cipher_suite = .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        .lifetime_seconds = 30 * 24 * 60 * 60, // 30 days
        .extensions = &.{},
    };
    
    // Create real key package using MLS library
    const creator_kp = mls.key_packages.generateKeyPackage(
        allocator,
        &mls_provider,
        creator_privkey,
        kp_params,
    ) catch return false;
    defer mls.key_packages.freeKeyPackage(allocator, creator_kp);
    
    // Initialize real MLS state machine
    var state_machine = mls.state_machine.MLSStateMachine.initializeGroup(
        allocator,
        group_id[0..32].*,
        creator_kp,
        &mls_provider,
    ) catch return false;
    defer state_machine.deinit();
    
    // Serialize state
    const serialized = serializeStateMachine(allocator, &state_machine) catch return false;
    defer allocator.free(serialized);
    
    // Check buffer size
    if (out_state_len.* < serialized.len) {
        out_state_len.* = @intCast(serialized.len);
        return false;
    }
    
    // Copy result
    @memcpy(out_state[0..serialized.len], serialized);
    out_state_len.* = @intCast(serialized.len);
    
    return true;
}

/// Add a member proposal
export fn wasm_state_machine_propose_add(
    state_data: [*]const u8,
    state_data_len: u32,
    sender_index: u32,
    _: [*]const u8, // 32 bytes - new_member_identity (unused)
    new_member_signing_key: [*]const u8, // 32 bytes
    out_state: [*]u8,
    out_state_len: *u32,
) bool {
    const allocator = wasm_exports.getAllocator();
    
    // Deserialize state
    var state_machine = deserializeStateMachine(
        allocator,
        state_data[0..state_data_len],
    ) catch return false;
    defer state_machine.deinit();
    
    // Create MLS provider with WASM-safe abstractions
    var mls_provider = mls.provider.MlsProvider.init(allocator);
    
    // Convert signing key to private key
    const new_member_privkey = new_member_signing_key[0..32].*;
    
    // Create key package params
    const kp_params = mls.key_packages.KeyPackageParams{
        .cipher_suite = .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        .lifetime_seconds = 30 * 24 * 60 * 60, // 30 days
        .extensions = &.{},
    };
    
    // Create real key package using MLS library
    const new_kp = mls.key_packages.generateKeyPackage(
        allocator,
        &mls_provider,
        new_member_privkey,
        kp_params,
    ) catch return false;
    defer mls.key_packages.freeKeyPackage(allocator, new_kp);
    
    // Propose add using real MLS state machine
    state_machine.proposeAdd(sender_index, new_kp) catch return false;
    
    // Serialize updated state
    const serialized = serializeStateMachine(allocator, &state_machine) catch return false;
    defer allocator.free(serialized);
    
    // Check buffer size
    if (out_state_len.* < serialized.len) {
        out_state_len.* = @intCast(serialized.len);
        return false;
    }
    
    // Copy result
    @memcpy(out_state[0..serialized.len], serialized);
    out_state_len.* = @intCast(serialized.len);
    
    return true;
}

/// Commit pending proposals
export fn wasm_state_machine_commit_proposals(
    state_data: [*]const u8,
    state_data_len: u32,
    committer_index: u32,
    out_state: [*]u8,
    out_state_len: *u32,
    out_epoch: *u64,
    out_exporter_secret: [*]u8, // 32 bytes
) bool {
    const allocator = wasm_exports.getAllocator();
    
    // Deserialize state
    var state_machine = deserializeStateMachine(
        allocator,
        state_data[0..state_data_len],
    ) catch return false;
    defer state_machine.deinit();
    
    // Create MLS provider with WASM-safe abstractions
    var mls_provider = mls.provider.MlsProvider.init(allocator);
    
    // Commit proposals using real MLS state machine
    const commit_result = state_machine.commitProposals(
        committer_index,
        &mls_provider,
    ) catch return false;
    
    // Copy outputs
    out_epoch.* = commit_result.epoch;
    @memcpy(out_exporter_secret[0..32], &state_machine.epoch_secrets.exporter_secret);
    
    // Serialize updated state
    const serialized = serializeStateMachine(allocator, &state_machine) catch return false;
    defer allocator.free(serialized);
    
    // Check buffer size
    if (out_state_len.* < serialized.len) {
        out_state_len.* = @intCast(serialized.len);
        return false;
    }
    
    // Copy result
    @memcpy(out_state[0..serialized.len], serialized);
    out_state_len.* = @intCast(serialized.len);
    
    return true;
}

/// Get current state info
export fn wasm_state_machine_get_info(
    state_data: [*]const u8,
    state_data_len: u32,
    out_epoch: *u64,
    out_member_count: *u32,
    out_pending_proposals: *u32,
    out_exporter_secret: [*]u8, // 32 bytes
    out_tree_hash: [*]u8, // 32 bytes
) bool {
    const allocator = wasm_exports.getAllocator();
    
    // Deserialize state
    var state_machine = deserializeStateMachine(
        allocator,
        state_data[0..state_data_len],
    ) catch return false;
    defer state_machine.deinit();
    
    // Copy outputs
    out_epoch.* = state_machine.epoch;
    out_member_count.* = @intCast(state_machine.getMemberCount());
    out_pending_proposals.* = @intCast(state_machine.pending_proposals.items.len);
    @memcpy(out_exporter_secret[0..32], &state_machine.epoch_secrets.exporter_secret);
    @memcpy(out_tree_hash[0..32], &state_machine.tree_hash);
    
    return true;
}

/// Simple serialization format for state machine
/// Format: [epoch:8][member_count:4][members...][proposal_count:4][proposals...]
fn serializeStateMachine(
    allocator: std.mem.Allocator,
    state: *const mls.state_machine.MLSStateMachine,
) ![]u8 {
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    
    // Write epoch
    try buffer.writer().writeInt(u64, state.epoch, .big);
    
    // Write group ID
    try buffer.writer().writeAll(&state.group_id);
    
    // Write tree hash
    try buffer.writer().writeAll(&state.tree_hash);
    
    // Write transcript hashes
    try buffer.writer().writeAll(&state.confirmed_transcript_hash);
    try buffer.writer().writeAll(&state.interim_transcript_hash);
    
    // Write epoch secrets
    try buffer.writer().writeAll(std.mem.asBytes(&state.epoch_secrets));
    
    // Write member count and members
    try buffer.writer().writeInt(u32, @intCast(state.members.items.len), .big);
    for (state.members.items) |member| {
        try buffer.writer().writeInt(u32, member.leaf_index, .big);
        try buffer.writer().writeAll(&member.identity);
        try buffer.writer().writeAll(&member.signing_key);
        try buffer.writer().writeInt(u8, @intFromEnum(member.state), .big);
    }
    
    // Write proposal count
    try buffer.writer().writeInt(u32, @intCast(state.pending_proposals.items.len), .big);
    // TODO: Serialize proposals if needed
    
    return buffer.toOwnedSlice();
}

/// Deserialize state machine
fn deserializeStateMachine(
    allocator: std.mem.Allocator,
    data: []const u8,
) !mls.state_machine.MLSStateMachine {
    var stream = std.io.fixedBufferStream(data);
    const reader = stream.reader();
    
    // Read epoch
    const epoch = try reader.readInt(u64, .big);
    
    // Read group ID
    var group_id: [32]u8 = undefined;
    _ = try reader.read(&group_id);
    
    // Read tree hash
    var tree_hash: [32]u8 = undefined;
    _ = try reader.read(&tree_hash);
    
    // Read transcript hashes
    var confirmed_transcript_hash: [32]u8 = undefined;
    _ = try reader.read(&confirmed_transcript_hash);
    
    var interim_transcript_hash: [32]u8 = undefined;
    _ = try reader.read(&interim_transcript_hash);
    
    // Read epoch secrets
    var epoch_secrets: mls.state_machine.MLSStateMachine.EpochSecrets = undefined;
    _ = try reader.read(std.mem.asBytes(&epoch_secrets));
    
    // Read members
    const member_count = try reader.readInt(u32, .big);
    var members = std.ArrayList(mls.state_machine.MLSStateMachine.Member).init(allocator);
    
    var i: u32 = 0;
    while (i < member_count) : (i += 1) {
        const leaf_index = try reader.readInt(u32, .big);
        var identity: [64]u8 = undefined;
        _ = try reader.read(&identity);
        var signing_key: [32]u8 = undefined;
        _ = try reader.read(&signing_key);
        const state_value = try reader.readInt(u8, .big);
        
        const member = mls.state_machine.MLSStateMachine.Member{
            .leaf_index = leaf_index,
            .identity = identity,
            .signing_key = signing_key,
            .credential = .{ .basic = .{ .identity = &identity } },
            .capabilities = .{
                .versions = &.{.mls10},
                .ciphersuites = &.{.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519},
                .extensions = &.{},
                .proposals = &.{.add, .update, .remove},
                .credentials = &.{.basic},
            },
            .leaf_node = .{
                .encryption_key = .{
                    .data = &signing_key, // Using signing key as placeholder
                },
                .signature_key = .{
                    .data = &signing_key,
                },
                .credential = .{ .basic = .{ .identity = &identity } },
                .capabilities = .{
                    .versions = &.{.mls10},
                    .ciphersuites = &.{.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519},
                    .extensions = &.{},
                    .proposals = &.{.add, .update, .remove},
                    .credentials = &.{.basic},
                },
                .leaf_node_source = .{ .key_package = {} },
                .extensions = &.{},
                .signature = &.{}, // Empty signature for now
            },
            .state = @enumFromInt(state_value),
        };
        try members.append(member);
    }
    
    // Read proposal count (but don't deserialize proposals yet)
    const proposal_count = try reader.readInt(u32, .big);
    _ = proposal_count;
    
    // Create group context
    const group_context = mls.state_machine.MLSStateMachine.GroupContext{
        .version = .mls10,
        .cipher_suite = .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        .group_id = group_id,
        .epoch = epoch,
        .tree_hash = tree_hash,
        .confirmed_transcript_hash = confirmed_transcript_hash,
        .extensions = &.{},
    };
    
    return mls.state_machine.MLSStateMachine{
        .epoch = epoch,
        .group_id = group_id,
        .members = members,
        .pending_proposals = std.ArrayList(mls.state_machine.MLSStateMachine.Proposal).init(allocator),
        .tree_hash = tree_hash,
        .confirmed_transcript_hash = confirmed_transcript_hash,
        .interim_transcript_hash = interim_transcript_hash,
        .group_context = group_context,
        .epoch_secrets = epoch_secrets,
        .allocator = allocator,
    };
}

