const std = @import("std");
const types = @import("types.zig");
const crypto_utils = @import("crypto_utils.zig");
const provider = @import("provider.zig");
const key_packages = @import("key_packages.zig");
const welcomes = @import("welcomes.zig");
const mls_messages = @import("mls_messages.zig");
const crypto = @import("../crypto.zig");

/// MLS Group State Machine
/// Manages the lifecycle of an MLS group including epochs, membership, and state transitions
pub const MLSStateMachine = struct {
    /// Current epoch number
    epoch: u64,
    
    /// Group identifier
    group_id: [32]u8,
    
    /// Group members indexed by leaf index
    members: std.ArrayList(Member),
    
    /// Pending proposals for the current epoch
    pending_proposals: std.ArrayList(Proposal),
    
    /// Tree hash for the current epoch
    tree_hash: [32]u8,
    
    /// Confirmed transcript hash
    confirmed_transcript_hash: [32]u8,
    
    /// Interim transcript hash (includes pending proposals)
    interim_transcript_hash: [32]u8,
    
    /// Group context
    group_context: GroupContext,
    
    /// Epoch secrets
    epoch_secrets: EpochSecrets,
    
    /// Allocator for dynamic memory
    allocator: std.mem.Allocator,
    
    /// Member information
    pub const Member = struct {
        leaf_index: u32,
        identity: [64]u8, // hex-encoded public key
        signing_key: [32]u8,
        credential: types.Credential,
        capabilities: types.Capabilities,
        leaf_node: types.LeafNode,
        /// Member's current state in the group
        state: MemberState,
    };
    
    /// Member states
    pub const MemberState = enum {
        active,
        pending_remove,
        pending_update,
    };
    
    /// Proposal types
    pub const ProposalType = enum {
        add,
        remove,
        update,
        psk,
        reinit,
        external_init,
        group_context_extensions,
    };
    
    /// Proposal structure
    pub const Proposal = struct {
        proposal_type: ProposalType,
        sender: u32, // leaf index of sender
        /// Proposal-specific data
        data: union(ProposalType) {
            add: struct {
                key_package: types.KeyPackage,
            },
            remove: struct {
                removed: u32, // leaf index to remove
            },
            update: struct {
                leaf_node: types.LeafNode,
            },
            psk: void, // PSK proposals not implemented
            reinit: void, // Reinit not implemented
            external_init: void, // External init not implemented
            group_context_extensions: void, // Extensions update not implemented
        },
    };
    
    /// Group context as per MLS spec
    pub const GroupContext = struct {
        version: types.ProtocolVersion,
        cipher_suite: types.Ciphersuite,
        group_id: [32]u8,
        epoch: u64,
        tree_hash: [32]u8,
        confirmed_transcript_hash: [32]u8,
        extensions: []const types.Extension,
    };
    
    /// Epoch secrets for key derivation
    pub const EpochSecrets = struct {
        joiner_secret: [32]u8,
        member_secret: [32]u8,
        epoch_secret: [32]u8,
        epoch_authenticator: [32]u8,
        external_secret: [32]u8,
        confirmation_key: [32]u8,
        membership_key: [32]u8,
        resumption_psk: [32]u8,
        init_secret: [32]u8,
        sender_data_secret: [32]u8,
        encryption_secret: [32]u8,
        exporter_secret: [32]u8,
        external_pub: [32]u8,
    };
    
    /// Initialize a new group (creator's perspective)
    pub fn initializeGroup(
        allocator: std.mem.Allocator,
        group_id: [32]u8,
        creator_key_package: types.KeyPackage,
        mls_provider: *provider.MlsProvider,
    ) !MLSStateMachine {
        var members = std.ArrayList(Member).init(allocator);
        errdefer members.deinit();
        
        // Add creator as first member (leaf index 0)
        var identity_array: [64]u8 = undefined;
        switch (creator_key_package.leaf_node.credential) {
            .basic => |basic| {
                if (basic.identity.len != 64) return error.InvalidIdentityLength;
                @memcpy(&identity_array, basic.identity);
            },
            else => return error.UnsupportedCredentialType,
        }
        
        var signing_key_array: [32]u8 = undefined;
        if (creator_key_package.leaf_node.signature_key.data.len != 32) {
            return error.InvalidSigningKeyLength;
        }
        @memcpy(&signing_key_array, creator_key_package.leaf_node.signature_key.data);
        
        const creator_member = Member{
            .leaf_index = 0,
            .identity = identity_array,
            .signing_key = signing_key_array,
            .credential = creator_key_package.leaf_node.credential,
            .capabilities = creator_key_package.leaf_node.capabilities,
            .leaf_node = creator_key_package.leaf_node,
            .state = .active,
        };
        try members.append(creator_member);
        
        // Initialize group context
        const group_context = GroupContext{
            .version = creator_key_package.version,
            .cipher_suite = creator_key_package.cipher_suite,
            .group_id = group_id,
            .epoch = 0,
            .tree_hash = [_]u8{0} ** 32, // Will be computed
            .confirmed_transcript_hash = [_]u8{0} ** 32,
            .extensions = &.{},
        };
        
        // Derive initial epoch secrets
        const epoch_secrets = try deriveEpochSecrets(
            mls_provider,
            group_context.cipher_suite,
            &[_]u8{0} ** 32, // init_secret for epoch 0
        );
        
        var state = MLSStateMachine{
            .epoch = 0,
            .group_id = group_id,
            .members = members,
            .pending_proposals = std.ArrayList(Proposal).init(allocator),
            .tree_hash = [_]u8{0} ** 32,
            .confirmed_transcript_hash = [_]u8{0} ** 32,
            .interim_transcript_hash = [_]u8{0} ** 32,
            .group_context = group_context,
            .epoch_secrets = epoch_secrets,
            .allocator = allocator,
        };
        
        // Compute initial tree hash
        try state.updateTreeHash();
        
        return state;
    }
    
    /// Join a group from a Welcome message
    pub fn joinFromWelcome(
        allocator: std.mem.Allocator,
        welcome: types.Welcome,
        our_key_package: types.KeyPackage,
        mls_provider: *provider.MlsProvider,
    ) !MLSStateMachine {
        // This would decrypt the Welcome and initialize state
        // For now, return a simplified version
        _ = allocator;
        _ = welcome;
        _ = our_key_package;
        _ = mls_provider;
        return error.NotImplemented;
    }
    
    /// Propose adding a new member
    pub fn proposeAdd(
        self: *MLSStateMachine,
        sender_index: u32,
        key_package: types.KeyPackage,
    ) !void {
        if (sender_index >= self.members.items.len) {
            return error.InvalidSenderIndex;
        }
        
        const proposal = Proposal{
            .proposal_type = .add,
            .sender = sender_index,
            .data = .{ .add = .{ .key_package = key_package } },
        };
        
        try self.pending_proposals.append(proposal);
        try self.updateInterimTranscriptHash();
    }
    
    /// Propose removing a member
    pub fn proposeRemove(
        self: *MLSStateMachine,
        sender_index: u32,
        removed_index: u32,
    ) !void {
        if (sender_index >= self.members.items.len) {
            return error.InvalidSenderIndex;
        }
        if (removed_index >= self.members.items.len) {
            return error.InvalidRemovedIndex;
        }
        
        const proposal = Proposal{
            .proposal_type = .remove,
            .sender = sender_index,
            .data = .{ .remove = .{ .removed = removed_index } },
        };
        
        try self.pending_proposals.append(proposal);
        self.members.items[removed_index].state = .pending_remove;
        try self.updateInterimTranscriptHash();
    }
    
    /// Propose updating own leaf node
    pub fn proposeUpdate(
        self: *MLSStateMachine,
        sender_index: u32,
        new_leaf_node: types.LeafNode,
    ) !void {
        if (sender_index >= self.members.items.len) {
            return error.InvalidSenderIndex;
        }
        
        const proposal = Proposal{
            .proposal_type = .update,
            .sender = sender_index,
            .data = .{ .update = .{ .leaf_node = new_leaf_node } },
        };
        
        try self.pending_proposals.append(proposal);
        self.members.items[sender_index].state = .pending_update;
        try self.updateInterimTranscriptHash();
    }
    
    /// Commit pending proposals and advance epoch
    pub fn commitProposals(
        self: *MLSStateMachine,
        committer_index: u32,
        mls_provider: *provider.MlsProvider,
    ) !CommitResult {
        if (committer_index >= self.members.items.len) {
            return error.InvalidCommitterIndex;
        }
        
        if (self.pending_proposals.items.len == 0) {
            return error.NoPendingProposals;
        }
        
        // Process proposals in order
        var path_required = false;
        var added_members = std.ArrayList(Member).init(self.allocator);
        defer added_members.deinit();
        
        for (self.pending_proposals.items) |proposal| {
            switch (proposal.data) {
                .add => |add_data| {
                    // Add new member at next available index
                    const new_index = self.members.items.len + added_members.items.len;
                    var new_identity: [64]u8 = undefined;
                    switch (add_data.key_package.leaf_node.credential) {
                        .basic => |basic| {
                            if (basic.identity.len != 64) return error.InvalidIdentityLength;
                            @memcpy(&new_identity, basic.identity);
                        },
                        else => return error.UnsupportedCredentialType,
                    }
                    
                    var new_signing_key: [32]u8 = undefined;
                    if (add_data.key_package.leaf_node.signature_key.data.len != 32) {
                        return error.InvalidSigningKeyLength;
                    }
                    @memcpy(&new_signing_key, add_data.key_package.leaf_node.signature_key.data);
                    
                    const new_member = Member{
                        .leaf_index = @intCast(new_index),
                        .identity = new_identity,
                        .signing_key = new_signing_key,
                        .credential = add_data.key_package.leaf_node.credential,
                        .capabilities = add_data.key_package.leaf_node.capabilities,
                        .leaf_node = add_data.key_package.leaf_node,
                        .state = .active,
                    };
                    try added_members.append(new_member);
                    path_required = true;
                },
                .remove => |remove_data| {
                    // Mark for removal (will be processed after commit)
                    self.members.items[remove_data.removed].state = .pending_remove;
                    path_required = true;
                },
                .update => |update_data| {
                    // Update leaf node
                    self.members.items[proposal.sender].leaf_node = update_data.leaf_node;
                    if (update_data.leaf_node.signature_key.data.len != 32) {
                        return error.InvalidSigningKeyLength;
                    }
                    @memcpy(&self.members.items[proposal.sender].signing_key, update_data.leaf_node.signature_key.data);
                    self.members.items[proposal.sender].state = .active;
                    if (proposal.sender == committer_index) {
                        path_required = true;
                    }
                },
                else => return error.UnsupportedProposalType,
            }
        }
        
        // Create commit message
        const old_epoch = self.epoch;
        const new_epoch = old_epoch + 1;
        
        // Update epoch
        self.epoch = new_epoch;
        self.group_context.epoch = new_epoch;
        
        // Add new members
        for (added_members.items) |member| {
            try self.members.append(member);
        }
        
        // Remove pending members
        var i: usize = 0;
        while (i < self.members.items.len) {
            if (self.members.items[i].state == .pending_remove) {
                _ = self.members.orderedRemove(i);
            } else {
                i += 1;
            }
        }
        
        // Reindex members
        for (self.members.items, 0..) |*member, index| {
            member.leaf_index = @intCast(index);
        }
        
        // Derive new epoch secrets
        var commit_secret: [32]u8 = undefined;
        mls_provider.rand.fill(&commit_secret);
        
        self.epoch_secrets = try deriveEpochSecrets(
            mls_provider,
            self.group_context.cipher_suite,
            &commit_secret,
        );
        
        // Update transcript hashes
        self.confirmed_transcript_hash = self.interim_transcript_hash;
        self.group_context.confirmed_transcript_hash = self.confirmed_transcript_hash;
        
        // Update tree hash
        try self.updateTreeHash();
        
        // Clear pending proposals
        self.pending_proposals.clearRetainingCapacity();
        
        return CommitResult{
            .epoch = new_epoch,
            .added_members = added_members.items.len,
            .removed_members = 0, // TODO: track removed count
            .path_required = path_required,
        };
    }
    
    /// Result of committing proposals
    pub const CommitResult = struct {
        epoch: u64,
        added_members: usize,
        removed_members: usize,
        path_required: bool,
    };
    
    /// Get current member count
    pub fn getMemberCount(self: *const MLSStateMachine) usize {
        return self.members.items.len;
    }
    
    /// Get member by leaf index
    pub fn getMember(self: *const MLSStateMachine, leaf_index: u32) ?*const Member {
        if (leaf_index >= self.members.items.len) {
            return null;
        }
        return &self.members.items[leaf_index];
    }
    
    /// Get member by identity
    pub fn getMemberByIdentity(self: *const MLSStateMachine, identity: [64]u8) ?*const Member {
        for (self.members.items) |*member| {
            if (std.mem.eql(u8, &member.identity, &identity)) {
                return member;
            }
        }
        return null;
    }
    
    /// Update tree hash (simplified)
    fn updateTreeHash(self: *MLSStateMachine) !void {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        
        // Hash group ID
        hasher.update(&self.group_id);
        
        // Hash epoch
        var epoch_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &epoch_bytes, self.epoch, .big);
        hasher.update(&epoch_bytes);
        
        // Hash members
        for (self.members.items) |member| {
            hasher.update(&member.signing_key);
            hasher.update(&member.identity);
        }
        
        hasher.final(&self.tree_hash);
        self.group_context.tree_hash = self.tree_hash;
    }
    
    /// Update interim transcript hash
    fn updateInterimTranscriptHash(self: *MLSStateMachine) !void {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        
        // Start with confirmed transcript hash
        hasher.update(&self.confirmed_transcript_hash);
        
        // Hash pending proposals
        for (self.pending_proposals.items) |proposal| {
            hasher.update(&[_]u8{@intFromEnum(proposal.proposal_type)});
            var sender_bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &sender_bytes, proposal.sender, .big);
            hasher.update(&sender_bytes);
        }
        
        hasher.final(&self.interim_transcript_hash);
    }
    
    /// Derive epoch secrets from commit secret
    fn deriveEpochSecrets(
        mls_provider: *provider.MlsProvider,
        cipher_suite: types.Ciphersuite,
        commit_secret: []const u8,
    ) !EpochSecrets {
        _ = mls_provider;
        _ = cipher_suite;
        
        // Simplified epoch secret derivation
        // Real implementation would use proper HKDF with labeled derivation
        var secrets: EpochSecrets = undefined;
        
        // For now, use SHA256 to derive different secrets
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        
        // Derive each secret with a different label
        const labels = [_][]const u8{
            "joiner", "member", "epoch", "authenticator",
            "external", "confirm", "membership", "resumption",
            "init", "sender_data", "encryption", "exporter",
            "external_pub",
        };
        
        const secret_fields = [_]*[32]u8{
            &secrets.joiner_secret,
            &secrets.member_secret,
            &secrets.epoch_secret,
            &secrets.epoch_authenticator,
            &secrets.external_secret,
            &secrets.confirmation_key,
            &secrets.membership_key,
            &secrets.resumption_psk,
            &secrets.init_secret,
            &secrets.sender_data_secret,
            &secrets.encryption_secret,
            &secrets.exporter_secret,
            &secrets.external_pub,
        };
        
        for (labels, secret_fields) |label, field| {
            hasher = std.crypto.hash.sha2.Sha256.init(.{});
            hasher.update(commit_secret);
            hasher.update(label);
            hasher.final(field);
        }
        
        return secrets;
    }
    
    /// Clean up resources
    pub fn deinit(self: *MLSStateMachine) void {
        self.members.deinit();
        self.pending_proposals.deinit();
    }
};

// Tests
test "MLS state machine - group creation" {
    const allocator = std.testing.allocator;
    
    // Create MLS provider
    var mls_provider = provider.MlsProvider.init(allocator);
    
    // Create creator's key package with a valid private key
    var creator_privkey: [32]u8 = undefined;
    @memcpy(&creator_privkey, &[_]u8{0x01} ** 32);
    // Ensure it's a valid secp256k1 key by using the actual key generation
    creator_privkey = crypto.deriveValidKeyFromSeed(creator_privkey) catch {
        // If that fails, generate a real key
        creator_privkey = try crypto.generatePrivateKey();
    };
    
    const creator_kp = try key_packages.generateKeyPackage(
        allocator,
        &mls_provider,
        creator_privkey,
        .{}, // default params
    );
    defer key_packages.freeKeyPackage(allocator, creator_kp);
    
    // Initialize group
    const group_id = [_]u8{0x42} ** 32;
    var state_machine = try MLSStateMachine.initializeGroup(
        allocator,
        group_id,
        creator_kp,
        &mls_provider,
    );
    defer state_machine.deinit();
    
    // Verify initial state
    try std.testing.expectEqual(@as(u64, 0), state_machine.epoch);
    try std.testing.expectEqual(@as(usize, 1), state_machine.getMemberCount());
    try std.testing.expectEqual(group_id, state_machine.group_id);
    
    const creator = state_machine.getMember(0).?;
    try std.testing.expectEqual(@as(u32, 0), creator.leaf_index);
    try std.testing.expectEqual(MLSStateMachine.MemberState.active, creator.state);
}

test "MLS state machine - add member proposal and commit" {
    const allocator = std.testing.allocator;
    
    // Create MLS provider
    var mls_provider = provider.MlsProvider.init(allocator);
    
    // Create key packages with valid private keys
    const alice_privkey = try crypto.generatePrivateKey();
    const alice_kp = try key_packages.generateKeyPackage(
        allocator,
        &mls_provider,
        alice_privkey,
        .{},
    );
    defer key_packages.freeKeyPackage(allocator, alice_kp);
    
    const bob_privkey = try crypto.generatePrivateKey();
    const bob_kp = try key_packages.generateKeyPackage(
        allocator,
        &mls_provider,
        bob_privkey,
        .{},
    );
    defer key_packages.freeKeyPackage(allocator, bob_kp);
    
    // Initialize group with Alice
    const group_id = [_]u8{0x42} ** 32;
    var state_machine = try MLSStateMachine.initializeGroup(
        allocator,
        group_id,
        alice_kp,
        &mls_provider,
    );
    defer state_machine.deinit();
    
    // Alice proposes to add Bob
    try state_machine.proposeAdd(0, bob_kp);
    try std.testing.expectEqual(@as(usize, 1), state_machine.pending_proposals.items.len);
    
    // Alice commits the proposal
    const commit_result = try state_machine.commitProposals(0, &mls_provider);
    
    // Verify state after commit
    try std.testing.expectEqual(@as(u64, 1), commit_result.epoch);
    try std.testing.expectEqual(@as(u64, 1), state_machine.epoch);
    try std.testing.expectEqual(@as(usize, 1), commit_result.added_members);
    try std.testing.expectEqual(@as(usize, 2), state_machine.getMemberCount());
    try std.testing.expectEqual(@as(usize, 0), state_machine.pending_proposals.items.len);
    
    // Verify Bob was added
    const bob = state_machine.getMember(1).?;
    try std.testing.expectEqual(@as(u32, 1), bob.leaf_index);
    try std.testing.expectEqual(MLSStateMachine.MemberState.active, bob.state);
}

test "MLS state machine - remove member proposal and commit" {
    const allocator = std.testing.allocator;
    
    // Create MLS provider
    var mls_provider = provider.MlsProvider.init(allocator);
    
    // Create key packages for 3 members
    const alice_privkey = try crypto.generatePrivateKey();
    const alice_kp = try key_packages.generateKeyPackage(allocator, &mls_provider, alice_privkey, .{});
    defer key_packages.freeKeyPackage(allocator, alice_kp);
    
    const bob_privkey = try crypto.generatePrivateKey();
    const bob_kp = try key_packages.generateKeyPackage(allocator, &mls_provider, bob_privkey, .{});
    defer key_packages.freeKeyPackage(allocator, bob_kp);
    
    const charlie_privkey = try crypto.generatePrivateKey();
    const charlie_kp = try key_packages.generateKeyPackage(allocator, &mls_provider, charlie_privkey, .{});
    defer key_packages.freeKeyPackage(allocator, charlie_kp);
    
    // Initialize group with Alice
    const group_id = [_]u8{0x42} ** 32;
    var state_machine = try MLSStateMachine.initializeGroup(allocator, group_id, alice_kp, &mls_provider);
    defer state_machine.deinit();
    
    // Add Bob and Charlie
    try state_machine.proposeAdd(0, bob_kp);
    try state_machine.proposeAdd(0, charlie_kp);
    _ = try state_machine.commitProposals(0, &mls_provider);
    
    try std.testing.expectEqual(@as(usize, 3), state_machine.getMemberCount());
    
    // Alice proposes to remove Bob (index 1)
    try state_machine.proposeRemove(0, 1);
    try std.testing.expectEqual(MLSStateMachine.MemberState.pending_remove, state_machine.members.items[1].state);
    
    // Alice commits the removal
    const commit_result = try state_machine.commitProposals(0, &mls_provider);
    
    // Verify state after commit
    try std.testing.expectEqual(@as(u64, 2), commit_result.epoch);
    try std.testing.expectEqual(@as(usize, 2), state_machine.getMemberCount());
    
    // Verify member indices were updated
    const alice = state_machine.getMember(0).?;
    const charlie = state_machine.getMember(1).?;
    try std.testing.expectEqual(@as(u32, 0), alice.leaf_index);
    try std.testing.expectEqual(@as(u32, 1), charlie.leaf_index);
    
    // Bob should be gone
    try std.testing.expectEqual(@as(?*const MLSStateMachine.Member, null), state_machine.getMember(2));
}