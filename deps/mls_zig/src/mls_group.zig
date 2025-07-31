const std = @import("std");
const Allocator = std.mem.Allocator;
const crypto = std.crypto;
const testing = std.testing;
const wasm_random = @import("wasm_random.zig");

const CipherSuite = @import("cipher_suite.zig").CipherSuite;
const Secret = @import("cipher_suite.zig").Secret;
const Credential = @import("credentials.zig").Credential;
const KeyPackage = @import("key_package.zig").KeyPackage;
const KeyPackageBundle = @import("key_package.zig").KeyPackageBundle;
const LeafNode = @import("leaf_node.zig").LeafNode;
const TreeSync = @import("tree_kem.zig").TreeSync;
const createUpdatePath = @import("tree_kem.zig").createUpdatePath;
const applyUpdatePath = @import("tree_kem.zig").applyUpdatePath;
const tls_encode = @import("tls_encode.zig");
const tls = std.crypto.tls;
const LeafNodeIndex = @import("tree_math.zig").LeafNodeIndex;

/// Errors specific to MLS group operations
pub const MlsGroupError = error{
    InvalidGroupState,
    InvalidProposal,
    InvalidCommit,
    MemberNotFound,
    ProposalNotFound,
    InvalidWelcome,
    UnsupportedVersion,
    InvalidEpoch,
    DuplicateMember,
    EmptyGroup,
};

/// MLS protocol version
pub const ProtocolVersion = enum(u16) {
    mls10 = 0x0100,

    pub fn serialize(self: ProtocolVersion, writer: anytype) !void {
        // Manual u16 serialization in big-endian
        var buf: [2]u8 = undefined;
        std.mem.writeInt(u16, &buf, @intFromEnum(self), .big);
        try writer.writeAll(&buf);
    }

    pub fn deserialize(reader: anytype) !ProtocolVersion {
        var buf: [2]u8 = undefined;
        _ = try reader.readAll(&buf);
        var decoder = tls.Decoder.fromTheirSlice(&buf);
        const value = decoder.decode(u16);
        return @enumFromInt(value);
    }
};

/// MLS content type
pub const ContentType = enum(u8) {
    application = 0x01,
    proposal = 0x02,
    commit = 0x03,

    pub fn serialize(self: ContentType, writer: anytype) !void {
        try tls_encode.writeInt(writer, u8, @intFromEnum(self));
    }

    pub fn deserialize(reader: anytype) !ContentType {
        var buf: [1]u8 = undefined;
        _ = try reader.readAll(&buf);
        var decoder = tls.Decoder.fromTheirSlice(&buf);
        const value = decoder.decode(u8);
        return @enumFromInt(value);
    }
};

/// MLS proposal type
pub const ProposalType = enum(u16) {
    add = 0x0001,
    update = 0x0002,
    remove = 0x0003,
    psk = 0x0004,
    reinit = 0x0005,
    external_init = 0x0006,
    group_context_extensions = 0x0007,

    pub fn serialize(self: ProposalType, writer: anytype) !void {
        // Manual u16 serialization in big-endian
        var buf: [2]u8 = undefined;
        std.mem.writeInt(u16, &buf, @intFromEnum(self), .big);
        try writer.writeAll(&buf);
    }

    pub fn deserialize(reader: anytype) !ProposalType {
        var buf: [2]u8 = undefined;
        _ = try reader.readAll(&buf);
        var decoder = tls.Decoder.fromTheirSlice(&buf);
        const value = decoder.decode(u16);
        return @enumFromInt(value);
    }
};

/// Proposal reference for commit messages
pub const ProposalRef = struct {
    proposal_hash: []u8,
    allocator: std.mem.Allocator,

    pub fn init(allocator: Allocator, hash: []const u8) !ProposalRef {
        return ProposalRef{
            .proposal_hash = try allocator.dupe(u8, hash),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ProposalRef) void {
        self.allocator.free(self.proposal_hash);
    }
};

/// Add proposal
pub const AddProposal = struct {
    key_package: KeyPackage,

    pub fn init(key_package: KeyPackage) AddProposal {
        return AddProposal{ .key_package = key_package };
    }

    pub fn deinit(self: *AddProposal, allocator: Allocator) void {
        self.key_package.deinit(allocator);
    }
};

/// Update proposal
pub const UpdateProposal = struct {
    leaf_node: LeafNode,

    pub fn init(leaf_node: LeafNode) UpdateProposal {
        return UpdateProposal{ .leaf_node = leaf_node };
    }

    pub fn deinit(self: *UpdateProposal, allocator: Allocator) void {
        self.leaf_node.deinit(allocator);
    }
};

/// Remove proposal
pub const RemoveProposal = struct {
    removed_index: LeafNodeIndex,

    pub fn init(index: LeafNodeIndex) RemoveProposal {
        return RemoveProposal{ .removed_index = index };
    }
};

/// Generic proposal wrapper
pub const Proposal = union(ProposalType) {
    add: AddProposal,
    update: UpdateProposal,
    remove: RemoveProposal,
    psk: void, // Not implemented
    reinit: void, // Not implemented
    external_init: void, // Not implemented
    group_context_extensions: void, // Not implemented

    pub fn deinit(self: *Proposal, allocator: Allocator) void {
        switch (self.*) {
            .add => |*p| p.deinit(allocator),
            .update => |*p| p.deinit(allocator),
            .remove => {},
            else => {},
        }
    }
};

/// Group context containing group state
pub const GroupContext = struct {
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    group_id: []u8,
    epoch: u64,
    tree_hash: []u8,
    confirmed_transcript_hash: []u8,
    extensions: []u8,
    allocator: std.mem.Allocator,

    pub fn init(
        allocator: Allocator,
        cipher_suite: CipherSuite,
        group_id: []const u8,
    ) !GroupContext {
        return GroupContext{
            .protocol_version = .mls10,
            .cipher_suite = cipher_suite,
            .group_id = try allocator.dupe(u8, group_id),
            .epoch = 0,
            .tree_hash = try allocator.dupe(u8, &[_]u8{}),
            .confirmed_transcript_hash = try allocator.dupe(u8, &[_]u8{}),
            .extensions = try allocator.dupe(u8, &[_]u8{}),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *GroupContext) void {
        self.allocator.free(self.group_id);
        self.allocator.free(self.tree_hash);
        self.allocator.free(self.confirmed_transcript_hash);
        self.allocator.free(self.extensions);
    }

    pub fn serialize(self: GroupContext, writer: anytype) !void {
        // Manual TLS serialization using standard writer
        try self.protocol_version.serialize(writer);
        
        // Cipher suite (u16)
        var buf: [8]u8 = undefined;
        std.mem.writeInt(u16, buf[0..2], @intFromEnum(self.cipher_suite), .big);
        try writer.writeAll(buf[0..2]);
        
        // Group ID (variable bytes with u16 length)
        try tls_encode.writeVarBytes(writer, u16, self.group_id);
        
        // Epoch (u64)
        try tls_encode.writeInt(writer, u64, self.epoch);
        
        // Tree hash (variable bytes with u16 length)
        try tls_encode.writeVarBytes(writer, u16, self.tree_hash);
        
        // Confirmed transcript hash (variable bytes with u16 length)
        try tls_encode.writeVarBytes(writer, u16, self.confirmed_transcript_hash);
        
        // Extensions (variable bytes with u16 length)
        try tls_encode.writeVarBytes(writer, u16, self.extensions);
    }

    pub fn deserialize(allocator: Allocator, reader: anytype) !GroupContext {
        const protocol_version = try ProtocolVersion.deserialize(reader);
        
        // Read cipher suite
        var cs_buf: [2]u8 = undefined;
        _ = try reader.readAll(&cs_buf);
        var cs_decoder = tls.Decoder.fromTheirSlice(&cs_buf);
        const cipher_suite = @as(CipherSuite, @enumFromInt(cs_decoder.decode(u16)));
        
        const group_id_data = try tls_encode.readVarBytes(&tls.Decoder.fromTheirSlice(&[_]u8{}), u16, allocator);
        defer allocator.free(group_id_data);
        const group_id = try allocator.dupe(u8, group_id_data);
        errdefer allocator.free(group_id);
        
        // Read epoch
        var epoch_buf: [8]u8 = undefined;
        _ = try reader.readAll(&epoch_buf);
        var epoch_decoder = tls.Decoder.fromTheirSlice(&epoch_buf);
        const epoch = epoch_decoder.decode(u64);
        
        const tree_hash_data = try tls_encode.readVarBytes(&tls.Decoder.fromTheirSlice(&[_]u8{}), u16, allocator);
        defer allocator.free(tree_hash_data);
        const tree_hash = try allocator.dupe(u8, tree_hash_data);
        errdefer allocator.free(tree_hash);
        
        const confirmed_transcript_hash_data = try tls_encode.readVarBytes(&tls.Decoder.fromTheirSlice(&[_]u8{}), u16, allocator);
        defer allocator.free(confirmed_transcript_hash_data);
        const confirmed_transcript_hash = try allocator.dupe(u8, confirmed_transcript_hash_data);
        errdefer allocator.free(confirmed_transcript_hash);
        
        const extensions_data = try tls_encode.readVarBytes(&tls.Decoder.fromTheirSlice(&[_]u8{}), u16, allocator);
        defer allocator.free(extensions_data);
        const extensions = try allocator.dupe(u8, extensions_data);

        return GroupContext{
            .protocol_version = protocol_version,
            .cipher_suite = cipher_suite,
            .group_id = group_id,
            .epoch = epoch,
            .tree_hash = tree_hash,
            .confirmed_transcript_hash = confirmed_transcript_hash,
            .extensions = extensions,
            .allocator = allocator,
        };
    }

    /// Compute serialized group context for signing
    pub fn computeBytes(self: GroupContext, allocator: Allocator) ![]u8 {
        var list = std.ArrayList(u8).init(allocator);
        defer list.deinit();

        // Serialize manually to avoid TlsWriter/ArrayList incompatibility
        // Protocol version
        try self.protocol_version.serialize(list.writer());
        // Cipher suite
        var cs_bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &cs_bytes, @intFromEnum(self.cipher_suite), .big);
        try list.appendSlice(&cs_bytes);
        // Group ID with length prefix
        var gid_len: [2]u8 = undefined;
        std.mem.writeInt(u16, &gid_len, @intCast(self.group_id.len), .big);
        try list.appendSlice(&gid_len);
        try list.appendSlice(self.group_id);
        // Epoch
        var epoch_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &epoch_bytes, self.epoch, .big);
        try list.appendSlice(&epoch_bytes);
        // Tree hash with length prefix
        var th_len: [2]u8 = undefined;
        std.mem.writeInt(u16, &th_len, @intCast(self.tree_hash.len), .big);
        try list.appendSlice(&th_len);
        try list.appendSlice(self.tree_hash);
        // Confirmed transcript hash with length prefix
        var cth_len: [2]u8 = undefined;
        std.mem.writeInt(u16, &cth_len, @intCast(self.confirmed_transcript_hash.len), .big);
        try list.appendSlice(&cth_len);
        try list.appendSlice(self.confirmed_transcript_hash);
        // Extensions with length prefix
        var ext_len: [2]u8 = undefined;
        std.mem.writeInt(u16, &ext_len, @intCast(self.extensions.len), .big);
        try list.appendSlice(&ext_len);
        try list.appendSlice(self.extensions);

        return list.toOwnedSlice();
    }
};

/// Welcome message for new members
pub const Welcome = struct {
    cipher_suite: CipherSuite,
    secrets: []u8, // Encrypted group secrets
    encrypted_group_info: []u8,
    allocator: std.mem.Allocator,

    pub fn init(
        allocator: Allocator,
        cipher_suite: CipherSuite,
        secrets: []const u8,
        group_info: []const u8,
    ) !Welcome {
        return Welcome{
            .cipher_suite = cipher_suite,
            .secrets = try allocator.dupe(u8, secrets),
            .encrypted_group_info = try allocator.dupe(u8, group_info),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Welcome) void {
        self.allocator.free(self.secrets);
        self.allocator.free(self.encrypted_group_info);
    }

    pub fn serialize(self: Welcome, writer: anytype) !void {
        // Manual TLS serialization using standard writer
        var buf: [4]u8 = undefined;
        
        // Cipher suite (u16)
        std.mem.writeInt(u16, buf[0..2], @intFromEnum(self.cipher_suite), .big);
        try writer.writeAll(buf[0..2]);
        
        // Secrets (variable bytes with u32 length)
        try tls_encode.writeVarBytes(writer, u32, self.secrets);
        
        // Encrypted group info (variable bytes with u32 length)
        try tls_encode.writeVarBytes(writer, u32, self.encrypted_group_info);
    }

    pub fn deserialize(allocator: Allocator, reader: anytype) !Welcome {
        // Read cipher suite
        var cs_buf: [2]u8 = undefined;
        _ = try reader.readAll(&cs_buf);
        var cs_decoder = tls.Decoder.fromTheirSlice(&cs_buf);
        const cipher_suite = @as(CipherSuite, @enumFromInt(cs_decoder.decode(u16)));
        
        // Read secrets length
        var secrets_len_buf: [4]u8 = undefined;
        _ = try reader.readAll(&secrets_len_buf);
        var secrets_decoder = tls.Decoder.fromTheirSlice(&secrets_len_buf);
        const secrets_len = secrets_decoder.decode(u32);
        const secrets = try allocator.alloc(u8, secrets_len);
        _ = try reader.readAll(secrets);
        errdefer allocator.free(secrets);
        
        // Read group info length
        var info_len_buf: [4]u8 = undefined;
        _ = try reader.readAll(&info_len_buf);
        var info_decoder = tls.Decoder.fromTheirSlice(&info_len_buf);
        const info_len = info_decoder.decode(u32);
        const encrypted_group_info = try allocator.alloc(u8, info_len);
        _ = try reader.readAll(encrypted_group_info);

        return Welcome{
            .cipher_suite = cipher_suite,
            .secrets = secrets,
            .encrypted_group_info = encrypted_group_info,
            .allocator = allocator,
        };
    }
};

/// Commit message
pub const Commit = struct {
    proposals: []ProposalRef,
    update_path: ?@import("tree_kem.zig").UpdatePath,

    pub fn init(
        allocator: Allocator,
        proposals: []const ProposalRef,
        update_path: ?@import("tree_kem.zig").UpdatePath,
    ) !Commit {
        const props = try allocator.alloc(ProposalRef, proposals.len);
        for (proposals, 0..) |prop, i| {
            props[i] = try ProposalRef.init(allocator, prop.proposal_hash);
        }

        return Commit{
            .proposals = props,
            .update_path = update_path,
        };
    }

    pub fn deinit(self: *Commit, allocator: Allocator) void {
        for (self.proposals) |*prop| {
            prop.deinit();
        }
        allocator.free(self.proposals);
        if (self.update_path) |*path| {
            path.deinit(allocator);
        }
    }
};

/// Main MLS group structure
pub const MlsGroup = struct {
    allocator: Allocator,
    cipher_suite: CipherSuite,
    group_context: GroupContext,
    tree: TreeSync,
    my_index: LeafNodeIndex,
    my_key_package_bundle: KeyPackageBundle,
    pending_proposals: std.ArrayList(Proposal),
    epoch_secrets: ?EpochSecrets,

    /// Create a new MLS group as the founder
    pub fn createGroup(
        allocator: Allocator,
        cipher_suite: CipherSuite,
        my_key_package_bundle: KeyPackageBundle,
        random_fn: ?wasm_random.RandomFunction,
    ) !MlsGroup {
        // Generate random group ID
        var group_id: [32]u8 = undefined;
        
        // Use provided random function or fall back to wasm_random
        if (random_fn) |rand_fn| {
            rand_fn(&group_id);
        } else {
            wasm_random.secure_random.bytes(&group_id);
        }

        var group_context = try GroupContext.init(allocator, cipher_suite, &group_id);
        errdefer group_context.deinit();

        // Create tree with just the founder
        var tree = try TreeSync.init(allocator, cipher_suite, 1);
        errdefer tree.deinit();

        // Add founder's leaf node
        // TODO: Add founder's leaf node to tree
        var founder_leaf = try LeafNode.fromKeyPackage(
            allocator,
            cipher_suite,
            my_key_package_bundle.key_package,
            my_key_package_bundle.private_signature_key,
        );
        defer founder_leaf.deinit(allocator);

        // TODO: Properly add founder to tree
        // For now, the tree is initialized with empty nodes

        return MlsGroup{
            .allocator = allocator,
            .cipher_suite = cipher_suite,
            .group_context = group_context,
            .tree = tree,
            .my_index = LeafNodeIndex.new(0),
            .my_key_package_bundle = my_key_package_bundle,
            .pending_proposals = std.ArrayList(Proposal).init(allocator),
            .epoch_secrets = null,
        };
    }

    pub fn deinit(self: *MlsGroup) void {
        self.group_context.deinit();
        self.tree.deinit();
        for (self.pending_proposals.items) |*prop| {
            prop.deinit(self.allocator);
        }
        self.pending_proposals.deinit();
        if (self.epoch_secrets) |*secrets| {
            secrets.deinit();
        }
    }

    /// Propose adding a new member
    pub fn proposeAdd(self: *MlsGroup, key_package: KeyPackage) !void {
        const proposal = Proposal{
            .add = AddProposal.init(key_package),
        };
        try self.pending_proposals.append(proposal);
    }

    /// Propose removing a member
    pub fn proposeRemove(self: *MlsGroup, removed_index: LeafNodeIndex) !void {
        const proposal = Proposal{
            .remove = RemoveProposal.init(removed_index),
        };
        try self.pending_proposals.append(proposal);
    }

    /// Commit pending proposals
    pub fn commit(self: *MlsGroup, random_fn: ?wasm_random.RandomFunction) !Commit {
        if (self.pending_proposals.items.len == 0) {
            return MlsGroupError.InvalidCommit;
        }

        // Create proposal references
        var proposals = try self.allocator.alloc(ProposalRef, self.pending_proposals.items.len);
        defer self.allocator.free(proposals);

        for (self.pending_proposals.items, 0..) |_, i| {
            // TODO: Compute actual proposal hash
            const dummy_hash = [_]u8{@intCast(i)} ** 32;
            proposals[i] = try ProposalRef.init(self.allocator, &dummy_hash);
        }

        // Create update path
        const group_context_bytes = try self.group_context.computeBytes(self.allocator);
        defer self.allocator.free(group_context_bytes);

        // Create new leaf node for update
        var new_leaf = try LeafNode.fromKeyPackage(
            self.allocator,
            self.cipher_suite,
            self.my_key_package_bundle.key_package,
            self.my_key_package_bundle.private_signature_key,
        );
        defer new_leaf.deinit(self.allocator);

        const update_result = try createUpdatePath(
            self.allocator,
            &self.tree,
            self.my_index,
            new_leaf,
            group_context_bytes,
            random_fn,
        );

        // Apply proposals
        for (self.pending_proposals.items) |prop| {
            try self.applyProposal(prop);
        }

        // Advance epoch
        self.group_context.epoch += 1;
        
        // Derive epoch secrets from commit secret
        const key_schedule = @import("key_schedule.zig").KeySchedule.init(self.allocator, self.cipher_suite);
        
        // Convert VarBytes epoch secrets to mls_group's Secret-based epoch secrets
        var derived_secrets = try key_schedule.deriveEpochSecrets(
            update_result.commit_secret,
            null, // No PSK for now
            group_context_bytes,
        );
        defer derived_secrets.deinit();
        
        // Free old epoch secrets if they exist
        if (self.epoch_secrets) |*old_secrets| {
            old_secrets.deinit();
        }
        
        // Convert ArrayList to Secret and store in MlsGroup's epoch_secrets
        self.epoch_secrets = EpochSecrets{
            .joiner_secret = try Secret.initFromSlice(self.allocator, derived_secrets.joiner_secret.items),
            .epoch_secret = try Secret.initFromSlice(self.allocator, derived_secrets.epoch_secret.items),
            .sender_data_secret = try Secret.initFromSlice(self.allocator, derived_secrets.sender_data_secret.items),
            .encryption_secret = try Secret.initFromSlice(self.allocator, derived_secrets.encryption_secret.items),
            .exporter_secret = try Secret.initFromSlice(self.allocator, derived_secrets.exporter_secret.items),
            .authentication_secret = try Secret.initFromSlice(self.allocator, derived_secrets.epoch_authenticator.items),
            .external_secret = try Secret.initFromSlice(self.allocator, derived_secrets.external_secret.items),
            .confirmation_key = try Secret.initFromSlice(self.allocator, derived_secrets.confirmation_key.items),
            .membership_key = try Secret.initFromSlice(self.allocator, derived_secrets.membership_key.items),
            .resumption_psk = try Secret.initFromSlice(self.allocator, derived_secrets.resumption_psk.items),
        };

        // Clear pending proposals
        for (self.pending_proposals.items) |*prop| {
            prop.deinit(self.allocator);
        }
        self.pending_proposals.clearRetainingCapacity();

        return Commit.init(self.allocator, proposals, update_result.update_path);
    }

    /// Apply a single proposal to the group state
    fn applyProposal(self: *MlsGroup, proposal: Proposal) !void {
        _ = self;
        switch (proposal) {
            .add => |add| {
                // TODO: Add member to tree
                _ = add;
            },
            .remove => |remove| {
                // TODO: Remove member from tree
                _ = remove;
            },
            .update => |update| {
                // TODO: Update member in tree
                _ = update;
            },
            else => return MlsGroupError.InvalidProposal,
        }
    }

    /// Generate a welcome message for new members
    pub fn generateWelcome(self: *MlsGroup) !Welcome {
        // TODO: Implement welcome generation
        // This would include:
        // 1. Encrypting group secrets to new members
        // 2. Creating GroupInfo with current tree state
        // 3. Encrypting GroupInfo

        const dummy_secrets = [_]u8{0x00} ** 32;
        const dummy_group_info = [_]u8{0x01} ** 64;

        return Welcome.init(
            self.allocator,
            self.cipher_suite,
            &dummy_secrets,
            &dummy_group_info,
        );
    }

    /// Process a welcome message to join a group
    pub fn processWelcome(
        allocator: Allocator,
        welcome: Welcome,
        my_key_package_bundle: KeyPackageBundle,
    ) !MlsGroup {
        // TODO: Implement welcome processing
        // This would include:
        // 1. Decrypting group secrets
        // 2. Decrypting and parsing GroupInfo
        // 3. Reconstructing tree state
        // 4. Finding our position in the tree

        // For now, create a dummy group
        const group = try createGroup(allocator, welcome.cipher_suite, my_key_package_bundle, null);
        return group;
    }

    /// Get current epoch
    pub fn epoch(self: MlsGroup) u64 {
        return self.group_context.epoch;
    }

    /// Get group ID
    pub fn groupId(self: MlsGroup) []const u8 {
        return self.group_context.group_id.asSlice();
    }
    
    /// Get the current group's exporter secret for key derivation
    /// Returns null if the group hasn't been initialized with epoch secrets yet
    pub fn getExporterSecret(self: MlsGroup) ?[]const u8 {
        if (self.epoch_secrets) |secrets| {
            return secrets.exporter_secret.asSlice();
        }
        return null;
    }
    
    /// Derive a NIP-44 key from the group's exporter secret
    /// This is the main function used for NIP-EE integration
    pub fn deriveNipeeKey(
        self: MlsGroup,
        allocator: Allocator,
        context: []const u8,
        length: u16,
    ) !?Secret {
        if (self.getExporterSecret()) |exporter_secret| {
            return self.cipher_suite.exporterSecret(
                allocator,
                exporter_secret,
                "nostr",
                context,
                length
            );
        }
        return null;
    }

    /// Serialize MlsGroup state to bytes for WASM compatibility
    /// TODO: This is a minimal implementation - expand incrementally as needed
    pub fn serialize(self: *const MlsGroup, allocator: Allocator) ![]u8 {
        var buffer = std.ArrayList(u8).init(allocator);
        errdefer buffer.deinit();
        
        // Serialize manually for now to avoid TlsWriter compatibility issues
        // Cipher suite (u16)
        const cs_bytes = std.mem.toBytes(std.mem.nativeToBig(u16, @intFromEnum(self.cipher_suite)));
        try buffer.appendSlice(&cs_bytes);
        
        // Epoch (u64)
        const epoch_bytes = std.mem.toBytes(std.mem.nativeToBig(u64, self.group_context.epoch));
        try buffer.appendSlice(&epoch_bytes);
        
        // My index (u32)
        const index_bytes = std.mem.toBytes(std.mem.nativeToBig(u32, self.my_index.asU32()));
        try buffer.appendSlice(&index_bytes);
        
        // Pending proposals count (u32)
        const prop_count = std.mem.toBytes(std.mem.nativeToBig(u32, @intCast(self.pending_proposals.items.len)));
        try buffer.appendSlice(&prop_count);
        
        // Group ID length and data
        const group_id_slice = self.group_context.group_id.asSlice();
        const group_id_len = std.mem.toBytes(std.mem.nativeToBig(u16, @intCast(group_id_slice.len)));
        try buffer.appendSlice(&group_id_len);
        try buffer.appendSlice(group_id_slice);
        
        return buffer.toOwnedSlice();
    }
    
    /// Deserialize MlsGroup state from bytes for WASM compatibility  
    /// TODO: This is a minimal implementation - expand incrementally as needed
    pub fn deserialize(allocator: Allocator, data: []const u8) !MlsGroup {
        if (data.len < 18) return error.InvalidData; // Minimum size check
        
        var offset: usize = 0;
        
        // Deserialize manually to match our manual serialization
        // Cipher suite (u16)
        const cs_value = std.mem.bigToNative(u16, std.mem.bytesToValue(u16, data[offset..offset+2]));
        offset += 2;
        const cipher_suite = @as(CipherSuite, @enumFromInt(cs_value));
        
        // Epoch (u64) 
        const epoch_value = std.mem.bigToNative(u64, std.mem.bytesToValue(u64, data[offset..offset+8]));
        offset += 8;
        
        // My index (u32)
        const my_index_val = std.mem.bigToNative(u32, std.mem.bytesToValue(u32, data[offset..offset+4]));
        offset += 4;
        
        // Pending proposals count (u32) - unused for now
        _ = std.mem.bigToNative(u32, std.mem.bytesToValue(u32, data[offset..offset+4]));
        offset += 4;
        
        // Group ID length and data
        if (offset + 2 > data.len) return error.InvalidData;
        const group_id_len = std.mem.bigToNative(u16, std.mem.bytesToValue(u16, data[offset..offset+2]));
        offset += 2;
        
        if (offset + group_id_len > data.len) return error.InvalidData;
        const group_id_data = data[offset..offset+group_id_len];
        
        // Create minimal group context
        var group_context = try GroupContext.init(allocator, cipher_suite, group_id_data[0..32]);
        group_context.epoch = epoch_value;
        
        // Create empty tree (TODO: serialize/deserialize properly)
        const tree = try TreeSync.init(allocator, cipher_suite, 1);
        
        // Create temporary key package bundle (TODO: serialize/deserialize properly)
        // For now, create a minimal one
        var temp_credential = try @import("credentials.zig").BasicCredential.init(allocator, "temp");
        defer temp_credential.deinit();
        var credential = try @import("credentials.zig").Credential.fromBasic(allocator, &temp_credential);
        defer credential.deinit();
        
        const key_package_bundle = try @import("key_package.zig").KeyPackageBundle.init(
            allocator,
            cipher_suite,
            credential,
            null, // random function
        );
        
        return MlsGroup{
            .allocator = allocator,
            .cipher_suite = cipher_suite,
            .group_context = group_context,
            .tree = tree,
            .my_index = @import("tree_math.zig").LeafNodeIndex.new(my_index_val),
            .my_key_package_bundle = key_package_bundle,
            .pending_proposals = std.ArrayList(Proposal).init(allocator),
            .epoch_secrets = null, // TODO: Serialize/deserialize epoch secrets
        };
    }
};

/// Epoch secrets derived from commit secret
pub const EpochSecrets = struct {
    joiner_secret: Secret,
    epoch_secret: Secret,
    sender_data_secret: Secret,
    encryption_secret: Secret,
    exporter_secret: Secret,
    authentication_secret: Secret,
    external_secret: Secret,
    confirmation_key: Secret,
    membership_key: Secret,
    resumption_psk: Secret,

    pub fn deinit(self: *EpochSecrets) void {
        self.joiner_secret.deinit();
        self.epoch_secret.deinit();
        self.sender_data_secret.deinit();
        self.encryption_secret.deinit();
        self.exporter_secret.deinit();
        self.authentication_secret.deinit();
        self.external_secret.deinit();
        self.confirmation_key.deinit();
        self.membership_key.deinit();
        self.resumption_psk.deinit();
    }

    // TODO: Add serialization for epoch secrets when needed
    // For now, not needed for minimal MlsGroup serialization
};

test "MLS group creation" {
    const allocator = testing.allocator;
    const cs = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    // Create credential
    var credential = try @import("credentials.zig").BasicCredential.init(
        allocator,
        &[_]u8{0x01} ** 32,
    );
    defer credential.deinit();

    var cred = try Credential.fromBasic(allocator, &credential);
    defer cred.deinit();

    // Create KeyPackageBundle
    var bundle = try KeyPackageBundle.init(allocator, cs, cred, null);
    defer bundle.deinit();

    // Create the group
    var group = try MlsGroup.createGroup(allocator, cs, bundle, null);
    defer group.deinit();

    // Verify group properties
    try testing.expectEqual(cs, group.cipher_suite);
    try testing.expectEqual(@as(u64, 0), group.epoch());
    try testing.expect(group.groupId().len == 32); // Random group ID should be 32 bytes

    // Verify tree state
    try testing.expectEqual(@as(u32, 1), group.tree.tree.leafCount());
}

test "Welcome message serialization" {
    const allocator = testing.allocator;
    const cs = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    const secrets = [_]u8{0x42} ** 32;
    const group_info = [_]u8{0x43} ** 64;

    var welcome = try Welcome.init(allocator, cs, &secrets, &group_info);
    defer welcome.deinit();

    // Test serialization
    var buffer: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);
    try welcome.serialize(stream.writer());

    // Test deserialization
    var read_stream = std.io.fixedBufferStream(buffer[0..stream.pos]);
    var decoded = try Welcome.deserialize(allocator, read_stream.reader());
    defer decoded.deinit();

    try testing.expectEqual(welcome.cipher_suite, decoded.cipher_suite);
    try testing.expectEqualSlices(u8, welcome.secrets, decoded.secrets);
}

test "Group context serialization" {
    const allocator = testing.allocator;
    const cs = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    const group_id = [_]u8{0x44} ** 32;
    var ctx = try GroupContext.init(allocator, cs, &group_id);
    defer ctx.deinit();

    ctx.epoch = 42;

    // Test compute bytes
    const bytes = try ctx.computeBytes(allocator);
    defer allocator.free(bytes);

    try testing.expect(bytes.len > 0);
}

test "Complete MLS flow with two members" {
    const allocator = testing.allocator;
    const cs = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    // Create founder credential and bundle
    var founder_cred = try @import("credentials.zig").BasicCredential.init(
        allocator,
        &[_]u8{0x01} ** 32,
    );
    defer founder_cred.deinit();

    var founder_credential = try Credential.fromBasic(allocator, &founder_cred);
    defer founder_credential.deinit();

    var founder_bundle = try KeyPackageBundle.init(allocator, cs, founder_credential, null);
    defer founder_bundle.deinit();

    // Create the group with founder
    var group = try MlsGroup.createGroup(allocator, cs, founder_bundle);
    defer group.deinit();

    // Verify initial state
    try testing.expectEqual(@as(u64, 0), group.epoch());
    try testing.expectEqual(@as(u32, 1), group.tree.tree.leafCount());

    // Create second member credential and bundle
    var member_cred = try @import("credentials.zig").BasicCredential.init(
        allocator,
        &[_]u8{0x02} ** 32,
    );
    defer member_cred.deinit();

    var member_credential = try Credential.fromBasic(allocator, &member_cred);
    defer member_credential.deinit();

    var member_bundle = try KeyPackageBundle.init(allocator, cs, member_credential, null);
    defer member_bundle.deinit();

    // Propose adding the second member
    try group.proposeAdd(member_bundle.key_package);

    // Verify proposal was added
    try testing.expectEqual(@as(usize, 1), group.pending_proposals.items.len);

    // Commit the proposal
    var commit = try group.commit();
    defer commit.deinit(allocator);

    // Verify state after commit
    try testing.expectEqual(@as(u64, 1), group.epoch()); // Epoch should advance
    try testing.expectEqual(@as(usize, 0), group.pending_proposals.items.len); // Proposals cleared

    // Generate welcome message
    var welcome = try group.generateWelcome();
    defer welcome.deinit();

    // Verify welcome message
    try testing.expectEqual(cs, welcome.cipher_suite);
    try testing.expect(welcome.secrets.asSlice().len > 0);
    try testing.expect(welcome.encrypted_group_info.asSlice().len > 0);
}

test "NIP-EE exporter secret integration" {
    const allocator = testing.allocator;
    const cs = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    // Create a group
    var founder_cred = try @import("credentials.zig").BasicCredential.init(
        allocator,
        &[_]u8{0x01} ** 32,
    );
    defer founder_cred.deinit();

    var founder_credential = try Credential.fromBasic(allocator, &founder_cred);
    defer founder_credential.deinit();

    var founder_bundle = try KeyPackageBundle.init(allocator, cs, founder_credential, null);
    defer founder_bundle.deinit();

    var group = try MlsGroup.createGroup(allocator, cs, founder_bundle);
    defer group.deinit();

    // Test exporter secret derivation for NIP-EE
    // This would be used to derive keys for NIP-44 encryption
    const dummy_exporter_secret = [_]u8{0x42} ** 32;
    const context = "conversation_key_v1";
    const length = 32;

    var nostr_key = try cs.exporterSecret(
        allocator,
        &dummy_exporter_secret,
        "nostr",
        context,
        length
    );
    defer nostr_key.deinit();

    // Verify the derived key
    try testing.expectEqual(@as(usize, length), nostr_key.asSlice().len);

    // Test that different contexts produce different keys
    var different_key = try cs.exporterSecret(
        allocator,
        &dummy_exporter_secret,
        "nostr",
        "different_context",
        length
    );
    defer different_key.deinit();

    try testing.expect(!std.mem.eql(u8, nostr_key.asSlice(), different_key.asSlice()));
}