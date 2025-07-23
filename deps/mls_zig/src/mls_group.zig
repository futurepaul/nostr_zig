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
const VarBytes = @import("tls_codec.zig").VarBytes;
const TlsReader = @import("tls_codec.zig").TlsReader;
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
        var tls_reader = TlsReader(@TypeOf(reader)).init(reader);
        const value = try tls_reader.readU16();
        return @enumFromInt(value);
    }
};

/// MLS content type
pub const ContentType = enum(u8) {
    application = 0x01,
    proposal = 0x02,
    commit = 0x03,

    pub fn serialize(self: ContentType, writer: anytype) !void {
        try writer.writeU8(@intFromEnum(self));
    }

    pub fn deserialize(reader: anytype) !ContentType {
        const value = try reader.readU8();
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
        var tls_reader = TlsReader(@TypeOf(reader)).init(reader);
        const value = try tls_reader.readU16();
        return @enumFromInt(value);
    }
};

/// Proposal reference for commit messages
pub const ProposalRef = struct {
    proposal_hash: VarBytes,

    pub fn init(allocator: Allocator, hash: []const u8) !ProposalRef {
        return ProposalRef{
            .proposal_hash = try VarBytes.init(allocator, hash),
        };
    }

    pub fn deinit(self: *ProposalRef) void {
        self.proposal_hash.deinit();
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
    group_id: VarBytes,
    epoch: u64,
    tree_hash: VarBytes,
    confirmed_transcript_hash: VarBytes,
    extensions: VarBytes,

    pub fn init(
        allocator: Allocator,
        cipher_suite: CipherSuite,
        group_id: []const u8,
    ) !GroupContext {
        return GroupContext{
            .protocol_version = .mls10,
            .cipher_suite = cipher_suite,
            .group_id = try VarBytes.init(allocator, group_id),
            .epoch = 0,
            .tree_hash = try VarBytes.init(allocator, &[_]u8{}),
            .confirmed_transcript_hash = try VarBytes.init(allocator, &[_]u8{}),
            .extensions = try VarBytes.init(allocator, &[_]u8{}),
        };
    }

    pub fn deinit(self: *GroupContext) void {
        self.group_id.deinit();
        self.tree_hash.deinit();
        self.confirmed_transcript_hash.deinit();
        self.extensions.deinit();
    }

    pub fn serialize(self: GroupContext, writer: anytype) !void {
        // Manual TLS serialization using standard writer
        try self.protocol_version.serialize(writer);
        
        // Cipher suite (u16)
        var buf: [8]u8 = undefined;
        std.mem.writeInt(u16, buf[0..2], @intFromEnum(self.cipher_suite), .big);
        try writer.writeAll(buf[0..2]);
        
        // Group ID (variable bytes with u16 length)
        std.mem.writeInt(u16, buf[0..2], @intCast(self.group_id.asSlice().len), .big);
        try writer.writeAll(buf[0..2]);
        try writer.writeAll(self.group_id.asSlice());
        
        // Epoch (u64)
        std.mem.writeInt(u64, buf[0..8], self.epoch, .big);
        try writer.writeAll(buf[0..8]);
        
        // Tree hash (variable bytes with u16 length)
        std.mem.writeInt(u16, buf[0..2], @intCast(self.tree_hash.asSlice().len), .big);
        try writer.writeAll(buf[0..2]);
        try writer.writeAll(self.tree_hash.asSlice());
        
        // Confirmed transcript hash (variable bytes with u16 length)
        std.mem.writeInt(u16, buf[0..2], @intCast(self.confirmed_transcript_hash.asSlice().len), .big);
        try writer.writeAll(buf[0..2]);
        try writer.writeAll(self.confirmed_transcript_hash.asSlice());
        
        // Extensions (variable bytes with u16 length)
        std.mem.writeInt(u16, buf[0..2], @intCast(self.extensions.asSlice().len), .big);
        try writer.writeAll(buf[0..2]);
        try writer.writeAll(self.extensions.asSlice());
    }

    pub fn deserialize(allocator: Allocator, reader: anytype) !GroupContext {
        var tls_reader = TlsReader(@TypeOf(reader)).init(reader);
        const protocol_version = try ProtocolVersion.deserialize(reader);
        const cipher_suite = @as(CipherSuite, @enumFromInt(try tls_reader.readU16()));
        const group_id_data = try tls_reader.readVarBytes(u16, allocator);
        defer allocator.free(group_id_data);
        var group_id = try VarBytes.init(allocator, group_id_data);
        errdefer group_id.deinit();
        const epoch = try reader.readU64();
        const tree_hash_data = try reader.readVarBytes(u16, allocator);
        defer allocator.free(tree_hash_data);
        var tree_hash = try VarBytes.init(allocator, tree_hash_data);
        errdefer tree_hash.deinit();
        const confirmed_transcript_hash_data = try reader.readVarBytes(u16, allocator);
        defer allocator.free(confirmed_transcript_hash_data);
        var confirmed_transcript_hash = try VarBytes.init(allocator, confirmed_transcript_hash_data);
        errdefer confirmed_transcript_hash.deinit();
        const extensions_data = try reader.readVarBytes(u16, allocator);
        defer allocator.free(extensions_data);
        const extensions = try VarBytes.init(allocator, extensions_data);

        return GroupContext{
            .protocol_version = protocol_version,
            .cipher_suite = cipher_suite,
            .group_id = group_id,
            .epoch = epoch,
            .tree_hash = tree_hash,
            .confirmed_transcript_hash = confirmed_transcript_hash,
            .extensions = extensions,
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
        std.mem.writeInt(u16, &gid_len, @intCast(self.group_id.asSlice().len), .big);
        try list.appendSlice(&gid_len);
        try list.appendSlice(self.group_id.asSlice());
        // Epoch
        var epoch_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &epoch_bytes, self.epoch, .big);
        try list.appendSlice(&epoch_bytes);
        // Tree hash with length prefix
        var th_len: [2]u8 = undefined;
        std.mem.writeInt(u16, &th_len, @intCast(self.tree_hash.asSlice().len), .big);
        try list.appendSlice(&th_len);
        try list.appendSlice(self.tree_hash.asSlice());
        // Confirmed transcript hash with length prefix
        var cth_len: [2]u8 = undefined;
        std.mem.writeInt(u16, &cth_len, @intCast(self.confirmed_transcript_hash.asSlice().len), .big);
        try list.appendSlice(&cth_len);
        try list.appendSlice(self.confirmed_transcript_hash.asSlice());
        // Extensions with length prefix
        var ext_len: [2]u8 = undefined;
        std.mem.writeInt(u16, &ext_len, @intCast(self.extensions.asSlice().len), .big);
        try list.appendSlice(&ext_len);
        try list.appendSlice(self.extensions.asSlice());

        return list.toOwnedSlice();
    }
};

/// Welcome message for new members
pub const Welcome = struct {
    cipher_suite: CipherSuite,
    secrets: VarBytes, // Encrypted group secrets
    encrypted_group_info: VarBytes,

    pub fn init(
        allocator: Allocator,
        cipher_suite: CipherSuite,
        secrets: []const u8,
        group_info: []const u8,
    ) !Welcome {
        return Welcome{
            .cipher_suite = cipher_suite,
            .secrets = try VarBytes.init(allocator, secrets),
            .encrypted_group_info = try VarBytes.init(allocator, group_info),
        };
    }

    pub fn deinit(self: *Welcome) void {
        self.secrets.deinit();
        self.encrypted_group_info.deinit();
    }

    pub fn serialize(self: Welcome, writer: anytype) !void {
        // Manual TLS serialization using standard writer
        var buf: [4]u8 = undefined;
        
        // Cipher suite (u16)
        std.mem.writeInt(u16, buf[0..2], @intFromEnum(self.cipher_suite), .big);
        try writer.writeAll(buf[0..2]);
        
        // Secrets (variable bytes with u32 length)
        std.mem.writeInt(u32, buf[0..4], @intCast(self.secrets.asSlice().len), .big);
        try writer.writeAll(buf[0..4]);
        try writer.writeAll(self.secrets.asSlice());
        
        // Encrypted group info (variable bytes with u32 length)
        std.mem.writeInt(u32, buf[0..4], @intCast(self.encrypted_group_info.asSlice().len), .big);
        try writer.writeAll(buf[0..4]);
        try writer.writeAll(self.encrypted_group_info.asSlice());
    }

    pub fn deserialize(allocator: Allocator, reader: anytype) !Welcome {
        var tls_reader = TlsReader(@TypeOf(reader)).init(reader);
        const cipher_suite = @as(CipherSuite, @enumFromInt(try tls_reader.readU16()));
        const secrets_data = try tls_reader.readVarBytes(u32, allocator);
        defer allocator.free(secrets_data);
        var secrets = try VarBytes.init(allocator, secrets_data);
        errdefer secrets.deinit();
        const group_info_data = try tls_reader.readVarBytes(u32, allocator);
        defer allocator.free(group_info_data);
        const encrypted_group_info = try VarBytes.init(allocator, group_info_data);

        return Welcome{
            .cipher_suite = cipher_suite,
            .secrets = secrets,
            .encrypted_group_info = encrypted_group_info,
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
            props[i] = try ProposalRef.init(allocator, prop.proposal_hash.asSlice());
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
    var reader = TlsReader(@TypeOf(read_stream.reader())).init(read_stream.reader());
    var decoded = try Welcome.deserialize(allocator, &reader);
    defer decoded.deinit();

    try testing.expectEqual(welcome.cipher_suite, decoded.cipher_suite);
    try testing.expectEqualSlices(u8, welcome.secrets.asSlice(), decoded.secrets.asSlice());
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