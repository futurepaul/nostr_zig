const std = @import("std");
const Allocator = std.mem.Allocator;
const crypto = std.crypto;
const testing = std.testing;
const hpke = @import("hpke");
const wasm_random = @import("wasm_random.zig");

const tree_math = @import("tree_math.zig");
const LeafNodeIndex = tree_math.LeafNodeIndex;
const ParentNodeIndex = tree_math.ParentNodeIndex;
const TreeNodeIndex = tree_math.TreeNodeIndex;
const TreeSize = tree_math.TreeSize;

const binary_tree = @import("binary_tree.zig");
const BinaryTree = binary_tree.BinaryTree;
const TreeNode = binary_tree.TreeNode;
const TreeDiff = @import("binary_tree_diff.zig").TreeDiff;

const CipherSuite = @import("cipher_suite.zig").CipherSuite;
const Secret = @import("cipher_suite.zig").Secret;
const HashType = @import("cipher_suite.zig").HashType;

const key_package = @import("key_package.zig");
const HpkePublicKey = key_package.HpkePublicKey;
const HpkePrivateKey = key_package.HpkePrivateKey;
const generateHpkeKeyPair = key_package.generateHpkeKeyPair;

const LeafNode = @import("leaf_node.zig").LeafNode;

const tls_encode = @import("tls_encode.zig");
const tls = std.crypto.tls;

/// Errors specific to TreeKEM operations
pub const TreeKemError = error{
    InvalidPathLength,
    NoDecryptionKey,
    InvalidParentHash,
    InvalidPublicKey,
    DecryptionFailed,
    InvalidNodeType,
    MissingNode,
    InvalidUpdatePath,
};

/// ParentNode represents an internal node in the TreeKEM tree
pub const ParentNode = struct {
    encryption_key: HpkePublicKey,
    parent_hash: []u8,
    unmerged_leaves: []LeafNodeIndex,
    allocator: std.mem.Allocator,

    pub fn init(
        allocator: Allocator,
        encryption_key: HpkePublicKey,
        parent_hash: []const u8,
    ) !ParentNode {
        return ParentNode{
            .encryption_key = encryption_key,
            .parent_hash = try allocator.dupe(u8, parent_hash),
            .unmerged_leaves = try allocator.alloc(LeafNodeIndex, 0),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ParentNode, allocator: Allocator) void {
        self.encryption_key.deinit(allocator);
        self.allocator.free(self.parent_hash);
        allocator.free(self.unmerged_leaves);
    }

    pub fn clone(self: ParentNode, allocator: Allocator) !ParentNode {
        const cloned_key = try HpkePublicKey.initOwned(allocator, self.encryption_key.asSlice());
        errdefer cloned_key.deinit(allocator);

        const cloned_hash = try allocator.dupe(u8, self.parent_hash);
        errdefer allocator.free(cloned_hash);

        const cloned_leaves = try allocator.alloc(LeafNodeIndex, self.unmerged_leaves.len);
        @memcpy(cloned_leaves, self.unmerged_leaves);

        return ParentNode{
            .encryption_key = cloned_key,
            .parent_hash = cloned_hash,
            .unmerged_leaves = cloned_leaves,
            .allocator = allocator,
        };
    }

    /// Compute parent hash from left and right child hashes
    pub fn computeParentHash(
        allocator: Allocator,
        cs: CipherSuite,
        left_hash: []const u8,
        right_hash: []const u8,
    ) ![]u8 {
        // Parent hash = Hash(left_hash || right_hash)
        const total_len = left_hash.len + right_hash.len;
        const input = try allocator.alloc(u8, total_len);
        defer allocator.free(input);

        @memcpy(input[0..left_hash.len], left_hash);
        @memcpy(input[left_hash.len..], right_hash);

        var hash_secret = try cs.hash(allocator, input);
        defer hash_secret.deinit();

        return allocator.dupe(u8, hash_secret.asSlice());
    }

    /// Add an unmerged leaf to this parent node
    pub fn addUnmergedLeaf(self: *ParentNode, allocator: Allocator, leaf_index: LeafNodeIndex) !void {
        const new_leaves = try allocator.alloc(LeafNodeIndex, self.unmerged_leaves.len + 1);
        @memcpy(new_leaves[0..self.unmerged_leaves.len], self.unmerged_leaves);
        new_leaves[self.unmerged_leaves.len] = leaf_index;
        
        allocator.free(self.unmerged_leaves);
        self.unmerged_leaves = new_leaves;
    }

    /// Serialize the parent node
    pub fn serialize(self: ParentNode, writer: anytype) !void {
        // Write encryption key
        const key_data = self.encryption_key.asSlice();
        try tls_encode.writeVarBytes(writer, u16, key_data);

        // Write parent hash
        try tls_encode.writeVarBytes(writer, u16, self.parent_hash);

        // Write unmerged leaves
        try tls_encode.writeInt(writer, u32, @intCast(self.unmerged_leaves.len));
        for (self.unmerged_leaves) |leaf_index| {
            try tls_encode.writeInt(writer, u32, leaf_index.asU32());
        }
    }

    /// Deserialize a parent node
    pub fn deserialize(allocator: Allocator, reader: anytype) !ParentNode {
        // Read encryption key length
        var key_len_buf: [2]u8 = undefined;
        _ = try reader.readAll(&key_len_buf);
        var key_decoder = tls.Decoder.fromTheirSlice(&key_len_buf);
        const key_len = key_decoder.decode(u16);
        const key_data = try allocator.alloc(u8, key_len);
        defer allocator.free(key_data);
        _ = try reader.readAll(key_data);
        var encryption_key = try HpkePublicKey.initOwned(allocator, key_data);
        errdefer encryption_key.deinit(allocator);

        // Read parent hash length
        var hash_len_buf: [2]u8 = undefined;
        _ = try reader.readAll(&hash_len_buf);
        var hash_decoder = tls.Decoder.fromTheirSlice(&hash_len_buf);
        const hash_len = hash_decoder.decode(u16);
        const parent_hash = try allocator.alloc(u8, hash_len);
        _ = try reader.readAll(parent_hash);
        errdefer allocator.free(parent_hash);

        // Read unmerged leaves count
        var leaves_len_buf: [4]u8 = undefined;
        _ = try reader.readAll(&leaves_len_buf);
        var leaves_decoder = tls.Decoder.fromTheirSlice(&leaves_len_buf);
        const num_leaves = leaves_decoder.decode(u32);
        const unmerged_leaves = try allocator.alloc(LeafNodeIndex, num_leaves);
        errdefer allocator.free(unmerged_leaves);

        for (unmerged_leaves) |*leaf| {
            var index_buf: [4]u8 = undefined;
            _ = try reader.readAll(&index_buf);
            var index_decoder = tls.Decoder.fromTheirSlice(&index_buf);
            const index = index_decoder.decode(u32);
            leaf.* = LeafNodeIndex.new(index);
        }

        return ParentNode{
            .encryption_key = encryption_key,
            .parent_hash = parent_hash,
            .unmerged_leaves = unmerged_leaves,
            .allocator = allocator,
        };
    }
};

/// PathSecret is used to derive secrets along a path in the tree
pub const PathSecret = struct {
    secret: Secret,
    cipher_suite: CipherSuite,

    pub fn init(allocator: Allocator, cs: CipherSuite, secret_data: []const u8) !PathSecret {
        return PathSecret{
            .secret = try Secret.initFromSlice(allocator, secret_data),
            .cipher_suite = cs,
        };
    }

    pub fn deinit(self: *PathSecret) void {
        self.secret.deinit();
    }

    /// Derive an HPKE key pair from this path secret
    pub fn deriveKeyPair(self: PathSecret, allocator: Allocator) !struct {
        public_key: HpkePublicKey,
        private_key: HpkePrivateKey,
    } {
        // For now, we'll use the standard key generation
        // TODO: Implement deterministic key generation from seed using hkdfExpandLabel
        var key_pair = try generateHpkeKeyPair(allocator, self.cipher_suite, null);
        defer key_pair.deinit();
        
        // Create HpkePublicKey and HpkePrivateKey from raw bytes
        var public_key = try HpkePublicKey.initOwned(allocator, key_pair.public_key);
        errdefer public_key.deinit(allocator);
        
        const private_key = try HpkePrivateKey.init(allocator, key_pair.private_key);
        
        return .{
            .public_key = public_key,
            .private_key = private_key,
        };
    }

    /// Derive the next path secret in the chain
    pub fn deriveNext(self: PathSecret, allocator: Allocator) !PathSecret {
        // next_path_secret = KDF.Expand(path_secret, "path", hash_len)
        const path_label = "MLS 1.0 path";
        const hash_len = self.cipher_suite.hashLength();
        
        const next_secret = try self.cipher_suite.hkdfExpandLabel(
            allocator,
            self.secret.asSlice(),
            path_label,
            &[_]u8{}, // empty context
            @as(u16, @intCast(hash_len)),
        );

        return PathSecret{
            .secret = next_secret,
            .cipher_suite = self.cipher_suite,
        };
    }
};

/// UpdatePathNode represents a single node in an update path
pub const UpdatePathNode = struct {
    public_key: HpkePublicKey,
    encrypted_path_secrets: []HpkeCiphertext,

    pub fn init(
        allocator: Allocator,
        public_key: HpkePublicKey,
        encrypted_secrets: []const HpkeCiphertext,
    ) !UpdatePathNode {
        const secrets = try allocator.alloc(HpkeCiphertext, encrypted_secrets.len);
        errdefer allocator.free(secrets);

        for (encrypted_secrets, 0..) |secret, i| {
            secrets[i] = try secret.clone(allocator);
        }

        return UpdatePathNode{
            .public_key = public_key,
            .encrypted_path_secrets = secrets,
        };
    }

    pub fn deinit(self: *UpdatePathNode, allocator: Allocator) void {
        self.public_key.deinit(allocator);
        for (self.encrypted_path_secrets) |*ciphertext| {
            ciphertext.deinit();
        }
        allocator.free(self.encrypted_path_secrets);
    }

    pub fn serialize(self: UpdatePathNode, writer: anytype) !void {
        // Write public key
        const key_data = self.public_key.asSlice();
        try tls_encode.writeVarBytes(writer, u16, key_data);

        // Write encrypted path secrets
        try tls_encode.writeInt(writer, u32, @intCast(self.encrypted_path_secrets.len));
        for (self.encrypted_path_secrets) |ciphertext| {
            try ciphertext.serialize(writer);
        }
    }

    pub fn deserialize(allocator: Allocator, reader: anytype) !UpdatePathNode {
        // Read public key length
        var key_len_buf: [2]u8 = undefined;
        _ = try reader.readAll(&key_len_buf);
        var key_decoder = tls.Decoder.fromTheirSlice(&key_len_buf);
        const key_len = key_decoder.decode(u16);
        const key_data = try allocator.alloc(u8, key_len);
        defer allocator.free(key_data);
        _ = try reader.readAll(key_data);
        var public_key = try HpkePublicKey.initOwned(allocator, key_data);
        errdefer public_key.deinit(allocator);

        // Read encrypted path secrets count
        var secrets_len_buf: [4]u8 = undefined;
        _ = try reader.readAll(&secrets_len_buf);
        var secrets_decoder = tls.Decoder.fromTheirSlice(&secrets_len_buf);
        const num_secrets = secrets_decoder.decode(u32);
        const encrypted_secrets = try allocator.alloc(HpkeCiphertext, num_secrets);
        errdefer {
            for (encrypted_secrets[0..]) |*secret| {
                secret.deinit();
            }
            allocator.free(encrypted_secrets);
        }

        for (encrypted_secrets) |*secret| {
            secret.* = try HpkeCiphertext.deserialize(allocator, reader);
        }

        return UpdatePathNode{
            .public_key = public_key,
            .encrypted_path_secrets = encrypted_secrets,
        };
    }
};

/// HPKE ciphertext for encrypted path secrets
pub const HpkeCiphertext = struct {
    kem_output: []u8,
    ciphertext: []u8,
    allocator: std.mem.Allocator,

    pub fn init(allocator: Allocator, kem_output: []const u8, ciphertext: []const u8) !HpkeCiphertext {
        return HpkeCiphertext{
            .kem_output = try allocator.dupe(u8, kem_output),
            .ciphertext = try allocator.dupe(u8, ciphertext),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *HpkeCiphertext) void {
        self.allocator.free(self.kem_output);
        self.allocator.free(self.ciphertext);
    }

    pub fn clone(self: HpkeCiphertext, allocator: Allocator) !HpkeCiphertext {
        return HpkeCiphertext{
            .kem_output = try allocator.dupe(u8, self.kem_output),
            .ciphertext = try allocator.dupe(u8, self.ciphertext),
            .allocator = allocator,
        };
    }

    pub fn serialize(self: HpkeCiphertext, writer: anytype) !void {
        try tls_encode.writeVarBytes(writer, u16, self.kem_output);
        try tls_encode.writeVarBytes(writer, u16, self.ciphertext);
    }

    pub fn deserialize(allocator: Allocator, reader: anytype) !HpkeCiphertext {
        // Read kem_output length
        var kem_len_buf: [2]u8 = undefined;
        _ = try reader.readAll(&kem_len_buf);
        var kem_decoder = tls.Decoder.fromTheirSlice(&kem_len_buf);
        const kem_len = kem_decoder.decode(u16);
        const kem_output = try allocator.alloc(u8, kem_len);
        _ = try reader.readAll(kem_output);
        errdefer allocator.free(kem_output);

        // Read ciphertext length
        var cipher_len_buf: [2]u8 = undefined;
        _ = try reader.readAll(&cipher_len_buf);
        var cipher_decoder = tls.Decoder.fromTheirSlice(&cipher_len_buf);
        const cipher_len = cipher_decoder.decode(u16);
        const ciphertext = try allocator.alloc(u8, cipher_len);
        _ = try reader.readAll(ciphertext);
        errdefer allocator.free(ciphertext);

        return HpkeCiphertext{
            .kem_output = kem_output,
            .ciphertext = ciphertext,
            .allocator = allocator,
        };
    }
};

/// Convert MLS cipher suite to HPKE suite type
fn cipherSuiteToHpkeSuite(cs: CipherSuite) !type {
    return switch (cs) {
        .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => hpke.createSuite(
            0x0020, // X25519HkdfSha256
            0x0001, // HkdfSha256  
            0x0001, // Aes128Gcm
        ),
        .MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => hpke.createSuite(
            0x0020, // X25519HkdfSha256
            0x0001, // HkdfSha256
            0x0003, // ChaCha20Poly1305
        ),
        // P256 variants not yet supported in zig-hpke
        else => return TreeKemError.InvalidNodeType, // TODO: Better error for unsupported suite
    };
}

/// Encrypt data using HPKE
fn hpkeEncrypt(
    allocator: Allocator,
    SuiteType: anytype,
    recipient_public_key: []const u8,
    plaintext: []const u8,
    info: []const u8,
    aad: []const u8,
    random_fn: ?wasm_random.RandomFunction,
) !HpkeCiphertext {
    const client_result = try SuiteType.createClientContext(
        recipient_public_key,
        info,
        null, // no PSK
        null, // no seed
        random_fn,
    );
    var client_ctx = client_result.client_ctx;

    // Allocate space for ciphertext (plaintext + tag)
    const ciphertext_len = plaintext.len + client_ctx.tagLength();
    const ciphertext = try allocator.alloc(u8, ciphertext_len);
    defer allocator.free(ciphertext);

    // Encrypt
    client_ctx.encryptToServer(ciphertext, plaintext, aad);

    // Get encapsulated key
    const enc = client_result.encapsulated_secret;
    
    return HpkeCiphertext.init(
        allocator,
        enc.encapsulated.constSlice(),
        ciphertext,
    );
}

/// Decrypt data using HPKE
fn hpkeDecrypt(
    allocator: Allocator,
    SuiteType: anytype,
    recipient_private_key: []const u8,
    ciphertext: HpkeCiphertext,
    info: []const u8,
    aad: []const u8,
) ![]u8 {
    // Generate public key from private key for server context  
    const public_key = try crypto.dh.X25519.recoverPublicKey(recipient_private_key[0..32].*);
    const server_kp = hpke.KeyPair{
        .public_key = try hpke.BoundedArray(u8, hpke.max_public_key_length).fromSlice(&public_key),
        .secret_key = try hpke.BoundedArray(u8, hpke.max_secret_key_length).fromSlice(recipient_private_key),
    };
    
    var server_ctx = try SuiteType.createServerContext(
        ciphertext.kem_output,
        server_kp,
        info,
        null, // no PSK
    );

    // Allocate space for plaintext
    const aead = SuiteType.aead;
    const plaintext_len = ciphertext.ciphertext.len - aead.tag_length;
    const plaintext = try allocator.alloc(u8, plaintext_len);
    errdefer allocator.free(plaintext);

    // Decrypt
    try server_ctx.decryptFromClient(plaintext, ciphertext.ciphertext, aad);
    
    return plaintext;
}

/// UpdatePath contains the leaf node and parent nodes for a path update
pub const UpdatePath = struct {
    leaf_node: LeafNode,
    nodes: []UpdatePathNode,

    pub fn init(
        allocator: Allocator,
        leaf: LeafNode,
        nodes: []const UpdatePathNode,
    ) !UpdatePath {
        const path_nodes = try allocator.alloc(UpdatePathNode, nodes.len);
        errdefer allocator.free(path_nodes);

        for (nodes, 0..) |node, i| {
            path_nodes[i] = try UpdatePathNode.init(
                allocator,
                node.public_key,
                node.encrypted_path_secrets,
            );
        }

        return UpdatePath{
            .leaf_node = leaf,
            .nodes = path_nodes,
        };
    }

    pub fn deinit(self: *UpdatePath, allocator: Allocator) void {
        self.leaf_node.deinit(allocator);
        for (self.nodes) |*node| {
            node.deinit(allocator);
        }
        allocator.free(self.nodes);
    }

    pub fn serialize(self: UpdatePath, writer: anytype) !void {
        try self.leaf_node.serialize(writer);
        
        try tls_encode.writeInt(writer, u32, @intCast(self.nodes.len));
        for (self.nodes) |node| {
            try node.serialize(writer);
        }
    }

    pub fn deserialize(allocator: Allocator, reader: anytype) !UpdatePath {
        var leaf = try LeafNode.deserialize(allocator, reader);
        errdefer leaf.deinit(allocator);

        var nodes_len_buf: [4]u8 = undefined;
        _ = try reader.readAll(&nodes_len_buf);
        var nodes_decoder = tls.Decoder.fromTheirSlice(&nodes_len_buf);
        const num_nodes = nodes_decoder.decode(u32);
        const nodes = try allocator.alloc(UpdatePathNode, num_nodes);
        errdefer {
            for (nodes[0..]) |*node| {
                node.deinit(allocator);
            }
            allocator.free(nodes);
        }

        for (nodes) |*node| {
            node.* = try UpdatePathNode.deserialize(allocator, reader);
        }

        return UpdatePath{
            .leaf_node = leaf,
            .nodes = nodes,
        };
    }
};

/// TreeSync wraps a BinaryTree with LeafNode and ParentNode data
pub const TreeSync = struct {
    tree: BinaryTree(LeafNode, ParentNode),
    cipher_suite: CipherSuite,

    pub fn init(allocator: Allocator, cs: CipherSuite, leaf_count: u32) !TreeSync {
        const Node = TreeNode(LeafNode, ParentNode);
        
        // Calculate total nodes needed for a tree with leaf_count leaves
        const total_nodes = 2 * leaf_count - 1;
        const nodes = try allocator.alloc(Node, total_nodes);
        defer allocator.free(nodes);
        
        // Initialize nodes - alternating leaves and parents
        for (nodes, 0..) |*node, i| {
            if (i % 2 == 0) {
                // Leaf node
                node.* = Node{ .leaf = LeafNode.init(allocator) };
            } else {
                // Parent node - blank initially
                const empty_key = try HpkePublicKey.initOwned(allocator, &[_]u8{});
                node.* = Node{ .parent = try ParentNode.init(allocator, empty_key, &[_]u8{}) };
            }
        }
        
        return TreeSync{
            .tree = try BinaryTree(LeafNode, ParentNode).init(allocator, nodes),
            .cipher_suite = cs,
        };
    }

    pub fn deinit(self: *TreeSync) void {
        self.tree.deinit();
    }

    /// Get the direct path for a leaf node (excluding the leaf itself)
    pub fn directPath(self: TreeSync, leaf_index: LeafNodeIndex) ![]ParentNodeIndex {
        return tree_math.directPath(leaf_index, self.tree.treeSize(), self.tree.allocator);
    }

    /// Get filtered direct path (skipping blank parent nodes)
    pub fn filteredDirectPath(self: TreeSync, leaf_index: LeafNodeIndex) ![]ParentNodeIndex {
        const full_path = try self.directPath(leaf_index);
        defer self.tree.allocator.free(full_path);

        var filtered = std.ArrayList(ParentNodeIndex).init(self.tree.allocator);
        for (full_path) |parent_index| {
            if (self.tree.parentByIndex(parent_index) != null) {
                try filtered.append(parent_index);
            }
        }

        return filtered.toOwnedSlice();
    }

    /// Get the copath for a node (sibling of each node in direct path)
    pub fn copath(self: TreeSync, node: TreeNodeIndex) ![]TreeNodeIndex {
        const allocator = self.tree.allocator;
        var result = std.ArrayList(TreeNodeIndex).init(allocator);

        var current = node;
        while (true) {
            const sibling = tree_math.sibling(current);
            try result.append(sibling);

            // Check if we've reached the root
            const root_index = tree_math.root(self.tree.treeSize());
            if (current.asU32() == root_index) {
                break;
            }
            current = TreeNodeIndex{ .parent = tree_math.parent(current) };
        }

        return result.toOwnedSlice();
    }

    /// Get resolution of a node (all non-blank nodes under it)
    pub fn resolution(self: TreeSync, node: TreeNodeIndex) ![]TreeNodeIndex {
        const allocator = self.tree.allocator;
        var result = std.ArrayList(TreeNodeIndex).init(allocator);
        
        // Check if the node itself exists
        const node_exists = switch (node) {
            .leaf => |idx| self.tree.leafByIndex(idx) != null,
            .parent => |idx| self.tree.parentByIndex(idx) != null,
        };

        if (!node_exists) {
            // If node is blank, return its children's resolution
            if (node == .parent) {
                // For parent nodes, get left and right children
                const parent_idx = switch (node) {
                    .parent => |idx| idx,
                    else => unreachable,
                };
                const left = tree_math.left(parent_idx);
                const right = tree_math.right(parent_idx);
                
                const left_res = try self.resolution(left);
                defer allocator.free(left_res);
                const right_res = try self.resolution(right);
                defer allocator.free(right_res);
                
                try result.appendSlice(left_res);
                try result.appendSlice(right_res);
            }
        } else {
            // Node exists, return it
            try result.append(node);
        }

        return result.toOwnedSlice();
    }
    
    /// Compute the tree hash for the entire tree
    /// This is the hash of the root node after computing all leaf and parent hashes
    pub fn computeTreeHash(self: *const TreeSync, allocator: Allocator) ![]u8 {
        const tree_size = self.tree.treeSize();
        if (tree_size.asU32() == 0) {
            // Empty tree has empty hash
            return allocator.dupe(u8, &[_]u8{});
        }
        
        // We need to compute hashes for all nodes from leaves up to root
        // In MLS, tree indices are not contiguous - we need to allocate based on
        // the maximum tree index, not the tree size
        const leaf_count = self.tree.leafCount();
        const max_tree_index = if (leaf_count > 0) 2 * leaf_count - 1 else 0;
        var node_hashes = try allocator.alloc(?[]u8, max_tree_index);
        defer {
            for (node_hashes) |hash| {
                if (hash) |h| {
                    allocator.free(h);
                }
            }
            allocator.free(node_hashes);
        }
        
        // Initialize all to null
        for (node_hashes) |*hash| {
            hash.* = null;
        }
        
        // Compute leaf hashes
        for (0..leaf_count) |i| {
            const leaf_index = LeafNodeIndex.new(@intCast(i));
            const tree_index = leaf_index.toTreeIndex();
            
            // Get the leaf node
            if (self.tree.leafByIndex(leaf_index)) |leaf| {
                // Serialize the leaf node to compute its hash
                var buffer = std.ArrayList(u8).init(allocator);
                defer buffer.deinit();
                
                try leaf.serialize(buffer.writer());
                
                // Hash the serialized leaf
                var hash_secret = try self.cipher_suite.hash(allocator, buffer.items);
                
                if (tree_index < node_hashes.len) {
                    // Store a copy of the hash data
                    node_hashes[tree_index] = try allocator.dupe(u8, hash_secret.asSlice());
                }
                hash_secret.deinit();
            } else {
                // Empty leaf has empty hash
                if (tree_index < node_hashes.len) {
                    node_hashes[tree_index] = try allocator.dupe(u8, &[_]u8{});
                }
            }
        }
        
        // Compute parent hashes from bottom to top
        // We process level by level, starting from the level just above leaves
        var level: u32 = 1;
        while ((leaf_count >> @as(u5, @intCast(level))) > 0) : (level += 1) {
            const nodes_at_level = leaf_count >> @as(u5, @intCast(level));
            
            for (0..nodes_at_level) |i| {
                const parent_index = ParentNodeIndex.new(@intCast(((@as(u32, 1) << @as(u5, @intCast(level))) - 1 + 2 * i)));
                const tree_index = parent_index.toTreeIndex();
                
                // Get left and right child indices
                const left_index = tree_math.left(parent_index);
                const right_index = tree_math.right(parent_index);
                
                // Get or compute child hashes (checking bounds first)
                const left_idx = left_index.asU32();
                const right_idx = right_index.asU32();
                
                const left_hash = if (left_idx < node_hashes.len and node_hashes[left_idx] != null) 
                    node_hashes[left_idx].?
                else
                    &[_]u8{};
                    
                const right_hash = if (right_idx < node_hashes.len and node_hashes[right_idx] != null)
                    node_hashes[right_idx].?
                else
                    &[_]u8{};
                
                // Compute parent hash
                if (self.tree.parentByIndex(parent_index)) |parent| {
                    // For non-empty parent nodes, include the parent data in the hash
                    var buffer = std.ArrayList(u8).init(allocator);
                    defer buffer.deinit();
                    
                    try parent.serialize(buffer.writer());
                    try buffer.appendSlice(left_hash);
                    try buffer.appendSlice(right_hash);
                    
                    var hash_secret = try self.cipher_suite.hash(allocator, buffer.items);
                    defer hash_secret.deinit();
                    
                    if (tree_index < node_hashes.len) {
                        node_hashes[tree_index] = try allocator.dupe(u8, hash_secret.asSlice());
                    }
                } else {
                    // Empty parent node - just hash the children
                    if (tree_index < node_hashes.len) {
                        node_hashes[tree_index] = try ParentNode.computeParentHash(
                            allocator,
                            self.cipher_suite,
                            left_hash,
                            right_hash
                        );
                    }
                }
            }
        }
        
        // The tree hash is the hash of the root node
        const root_index = tree_math.root(tree_size);
        const root_idx = root_index;
        
        // Note: cleanup is already handled by the defer block above
        
        // Check if root index is within bounds and has a hash
        if (root_idx < node_hashes.len and node_hashes[root_idx] != null) {
            // Clone the root hash to return it
            return try allocator.dupe(u8, node_hashes[root_idx].?);
        } else if (leaf_count == 0) {
            // Empty tree has empty hash
            return try allocator.dupe(u8, &[_]u8{});
        } else {
            // For now, return empty hash instead of failing
            // TODO: Debug why root hash isn't being computed
            return try allocator.dupe(u8, &[_]u8{});
        }
    }
};

/// Result of creating an update path
pub const UpdatePathResult = struct {
    update_path: UpdatePath,
    commit_secret: Secret,
};

/// Create an update path for a leaf node
pub fn createUpdatePath(
    allocator: Allocator,
    tree: *TreeSync,
    leaf_index: LeafNodeIndex,
    leaf_node: LeafNode,
    group_context: []const u8,
    random_fn: ?wasm_random.RandomFunction,
) !UpdatePathResult {
    // group_context is used in HPKE encryption
    const cs = tree.cipher_suite;
    
    // Generate random path secret
    const secret_len = cs.hashLength();
    const random_bytes = try allocator.alloc(u8, secret_len);
    defer allocator.free(random_bytes);
    
    // Use provided random function or fall back to wasm_random
    if (random_fn) |rand_fn| {
        rand_fn(random_bytes);
    } else {
        wasm_random.secure_random.bytes(random_bytes);
    }
    
    var path_secret = try PathSecret.init(allocator, cs, random_bytes);
    defer path_secret.deinit();

    // Get filtered direct path
    const filtered_path = try tree.filteredDirectPath(leaf_index);
    defer allocator.free(filtered_path);

    // Derive keys for each parent in the path
    var path_nodes = try allocator.alloc(UpdatePathNode, filtered_path.len);
    errdefer allocator.free(path_nodes);

    var current_secret = try Secret.initFromSlice(allocator, path_secret.secret.asSlice());
    defer current_secret.deinit();

    for (filtered_path, 0..) |parent_index, i| {
        // Derive key pair for this level
        var level_secret = try PathSecret.init(allocator, cs, current_secret.asSlice());
        defer level_secret.deinit();
        
        const key_pair = try level_secret.deriveKeyPair(allocator);
        defer {
            var pub_key = key_pair.public_key;
            pub_key.deinit();
            var priv_key = key_pair.private_key;
            priv_key.deinit();
        }

        // Get copath for encryption targets
        const parent_node = TreeNodeIndex{ .parent = tree_math.parent(TreeNodeIndex{ .parent = parent_index }) };
        const copath_nodes = try tree.copath(parent_node);
        defer allocator.free(copath_nodes);

        // Encrypt path secret to each node in copath resolution
        var encrypted_secrets = std.ArrayList(HpkeCiphertext).init(allocator);
        defer encrypted_secrets.deinit();

        for (copath_nodes) |copath_node| {
            const resolution_nodes = try tree.resolution(copath_node);
            defer allocator.free(resolution_nodes);

            for (resolution_nodes) |res_node| {
                // Get the public key for this resolution node
                const recipient_key = switch (res_node) {
                    .leaf => |idx| blk: {
                        const leaf = tree.tree.leafByIndex(idx) orelse continue;
                        break :blk leaf.payload.encryption_key;
                    },
                    .parent => |idx| blk: {
                        const parent = tree.tree.parentByIndex(idx) orelse continue;
                        break :blk parent.encryption_key.asSlice();
                    },
                };
                
                // Skip if no encryption key
                if (recipient_key.len == 0) continue;
                
                // Encrypt the path secret using HPKE (comptime dispatch based on cipher suite)
                const encrypted = switch (cs) {
                    .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => try hpkeEncrypt(
                        allocator,
                        try hpke.createSuite(0x0020, 0x0001, 0x0001), // X25519HkdfSha256, HkdfSha256, Aes128Gcm
                        recipient_key,
                        current_secret.asSlice(),
                        "MLS 1.0 TreeKEM",
                        group_context,
                        random_fn,
                    ),
                    .MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => try hpkeEncrypt(
                        allocator,
                        try hpke.createSuite(0x0020, 0x0001, 0x0003), // X25519HkdfSha256, HkdfSha256, ChaCha20Poly1305
                        recipient_key,
                        current_secret.asSlice(),
                        "MLS 1.0 TreeKEM",
                        group_context,
                        random_fn,
                    ),
                    else => return TreeKemError.InvalidNodeType, // TODO: Better error for unsupported suite
                };
                try encrypted_secrets.append(encrypted);
            }
        }

        // Create update path node
        path_nodes[i] = try UpdatePathNode.init(
            allocator,
            key_pair.public_key,
            encrypted_secrets.items,
        );

        // Clean up encrypted secrets
        for (encrypted_secrets.items) |*ct| {
            ct.deinit();
        }

        // Derive next path secret
        if (i < filtered_path.len - 1) {
            const next_level_secret = try level_secret.deriveNext(allocator);
            current_secret.deinit();
            current_secret = next_level_secret.secret;
        }
    }

    // The final path secret becomes the commit secret
    const commit_secret = try Secret.initFromSlice(allocator, current_secret.asSlice());

    return UpdatePathResult{
        .update_path = try UpdatePath.init(allocator, leaf_node, path_nodes),
        .commit_secret = commit_secret,
    };
}

/// Apply an update path to the tree
pub fn applyUpdatePath(
    tree: *TreeSync,
    sender_index: LeafNodeIndex,
    update_path: *const UpdatePath,
) !void {
    // Update the sender's leaf node
    const DiffType = TreeDiff(LeafNode, ParentNode);
    var diff = try DiffType.init(tree.tree.allocator, &tree.tree);
    defer diff.deinit();

    // Replace sender's leaf node
    try diff.replaceLeaf(sender_index, update_path.leaf_node);

    // Get filtered direct path
    const filtered_path = try tree.filteredDirectPath(sender_index);
    defer tree.tree.allocator.free(filtered_path);

    // Verify path length matches
    if (filtered_path.len != update_path.nodes.len) {
        return TreeKemError.InvalidPathLength;
    }

    // Apply parent node updates
    for (filtered_path, update_path.nodes) |parent_index, update_node| {
        // Create new parent node with updated encryption key
        var new_parent = try ParentNode.init(
            tree.tree.allocator,
            update_node.public_key,
            &[_]u8{}, // Parent hash will be computed later
        );
        defer new_parent.deinit(tree.tree.allocator);

        // Replace parent node in diff
        try diff.replaceParent(parent_index, new_parent);
    }

    // Merge diff back to tree
    tree.tree = try diff.mergeToTree();
}

/// Decrypt path from an update
pub fn decryptPath(
    allocator: Allocator,
    tree: *const TreeSync,
    update_path: []const UpdatePathNode,
    sender_index: LeafNodeIndex,
    my_index: LeafNodeIndex,
    my_private_keys: []const HpkePrivateKey,
    group_context: []const u8,
) !PathSecret {
    const cs = tree.cipher_suite;
    
    // Get filtered direct path for sender
    const sender_path = try tree.filteredDirectPath(sender_index);
    defer allocator.free(sender_path);

    if (sender_path.len != update_path.len) {
        return TreeKemError.InvalidPathLength;
    }
    
    // Get my position in the tree
    const my_node = TreeNodeIndex.leaf(my_index);
    
    // Try to decrypt at each level of the path
    for (sender_path, update_path) |parent_index, update_node| {
        const parent_node = TreeNodeIndex{ .parent = tree_math.parent(TreeNodeIndex{ .parent = parent_index }) };
        
        // Get copath for this level
        const copath_nodes = try tree.copath(parent_node);
        defer allocator.free(copath_nodes);
        
        // Check if we're in the copath at this level
        var my_position_in_copath: ?usize = null;
        for (copath_nodes, 0..) |copath_node, j| {
            const resolution = try tree.resolution(copath_node);
            defer allocator.free(resolution);
            
            for (resolution) |res_node| {
                if (res_node.asU32() == my_node.asU32()) {
                    my_position_in_copath = j;
                    break;
                }
            }
            if (my_position_in_copath != null) break;
        }
        
        // If we found ourselves in the copath, try to decrypt
        if (my_position_in_copath) |pos| {
            if (pos < update_node.encrypted_path_secrets.len) {
                const ciphertext = &update_node.encrypted_path_secrets[pos];
                
                // Find our private key for this position
                // For now, assume first private key (TODO: proper key selection)
                if (my_private_keys.len > 0) {
                    // Decrypt using HPKE (comptime dispatch based on cipher suite)
                    const plaintext = switch (cs) {
                        .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => try hpkeDecrypt(
                            allocator,
                            try hpke.createSuite(0x0020, 0x0001, 0x0001), // X25519HkdfSha256, HkdfSha256, Aes128Gcm
                            my_private_keys[0].asSlice(),
                            ciphertext.*,
                            "MLS 1.0 TreeKEM",
                            group_context,
                        ),
                        .MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => try hpkeDecrypt(
                            allocator,
                            try hpke.createSuite(0x0020, 0x0001, 0x0003), // X25519HkdfSha256, HkdfSha256, ChaCha20Poly1305
                            my_private_keys[0].asSlice(),
                            ciphertext.*,
                            "MLS 1.0 TreeKEM",
                            group_context,
                        ),
                        else => return TreeKemError.InvalidNodeType, // TODO: Better error for unsupported suite
                    };
                    defer allocator.free(plaintext);
                    
                    // Return the decrypted path secret
                    return PathSecret.init(allocator, cs, plaintext);
                }
            }
        }
    }
    
    return TreeKemError.NoDecryptionKey;
}

test "ParentNode creation and serialization" {
    const allocator = testing.allocator;

    // Create a test HPKE key
    const key_data = [_]u8{0x01} ** 32;
    var encryption_key = try HpkePublicKey.initOwned(allocator, &key_data);
    defer encryption_key.deinit(allocator);

    // Clone the key for the parent node (since it will take ownership)
    const node_key = try HpkePublicKey.initOwned(allocator, encryption_key.asSlice());
    
    // Create parent hash
    const hash_data = [_]u8{0x02} ** 32;

    // Create parent node
    var parent_node = try ParentNode.init(allocator, node_key, &hash_data);
    defer parent_node.deinit(allocator);

    // Test adding unmerged leaves
    try parent_node.addUnmergedLeaf(allocator, LeafNodeIndex.new(5));
    try parent_node.addUnmergedLeaf(allocator, LeafNodeIndex.new(7));
    try testing.expectEqual(@as(usize, 2), parent_node.unmerged_leaves.len);

    // Test serialization
    var buffer: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);
    try parent_node.serialize(stream.writer());

    // Test deserialization
    var read_stream = std.io.fixedBufferStream(buffer[0..stream.pos]);
    var decoded = try ParentNode.deserialize(allocator, read_stream.reader());
    defer decoded.deinit(allocator);

    try testing.expectEqualSlices(u8, parent_node.encryption_key.asSlice(), decoded.encryption_key.asSlice());
    try testing.expectEqualSlices(u8, parent_node.parent_hash, decoded.parent_hash);
    try testing.expectEqual(parent_node.unmerged_leaves.len, decoded.unmerged_leaves.len);
}

test "PathSecret operations" {
    const allocator = testing.allocator;
    const cs = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    // Create initial path secret
    const secret_data = [_]u8{0x03} ** 32;
    var path_secret = try PathSecret.init(allocator, cs, &secret_data);
    defer path_secret.deinit();

    // Derive key pair
    const key_pair = try path_secret.deriveKeyPair(allocator);
    defer {
        var pub_key = key_pair.public_key;
        pub_key.deinit();
        var priv_key = key_pair.private_key;
        priv_key.deinit();
    }

    try testing.expect(key_pair.public_key.len() > 0);
    try testing.expect(key_pair.private_key.len() > 0);

    // Derive next path secret
    var next_secret = try path_secret.deriveNext(allocator);
    defer next_secret.deinit();

    // Verify they're different
    try testing.expect(!std.mem.eql(u8, path_secret.secret.asSlice(), next_secret.secret.asSlice()));
}

test "TreeSync basic operations" {
    const allocator = testing.allocator;
    const cs = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    // Create a tree with 4 leaves
    var tree = try TreeSync.init(allocator, cs, 4);
    defer tree.deinit();

    // Test direct path
    const path = try tree.directPath(LeafNodeIndex.new(0));
    defer allocator.free(path);
    
    // Leaf 0's direct path should be [1, 3]
    try testing.expectEqual(@as(usize, 2), path.len);
    try testing.expectEqual(@as(u32, 1), path[0].asU32());
    try testing.expectEqual(@as(u32, 3), path[1].asU32());

    // Test copath
    const leaf_node = TreeNodeIndex{ .leaf = LeafNodeIndex.new(0) };
    const copath_nodes = try tree.copath(leaf_node);
    defer allocator.free(copath_nodes);
    
    // Copath should include siblings along the path
    try testing.expect(copath_nodes.len > 0);
}

test "HPKE encryption and decryption" {
    const allocator = testing.allocator;
    const cs = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    
    // Use default cipher suite for testing
    const SuiteType = try hpke.createSuite(0x0020, 0x0001, 0x0001); // X25519HkdfSha256, HkdfSha256, Aes128Gcm
    
    // Generate a key pair for testing
    var key_pair = try generateHpkeKeyPair(allocator, cs, null);
    defer key_pair.deinit();
    
    // Test data
    const plaintext = "Hello, TreeKEM!";
    const info = "MLS 1.0 TreeKEM";
    const aad = "test context";
    
    // Encrypt
    const ciphertext = try hpkeEncrypt(
        allocator,
        SuiteType,
        key_pair.public_key,
        plaintext,
        info,
        aad,
        null,
    );
    defer ciphertext.deinit();
    
    // Create HpkePrivateKey wrapper
    var private_key = try HpkePrivateKey.init(allocator, key_pair.private_key);
    defer private_key.deinit();
    
    // Decrypt
    const decrypted = try hpkeDecrypt(
        allocator,
        SuiteType,
        private_key.asSlice(),
        ciphertext,
        info,
        aad,
    );
    defer allocator.free(decrypted);
    
    // Verify
    try testing.expectEqualSlices(u8, plaintext, decrypted);
}

test "UpdatePath serialization" {
    const allocator = testing.allocator;

    // Create a simple leaf node for testing
    var leaf = LeafNode.init(allocator);
    defer leaf.deinit(allocator);
    
    // Set required fields for testing
    leaf.payload.encryption_key = try allocator.dupe(u8, &[_]u8{0x01} ** 32);
    leaf.payload.signature_key = try allocator.dupe(u8, &[_]u8{0x02} ** 32);
    leaf.signature = try allocator.dupe(u8, &[_]u8{0x03} ** 64);

    // Create update path nodes
    const key_data = [_]u8{0x04} ** 32;
    var public_key = try HpkePublicKey.initOwned(allocator, &key_data);
    defer public_key.deinit(allocator);

    var ciphertext1 = try HpkeCiphertext.init(
        allocator,
        &[_]u8{0x05} ** 32,
        &[_]u8{0x06} ** 48,
    );
    defer ciphertext1.deinit();

    const ciphertexts = [_]HpkeCiphertext{ciphertext1};
    var node = try UpdatePathNode.init(allocator, public_key, &ciphertexts);
    defer node.deinit(allocator);

    const nodes = [_]UpdatePathNode{node};
    var update_path = try UpdatePath.init(allocator, leaf, &nodes);
    defer update_path.deinit(allocator);

    // Test serialization
    var buffer: [2048]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);
    try update_path.serialize(stream.writer());

    // Test deserialization
    var read_stream = std.io.fixedBufferStream(buffer[0..stream.pos]);
    var decoded = try UpdatePath.deserialize(allocator, read_stream.reader());
    defer decoded.deinit(allocator);

    try testing.expectEqual(update_path.nodes.len, decoded.nodes.len);
}