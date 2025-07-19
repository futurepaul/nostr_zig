const std = @import("std");
const mls_zig = @import("mls_zig");
const wasm_random = @import("../wasm_random.zig");

/// TreeKEM operations for MLS
/// This module provides TreeKEM functionality using the default cipher suite
pub const TreeKem = struct {
    /// Default cipher suite for all operations
    pub const cipher_suite = mls_zig.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    
    /// Create an update path for TreeKEM
    pub fn createUpdatePath(
        allocator: std.mem.Allocator,
        tree_size: u32,
        leaf_index: u32,
        leaf_node: []const u8,
        group_context: []const u8,
        random_fn: ?wasm_random.RandomFunction,
    ) !UpdatePath {
        // Create TreeSync structure
        var tree = try mls_zig.tree_kem.TreeSync.init(allocator, cipher_suite, tree_size);
        defer tree.deinit();
        
        // Parse leaf node
        var stream = std.io.fixedBufferStream(leaf_node);
        var tls_reader = mls_zig.tls_codec.TlsReader(@TypeOf(stream.reader())).init(stream.reader());
        const parsed_leaf = try mls_zig.leaf_node.LeafNode.deserialize(allocator, &tls_reader);
        defer {
            var mutable_leaf = parsed_leaf;
            mutable_leaf.deinit(allocator);
        }
        
        // Create update path using mls_zig
        const leaf_idx = mls_zig.tree_math.LeafNodeIndex.new(leaf_index);
        const result = try mls_zig.tree_kem.createUpdatePath(
            allocator,
            &tree,
            leaf_idx,
            parsed_leaf,
            group_context,
            random_fn orelse null,
        );
        defer result.update_path.deinit(allocator);
        defer result.commit_secret.deinit();
        
        // Convert to our format
        var nodes = try allocator.alloc(UpdatePathNode, result.update_path.nodes.len);
        errdefer allocator.free(nodes);
        
        for (result.update_path.nodes, 0..) |node, i| {
            // Copy public key
            const pub_key = try allocator.dupe(u8, node.public_key.asSlice());
            errdefer allocator.free(pub_key);
            
            // Copy encrypted secrets
            var secrets = try allocator.alloc(HpkeCiphertext, node.encrypted_path_secrets.len);
            errdefer allocator.free(secrets);
            
            for (node.encrypted_path_secrets, 0..) |secret, j| {
                secrets[j] = HpkeCiphertext{
                    .kem_output = try allocator.dupe(u8, secret.kem_output.asSlice()),
                    .ciphertext = try allocator.dupe(u8, secret.ciphertext.asSlice()),
                };
            }
            
            nodes[i] = UpdatePathNode{
                .public_key = pub_key,
                .encrypted_path_secrets = secrets,
            };
        }
        
        // Serialize leaf node
        var leaf_buffer = std.ArrayList(u8).init(allocator);
        defer leaf_buffer.deinit();
        try result.update_path.leaf_node.serialize(leaf_buffer.writer());
        
        // Copy commit secret
        var commit_secret: [32]u8 = undefined;
        if (result.commit_secret.asSlice().len != 32) {
            return error.InvalidCommitSecretLength;
        }
        @memcpy(&commit_secret, result.commit_secret.asSlice()[0..32]);
        
        return UpdatePath{
            .leaf_node = try allocator.dupe(u8, leaf_buffer.items),
            .nodes = nodes,
            .commit_secret = commit_secret,
        };
    }
    
    /// Apply an update path to the tree
    pub fn applyUpdatePath(
        allocator: std.mem.Allocator,
        tree_size: u32,
        sender_index: u32,
        update_path: UpdatePath,
    ) ![32]u8 {
        // Create TreeSync structure
        var tree = try mls_zig.tree_kem.TreeSync.init(allocator, cipher_suite, tree_size);
        defer tree.deinit();
        
        // Convert update path to mls_zig format
        var stream = std.io.fixedBufferStream(update_path.leaf_node);
        var tls_reader = mls_zig.tls_codec.TlsReader(@TypeOf(stream.reader())).init(stream.reader());
        const leaf_node = try mls_zig.leaf_node.LeafNode.deserialize(allocator, &tls_reader);
        defer {
            var mutable_leaf = leaf_node;
            mutable_leaf.deinit(allocator);
        }
        
        var path_nodes = try allocator.alloc(mls_zig.tree_kem.UpdatePathNode, update_path.nodes.len);
        defer allocator.free(path_nodes);
        
        for (update_path.nodes, 0..) |node, i| {
            // Convert public key
            var pub_key = try mls_zig.key_package.HpkePublicKey.init(allocator, node.public_key);
            defer pub_key.deinit();
            
            // Convert encrypted secrets
            var secrets = try allocator.alloc(mls_zig.tree_kem.HpkeCiphertext, node.encrypted_path_secrets.len);
            defer allocator.free(secrets);
            
            for (node.encrypted_path_secrets, 0..) |secret, j| {
                secrets[j] = try mls_zig.tree_kem.HpkeCiphertext.init(
                    allocator,
                    secret.kem_output,
                    secret.ciphertext,
                );
            }
            defer {
                for (secrets) |*s| s.deinit();
            }
            
            path_nodes[i] = try mls_zig.tree_kem.UpdatePathNode.init(
                allocator,
                pub_key,
                secrets,
            );
        }
        defer {
            for (path_nodes) |*n| n.deinit(allocator);
        }
        
        var mls_update_path = try mls_zig.tree_kem.UpdatePath.init(
            allocator,
            leaf_node,
            path_nodes,
        );
        defer mls_update_path.deinit(allocator);
        
        // Apply the update path
        const sender_idx = mls_zig.tree_math.LeafNodeIndex.new(sender_index);
        const commit_secret = try mls_zig.tree_kem.applyUpdatePath(
            allocator,
            &tree,
            sender_idx,
            mls_update_path,
        );
        defer commit_secret.deinit();
        
        var result: [32]u8 = undefined;
        if (commit_secret.asSlice().len != 32) {
            return error.InvalidCommitSecretLength;
        }
        @memcpy(&result, commit_secret.asSlice()[0..32]);
        
        return result;
    }
    
    /// Decrypt path secrets from an update path
    pub fn decryptPath(
        allocator: std.mem.Allocator,
        tree_size: u32,
        self_index: u32,
        sender_index: u32,
        update_path: UpdatePath,
        private_key: []const u8,
        group_context: []const u8,
    ) !?[32]u8 {
        // Create TreeSync structure
        var tree = try mls_zig.tree_kem.TreeSync.init(allocator, cipher_suite, tree_size);
        defer tree.deinit();
        
        // Convert update path nodes
        var path_nodes = try allocator.alloc(mls_zig.tree_kem.UpdatePathNode, update_path.nodes.len);
        defer allocator.free(path_nodes);
        
        for (update_path.nodes, 0..) |node, i| {
            var pub_key = try mls_zig.key_package.HpkePublicKey.init(allocator, node.public_key);
            defer pub_key.deinit();
            
            var secrets = try allocator.alloc(mls_zig.tree_kem.HpkeCiphertext, node.encrypted_path_secrets.len);
            defer allocator.free(secrets);
            
            for (node.encrypted_path_secrets, 0..) |secret, j| {
                secrets[j] = try mls_zig.tree_kem.HpkeCiphertext.init(
                    allocator,
                    secret.kem_output,
                    secret.ciphertext,
                );
            }
            defer {
                for (secrets) |*s| s.deinit();
            }
            
            path_nodes[i] = try mls_zig.tree_kem.UpdatePathNode.init(
                allocator,
                pub_key,
                secrets,
            );
        }
        defer {
            for (path_nodes) |*n| n.deinit(allocator);
        }
        
        // Create array with single private key
        var private_keys = [_]mls_zig.key_package.HpkePrivateKey{try mls_zig.key_package.HpkePrivateKey.init(allocator, private_key)};
        defer private_keys[0].deinit();
        
        // Decrypt path
        const self_idx = mls_zig.tree_math.LeafNodeIndex.new(self_index);
        const sender_idx = mls_zig.tree_math.LeafNodeIndex.new(sender_index);
        
        const path_secret = mls_zig.tree_kem.decryptPath(
            allocator,
            &tree,
            path_nodes,
            sender_idx,
            self_idx,
            &private_keys,
            group_context,
        ) catch |err| {
            // If decryption fails, return null (member not in resolution)
            if (err == mls_zig.tree_kem.TreeKemError.NoDecryptionKey or
                err == mls_zig.tree_kem.TreeKemError.DecryptionFailed) {
                return null;
            }
            return err;
        };
        defer path_secret.deinit();
        
        var result: [32]u8 = undefined;
        if (path_secret.secret.asSlice().len != 32) {
            return error.InvalidPathSecretLength;
        }
        @memcpy(&result, path_secret.secret.asSlice()[0..32]);
        
        return result;
    }
    
    /// Encrypt to multiple members (for Welcome messages)
    pub fn encryptToMembers(
        allocator: std.mem.Allocator,
        members: []const Member,
        plaintext: []const u8,
        info: []const u8,
        aad: []const u8,
        random_fn: ?wasm_random.RandomFunction,
    ) ![]HpkeCiphertext {
        // Use default HPKE suite for X25519, HKDF-SHA256, AES-128-GCM
        const hpke_suite = try mls_zig.hpke.createSuite(0x0020, 0x0001, 0x0001);
        
        var results = try allocator.alloc(HpkeCiphertext, members.len);
        errdefer allocator.free(results);
        
        for (members, 0..) |member, i| {
            // Encrypt to this member
            const client_result = try hpke_suite.createClientContext(
                member.public_key,
                info,
                null, // no PSK
                null, // no seed
                random_fn orelse null,
            );
            var client_ctx = client_result.client_ctx;
            
            // Allocate space for ciphertext (plaintext + tag)
            const ciphertext_len = plaintext.len + client_ctx.tagLength();
            const ciphertext = try allocator.alloc(u8, ciphertext_len);
            errdefer allocator.free(ciphertext);
            
            // Encrypt
            client_ctx.encryptToServer(ciphertext, plaintext, aad);
            
            results[i] = HpkeCiphertext{
                .kem_output = try allocator.dupe(u8, client_result.encapsulated_secret.encapsulated.constSlice()),
                .ciphertext = ciphertext,
            };
        }
        
        return results;
    }
};

/// HPKE ciphertext structure
pub const HpkeCiphertext = struct {
    kem_output: []const u8,
    ciphertext: []const u8,
    
    pub fn deinit(self: *HpkeCiphertext, allocator: std.mem.Allocator) void {
        allocator.free(self.kem_output);
        allocator.free(self.ciphertext);
    }
};

/// TreeKEM update path structure
pub const UpdatePath = struct {
    leaf_node: []const u8,
    nodes: []const UpdatePathNode,
    commit_secret: [32]u8,
    
    pub fn deinit(self: *UpdatePath, allocator: std.mem.Allocator) void {
        allocator.free(self.leaf_node);
        for (self.nodes) |node| {
            var mut_node = node;
            mut_node.deinit(allocator);
        }
        allocator.free(self.nodes);
    }
};

/// TreeKEM update path node
pub const UpdatePathNode = struct {
    public_key: []const u8,
    encrypted_path_secrets: []const HpkeCiphertext,
    
    pub fn deinit(self: *UpdatePathNode, allocator: std.mem.Allocator) void {
        allocator.free(self.public_key);
        for (self.encrypted_path_secrets) |*secret| {
            var mut_secret = secret;
            mut_secret.deinit(allocator);
        }
        allocator.free(self.encrypted_path_secrets);
    }
};

/// TreeKEM member for encryption
pub const Member = struct {
    index: u32,
    public_key: []const u8,
};

test "TreeKEM encryption to members" {
    std.debug.print("\n=== Running TreeKEM encryption test ===\n", .{});
    const allocator = std.testing.allocator;
    
    // Generate test keys using HPKE
    const hpke_suite = try mls_zig.hpke.createSuite(0x0020, 0x0001, 0x0001);
    
    var members: [2]Member = undefined;
    var keypairs: [2]mls_zig.hpke.KeyPair = undefined;
    
    for (&keypairs, 0..) |*kp, i| {
        // Generate deterministic seed
        var seed: [32]u8 = undefined;
        wasm_random.secure_random.bytes(&seed);
        
        // Generate key pair
        kp.* = try hpke_suite.deterministicKeyPair(&seed);
        
        members[i] = Member{
            .index = @intCast(i),
            .public_key = kp.public_key.constSlice(),
        };
    }
    
    // Test encryption
    const plaintext = "test secret data";
    const info = "test info";
    const aad = "test aad";
    
    const ciphertexts = try TreeKem.encryptToMembers(
        allocator,
        &members,
        plaintext,
        info,
        aad,
        null,
    );
    defer {
        for (ciphertexts) |*ct| {
            var mut_ct = ct;
            mut_ct.deinit(allocator);
        }
        allocator.free(ciphertexts);
    }
    
    try std.testing.expectEqual(@as(usize, 2), ciphertexts.len);
    
    // Verify each ciphertext has content
    for (ciphertexts) |ct| {
        try std.testing.expect(ct.kem_output.len > 0);
        try std.testing.expect(ct.ciphertext.len > 0);
    }
    
    std.debug.print("=== TreeKEM encryption test PASSED ===\n", .{});
}