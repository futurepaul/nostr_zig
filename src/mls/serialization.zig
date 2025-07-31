const std = @import("std");
const tls = std.crypto.tls;
const types = @import("types.zig");
const mls_zig = @import("mls_zig");

/// Serialize MLS types using TLS wire format
pub const Serializer = struct {
    /// Serialize a KeyPackage to TLS wire format
    pub fn serializeKeyPackage(allocator: std.mem.Allocator, key_package: types.KeyPackage) ![]u8 {
        var buffer = std.ArrayList(u8).init(allocator);
        defer buffer.deinit();
        
        var stream = std.io.fixedBufferStream(buffer.items);
        var writer = mls_zig.tls_encode.TlsWriter(@TypeOf(stream.writer())).init(stream.writer());
        
        // Write version
        try writer.writeU16(@intFromEnum(key_package.version));
        
        // Write cipher suite
        try writer.writeU16(@intFromEnum(key_package.cipher_suite));
        
        // Write init key (HPKE public key)
        try writer.writeVarBytes(u16, &key_package.init_key);
        
        // Write leaf node
        try serializeLeafNode(&writer, key_package.leaf_node);
        
        // Write extensions
        try serializeExtensions(&writer, key_package.extensions);
        
        // Write signature
        try writer.writeVarBytes(u16, key_package.signature);
        
        return try buffer.toOwnedSlice();
    }
    
    /// Serialize a Welcome message to TLS wire format
    pub fn serializeWelcome(allocator: std.mem.Allocator, welcome: types.Welcome) ![]u8 {
        var buffer = std.ArrayList(u8).init(allocator);
        defer buffer.deinit();
        
        var stream = std.io.fixedBufferStream(buffer.items);
        var writer = mls_zig.tls_encode.TlsWriter(@TypeOf(stream.writer())).init(stream.writer());
        
        // Write cipher suite
        try writer.writeU16(@intFromEnum(welcome.cipher_suite));
        
        // Write secrets (array of encrypted group secrets)
        try writer.writeU32(@intCast(welcome.secrets.len));
        for (welcome.secrets) |secret| {
            try serializeEncryptedGroupSecrets(&writer, secret);
        }
        
        // Write encrypted group info
        try writer.writeVarBytes(u32, welcome.encrypted_group_info);
        
        return try buffer.toOwnedSlice();
    }
    
    /// Serialize an MLSMessage to TLS wire format
    pub fn serializeMLSMessage(allocator: std.mem.Allocator, message: types.MLSMessage) ![]u8 {
        var buffer = std.ArrayList(u8).init(allocator);
        defer buffer.deinit();
        
        var stream = std.io.fixedBufferStream(buffer.items);
        var writer = mls_zig.tls_encode.TlsWriter(@TypeOf(stream.writer())).init(stream.writer());
        
        // Write version
        try writer.writeU16(@intFromEnum(message.version));
        
        // Write wire format
        try writer.writeU8(@intFromEnum(message.wire_format));
        
        // Write content based on wire format
        switch (message.content) {
            .public_message => |pm| try serializePublicMessage(&writer, pm),
            .private_message => |pm| try serializePrivateMessage(&writer, pm),
            .welcome => |w| try serializeWelcomeContent(&writer, w),
            .group_info => |gi| try serializeGroupInfo(&writer, gi),
            .key_package => |kp| try serializeKeyPackageContent(&writer, kp),
        }
        
        return try buffer.toOwnedSlice();
    }
    
    // Helper functions for nested structures
    
    fn serializeLeafNode(writer: anytype, leaf_node: types.LeafNode) !void {
        // Write leaf node version
        try writer.writeU16(@intFromEnum(leaf_node.leaf_node_version));
        
        // Write encryption key
        try writer.writeVarBytes(u16, &leaf_node.encryption_key);
        
        // Write signature key  
        try writer.writeVarBytes(u16, &leaf_node.signature_key);
        
        // Write credential
        try serializeCredential(writer, leaf_node.credential);
        
        // Write capabilities
        try serializeCapabilities(writer, leaf_node.capabilities);
        
        // Write leaf node source
        try writer.writeU8(@intFromEnum(leaf_node.leaf_node_source));
        
        // Write extensions
        try serializeExtensions(writer, leaf_node.extensions);
        
        // Write signature
        try writer.writeVarBytes(u16, leaf_node.signature);
    }
    
    fn serializeCredential(writer: anytype, credential: types.Credential) !void {
        try writer.writeU8(@intFromEnum(credential));
        switch (credential) {
            .basic => |basic| {
                try writer.writeVarBytes(u16, basic.identity);
            },
            .x509 => |cert| {
                try writer.writeVarBytes(u24, cert);
            },
        }
    }
    
    fn serializeCapabilities(writer: anytype, capabilities: types.Capabilities) !void {
        // Write versions
        try writer.writeU8(@intCast(capabilities.versions.len));
        for (capabilities.versions) |version| {
            try writer.writeU16(@intFromEnum(version));
        }
        
        // Write cipher suites
        try writer.writeU8(@intCast(capabilities.cipher_suites.len));
        for (capabilities.cipher_suites) |cs| {
            try writer.writeU16(@intFromEnum(cs));
        }
        
        // Write extensions
        try writer.writeU8(@intCast(capabilities.extensions.len));
        for (capabilities.extensions) |ext| {
            try writer.writeU16(@intFromEnum(ext));
        }
        
        // Write credential types
        try writer.writeU8(@intCast(capabilities.credential_types.len));
        for (capabilities.credential_types) |ct| {
            try writer.writeU8(@intFromEnum(ct));
        }
    }
    
    fn serializeExtensions(writer: anytype, extensions: []const types.Extension) !void {
        try writer.writeU16(@intCast(extensions.len));
        for (extensions) |extension| {
            try writer.writeU16(@intFromEnum(extension.extension_type));
            try writer.writeVarBytes(u16, extension.extension_data);
        }
    }
    
    fn serializeEncryptedGroupSecrets(writer: anytype, secrets: types.EncryptedGroupSecrets) !void {
        // Write key package reference
        try writer.writeVarBytes(u16, secrets.new_member);
        
        // Write encrypted group secrets
        try writer.writeVarBytes(u32, secrets.encrypted_group_secrets);
    }
    
    fn serializePublicMessage(writer: anytype, message: types.PublicMessage) !void {
        // Simplified - would need full implementation
        _ = writer;
        _ = message;
    }
    
    fn serializePrivateMessage(writer: anytype, message: types.PrivateMessage) !void {
        // Write group id
        try writer.writeVarBytes(u16, &message.group_id);
        
        // Write epoch
        try writer.writeU64(message.epoch);
        
        // Write content type
        try writer.writeU8(@intFromEnum(message.content_type));
        
        // Write authenticated data
        try writer.writeVarBytes(u32, message.authenticated_data);
        
        // Write encrypted sender data
        try writer.writeVarBytes(u16, message.encrypted_sender_data);
        
        // Write ciphertext
        try writer.writeVarBytes(u32, message.ciphertext);
    }
    
    fn serializeWelcomeContent(writer: anytype, welcome: types.Welcome) !void {
        _ = writer;
        _ = welcome;
        // Already handled in serializeWelcome
    }
    
    fn serializeGroupInfo(writer: anytype, group_info: types.GroupInfo) !void {
        _ = writer;
        _ = group_info;
        // Would implement group info serialization
    }
    
    fn serializeKeyPackageContent(writer: anytype, key_package: types.KeyPackage) !void {
        _ = writer;
        _ = key_package;
        // Already handled in serializeKeyPackage
    }
};

/// Deserialize MLS types from TLS wire format
pub const Deserializer = struct {
    /// Deserialize a KeyPackage from TLS wire format
    pub fn deserializeKeyPackage(allocator: std.mem.Allocator, data: []const u8) !types.KeyPackage {
        var stream = std.io.fixedBufferStream(data);
        var reader = mls_zig.tls_encode.TlsReader(@TypeOf(stream.reader())).init(stream.reader());
        
        // Read version
        const version = @as(types.ProtocolVersion, @enumFromInt(try reader.readU16()));
        
        // Read cipher suite
        const cipher_suite = @as(types.Ciphersuite, @enumFromInt(try reader.readU16()));
        
        // Read init key
        const init_key_len = try reader.readU16();
        const init_key_data = try allocator.alloc(u8, init_key_len);
        try reader.readBytes(init_key_data);
        
        var init_key: types.HPKEPublicKey = undefined;
        @memcpy(&init_key, init_key_data[0..@min(init_key_data.len, 32)]);
        allocator.free(init_key_data);
        
        // Read leaf node
        const leaf_node = try deserializeLeafNode(allocator, &reader);
        
        // Read extensions
        const extensions = try deserializeExtensions(allocator, &reader);
        
        // Read signature
        const signature = try reader.readVarBytes(allocator, u16);
        
        return types.KeyPackage{
            .version = version,
            .cipher_suite = cipher_suite,
            .init_key = init_key,
            .leaf_node = leaf_node,
            .extensions = extensions,
            .signature = signature,
        };
    }
    
    /// Deserialize a Welcome message from TLS wire format
    pub fn deserializeWelcome(allocator: std.mem.Allocator, data: []const u8) !types.Welcome {
        var stream = std.io.fixedBufferStream(data);
        var reader = mls_zig.tls_encode.TlsReader(@TypeOf(stream.reader())).init(stream.reader());
        
        // Read cipher suite
        const cipher_suite = @as(types.Ciphersuite, @enumFromInt(try reader.readU16()));
        
        // Read secrets
        const secrets_len = try reader.readU32();
        const secrets = try allocator.alloc(types.EncryptedGroupSecrets, secrets_len);
        for (secrets) |*secret| {
            secret.* = try deserializeEncryptedGroupSecrets(allocator, &reader);
        }
        
        // Read encrypted group info
        const encrypted_group_info = try reader.readVarBytes(allocator, u32);
        
        return types.Welcome{
            .cipher_suite = cipher_suite,
            .secrets = secrets,
            .encrypted_group_info = encrypted_group_info,
        };
    }
    
    // Helper deserialization functions
    
    fn deserializeLeafNode(allocator: std.mem.Allocator, reader: anytype) !types.LeafNode {
        // Read leaf node version
        const leaf_node_version = @as(types.LeafNodeVersion, @enumFromInt(try reader.readU16()));
        
        // Read encryption key
        const enc_key_len = try reader.readU16();
        const enc_key_data = try allocator.alloc(u8, enc_key_len);
        defer allocator.free(enc_key_data);
        try reader.readBytes(enc_key_data);
        
        var encryption_key: types.HPKEPublicKey = undefined;
        @memcpy(&encryption_key, enc_key_data[0..@min(enc_key_data.len, 32)]);
        
        // Read signature key
        const sig_key_len = try reader.readU16();
        const sig_key_data = try allocator.alloc(u8, sig_key_len);
        defer allocator.free(sig_key_data);
        try reader.readBytes(sig_key_data);
        
        var signature_key: types.SignaturePublicKey = undefined;
        @memcpy(&signature_key, sig_key_data[0..@min(sig_key_data.len, 32)]);
        
        // Read credential
        const credential = try deserializeCredential(allocator, reader);
        
        // Read capabilities
        const capabilities = try deserializeCapabilities(allocator, reader);
        
        // Read leaf node source
        const leaf_node_source = @as(types.LeafNodeSource, @enumFromInt(try reader.readU8()));
        
        // Read extensions
        const extensions = try deserializeExtensions(allocator, reader);
        
        // Read signature
        const signature = try reader.readVarBytes(allocator, u16);
        
        return types.LeafNode{
            .leaf_node_version = leaf_node_version,
            .encryption_key = encryption_key,
            .signature_key = signature_key,
            .credential = credential,
            .capabilities = capabilities,
            .leaf_node_source = leaf_node_source,
            .extensions = extensions,
            .signature = signature,
        };
    }
    
    fn deserializeCredential(allocator: std.mem.Allocator, reader: anytype) !types.Credential {
        const cred_type = @as(types.CredentialType, @enumFromInt(try reader.readU8()));
        
        switch (cred_type) {
            .basic => {
                const identity = try reader.readVarBytes(allocator, u16);
                return types.Credential{ .basic = .{ .identity = identity } };
            },
            .x509 => {
                const cert = try reader.readVarBytes(allocator, u24);
                return types.Credential{ .x509 = cert };
            },
        }
    }
    
    fn deserializeCapabilities(allocator: std.mem.Allocator, reader: anytype) !types.Capabilities {
        // Read versions
        const versions_len = try reader.readU8();
        const versions = try allocator.alloc(types.ProtocolVersion, versions_len);
        for (versions) |*version| {
            version.* = @as(types.ProtocolVersion, @enumFromInt(try reader.readU16()));
        }
        
        // Read cipher suites
        const cipher_suites_len = try reader.readU8();
        const cipher_suites = try allocator.alloc(types.Ciphersuite, cipher_suites_len);
        for (cipher_suites) |*cs| {
            cs.* = @as(types.Ciphersuite, @enumFromInt(try reader.readU16()));
        }
        
        // Read extensions
        const extensions_len = try reader.readU8();
        const extensions = try allocator.alloc(types.ExtensionType, extensions_len);
        for (extensions) |*ext| {
            ext.* = @as(types.ExtensionType, @enumFromInt(try reader.readU16()));
        }
        
        // Read credential types
        const credential_types_len = try reader.readU8();
        const credential_types = try allocator.alloc(types.CredentialType, credential_types_len);
        for (credential_types) |*ct| {
            ct.* = @as(types.CredentialType, @enumFromInt(try reader.readU8()));
        }
        
        return types.Capabilities{
            .versions = versions,
            .cipher_suites = cipher_suites,
            .extensions = extensions,
            .credential_types = credential_types,
        };
    }
    
    fn deserializeExtensions(allocator: std.mem.Allocator, reader: anytype) ![]types.Extension {
        const count = try reader.readU16();
        const extensions = try allocator.alloc(types.Extension, count);
        
        for (extensions) |*extension| {
            const ext_type = @as(types.ExtensionType, @enumFromInt(try reader.readU16()));
            const ext_data = try reader.readVarBytes(allocator, u16);
            
            extension.* = types.Extension{
                .extension_type = ext_type,
                .extension_data = ext_data,
            };
        }
        
        return extensions;
    }
    
    fn deserializeEncryptedGroupSecrets(allocator: std.mem.Allocator, reader: anytype) !types.EncryptedGroupSecrets {
        const new_member = try reader.readVarBytes(allocator, u16);
        const encrypted_group_secrets = try reader.readVarBytes(allocator, u32);
        
        return types.EncryptedGroupSecrets{
            .new_member = new_member,
            .encrypted_group_secrets = encrypted_group_secrets,
        };
    }
};

test "serialize and deserialize key package" {
    const allocator = std.testing.allocator;
    
    // Create a test key package
    const key_package = types.KeyPackage{
        .version = .mls10,
        .cipher_suite = .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        .init_key = [_]u8{1} ** 32,
        .leaf_node = .{
            .leaf_node_version = .mls10,
            .encryption_key = [_]u8{2} ** 32,
            .signature_key = [_]u8{3} ** 32,
            .credential = .{ .basic = .{ .identity = try allocator.dupe(u8, "test-identity") } },
            .capabilities = .{
                .versions = &[_]types.ProtocolVersion{.mls10},
                .cipher_suites = &[_]types.Ciphersuite{.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519},
                .extensions = &[_]types.ExtensionType{},
                .credential_types = &[_]types.CredentialType{.basic},
            },
            .leaf_node_source = .key_package,
            .extensions = &[_]types.Extension{},
            .signature = try allocator.dupe(u8, &[_]u8{0xFF} ** 64),
        },
        .extensions = &[_]types.Extension{},
        .signature = try allocator.dupe(u8, &[_]u8{0xAA} ** 64),
    };
    defer allocator.free(key_package.leaf_node.credential.basic.identity);
    defer allocator.free(key_package.leaf_node.signature);
    defer allocator.free(key_package.signature);
    
    // Serialize
    const serialized = try Serializer.serializeKeyPackage(allocator, key_package);
    defer allocator.free(serialized);
    
    try std.testing.expect(serialized.len > 0);
    
    // Deserialize
    const deserialized = try Deserializer.deserializeKeyPackage(allocator, serialized);
    defer {
        allocator.free(deserialized.leaf_node.credential.basic.identity);
        allocator.free(deserialized.leaf_node.signature);
        allocator.free(deserialized.signature);
        allocator.free(deserialized.leaf_node.capabilities.versions);
        allocator.free(deserialized.leaf_node.capabilities.cipher_suites);
        allocator.free(deserialized.leaf_node.capabilities.extensions);
        allocator.free(deserialized.leaf_node.capabilities.credential_types);
        allocator.free(deserialized.extensions);
    }
    
    // Verify
    try std.testing.expectEqual(key_package.version, deserialized.version);
    try std.testing.expectEqual(key_package.cipher_suite, deserialized.cipher_suite);
    try std.testing.expectEqualSlices(u8, &key_package.init_key, &deserialized.init_key);
}