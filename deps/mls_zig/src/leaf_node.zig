const std = @import("std");
const Allocator = std.mem.Allocator;
const crypto = std.crypto;
const testing = std.testing;

const CipherSuite = @import("cipher_suite.zig").CipherSuite;
const Secret = @import("cipher_suite.zig").Secret;
const KeyPackage = @import("key_package.zig").KeyPackage;
const KeyPackageBundle = @import("key_package.zig").KeyPackageBundle;
const Credential = @import("credentials.zig").Credential;
const BasicCredential = @import("credentials.zig").BasicCredential;
const tls_codec = @import("tls_codec.zig");
const TlsWriter = tls_codec.TlsWriter;
const TlsReader = tls_codec.TlsReader;
const VarBytes = @import("tls_codec.zig").VarBytes;

/// Helper function to serialize a list with length prefix
fn serializeList(comptime T: type, items: []const T, writer: anytype) !void {
    try writer.writeU16(@intCast(items.len));
    for (items) |item| {
        try item.serialize(writer);
    }
}

/// Helper function to serialize enum lists 
fn serializeEnumList(comptime T: type, items: []const T, writer: anytype) !void {
    try writer.writeU16(@intCast(items.len));
    for (items) |item| {
        try writer.writeU16(@intFromEnum(item));
    }
}

/// Helper function to serialize a list with items that need allocator in serialize
fn serializeListWithAllocator(comptime T: type, items: []const T, writer: anytype) !void {
    try writer.writeU16(@intCast(items.len));
    for (items) |item| {
        try item.serialize(writer);
    }
}

/// Helper function to deserialize a list with length prefix
fn deserializeList(comptime T: type, allocator: Allocator, reader: anytype) ![]T {
    const len = try reader.readU16();
    const result = try allocator.alloc(T, len);
    for (result) |*item| {
        item.* = try T.deserialize(reader);
    }
    return result;
}

/// Helper function to deserialize a list that needs allocator
fn deserializeListWithAllocator(comptime T: type, allocator: Allocator, reader: anytype) ![]T {
    const len = try reader.readU16();
    const result = try allocator.alloc(T, len);
    for (result) |*item| {
        item.* = try T.deserialize(allocator, reader);
    }
    return result;
}

/// Helper function to deserialize enum lists
fn deserializeEnumList(comptime T: type, allocator: Allocator, reader: anytype) ![]T {
    const len = try reader.readU16();
    const result = try allocator.alloc(T, len);
    for (result) |*item| {
        const value = try reader.readU16();
        item.* = @enumFromInt(value);
    }
    return result;
}

pub const LeafNodeError = error{
    InvalidSignature,
    UnsupportedCredentialType,
    UnsupportedCipherSuite,
    InvalidCapabilities,
    MissingRequiredExtension,
    InvalidExtension,
    SerializationError,
    OutOfMemory,
};

/// Represents how a leaf node was created in the MLS tree
pub const LeafNodeSource = union(enum) {
    /// Created from a KeyPackage with optional lifetime
    KeyPackage: ?u64, // Optional lifetime
    /// Created from an Update proposal
    Update,
    /// Created from a Commit with parent hash
    Commit: [32]u8, // Parent hash

    pub fn serialize(self: LeafNodeSource, writer: anytype) !void {
        switch (self) {
            .KeyPackage => |lifetime| {
                try writer.writeU8(0); // Tag for KeyPackage
                if (lifetime) |lt| {
                    try writer.writeU8(1); // Has lifetime
                    try writer.writeU64(lt);
                } else {
                    try writer.writeU8(0); // No lifetime
                }
            },
            .Update => {
                try writer.writeU8(1); // Tag for Update
            },
            .Commit => |parent_hash| {
                try writer.writeU8(2); // Tag for Commit
                try writer.writeBytes(&parent_hash);
            },
        }
    }

    pub fn deserialize(reader: anytype) !LeafNodeSource {
        const tag = try reader.readU8();
        return switch (tag) {
            0 => { // KeyPackage
                const has_lifetime = try reader.readU8();
                if (has_lifetime == 1) {
                    const lifetime = try reader.readU64();
                    return LeafNodeSource{ .KeyPackage = lifetime };
                } else {
                    return LeafNodeSource{ .KeyPackage = null };
                }
            },
            1 => LeafNodeSource.Update, // Update
            2 => { // Commit
                var parent_hash: [32]u8 = undefined;
                try reader.readBytes(&parent_hash);
                return LeafNodeSource{ .Commit = parent_hash };
            },
            else => LeafNodeError.SerializationError,
        };
    }
};

/// Supported MLS protocol versions
pub const ProtocolVersion = enum(u16) {
    mls10 = 0x0001,

    pub fn serialize(self: ProtocolVersion, writer: anytype) !void {
        try writer.writeU16(@intFromEnum(self));
    }

    pub fn deserialize(reader: anytype) !ProtocolVersion {
        const value = try reader.readU16();
        return switch (value) {
            0x0001 => .mls10,
            else => LeafNodeError.SerializationError,
        };
    }
};

/// Supported proposal types in MLS
pub const ProposalType = enum(u16) {
    add = 0x0001,
    update = 0x0002,
    remove = 0x0003,
    psk = 0x0004,
    reinit = 0x0005,
    external_init = 0x0006,
    group_context_extensions = 0x0007,

    pub fn serialize(self: ProposalType, writer: anytype) !void {
        try writer.writeU16(@intFromEnum(self));
    }

    pub fn deserialize(reader: anytype) !ProposalType {
        const value = try reader.readU16();
        return switch (value) {
            0x0001 => .add,
            0x0002 => .update,
            0x0003 => .remove,
            0x0004 => .psk,
            0x0005 => .reinit,
            0x0006 => .external_init,
            0x0007 => .group_context_extensions,
            else => LeafNodeError.SerializationError,
        };
    }
};

/// Supported credential types
pub const CredentialType = enum(u16) {
    basic = 0x0001,
    x509 = 0x0002,

    pub fn serialize(self: CredentialType, writer: anytype) !void {
        try writer.writeU16(@intFromEnum(self));
    }

    pub fn deserialize(reader: anytype) !CredentialType {
        const value = try reader.readU16();
        return switch (value) {
            0x0001 => .basic,
            0x0002 => .x509,
            else => LeafNodeError.SerializationError,
        };
    }
};

/// Supported extension types
pub const ExtensionType = enum(u16) {
    capabilities = 0x0001,
    lifetime = 0x0002,
    key_id = 0x0003,
    parent_hash = 0x0004,
    ratchet_tree = 0x0005,
    nostr_group_data = 0xFF00, // Custom for Nostr
    last_resort = 0xFF01, // Custom for preventing key package reuse

    pub fn serialize(self: ExtensionType, writer: anytype) !void {
        try writer.writeU16(@intFromEnum(self));
    }

    pub fn deserialize(reader: anytype) !ExtensionType {
        const value = try reader.readU16();
        return switch (value) {
            0x0001 => .capabilities,
            0x0002 => .lifetime,
            0x0003 => .key_id,
            0x0004 => .parent_hash,
            0x0005 => .ratchet_tree,
            0xFF00 => .nostr_group_data,
            0xFF01 => .last_resort,
            else => LeafNodeError.SerializationError,
        };
    }
};

/// Extension data structure
pub const Extension = struct {
    extension_type: ExtensionType,
    extension_data: VarBytes,

    pub fn init(allocator: Allocator, ext_type: ExtensionType, data: []const u8) !Extension {
        const var_data = try VarBytes.init(allocator, data);
        return Extension{
            .extension_type = ext_type,
            .extension_data = var_data,
        };
    }

    pub fn deinit(self: *Extension) void {
        self.extension_data.deinit();
    }

    pub fn serialize(self: Extension, writer: anytype) !void {
        try self.extension_type.serialize(writer);
        try writer.writeVarBytes(u16, self.extension_data.asSlice());
    }

    pub fn deserialize(allocator: Allocator, reader: anytype) !Extension {
        const ext_type = try ExtensionType.deserialize(reader);
        const data_bytes = try reader.readVarBytes(u16, allocator);
        defer allocator.free(data_bytes);
        const ext_data = try VarBytes.init(allocator, data_bytes);
        return Extension{
            .extension_type = ext_type,
            .extension_data = ext_data,
        };
    }
};

/// List of extensions
pub const Extensions = struct {
    extensions: std.ArrayList(Extension),

    pub fn init(allocator: Allocator) Extensions {
        return Extensions{
            .extensions = std.ArrayList(Extension).init(allocator),
        };
    }

    pub fn deinit(self: *Extensions) void {
        for (self.extensions.items) |*ext| {
            ext.deinit();
        }
        self.extensions.deinit();
    }

    pub fn addExtension(self: *Extensions, extension: Extension) !void {
        try self.extensions.append(extension);
    }

    pub fn serialize(self: Extensions, writer: anytype) !void {
        try serializeListWithAllocator(Extension, self.extensions.items, writer);
    }

    pub fn deserialize(allocator: Allocator, reader: anytype) !Extensions {
        var extensions = Extensions.init(allocator);
        const ext_list = try deserializeListWithAllocator(Extension, allocator, reader);
        defer allocator.free(ext_list);

        for (ext_list) |ext| {
            try extensions.addExtension(ext);
        }
        return extensions;
    }
};

/// Capabilities supported by a leaf node
pub const Capabilities = struct {
    versions: std.ArrayList(ProtocolVersion),
    ciphersuites: std.ArrayList(CipherSuite),
    extensions: std.ArrayList(ExtensionType),
    proposals: std.ArrayList(ProposalType),
    credentials: std.ArrayList(CredentialType),

    pub fn init(allocator: Allocator) Capabilities {
        return Capabilities{
            .versions = std.ArrayList(ProtocolVersion).init(allocator),
            .ciphersuites = std.ArrayList(CipherSuite).init(allocator),
            .extensions = std.ArrayList(ExtensionType).init(allocator),
            .proposals = std.ArrayList(ProposalType).init(allocator),
            .credentials = std.ArrayList(CredentialType).init(allocator),
        };
    }

    pub fn deinit(self: *Capabilities) void {
        self.versions.deinit();
        self.ciphersuites.deinit();
        self.extensions.deinit();
        self.proposals.deinit();
        self.credentials.deinit();
    }

    pub fn addVersion(self: *Capabilities, version: ProtocolVersion) !void {
        try self.versions.append(version);
    }

    pub fn addCipherSuite(self: *Capabilities, cs: CipherSuite) !void {
        try self.ciphersuites.append(cs);
    }

    pub fn addExtension(self: *Capabilities, ext: ExtensionType) !void {
        try self.extensions.append(ext);
    }

    pub fn addProposal(self: *Capabilities, prop: ProposalType) !void {
        try self.proposals.append(prop);
    }

    pub fn addCredential(self: *Capabilities, cred: CredentialType) !void {
        try self.credentials.append(cred);
    }

    pub fn serialize(self: Capabilities, writer: anytype) !void {
        try serializeEnumList(ProtocolVersion, self.versions.items, writer);
        try serializeEnumList(CipherSuite, self.ciphersuites.items, writer);
        try serializeEnumList(ExtensionType, self.extensions.items, writer);
        try serializeEnumList(ProposalType, self.proposals.items, writer);
        try serializeEnumList(CredentialType, self.credentials.items, writer);
    }

    pub fn deserialize(allocator: Allocator, reader: anytype) !Capabilities {
        var caps = Capabilities.init(allocator);

        const versions = try deserializeEnumList(ProtocolVersion, allocator, reader);
        defer allocator.free(versions);
        for (versions) |version| {
            try caps.addVersion(version);
        }

        const ciphersuites = try deserializeEnumList(CipherSuite, allocator, reader);
        defer allocator.free(ciphersuites);
        for (ciphersuites) |cs| {
            try caps.addCipherSuite(cs);
        }

        const extensions = try deserializeEnumList(ExtensionType, allocator, reader);
        defer allocator.free(extensions);
        for (extensions) |ext| {
            try caps.addExtension(ext);
        }

        const proposals = try deserializeEnumList(ProposalType, allocator, reader);
        defer allocator.free(proposals);
        for (proposals) |prop| {
            try caps.addProposal(prop);
        }

        const credentials = try deserializeEnumList(CredentialType, allocator, reader);
        defer allocator.free(credentials);
        for (credentials) |cred| {
            try caps.addCredential(cred);
        }

        return caps;
    }
};

/// The payload of a leaf node (everything except the signature)
pub const LeafNodePayload = struct {
    encryption_key: VarBytes, // HPKE public key
    signature_key: VarBytes, // Signature public key
    credential: Credential,
    capabilities: Capabilities,
    leaf_node_source: LeafNodeSource,
    extensions: Extensions,

    pub fn init(allocator: Allocator) LeafNodePayload {
        return LeafNodePayload{
            .encryption_key = VarBytes.init(allocator, &[_]u8{}) catch unreachable,
            .signature_key = VarBytes.init(allocator, &[_]u8{}) catch unreachable,
            .credential = Credential.init(allocator, .basic, &[_]u8{}) catch unreachable,
            .capabilities = Capabilities.init(allocator),
            .leaf_node_source = LeafNodeSource.Update,
            .extensions = Extensions.init(allocator),
        };
    }

    pub fn deinit(self: *LeafNodePayload, allocator: Allocator) void {
        _ = allocator;
        self.encryption_key.deinit();
        self.signature_key.deinit();
        self.credential.deinit();
        self.capabilities.deinit();
        self.extensions.deinit();
    }

    pub fn serialize(self: LeafNodePayload, writer: anytype) !void {
        try writer.writeVarBytes(u16, self.encryption_key.asSlice());
        try writer.writeVarBytes(u16, self.signature_key.asSlice());
        try self.credential.tlsSerialize(writer);
        try self.capabilities.serialize(writer);
        try self.leaf_node_source.serialize(writer);
        try self.extensions.serialize(writer);
    }

    pub fn deserialize(allocator: Allocator, reader: anytype) !LeafNodePayload {
        const enc_key_bytes = try reader.readVarBytes(u16, allocator);
        defer allocator.free(enc_key_bytes);
        const encryption_key = try VarBytes.init(allocator, enc_key_bytes);
        
        const sig_key_bytes = try reader.readVarBytes(u16, allocator);
        defer allocator.free(sig_key_bytes);
        const signature_key = try VarBytes.init(allocator, sig_key_bytes);
        const credential = try Credential.tlsDeserialize(reader, allocator);
        const capabilities = try Capabilities.deserialize(allocator, reader);
        const leaf_node_source = try LeafNodeSource.deserialize(reader);
        const extensions = try Extensions.deserialize(allocator, reader);

        return LeafNodePayload{
            .encryption_key = encryption_key,
            .signature_key = signature_key,
            .credential = credential,
            .capabilities = capabilities,
            .leaf_node_source = leaf_node_source,
            .extensions = extensions,
        };
    }
};

/// Tree information for signing (To Be Signed context)
pub const TreeInfoTbs = struct {
    group_id: ?VarBytes, // Group ID if applicable
    leaf_index: ?u32, // Leaf index if applicable

    pub fn init(allocator: Allocator) TreeInfoTbs {
        _ = allocator;
        return TreeInfoTbs{
            .group_id = null,
            .leaf_index = null,
        };
    }

    pub fn initWithGroupAndIndex(allocator: Allocator, group_id: []const u8, leaf_index: u32) !TreeInfoTbs {
        var gid = try VarBytes.init(allocator, group_id.len);
        try gid.writeBytes(group_id);
        return TreeInfoTbs{
            .group_id = gid,
            .leaf_index = leaf_index,
        };
    }

    pub fn deinit(self: *TreeInfoTbs) void {
        if (self.group_id) |*gid| {
            gid.deinit();
        }
    }

    pub fn serialize(self: TreeInfoTbs, writer: anytype) !void {
        if (self.group_id) |group_id| {
            try writer.writeU8(1); // Has group info
            try group_id.serialize(writer);
            try writer.writeU32(self.leaf_index.?);
        } else {
            try writer.writeU8(0); // No group info
        }
    }
};

/// Leaf node To Be Signed structure
pub const LeafNodeTbs = struct {
    payload: LeafNodePayload,
    tree_info: TreeInfoTbs,

    pub fn init(allocator: Allocator, payload: LeafNodePayload, tree_info: TreeInfoTbs) LeafNodeTbs {
        _ = allocator;
        return LeafNodeTbs{
            .payload = payload,
            .tree_info = tree_info,
        };
    }

    pub fn deinit(self: *LeafNodeTbs, allocator: Allocator) void {
        self.payload.deinit(allocator);
        self.tree_info.deinit();
    }

    pub fn serialize(self: LeafNodeTbs, writer: anytype) !void {
        try self.payload.serialize(writer);
        try self.tree_info.serialize(writer);
    }

    /// Get the bytes to be signed for this leaf node
    pub fn unsignedPayload(self: LeafNodeTbs, allocator: Allocator) ![]u8 {
        var buffer = std.ArrayList(u8).init(allocator);
        defer buffer.deinit();
        var writer = TlsWriter(std.ArrayList(u8).Writer).init(buffer.writer());
        try self.serialize(&writer);
        return try allocator.dupe(u8, buffer.items);
    }
};

/// Complete leaf node with signature
pub const LeafNode = struct {
    payload: LeafNodePayload,
    signature: VarBytes,

    pub fn init(allocator: Allocator) LeafNode {
        return LeafNode{
            .payload = LeafNodePayload.init(allocator),
            .signature = VarBytes.init(allocator, &[_]u8{}) catch unreachable,
        };
    }

    pub fn deinit(self: *LeafNode, allocator: Allocator) void {
        self.payload.deinit(allocator);
        self.signature.deinit();
    }

    /// Create a new leaf node from a key package
    pub fn fromKeyPackage(
        allocator: Allocator,
        cs: CipherSuite,
        key_package: KeyPackage,
        signature_private_key: @import("key_package.zig").SignaturePrivateKey,
    ) !LeafNode {
        var payload = LeafNodePayload.init(allocator);
        
        // Copy encryption key from key package
        const enc_key_slice = key_package.init_key.asSlice();
        payload.encryption_key = try VarBytes.init(allocator, enc_key_slice);

        // Copy signature key from credential
        const sig_key_slice = key_package.credential.signature_key.asSlice();
        payload.signature_key = try VarBytes.init(allocator, sig_key_slice);

        // Copy credential
        payload.credential = try key_package.credential.credential.clone(allocator);

        // Set default capabilities
        try payload.capabilities.addVersion(.mls10);
        try payload.capabilities.addCipherSuite(cs);
        try payload.capabilities.addCredential(.basic);
        try payload.capabilities.addProposal(.add);
        try payload.capabilities.addProposal(.update);
        try payload.capabilities.addProposal(.remove);

        // Set source as KeyPackage
        payload.leaf_node_source = LeafNodeSource{ .KeyPackage = null };

        // Create TBS structure for signing
        const tree_info = TreeInfoTbs.init(allocator);
        const tbs = LeafNodeTbs.init(allocator, payload, tree_info);
        
        // Sign the leaf node
        const tbs_bytes = try tbs.unsignedPayload(allocator);
        defer allocator.free(tbs_bytes);
        
        const signature_bytes = try @import("key_package.zig").signWithLabel(
            allocator,
            cs,
            signature_private_key.asSlice(),
            "LeafNodeTBS",
            tbs_bytes,
        );
        defer signature_bytes.deinit();

        const signature = try VarBytes.init(allocator, signature_bytes.asSlice());

        return LeafNode{
            .payload = payload,
            .signature = signature,
        };
    }

    /// Verify the signature on this leaf node
    pub fn verifySignature(
        self: LeafNode,
        allocator: Allocator,
        cs: CipherSuite,
        tree_info: TreeInfoTbs,
    ) !bool {
        // Reconstruct the TBS structure
        const tbs = LeafNodeTbs.init(allocator, self.payload, tree_info);
        const tbs_bytes = try tbs.unsignedPayload(allocator);
        defer allocator.free(tbs_bytes);

        // Extract public key from payload
        const public_key_bytes = self.payload.signature_key.asSlice();
        const public_key = try Secret.fromBytes(allocator, public_key_bytes);
        defer public_key.deinit(allocator);

        // Verify signature
        return cs.verifyWithLabel(
            allocator,
            public_key,
            "LeafNodeTBS",
            &[_][]const u8{},
            tbs_bytes,
            self.signature.asSlice(),
        );
    }

    pub fn serialize(self: LeafNode, writer: anytype) !void {
        try self.payload.serialize(writer);
        try writer.writeVarBytes(u16, self.signature.asSlice());
    }

    pub fn deserialize(allocator: Allocator, reader: anytype) !LeafNode {
        const payload = try LeafNodePayload.deserialize(allocator, reader);
        const sig_bytes = try reader.readVarBytes(u16, allocator);
        defer allocator.free(sig_bytes);
        const signature = try VarBytes.init(allocator, sig_bytes);

        return LeafNode{
            .payload = payload,
            .signature = signature,
        };
    }

    /// Get the encryption public key
    pub fn getEncryptionKey(self: LeafNode) []const u8 {
        return self.payload.encryption_key.asSlice();
    }

    /// Get the signature public key
    pub fn getSignatureKey(self: LeafNode) []const u8 {
        return self.payload.signature_key.asSlice();
    }

    /// Get the credential
    pub fn getCredential(self: LeafNode) Credential {
        return self.payload.credential;
    }
};

test "LeafNodeSource serialization" {
    const allocator = testing.allocator;

    // Test KeyPackage source without lifetime
    const source1 = LeafNodeSource{ .KeyPackage = null };
    var buffer1 = std.ArrayList(u8).init(allocator);
    defer buffer1.deinit();
    var writer1 = TlsWriter(std.ArrayList(u8).Writer).init(buffer1.writer());
    try source1.serialize(&writer1);
    
    var stream1 = std.io.fixedBufferStream(buffer1.items);
    var reader1 = TlsReader(@TypeOf(stream1.reader())).init(stream1.reader());
    const deserialized1 = try LeafNodeSource.deserialize(&reader1);
    
    try testing.expect(std.meta.eql(source1, deserialized1));

    // Test KeyPackage source with lifetime
    const source2 = LeafNodeSource{ .KeyPackage = 3600 };
    var buffer2 = std.ArrayList(u8).init(allocator);
    defer buffer2.deinit();
    var writer2 = TlsWriter(std.ArrayList(u8).Writer).init(buffer2.writer());
    try source2.serialize(&writer2);
    
    var stream2 = std.io.fixedBufferStream(buffer2.items);
    var reader2 = TlsReader(@TypeOf(stream2.reader())).init(stream2.reader());
    const deserialized2 = try LeafNodeSource.deserialize(&reader2);
    
    try testing.expect(std.meta.eql(source2, deserialized2));

    // Test Update source
    const source3: LeafNodeSource = LeafNodeSource.Update;
    var buffer3 = std.ArrayList(u8).init(allocator);
    defer buffer3.deinit();
    var writer3 = TlsWriter(std.ArrayList(u8).Writer).init(buffer3.writer());
    try source3.serialize(&writer3);
    
    var stream3 = std.io.fixedBufferStream(buffer3.items);
    var reader3 = TlsReader(@TypeOf(stream3.reader())).init(stream3.reader());
    const deserialized3 = try LeafNodeSource.deserialize(&reader3);
    
    try testing.expect(std.meta.eql(source3, deserialized3));

    // Test Commit source
    const parent_hash = [_]u8{1} ** 32;
    const source4 = LeafNodeSource{ .Commit = parent_hash };
    var buffer4 = std.ArrayList(u8).init(allocator);
    defer buffer4.deinit();
    var writer4 = TlsWriter(std.ArrayList(u8).Writer).init(buffer4.writer());
    try source4.serialize(&writer4);
    
    var stream4 = std.io.fixedBufferStream(buffer4.items);
    var reader4 = TlsReader(@TypeOf(stream4.reader())).init(stream4.reader());
    const deserialized4 = try LeafNodeSource.deserialize(&reader4);
    
    try testing.expect(std.meta.eql(source4, deserialized4));
}

test "Extension creation and serialization" {
    const allocator = testing.allocator;

    // Create extension with test data
    const test_data = "test extension data";
    var ext = try Extension.init(allocator, .capabilities, test_data);
    defer ext.deinit();

    // Serialize
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    var writer = TlsWriter(std.ArrayList(u8).Writer).init(buffer.writer());
    try ext.serialize(&writer);

    // Deserialize
    var stream = std.io.fixedBufferStream(buffer.items);
    var reader = TlsReader(@TypeOf(stream.reader())).init(stream.reader());
    var deserialized = try Extension.deserialize(allocator, &reader);
    defer deserialized.deinit();

    // Verify
    try testing.expect(ext.extension_type == deserialized.extension_type);
    try testing.expectEqualSlices(u8, ext.extension_data.asSlice(), deserialized.extension_data.asSlice());
}

test "Capabilities creation and operations" {
    const allocator = testing.allocator;
    
    var caps = Capabilities.init(allocator);
    defer caps.deinit();

    // Add capabilities
    try caps.addVersion(.mls10);
    try caps.addCipherSuite(.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);
    try caps.addExtension(.capabilities);
    try caps.addProposal(.add);
    try caps.addCredential(.basic);

    // Verify counts
    try testing.expect(caps.versions.items.len == 1);
    try testing.expect(caps.ciphersuites.items.len == 1);
    try testing.expect(caps.extensions.items.len == 1);
    try testing.expect(caps.proposals.items.len == 1);
    try testing.expect(caps.credentials.items.len == 1);

    // Test serialization
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    var writer = TlsWriter(std.ArrayList(u8).Writer).init(buffer.writer());
    try caps.serialize(&writer);

    var stream = std.io.fixedBufferStream(buffer.items);
    var reader = TlsReader(@TypeOf(stream.reader())).init(stream.reader());
    var deserialized = try Capabilities.deserialize(allocator, &reader);
    defer deserialized.deinit();

    // Verify deserialized capabilities
    try testing.expect(deserialized.versions.items.len == caps.versions.items.len);
    try testing.expect(deserialized.ciphersuites.items.len == caps.ciphersuites.items.len);
    try testing.expect(deserialized.extensions.items.len == caps.extensions.items.len);
    try testing.expect(deserialized.proposals.items.len == caps.proposals.items.len);
    try testing.expect(deserialized.credentials.items.len == caps.credentials.items.len);
}

test "LeafNode creation from KeyPackage" {
    _ = testing.allocator;
    // TODO: Implement KeyPackageBundle.create method
    // For now, skip this test until KeyPackageBundle creation is implemented
    return error.SkipZigTest;
}

test "LeafNode signature verification" {
    _ = testing.allocator;
    // TODO: Implement KeyPackageBundle.create method
    return error.SkipZigTest;
}

test "LeafNode serialization round trip" {
    _ = testing.allocator;
    // TODO: Implement KeyPackageBundle.create method
    return error.SkipZigTest;
}

test "LeafNode with group context (Update source)" {
    _ = testing.allocator;
    // TODO: Implement KeyPackageBundle.create method
    return error.SkipZigTest;
}

test "Extension types enum values" {
    // Verify standard extension type values match MLS spec
    try testing.expect(@intFromEnum(ExtensionType.capabilities) == 0x0001);
    try testing.expect(@intFromEnum(ExtensionType.lifetime) == 0x0002);
    try testing.expect(@intFromEnum(ExtensionType.key_id) == 0x0003);
    try testing.expect(@intFromEnum(ExtensionType.parent_hash) == 0x0004);
    try testing.expect(@intFromEnum(ExtensionType.ratchet_tree) == 0x0005);
    
    // Verify custom Nostr extension values
    try testing.expect(@intFromEnum(ExtensionType.nostr_group_data) == 0xFF00);
    try testing.expect(@intFromEnum(ExtensionType.last_resort) == 0xFF01);
}

test "Proposal types enum values" {
    // Verify proposal type values match MLS spec  
    try testing.expect(@intFromEnum(ProposalType.add) == 0x0001);
    try testing.expect(@intFromEnum(ProposalType.update) == 0x0002);
    try testing.expect(@intFromEnum(ProposalType.remove) == 0x0003);
    try testing.expect(@intFromEnum(ProposalType.psk) == 0x0004);
    try testing.expect(@intFromEnum(ProposalType.reinit) == 0x0005);
    try testing.expect(@intFromEnum(ProposalType.external_init) == 0x0006);
    try testing.expect(@intFromEnum(ProposalType.group_context_extensions) == 0x0007);
}