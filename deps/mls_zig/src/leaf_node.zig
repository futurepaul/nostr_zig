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
const tls_encode = @import("tls_encode.zig");
const tls = std.crypto.tls;

/// Helper function to serialize a list with length prefix
fn serializeList(comptime T: type, items: []const T, writer: anytype) !void {
    try tls_encode.writeInt(writer, u16, @intCast(items.len));
    for (items) |item| {
        try item.serialize(writer);
    }
}

/// Helper function to serialize enum lists 
fn serializeEnumList(comptime T: type, items: []const T, writer: anytype) !void {
    try tls_encode.writeInt(writer, u16, @intCast(items.len));
    for (items) |item| {
        try tls_encode.writeInt(writer, u16, @intFromEnum(item));
    }
}

/// Helper function to serialize enum lists to ArrayList
fn serializeEnumListToList(comptime T: type, items: []const T, list: *std.ArrayList(u8)) !void {
    try tls_encode.encodeInt(list, u16, @intCast(items.len));
    for (items) |item| {
        try tls_encode.encodeInt(list, u16, @intFromEnum(item));
    }
}

/// Helper function to serialize a list with items that need allocator in serialize
fn serializeListWithAllocator(comptime T: type, items: []const T, writer: anytype) !void {
    try tls_encode.writeInt(writer, u16, @intCast(items.len));
    for (items) |item| {
        try item.serialize(writer);
    }
}

/// Helper function to serialize a list to ArrayList
fn serializeListToList(comptime T: type, items: []const T, list: *std.ArrayList(u8)) !void {
    try tls_encode.encodeInt(list, u16, @intCast(items.len));
    for (items) |item| {
        try item.serializeToList(list);
    }
}

/// Helper function to deserialize a list with length prefix
fn deserializeList(comptime T: type, allocator: Allocator, reader: anytype) ![]T {
    var len_buf: [2]u8 = undefined;
    _ = try reader.readAll(&len_buf);
    var decoder = tls.Decoder.fromTheirSlice(&len_buf);
    const len = decoder.decode(u16);
    const result = try allocator.alloc(T, len);
    for (result) |*item| {
        item.* = try T.deserialize(reader);
    }
    return result;
}

/// Helper function to deserialize a list that needs allocator
fn deserializeListWithAllocator(comptime T: type, allocator: Allocator, reader: anytype) ![]T {
    var len_buf: [2]u8 = undefined;
    _ = try reader.readAll(&len_buf);
    var decoder = tls.Decoder.fromTheirSlice(&len_buf);
    const len = decoder.decode(u16);
    const result = try allocator.alloc(T, len);
    for (result) |*item| {
        item.* = try T.deserialize(allocator, reader);
    }
    return result;
}

/// Helper function to deserialize enum lists
fn deserializeEnumList(comptime T: type, allocator: Allocator, reader: anytype) ![]T {
    var len_buf: [2]u8 = undefined;
    _ = try reader.readAll(&len_buf);
    var decoder = tls.Decoder.fromTheirSlice(&len_buf);
    const len = decoder.decode(u16);
    const result = try allocator.alloc(T, len);
    for (result) |*item| {
        var val_buf: [2]u8 = undefined;
        _ = try reader.readAll(&val_buf);
        var val_decoder = tls.Decoder.fromTheirSlice(&val_buf);
        const value = val_decoder.decode(u16);
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
                try tls_encode.writeInt(writer, u8, 0); // Tag for KeyPackage
                if (lifetime) |lt| {
                    try tls_encode.writeInt(writer, u8, 1); // Has lifetime
                    try tls_encode.writeInt(writer, u64, lt);
                } else {
                    try tls_encode.writeInt(writer, u8, 0); // No lifetime
                }
            },
            .Update => {
                try tls_encode.writeInt(writer, u8, 1); // Tag for Update
            },
            .Commit => |parent_hash| {
                try tls_encode.writeInt(writer, u8, 2); // Tag for Commit
                try writer.writeAll(&parent_hash);
            },
        }
    }

    pub fn serializeToList(self: LeafNodeSource, list: *std.ArrayList(u8)) !void {
        switch (self) {
            .KeyPackage => |lifetime| {
                try tls_encode.encodeInt(list, u8, 0); // Tag for KeyPackage
                if (lifetime) |lt| {
                    try tls_encode.encodeInt(list, u8, 1); // Has lifetime
                    try tls_encode.encodeInt(list, u64, lt);
                } else {
                    try tls_encode.encodeInt(list, u8, 0); // No lifetime
                }
            },
            .Update => {
                try tls_encode.encodeInt(list, u8, 1); // Tag for Update
            },
            .Commit => |parent_hash| {
                try tls_encode.encodeInt(list, u8, 2); // Tag for Commit
                try list.appendSlice(&parent_hash);
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
        try tls_encode.writeInt(writer, u16, @intFromEnum(self));
    }

    pub fn deserialize(reader: anytype) !ProtocolVersion {
        var buf: [2]u8 = undefined;
        _ = try reader.readAll(&buf);
        var decoder = tls.Decoder.fromTheirSlice(&buf);
        const value = decoder.decode(u16);
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
        try tls_encode.writeInt(writer, u16, @intFromEnum(self));
    }

    pub fn deserialize(reader: anytype) !ProposalType {
        var buf: [2]u8 = undefined;
        _ = try reader.readAll(&buf);
        var decoder = tls.Decoder.fromTheirSlice(&buf);
        const value = decoder.decode(u16);
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
        try tls_encode.writeInt(writer, u16, @intFromEnum(self));
    }

    pub fn deserialize(reader: anytype) !CredentialType {
        var buf: [2]u8 = undefined;
        _ = try reader.readAll(&buf);
        var decoder = tls.Decoder.fromTheirSlice(&buf);
        const value = decoder.decode(u16);
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
        try tls_encode.writeInt(writer, u16, @intFromEnum(self));
    }

    pub fn serializeToList(self: ExtensionType, list: *std.ArrayList(u8)) !void {
        try tls_encode.encodeInt(list, u16, @intFromEnum(self));
    }

    pub fn deserialize(reader: anytype) !ExtensionType {
        var buf: [2]u8 = undefined;
        _ = try reader.readAll(&buf);
        var decoder = tls.Decoder.fromTheirSlice(&buf);
        const value = decoder.decode(u16);
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
    extension_data: []u8,
    allocator: std.mem.Allocator,

    pub fn init(allocator: Allocator, ext_type: ExtensionType, data: []const u8) !Extension {
        return Extension{
            .extension_type = ext_type,
            .extension_data = try allocator.dupe(u8, data),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Extension) void {
        self.allocator.free(self.extension_data);
    }

    pub fn serialize(self: Extension, writer: anytype) !void {
        try self.extension_type.serialize(writer);
        try tls_encode.writeVarBytes(writer, u16, self.extension_data);
    }

    pub fn serializeToList(self: Extension, list: *std.ArrayList(u8)) !void {
        try self.extension_type.serializeToList(list);
        try tls_encode.encodeVarBytes(list, u16, self.extension_data);
    }

    pub fn deserialize(allocator: Allocator, reader: anytype) !Extension {
        const ext_type = try ExtensionType.deserialize(reader);
        // Read length prefix manually
        var len_buf: [2]u8 = undefined;
        _ = try reader.readAll(&len_buf);
        var decoder = tls.Decoder.fromTheirSlice(&len_buf);
        const len = decoder.decode(u16);
        
        const data_bytes = try allocator.alloc(u8, len);
        _ = try reader.readAll(data_bytes);
        
        return Extension{
            .extension_type = ext_type,
            .extension_data = data_bytes,
            .allocator = allocator,
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

    pub fn serializeToList(self: Extensions, list: *std.ArrayList(u8)) !void {
        try serializeListToList(Extension, self.extensions.items, list);
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

    pub fn serializeToList(self: Capabilities, list: *std.ArrayList(u8)) !void {
        try serializeEnumListToList(ProtocolVersion, self.versions.items, list);
        try serializeEnumListToList(CipherSuite, self.ciphersuites.items, list);
        try serializeEnumListToList(ExtensionType, self.extensions.items, list);
        try serializeEnumListToList(ProposalType, self.proposals.items, list);
        try serializeEnumListToList(CredentialType, self.credentials.items, list);
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
    encryption_key: []u8, // HPKE public key
    signature_key: []u8, // Signature public key
    credential: Credential,
    capabilities: Capabilities,
    leaf_node_source: LeafNodeSource,
    extensions: Extensions,
    allocator: std.mem.Allocator,

    pub fn init(allocator: Allocator) LeafNodePayload {
        return LeafNodePayload{
            .encryption_key = allocator.alloc(u8, 0) catch unreachable,
            .signature_key = allocator.alloc(u8, 0) catch unreachable,
            .credential = Credential.init(allocator, .basic, &[_]u8{}) catch unreachable,
            .capabilities = Capabilities.init(allocator),
            .leaf_node_source = LeafNodeSource.Update,
            .extensions = Extensions.init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *LeafNodePayload, allocator: Allocator) void {
        _ = allocator;
        self.allocator.free(self.encryption_key);
        self.allocator.free(self.signature_key);
        self.credential.deinit();
        self.capabilities.deinit();
        self.extensions.deinit();
    }

    pub fn serialize(self: LeafNodePayload, writer: anytype) !void {
        try tls_encode.writeVarBytes(writer, u16, self.encryption_key);
        try tls_encode.writeVarBytes(writer, u16, self.signature_key);
        try self.credential.tlsSerialize(writer);
        try self.capabilities.serialize(writer);
        try self.leaf_node_source.serialize(writer);
        try self.extensions.serialize(writer);
    }

    pub fn serializeToList(self: LeafNodePayload, list: *std.ArrayList(u8)) !void {
        try tls_encode.encodeVarBytes(list, u16, self.encryption_key);
        try tls_encode.encodeVarBytes(list, u16, self.signature_key);
        try self.credential.tlsSerializeToList(list);
        try self.capabilities.serializeToList(list);
        try self.leaf_node_source.serializeToList(list);
        try self.extensions.serializeToList(list);
    }

    pub fn deserialize(allocator: Allocator, reader: anytype) !LeafNodePayload {
        // Read encryption key length prefix manually
        var enc_len_buf: [2]u8 = undefined;
        _ = try reader.readAll(&enc_len_buf);
        var enc_decoder = tls.Decoder.fromTheirSlice(&enc_len_buf);
        const enc_len = enc_decoder.decode(u16);
        const encryption_key = try allocator.alloc(u8, enc_len);
        _ = try reader.readAll(encryption_key);
        
        // Read signature key length prefix manually
        var sig_len_buf: [2]u8 = undefined;
        _ = try reader.readAll(&sig_len_buf);
        var sig_decoder = tls.Decoder.fromTheirSlice(&sig_len_buf);
        const sig_len = sig_decoder.decode(u16);
        const signature_key = try allocator.alloc(u8, sig_len);
        _ = try reader.readAll(signature_key);
        
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
            .allocator = allocator,
        };
    }
};

/// Tree information for signing (To Be Signed context)
pub const TreeInfoTbs = struct {
    group_id: ?[]u8, // Group ID if applicable
    leaf_index: ?u32, // Leaf index if applicable
    allocator: ?std.mem.Allocator, // Only set if group_id is owned

    pub fn init(allocator: Allocator) TreeInfoTbs {
        _ = allocator;
        return TreeInfoTbs{
            .group_id = null,
            .leaf_index = null,
            .allocator = null,
        };
    }

    pub fn initWithGroupAndIndex(allocator: Allocator, group_id: []const u8, leaf_index: u32) !TreeInfoTbs {
        const gid = try allocator.dupe(u8, group_id);
        return TreeInfoTbs{
            .group_id = gid,
            .leaf_index = leaf_index,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *TreeInfoTbs) void {
        if (self.group_id) |gid| {
            if (self.allocator) |alloc| {
                alloc.free(gid);
            }
        }
    }

    pub fn serialize(self: TreeInfoTbs, writer: anytype) !void {
        if (self.group_id) |group_id| {
            try tls_encode.writeInt(writer, u8, 1); // Has group info
            try tls_encode.writeVarBytes(writer, u32, group_id);
            try tls_encode.writeInt(writer, u32, self.leaf_index.?);
        } else {
            try tls_encode.writeInt(writer, u8, 0); // No group info
        }
    }

    pub fn serializeToList(self: TreeInfoTbs, list: *std.ArrayList(u8)) !void {
        if (self.group_id) |group_id| {
            try tls_encode.encodeInt(list, u8, 1); // Has group info
            try tls_encode.encodeVarBytes(list, u32, group_id);
            try tls_encode.encodeInt(list, u32, self.leaf_index.?);
        } else {
            try tls_encode.encodeInt(list, u8, 0); // No group info
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
        
        // Manual serialization instead of TlsWriter
        try self.payload.serializeToList(&buffer);
        try self.tree_info.serializeToList(&buffer);
        
        return try allocator.dupe(u8, buffer.items);
    }
};

/// Complete leaf node with signature
pub const LeafNode = struct {
    payload: LeafNodePayload,
    signature: []u8,
    allocator: std.mem.Allocator,

    pub fn init(allocator: Allocator) LeafNode {
        return LeafNode{
            .payload = LeafNodePayload.init(allocator),
            .signature = allocator.alloc(u8, 0) catch unreachable,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *LeafNode, allocator: Allocator) void {
        self.payload.deinit(allocator);
        self.allocator.free(self.signature);
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
        const enc_key_slice = key_package.initKey().asSlice();
        payload.encryption_key = try allocator.dupe(u8, enc_key_slice);

        // Copy signature key from credential
        const sig_key_slice = key_package.signatureKey().asSlice();
        payload.signature_key = try allocator.dupe(u8, sig_key_slice);

        // Copy credential
        const kp_credential = key_package.credential();
        payload.credential = try Credential.init(
            allocator, 
            kp_credential.getType(), 
            kp_credential.getSerializedContent()
        );

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
        
        var signature_bytes = try @import("key_package.zig").signWithLabel(
            allocator,
            cs,
            signature_private_key.asSlice(),
            "LeafNodeTBS",
            tbs_bytes,
        );
        defer signature_bytes.deinit(allocator);

        const signature = try allocator.dupe(u8, signature_bytes.asSlice());

        return LeafNode{
            .payload = payload,
            .signature = signature,
            .allocator = allocator,
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
        const public_key_bytes = self.payload.signature_key;
        const public_key = try Secret.fromBytes(allocator, public_key_bytes);
        defer public_key.deinit(allocator);

        // Verify signature
        return cs.verifyWithLabel(
            allocator,
            public_key,
            "LeafNodeTBS",
            &[_][]const u8{},
            tbs_bytes,
            self.signature,
        );
    }

    pub fn serialize(self: LeafNode, writer: anytype) !void {
        try self.payload.serialize(writer);
        try tls_encode.writeVarBytes(writer, u16, self.signature);
    }

    pub fn deserialize(allocator: Allocator, reader: anytype) !LeafNode {
        const payload = try LeafNodePayload.deserialize(allocator, reader);
        
        // Read signature length prefix manually
        var sig_len_buf: [2]u8 = undefined;
        _ = try reader.readAll(&sig_len_buf);
        var sig_decoder = tls.Decoder.fromTheirSlice(&sig_len_buf);
        const sig_len = sig_decoder.decode(u16);
        const signature = try allocator.alloc(u8, sig_len);
        _ = try reader.readAll(signature);

        return LeafNode{
            .payload = payload,
            .signature = signature,
            .allocator = allocator,
        };
    }

    /// Get the encryption public key
    pub fn getEncryptionKey(self: LeafNode) []const u8 {
        return self.payload.encryption_key;
    }

    /// Get the signature public key
    pub fn getSignatureKey(self: LeafNode) []const u8 {
        return self.payload.signature_key;
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
    try source1.serialize(buffer1.writer());
    
    var stream1 = std.io.fixedBufferStream(buffer1.items);
    const deserialized1 = try LeafNodeSource.deserialize(stream1.reader());
    
    try testing.expect(std.meta.eql(source1, deserialized1));

    // Test KeyPackage source with lifetime
    const source2 = LeafNodeSource{ .KeyPackage = 3600 };
    var buffer2 = std.ArrayList(u8).init(allocator);
    defer buffer2.deinit();
    try source2.serialize(buffer2.writer());
    
    var stream2 = std.io.fixedBufferStream(buffer2.items);
    const deserialized2 = try LeafNodeSource.deserialize(stream2.reader());
    
    try testing.expect(std.meta.eql(source2, deserialized2));

    // Test Update source
    const source3: LeafNodeSource = LeafNodeSource.Update;
    var buffer3 = std.ArrayList(u8).init(allocator);
    defer buffer3.deinit();
    try source3.serialize(buffer3.writer());
    
    var stream3 = std.io.fixedBufferStream(buffer3.items);
    const deserialized3 = try LeafNodeSource.deserialize(stream3.reader());
    
    try testing.expect(std.meta.eql(source3, deserialized3));

    // Test Commit source
    const parent_hash = [_]u8{1} ** 32;
    const source4 = LeafNodeSource{ .Commit = parent_hash };
    var buffer4 = std.ArrayList(u8).init(allocator);
    defer buffer4.deinit();
    try source4.serialize(buffer4.writer());
    
    var stream4 = std.io.fixedBufferStream(buffer4.items);
    const deserialized4 = try LeafNodeSource.deserialize(stream4.reader());
    
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
    try ext.serialize(buffer.writer());

    // Deserialize
    var stream = std.io.fixedBufferStream(buffer.items);
    var deserialized = try Extension.deserialize(allocator, stream.reader());
    defer deserialized.deinit();

    // Verify
    try testing.expect(ext.extension_type == deserialized.extension_type);
    try testing.expectEqualSlices(u8, ext.extension_data, deserialized.extension_data);
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
    try caps.serialize(buffer.writer());

    var stream = std.io.fixedBufferStream(buffer.items);
    var deserialized = try Capabilities.deserialize(allocator, stream.reader());
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