const std = @import("std");
const testing = std.testing;
const crypto = std.crypto;
const Allocator = std.mem.Allocator;
const wasm_random = @import("wasm_random.zig");

const tls_codec = @import("tls_codec.zig");
const cipher_suite = @import("cipher_suite.zig");
const credentials = @import("credentials.zig");

pub const MLS_PROTOCOL_VERSION: u16 = 0x0001;

pub const HpkePublicKey = struct {
    data: []const u8,

    pub fn init(key_data: []const u8) HpkePublicKey {
        return HpkePublicKey{
            .data = key_data,
        };
    }

    pub fn initOwned(allocator: Allocator, key_data: []const u8) !HpkePublicKey {
        const data = try allocator.dupe(u8, key_data);
        return HpkePublicKey{
            .data = data,
        };
    }

    pub fn deinit(self: *HpkePublicKey, allocator: Allocator) void {
        allocator.free(self.data);
        self.data = &[_]u8{};
    }

    pub fn asSlice(self: HpkePublicKey) []const u8 {
        return self.data;
    }

    pub fn len(self: HpkePublicKey) usize {
        return self.data.len;
    }
    
    /// Create a deep copy of this HpkePublicKey
    pub fn clone(self: HpkePublicKey, allocator: Allocator) !HpkePublicKey {
        return HpkePublicKey.initOwned(allocator, self.data);
    }
};

pub const HpkePrivateKey = struct {
    data: []u8,

    pub fn init(key_data: []u8) HpkePrivateKey {
        return HpkePrivateKey{
            .data = key_data,
        };
    }

    pub fn initOwned(allocator: Allocator, key_data: []const u8) !HpkePrivateKey {
        const data = try allocator.dupe(u8, key_data);
        return HpkePrivateKey{
            .data = data,
        };
    }

    pub fn deinit(self: *HpkePrivateKey, allocator: Allocator) void {
        crypto.secureZero(u8, self.data);
        allocator.free(self.data);
        self.data = &[_]u8{};
    }

    pub fn asSlice(self: HpkePrivateKey) []const u8 {
        return self.data;
    }

    pub fn len(self: HpkePrivateKey) usize {
        return self.data.len;
    }
};

pub const SignaturePublicKey = struct {
    data: []const u8,

    pub fn init(key_data: []const u8) SignaturePublicKey {
        return SignaturePublicKey{
            .data = key_data,
        };
    }

    pub fn initOwned(allocator: Allocator, key_data: []const u8) !SignaturePublicKey {
        const data = try allocator.dupe(u8, key_data);
        return SignaturePublicKey{
            .data = data,
        };
    }

    pub fn deinit(self: *SignaturePublicKey, allocator: Allocator) void {
        allocator.free(self.data);
        self.data = &[_]u8{};
    }

    pub fn asSlice(self: SignaturePublicKey) []const u8 {
        return self.data;
    }

    pub fn len(self: SignaturePublicKey) usize {
        return self.data.len;
    }
    
    pub fn clone(self: SignaturePublicKey, allocator: Allocator) !SignaturePublicKey {
        return SignaturePublicKey.initOwned(allocator, self.data);
    }
};

pub const SignaturePrivateKey = struct {
    data: []u8,

    pub fn init(key_data: []u8) SignaturePrivateKey {
        return SignaturePrivateKey{
            .data = key_data,
        };
    }

    pub fn initOwned(allocator: Allocator, key_data: []const u8) !SignaturePrivateKey {
        const data = try allocator.dupe(u8, key_data);
        return SignaturePrivateKey{
            .data = data,
        };
    }

    pub fn deinit(self: *SignaturePrivateKey, allocator: Allocator) void {
        crypto.secureZero(u8, self.data);
        allocator.free(self.data);
        self.data = &[_]u8{};
    }

    pub fn asSlice(self: SignaturePrivateKey) []const u8 {
        return self.data;
    }

    pub fn len(self: SignaturePrivateKey) usize {
        return self.data.len;
    }
};

pub const Signature = struct {
    data: []const u8,

    pub fn init(signature_data: []const u8) Signature {
        return Signature{
            .data = signature_data,
        };
    }

    pub fn initOwned(allocator: Allocator, signature_data: []const u8) !Signature {
        const data = try allocator.dupe(u8, signature_data);
        return Signature{
            .data = data,
        };
    }

    pub fn deinit(self: *Signature, allocator: Allocator) void {
        allocator.free(self.data);
        self.data = &[_]u8{};
    }

    pub fn asSlice(self: Signature) []const u8 {
        return self.data;
    }

    pub fn len(self: Signature) usize {
        return self.data.len;
    }
    
    pub fn clone(self: Signature, allocator: Allocator) !Signature {
        return Signature.initOwned(allocator, self.data);
    }
};

pub const Lifetime = struct {
    not_before: u64,
    not_after: u64,

    pub fn init(not_before: u64, not_after: u64) Lifetime {
        return Lifetime{
            .not_before = not_before,
            .not_after = not_after,
        };
    }

    pub fn isValid(self: Lifetime, current_time: u64) bool {
        return current_time >= self.not_before and current_time <= self.not_after;
    }
};

pub const LeafNodeSource = union(enum) {
    key_package: Lifetime,
    update: void,
    commit: []u8,

    pub fn deinit(self: *LeafNodeSource, allocator: Allocator) void {
        switch (self.*) {
            .commit => |parent_hash| allocator.free(parent_hash),
            else => {},
        }
    }
    
    pub fn clone(self: LeafNodeSource, allocator: Allocator) !LeafNodeSource {
        switch (self) {
            .key_package => |lifetime| return LeafNodeSource{ .key_package = lifetime },
            .update => return LeafNodeSource{ .update = {} },
            .commit => |parent_hash| {
                const cloned_hash = try allocator.dupe(u8, parent_hash);
                return LeafNodeSource{ .commit = cloned_hash };
            },
        }
    }
    
};

pub const Capabilities = struct {
    versions: []u16,
    cipher_suites: []cipher_suite.CipherSuite,
    extensions: []u16,
    proposals: []u8,
    credentials: []u8,
    allocator: Allocator,

    pub fn init(allocator: Allocator) Capabilities {
        return Capabilities{
            .versions = &[_]u16{},
            .cipher_suites = &[_]cipher_suite.CipherSuite{},
            .extensions = &[_]u16{},
            .proposals = &[_]u8{},
            .credentials = &[_]u8{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Capabilities) void {
        self.allocator.free(self.versions);
        self.allocator.free(self.cipher_suites);
        self.allocator.free(self.extensions);
        self.allocator.free(self.proposals);
        self.allocator.free(self.credentials);
    }

    pub fn supportsVersion(self: Capabilities, version: u16) bool {
        for (self.versions) |v| {
            if (v == version) return true;
        }
        return false;
    }

    pub fn supportsCipherSuite(self: Capabilities, cs: cipher_suite.CipherSuite) bool {
        for (self.cipher_suites) |suite| {
            if (suite == cs) return true;
        }
        return false;
    }
    
    pub fn clone(self: Capabilities, allocator: Allocator) !Capabilities {
        return Capabilities{
            .versions = try allocator.dupe(u16, self.versions),
            .cipher_suites = try allocator.dupe(cipher_suite.CipherSuite, self.cipher_suites),
            .extensions = try allocator.dupe(u16, self.extensions),
            .proposals = try allocator.dupe(u8, self.proposals),
            .credentials = try allocator.dupe(u8, self.credentials),
            .allocator = allocator,
        };
    }
    
};

pub const Extension = struct {
    extension_type: u16,
    extension_data: []u8,
    allocator: Allocator,

    pub fn init(allocator: Allocator, ext_type: u16, data: []const u8) !Extension {
        const extension_data = try allocator.dupe(u8, data);
        return Extension{
            .extension_type = ext_type,
            .extension_data = extension_data,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Extension) void {
        self.allocator.free(self.extension_data);
        self.extension_data = &[_]u8{};
    }
    
    pub fn clone(self: Extension, allocator: Allocator) !Extension {
        return Extension.init(allocator, self.extension_type, self.extension_data);
    }
    
};

pub const Extensions = struct {
    extensions: []Extension,
    allocator: Allocator,

    pub fn init(allocator: Allocator) Extensions {
        return Extensions{
            .extensions = &[_]Extension{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Extensions) void {
        for (self.extensions) |*ext| {
            ext.deinit();
        }
        self.allocator.free(self.extensions);
    }

    pub fn addExtension(self: *Extensions, extension: Extension) !void {
        const new_extensions = try self.allocator.realloc(self.extensions, self.extensions.len + 1);
        new_extensions[self.extensions.len] = extension;
        self.extensions = new_extensions;
    }

    pub fn findExtension(self: Extensions, ext_type: u16) ?*const Extension {
        for (self.extensions) |*ext| {
            if (ext.extension_type == ext_type) return ext;
        }
        return null;
    }
    
    pub fn clone(self: Extensions, allocator: Allocator) !Extensions {
        var result = Extensions.init(allocator);
        for (self.extensions) |ext| {
            const cloned_ext = try ext.clone(allocator);
            try result.addExtension(cloned_ext);
        }
        return result;
    }
    
};

pub const LeafNode = struct {
    encryption_key: HpkePublicKey,
    signature_key: SignaturePublicKey,
    credential: credentials.Credential,
    capabilities: Capabilities,
    leaf_node_source: LeafNodeSource,
    extensions: Extensions,
    signature: Signature,

    pub fn deinit(self: *LeafNode, allocator: Allocator) void {
        self.encryption_key.deinit(allocator);
        self.signature_key.deinit(allocator);
        self.credential.deinit();
        self.capabilities.deinit();
        self.leaf_node_source.deinit(allocator);
        self.extensions.deinit();
        self.signature.deinit(allocator);
    }
    
    pub fn clone(self: LeafNode, allocator: Allocator) !LeafNode {
        return LeafNode{
            .encryption_key = try self.encryption_key.clone(allocator),
            .signature_key = try self.signature_key.clone(allocator),
            .credential = try self.credential.clone(allocator),
            .capabilities = try self.capabilities.clone(allocator),
            .leaf_node_source = try self.leaf_node_source.clone(allocator),
            .extensions = try self.extensions.clone(allocator),
            .signature = try self.signature.clone(allocator),
        };
    }
};

pub const KeyPackageTBS = struct {
    protocol_version: u16,
    cipher_suite: cipher_suite.CipherSuite,
    init_key: HpkePublicKey,
    leaf_node: LeafNode,
    extensions: Extensions,

    pub fn deinit(self: *KeyPackageTBS, allocator: Allocator) void {
        self.init_key.deinit(allocator);
        self.leaf_node.deinit(allocator);
        self.extensions.deinit();
    }
    
    pub fn clone(self: KeyPackageTBS, allocator: Allocator) !KeyPackageTBS {
        return KeyPackageTBS{
            .protocol_version = self.protocol_version,
            .cipher_suite = self.cipher_suite,
            .init_key = try self.init_key.clone(allocator),
            .leaf_node = try self.leaf_node.clone(allocator),
            .extensions = try self.extensions.clone(allocator),
        };
    }
    
};

pub const KeyPackage = struct {
    payload: KeyPackageTBS,
    signature: Signature,

    pub fn deinit(self: *KeyPackage, allocator: Allocator) void {
        self.payload.deinit(allocator);
        self.signature.deinit(allocator);
    }

    pub fn cipherSuite(self: KeyPackage) cipher_suite.CipherSuite {
        return self.payload.cipher_suite;
    }

    pub fn protocolVersion(self: KeyPackage) u16 {
        return self.payload.protocol_version;
    }

    pub fn initKey(self: KeyPackage) *const HpkePublicKey {
        return &self.payload.init_key;
    }

    pub fn leafNode(self: KeyPackage) *const LeafNode {
        return &self.payload.leaf_node;
    }

    pub fn encryptionKey(self: KeyPackage) *const HpkePublicKey {
        return &self.payload.leaf_node.encryption_key;
    }

    pub fn signatureKey(self: KeyPackage) *const SignaturePublicKey {
        return &self.payload.leaf_node.signature_key;
    }

    pub fn credential(self: KeyPackage) *const credentials.Credential {
        return &self.payload.leaf_node.credential;
    }
};

pub const KeyPackageBundle = struct {
    key_package: KeyPackage,
    private_init_key: HpkePrivateKey,
    private_encryption_key: HpkePrivateKey,
    private_signature_key: SignaturePrivateKey,

    /// Create a new KeyPackageBundle with generated keys and proper MLS signing
    pub fn init(
        allocator: Allocator,
        cs: cipher_suite.CipherSuite,
        credential: credentials.Credential,
        random_fn: ?wasm_random.RandomFunction,
    ) !KeyPackageBundle {
        // Generate signature key pair
        var sig_keypair = try generateSignatureKeyPair(allocator, cs);
        defer sig_keypair.deinit();

        // Generate HPKE key pairs for init and encryption keys
        var init_keypair = try generateHpkeKeyPair(allocator, cs, random_fn);
        defer init_keypair.deinit();

        var enc_keypair = try generateHpkeKeyPair(allocator, cs, random_fn);
        defer enc_keypair.deinit();

        // Create public key wrappers - these now own the memory from the keypairs
        var init_key = try HpkePublicKey.initOwned(allocator, init_keypair.public_key);
        errdefer init_key.deinit(allocator);
        
        // DEBUG: Check init_key immediately after creation
        if (@import("builtin").target.cpu.arch == .wasm32) {
            // Simple debug without complex logging for WASM
            const debug_len = init_key.asSlice().len;
            const debug_data = init_key.asSlice();
            // Log the length and first few bytes
            if (debug_len != 32) {
                @panic("CRITICAL: init_key length is not 32 bytes immediately after creation!");
            }
            if (debug_len > 0 and debug_data[0] == 0x20) {
                @panic("CRITICAL: init_key starts with 0x20 immediately after creation!");
            }
        }

        var enc_key = try HpkePublicKey.initOwned(allocator, enc_keypair.public_key);
        errdefer enc_key.deinit(allocator);

        var sig_key = try SignaturePublicKey.initOwned(allocator, sig_keypair.public_key);
        errdefer sig_key.deinit(allocator);

        // Create basic capabilities
        var capabilities = Capabilities.init(allocator);
        // Add default MLS version support
        const versions = try allocator.alloc(u16, 1);
        versions[0] = MLS_PROTOCOL_VERSION;
        capabilities.versions = versions;
        
        // Add cipher suite support
        const cipher_suites = try allocator.alloc(cipher_suite.CipherSuite, 1);
        cipher_suites[0] = cs;
        capabilities.cipher_suites = cipher_suites;

        // Empty extensions for now
        const extensions = Extensions.init(allocator);

        // Create LeafNodeSource for KeyPackage
        const lifetime = Lifetime.init(0, std.math.maxInt(u64)); // Max lifetime for simplicity
        const leaf_source = LeafNodeSource{ .key_package = lifetime };

        // Create a dummy signature (will be replaced)
        const dummy_sig = try Signature.initOwned(allocator, &[_]u8{0x00} ** 64);

        // Clone the credential to avoid ownership issues
        var cloned_cred = try credentials.Credential.init(
            allocator,
            credential.credential_type,
            credential.serialized_content.asSlice()
        );
        errdefer cloned_cred.deinit();

        // Create the LeafNode - we need to be careful about ownership
        // Since we're moving these structs around, we need to ensure the data stays valid
        const leaf_node = LeafNode{
            .encryption_key = enc_key,
            .signature_key = sig_key,
            .credential = cloned_cred,
            .capabilities = capabilities,
            .leaf_node_source = leaf_source,
            .extensions = extensions,
            .signature = dummy_sig,
        };

        // Create KeyPackageTBS for signing
        // IMPORTANT: We're moving init_key and leaf_node here, so we can't use them after this
        var key_package_tbs = KeyPackageTBS{
            .protocol_version = MLS_PROTOCOL_VERSION,
            .cipher_suite = cs,
            .init_key = init_key,
            .leaf_node = leaf_node,
            .extensions = Extensions.init(allocator),
        };

        // Serialize KeyPackageTBS manually to avoid TlsWriter/ArrayList incompatibility
        var tbs_data = std.ArrayList(u8).init(allocator);
        defer tbs_data.deinit();
        
        // Protocol version (u16)
        var proto_bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &proto_bytes, key_package_tbs.protocol_version, .big);
        try tbs_data.appendSlice(&proto_bytes);
        
        // Cipher suite (u16)
        var cs_bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &cs_bytes, @intFromEnum(key_package_tbs.cipher_suite), .big);
        try tbs_data.appendSlice(&cs_bytes);
        
        // Init key with length prefix (u16)
        const init_key_slice = key_package_tbs.init_key.asSlice();
        if (init_key_slice.len > std.math.maxInt(u16)) return error.ValueTooLarge;
        var init_key_len: [2]u8 = undefined;
        std.mem.writeInt(u16, &init_key_len, @intCast(init_key_slice.len), .big);
        try tbs_data.appendSlice(&init_key_len);
        try tbs_data.appendSlice(init_key_slice);
        
        // Serialize leaf node (simplified) with length prefixes (u16)
        const enc_key_slice = key_package_tbs.leaf_node.encryption_key.asSlice();
        if (enc_key_slice.len > std.math.maxInt(u16)) return error.ValueTooLarge;
        var enc_key_len: [2]u8 = undefined;
        std.mem.writeInt(u16, &enc_key_len, @intCast(enc_key_slice.len), .big);
        try tbs_data.appendSlice(&enc_key_len);
        try tbs_data.appendSlice(enc_key_slice);
        
        const sig_key_slice = key_package_tbs.leaf_node.signature_key.asSlice();
        if (sig_key_slice.len > std.math.maxInt(u16)) return error.ValueTooLarge;
        var sig_key_len: [2]u8 = undefined;
        std.mem.writeInt(u16, &sig_key_len, @intCast(sig_key_slice.len), .big);
        try tbs_data.appendSlice(&sig_key_len);
        try tbs_data.appendSlice(sig_key_slice);
        
        // Sign the KeyPackageTBS
        const signature = try signWithLabel(
            allocator,
            cs,
            sig_keypair.private_key,
            "KeyPackageTBS",
            tbs_data.items
        );

        // Create the final KeyPackage - transfer ownership
        const key_package = KeyPackage{
            .payload = key_package_tbs,
            .signature = signature,
        };
        
        // DEBUG: Check key lengths after KeyPackage creation
        if (@import("builtin").target.cpu.arch == .wasm32) {
            const kp_init_key_len = key_package.initKey().asSlice().len;
            const kp_init_key_data = key_package.initKey().asSlice();
            if (kp_init_key_len != 32) {
                @panic("CRITICAL: KeyPackage init_key length is not 32 bytes after creation!");
            }
            if (kp_init_key_len > 0 and kp_init_key_data[0] == 0x20) {
                @panic("CRITICAL: KeyPackage init_key starts with 0x20 after creation!");
            }
        }

        // Create private key wrappers
        var private_init_key = try HpkePrivateKey.initOwned(allocator, init_keypair.private_key);
        errdefer private_init_key.deinit(allocator);

        var private_enc_key = try HpkePrivateKey.initOwned(allocator, enc_keypair.private_key);
        errdefer private_enc_key.deinit(allocator);

        var private_sig_key = try SignaturePrivateKey.initOwned(allocator, sig_keypair.private_key);
        errdefer private_sig_key.deinit(allocator);

        // DEBUG: Check keys are valid before creating bundle
        if (@import("builtin").target.cpu.arch == .wasm32) {
            const pre_bundle_init_len = key_package.initKey().asSlice().len;
            const pre_bundle_enc_len = key_package.leafNode().encryption_key.asSlice().len;
            const pre_bundle_sig_len = key_package.leafNode().signature_key.asSlice().len;
            
            if (pre_bundle_init_len != 32 or pre_bundle_enc_len != 32 or pre_bundle_sig_len != 32) {
                @panic("CRITICAL: Keys corrupted before creating KeyPackageBundle!");
            }
        }
        
        const result = KeyPackageBundle{
            .key_package = key_package,
            .private_init_key = private_init_key,
            .private_encryption_key = private_enc_key,
            .private_signature_key = private_sig_key,
        };
        
        // DEBUG: Check if keys are valid just before returning
        if (@import("builtin").target.cpu.arch == .wasm32) {
            const debug_init_len = result.key_package.initKey().asSlice().len;
            const debug_init_data = result.key_package.initKey().asSlice();
            const debug_enc_len = result.key_package.leafNode().encryption_key.asSlice().len;
            const debug_sig_len = result.key_package.leafNode().signature_key.asSlice().len;
            
            if (debug_init_len != 32) {
                @panic("CRITICAL: Final KeyPackageBundle init_key length is not 32 bytes!");
            }
            if (debug_init_len > 0 and debug_init_data[0] == 0x20) {
                @panic("CRITICAL: Final KeyPackageBundle init_key starts with 0x20!");
            }
            if (debug_enc_len != 32) {
                @panic("CRITICAL: Final KeyPackageBundle enc_key length is not 32 bytes!");
            }
            if (debug_sig_len != 32) {
                @panic("CRITICAL: Final KeyPackageBundle sig_key length is not 32 bytes!");
            }
        }
        
        return result;
    }

    pub fn deinit(self: *KeyPackageBundle, allocator: Allocator) void {
        self.key_package.deinit(allocator);
        self.private_init_key.deinit(allocator);
        self.private_encryption_key.deinit(allocator);
        self.private_signature_key.deinit(allocator);
    }
};

pub const KeyPair = struct {
    public_key: []u8,
    private_key: []u8,
    allocator: Allocator,

    pub fn deinit(self: *KeyPair) void {
        self.allocator.free(self.public_key);
        crypto.secureZero(u8, self.private_key);
        self.allocator.free(self.private_key);
        self.public_key = &[_]u8{};
        self.private_key = &[_]u8{};
    }
};

pub fn generateSignatureKeyPair(
    allocator: Allocator,
    cs: cipher_suite.CipherSuite,
) !KeyPair {
    return switch (cs.signatureScheme()) {
        .ED25519 => {
            // Generate Ed25519 key pair using WASM-compatible random (needs 32-byte seed)
            var seed: [32]u8 = undefined;
            wasm_random.secure_random.bytes(&seed);
            
            const key_pair = try crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
            
            const public_key = try allocator.dupe(u8, &key_pair.public_key.toBytes());
            const private_key = try allocator.dupe(u8, &key_pair.secret_key.toBytes());
            
            return KeyPair{
                .public_key = public_key,
                .private_key = private_key,
                .allocator = allocator,
            };
        },
        .ECDSA_SECP256R1_SHA256 => {
            // Generate random scalar bytes using WASM-compatible random
            var private_scalar_bytes: [32]u8 = undefined;
            wasm_random.secure_random.bytes(&private_scalar_bytes);
            
            const private_scalar = try crypto.ecc.P256.scalar.Scalar.fromBytes(private_scalar_bytes, .big);
            const public_point = crypto.ecc.P256.basePoint.mul(private_scalar.toBytes(.big), .big) catch return error.InvalidKeyGeneration;
            
            const public_bytes = public_point.toUncompressedSec1();
            
            const public_key = try allocator.dupe(u8, &public_bytes);
            const private_key_bytes = private_scalar.toBytes(.big);
            const private_key = try allocator.dupe(u8, &private_key_bytes);
            
            return KeyPair{
                .public_key = public_key,
                .private_key = private_key,
                .allocator = allocator,
            };
        },
        else => error.UnsupportedSignatureScheme,
    };
}

pub fn generateHpkeKeyPair(
    allocator: Allocator,
    cs: cipher_suite.CipherSuite,
    random_fn: ?wasm_random.RandomFunction,
) !KeyPair {
    return switch (cs.hpkeKemType()) {
        .DHKEMX25519 => {
            // Generate random private key
            var private_key_bytes: [32]u8 = undefined;
            if (random_fn) |rand_fn| {
                rand_fn(&private_key_bytes);
            } else {
                wasm_random.secure_random.bytes(&private_key_bytes);
            }
            
            // Create key pair from private key
            const key_pair = try crypto.dh.X25519.KeyPair.generateDeterministic(private_key_bytes);
            
            const public_key = try allocator.dupe(u8, &key_pair.public_key);
            const private_key = try allocator.dupe(u8, &key_pair.secret_key);
            
            return KeyPair{
                .public_key = public_key,
                .private_key = private_key,
                .allocator = allocator,
            };
        },
        .DHKEMP256 => {
            // Generate random private scalar
            var private_scalar_bytes: [32]u8 = undefined;
            if (random_fn) |rand_fn| {
                rand_fn(&private_scalar_bytes);
            } else {
                wasm_random.secure_random.bytes(&private_scalar_bytes);
            }
            
            const private_scalar = try crypto.ecc.P256.scalar.Scalar.fromBytes(private_scalar_bytes, .big);
            const public_point = crypto.ecc.P256.basePoint.mul(private_scalar.toBytes(.big), .big) catch return error.InvalidKeyGeneration;
            
            const public_bytes = public_point.toUncompressedSec1();
            
            const public_key = try allocator.dupe(u8, &public_bytes);
            const private_key_bytes = private_scalar.toBytes(.big);
            const private_key = try allocator.dupe(u8, &private_key_bytes);
            
            return KeyPair{
                .public_key = public_key,
                .private_key = private_key,
                .allocator = allocator,
            };
        },
        else => error.UnsupportedHpkeKemType,
    };
}

pub fn signWithLabel(
    allocator: Allocator,
    cs: cipher_suite.CipherSuite,
    private_key: []const u8,
    label: []const u8,
    content: []const u8,
) !Signature {
    var sign_content = std.ArrayList(u8).init(allocator);
    defer sign_content.deinit();

    // Manual serialization instead of TlsWriter
    const full_label = try std.fmt.allocPrint(allocator, "{s}{s}", .{ cipher_suite.MLS_LABEL_PREFIX, label });
    defer allocator.free(full_label);
    
    try tls_codec.writeVarBytesToList(&sign_content, u8, full_label);
    try tls_codec.writeVarBytesToList(&sign_content, u32, content);

    const signature_data = switch (cs.signatureScheme()) {
        .ED25519 => blk: {
            // Ed25519 expects 64-byte keys
            if (private_key.len != 64) return error.InvalidPrivateKeySize;
            
            const secret_key = crypto.sign.Ed25519.SecretKey.fromBytes(private_key[0..64].*) catch return error.InvalidPrivateKey;
            const key_pair = crypto.sign.Ed25519.KeyPair.fromSecretKey(secret_key) catch return error.InvalidPrivateKey;
            
            const signature = key_pair.sign(sign_content.items, null) catch return error.SigningFailed;
            
            const sig_bytes = signature.toBytes();
            break :blk try allocator.dupe(u8, &sig_bytes);
        },
        .ECDSA_SECP256R1_SHA256 => blk: {
            if (private_key.len != 32) return error.InvalidPrivateKeySize;
            
            var hash: [32]u8 = undefined;
            crypto.hash.sha2.Sha256.hash(sign_content.items, &hash, .{});
            
            const secret_key = crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(private_key[0..32].*) catch return error.InvalidPrivateKey;
            const key_pair = crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair.fromSecretKey(secret_key) catch return error.InvalidPrivateKey;
            const signature = key_pair.sign(sign_content.items, null) catch return error.SigningFailed;
            
            const sig_bytes = signature.toBytes();
            break :blk try allocator.dupe(u8, &sig_bytes);
        },
        else => return error.UnsupportedSignatureScheme,
    };

    defer allocator.free(signature_data);
    return Signature.initOwned(allocator, signature_data);
}

pub fn verifyWithLabel(
    cs: cipher_suite.CipherSuite,
    public_key: []const u8,
    signature: []const u8,
    label: []const u8,
    content: []const u8,
    allocator: Allocator,
) !bool {
    var sign_content = std.ArrayList(u8).init(allocator);
    defer sign_content.deinit();

    // Manual serialization instead of TlsWriter
    const full_label = try std.fmt.allocPrint(allocator, "{s}{s}", .{ cipher_suite.MLS_LABEL_PREFIX, label });
    defer allocator.free(full_label);
    
    try tls_codec.writeVarBytesToList(&sign_content, u8, full_label);
    try tls_codec.writeVarBytesToList(&sign_content, u32, content);

    return switch (cs.signatureScheme()) {
        .ED25519 => blk: {
            if (public_key.len != 32 or signature.len != 64) break :blk false;
            
            const pub_key = crypto.sign.Ed25519.PublicKey.fromBytes(public_key[0..32].*) catch break :blk false;
            const sig = crypto.sign.Ed25519.Signature.fromBytes(signature[0..64].*);
            
            sig.verify(sign_content.items, pub_key) catch break :blk false;
            break :blk true;
        },
        .ECDSA_SECP256R1_SHA256 => blk: {
            if (public_key.len != 65 or signature.len != 64) break :blk false;
            
            const pub_key = crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey.fromSec1(public_key) catch break :blk false;
            const sig = crypto.sign.ecdsa.EcdsaP256Sha256.Signature.fromBytes(signature[0..64].*);
            sig.verify(sign_content.items, pub_key) catch break :blk false;
            break :blk true;
        },
        else => false,
    };
}

test "key package structures" {
    const allocator = testing.allocator;
    
    const test_key_data = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    var hpke_key = try HpkePublicKey.initOwned(allocator, &test_key_data);
    defer hpke_key.deinit(allocator);
    
    try testing.expectEqual(@as(usize, 4), hpke_key.len());
    try testing.expectEqualSlices(u8, &test_key_data, hpke_key.asSlice());
}

test "capabilities" {
    const allocator = testing.allocator;
    
    var caps = Capabilities.init(allocator);
    defer caps.deinit();
    
    try testing.expect(caps.supportsVersion(MLS_PROTOCOL_VERSION) == false);
    try testing.expect(caps.supportsCipherSuite(.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519) == false);
}

test "extensions" {
    const allocator = testing.allocator;
    
    var extensions = Extensions.init(allocator);
    defer extensions.deinit();
    
    const test_data = [_]u8{ 0xaa, 0xbb, 0xcc };
    const ext = try Extension.init(allocator, 0x1234, &test_data);
    try extensions.addExtension(ext);
    
    const found = extensions.findExtension(0x1234);
    try testing.expect(found != null);
    try testing.expectEqual(@as(u16, 0x1234), found.?.extension_type);
    try testing.expectEqualSlices(u8, &test_data, found.?.extension_data);
}

test "lifetime validation" {
    const lifetime = Lifetime.init(1000, 2000);
    
    try testing.expect(lifetime.isValid(1500) == true);
    try testing.expect(lifetime.isValid(500) == false);
    try testing.expect(lifetime.isValid(2500) == false);
    try testing.expect(lifetime.isValid(1000) == true);
    try testing.expect(lifetime.isValid(2000) == true);
}

test "ed25519 key generation" {
    const allocator = testing.allocator;
    const cs = cipher_suite.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    
    var key_pair = try generateSignatureKeyPair(allocator, cs);
    defer key_pair.deinit();
    
    try testing.expectEqual(@as(usize, 32), key_pair.public_key.len);
    try testing.expectEqual(@as(usize, 64), key_pair.private_key.len);
}

test "p256 key generation" {
    const allocator = testing.allocator;
    const cs = cipher_suite.CipherSuite.MLS_128_DHKEMP256_AES128GCM_SHA256_P256;
    
    var key_pair = try generateSignatureKeyPair(allocator, cs);
    defer key_pair.deinit();
    
    try testing.expectEqual(@as(usize, 65), key_pair.public_key.len);
    try testing.expectEqual(@as(usize, 32), key_pair.private_key.len);
}

test "x25519 hpke key generation" {
    const allocator = testing.allocator;
    const cs = cipher_suite.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    
    var key_pair = try generateHpkeKeyPair(allocator, cs, null);
    defer key_pair.deinit();
    
    try testing.expectEqual(@as(usize, 32), key_pair.public_key.len);
    try testing.expectEqual(@as(usize, 32), key_pair.private_key.len);
}

test "ed25519 signing and verification" {
    const allocator = testing.allocator;
    const cs = cipher_suite.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    
    var key_pair = try generateSignatureKeyPair(allocator, cs);
    defer key_pair.deinit();
    
    const test_content = "test message";
    const test_label = "test_label";
    
    var signature = try signWithLabel(allocator, cs, key_pair.private_key, test_label, test_content);
    defer signature.deinit(allocator);
    
    const is_valid = try verifyWithLabel(cs, key_pair.public_key, signature.asSlice(), test_label, test_content, allocator);
    try testing.expect(is_valid);
    
    const is_invalid = try verifyWithLabel(cs, key_pair.public_key, signature.asSlice(), "wrong_label", test_content, allocator);
    try testing.expect(!is_invalid);
}

test "p256 signing and verification" {
    const allocator = testing.allocator;
    const cs = cipher_suite.CipherSuite.MLS_128_DHKEMP256_AES128GCM_SHA256_P256;
    
    var key_pair = try generateSignatureKeyPair(allocator, cs);
    defer key_pair.deinit();
    
    const test_content = "test message";
    const test_label = "test_label";
    
    var signature = try signWithLabel(allocator, cs, key_pair.private_key, test_label, test_content);
    defer signature.deinit(allocator);
    
    const is_valid = try verifyWithLabel(cs, key_pair.public_key, signature.asSlice(), test_label, test_content, allocator);
    try testing.expect(is_valid);
    
    const is_invalid = try verifyWithLabel(cs, key_pair.public_key, signature.asSlice(), "wrong_label", test_content, allocator);
    try testing.expect(!is_invalid);
}

test "KeyPackageBundle creation and validation" {
    const allocator = testing.allocator;
    const cs = cipher_suite.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    // Create a basic credential
    var basic_cred = try credentials.BasicCredential.init(
        allocator,
        &[_]u8{0x01} ** 32,
    );
    defer basic_cred.deinit();

    var credential = try credentials.Credential.fromBasic(allocator, &basic_cred);
    defer credential.deinit();

    // Create KeyPackageBundle
    var bundle = try KeyPackageBundle.init(allocator, cs, credential, null);
    defer bundle.deinit(allocator);

    // Validate the bundle
    try testing.expectEqual(cs, bundle.key_package.cipherSuite());
    try testing.expectEqual(MLS_PROTOCOL_VERSION, bundle.key_package.protocolVersion());
    
    // Validate key sizes based on cipher suite
    try testing.expectEqual(@as(usize, 32), bundle.key_package.initKey().len());
    try testing.expectEqual(@as(usize, 32), bundle.key_package.encryptionKey().len());
    try testing.expectEqual(@as(usize, 32), bundle.key_package.signatureKey().len());
    
    // Validate private keys
    try testing.expectEqual(@as(usize, 32), bundle.private_init_key.len());
    try testing.expectEqual(@as(usize, 32), bundle.private_encryption_key.len());
    try testing.expectEqual(@as(usize, 64), bundle.private_signature_key.len());
    
    // Validate capabilities
    const leaf_node = bundle.key_package.leafNode();
    try testing.expect(leaf_node.capabilities.supportsVersion(MLS_PROTOCOL_VERSION));
    try testing.expect(leaf_node.capabilities.supportsCipherSuite(cs));
}

test "KeyPackageBundle with multiple cipher suites" {
    const allocator = testing.allocator;
    
    const test_cases = [_]cipher_suite.CipherSuite{
        .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        .MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
        .MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
    };

    for (test_cases) |cs| {
        // Create a basic credential
        var basic_cred = try credentials.BasicCredential.init(
            allocator,
            &[_]u8{0x02} ** 32,
        );
        defer basic_cred.deinit();

        var credential = try credentials.Credential.fromBasic(allocator, &basic_cred);
        defer credential.deinit();

        // Create KeyPackageBundle
        var bundle = try KeyPackageBundle.init(allocator, cs, credential, null);
        defer bundle.deinit();

        // Basic validation
        try testing.expectEqual(cs, bundle.key_package.cipherSuite());
        try testing.expect(bundle.key_package.initKey().len() > 0);
        try testing.expect(bundle.key_package.encryptionKey().len() > 0);
        try testing.expect(bundle.key_package.signatureKey().len() > 0);
    }
}