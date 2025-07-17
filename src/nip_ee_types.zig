const std = @import("std");
const crypto = @import("crypto.zig");

/// Strongly typed Nostr identity private key
pub const NostrPrivateKey = struct {
    bytes: [32]u8,
    
    pub fn generate() !NostrPrivateKey {
        const key_bytes = try crypto.generatePrivateKey();
        return NostrPrivateKey{ .bytes = key_bytes };
    }
    
    pub fn fromBytes(bytes: [32]u8) !NostrPrivateKey {
        // Validate the key
        _ = try crypto.getPublicKey(bytes);
        return NostrPrivateKey{ .bytes = bytes };
    }
    
    pub fn getPublicKey(self: NostrPrivateKey) ![32]u8 {
        return crypto.getPublicKey(self.bytes);
    }
    
    pub fn toHex(self: NostrPrivateKey) [64]u8 {
        return crypto.bytesToHexFixed(self.bytes);
    }
};

/// Strongly typed Nostr public key
pub const NostrPublicKey = struct {
    bytes: [32]u8,
    
    pub fn fromPrivateKey(private_key: NostrPrivateKey) !NostrPublicKey {
        const pub_bytes = try private_key.getPublicKey();
        return NostrPublicKey{ .bytes = pub_bytes };
    }
    
    pub fn fromBytes(bytes: [32]u8) NostrPublicKey {
        return NostrPublicKey{ .bytes = bytes };
    }
    
    pub fn toHex(self: NostrPublicKey) [64]u8 {
        return crypto.bytesToHexFixed(&self.bytes);
    }
};

/// Strongly typed MLS signing key (different from Nostr identity)
pub const MLSSigningKey = struct {
    private_bytes: [32]u8,
    public_bytes: [32]u8,
    
    pub fn generate() !MLSSigningKey {
        const private_bytes = try crypto.generatePrivateKey();
        const public_bytes = try crypto.getPublicKey(private_bytes);
        return MLSSigningKey{
            .private_bytes = private_bytes,
            .public_bytes = public_bytes,
        };
    }
    
    pub fn fromPrivateKey(private_bytes: [32]u8) !MLSSigningKey {
        const public_bytes = try crypto.getPublicKey(private_bytes);
        return MLSSigningKey{
            .private_bytes = private_bytes,
            .public_bytes = public_bytes,
        };
    }
    
    pub fn sign(self: MLSSigningKey, message: []const u8) ![64]u8 {
        return crypto.sign(message, self.private_bytes);
    }
    
    pub fn verify(self: MLSSigningKey, message: []const u8, signature: [64]u8) !bool {
        return crypto.verifyMessageSignature(message, signature, self.public_bytes);
    }
    
    pub fn publicKeyHex(self: MLSSigningKey) [64]u8 {
        return crypto.bytesToHexFixed(&self.public_bytes);
    }
};

/// Strongly typed group ID
pub const GroupID = struct {
    bytes: [32]u8,
    
    pub fn generate() GroupID {
        var bytes: [32]u8 = undefined;
        crypto.generateRandomBytes(&bytes);
        return GroupID{ .bytes = bytes };
    }
    
    pub fn fromBytes(bytes: [32]u8) GroupID {
        return GroupID{ .bytes = bytes };
    }
    
    pub fn toHex(self: GroupID) [64]u8 {
        return crypto.bytesToHexFixed(&self.bytes);
    }
};

/// Strongly typed exporter secret (used for NIP-44 encryption)
pub const ExporterSecret = struct {
    bytes: [32]u8,
    
    pub fn generate() ExporterSecret {
        var bytes: [32]u8 = undefined;
        crypto.generateRandomBytes(&bytes);
        return ExporterSecret{ .bytes = bytes };
    }
    
    pub fn fromBytes(bytes: [32]u8) ExporterSecret {
        return ExporterSecret{ .bytes = bytes };
    }
    
    /// Generate a valid secp256k1 private key from the exporter secret
    pub fn toNip44PrivateKey(self: ExporterSecret) ![32]u8 {
        return crypto.generateValidSecp256k1Key(self.bytes);
    }
    
    pub fn toHex(self: ExporterSecret) [64]u8 {
        return crypto.bytesToHexFixed(&self.bytes);
    }
};

/// User identity combining Nostr and MLS keys
pub const UserIdentity = struct {
    name: []const u8,
    nostr_private_key: NostrPrivateKey,
    nostr_public_key: NostrPublicKey,
    mls_signing_key: MLSSigningKey,
    
    pub fn create(allocator: std.mem.Allocator, name: []const u8) !UserIdentity {
        const nostr_private = try NostrPrivateKey.generate();
        const nostr_public = try NostrPublicKey.fromPrivateKey(nostr_private);
        const mls_signing = try MLSSigningKey.generate();
        
        // Copy the name to owned memory
        const owned_name = try allocator.dupe(u8, name);
        
        return UserIdentity{
            .name = owned_name,
            .nostr_private_key = nostr_private,
            .nostr_public_key = nostr_public,
            .mls_signing_key = mls_signing,
        };
    }
    
    pub fn deinit(self: UserIdentity, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
    }
    
    pub fn debugPrint(self: UserIdentity) void {
        std.debug.print("User: {s}\n", .{self.name});
        std.debug.print("  Nostr pubkey: {s}\n", .{self.nostr_public_key.toHex()});
        std.debug.print("  MLS signing pubkey: {s}\n", .{self.mls_signing_key.publicKeyHex()});
    }
};

/// KeyPackage structure for user discovery
pub const KeyPackage = struct {
    /// The user this KeyPackage belongs to
    user_identity: *const UserIdentity,
    
    /// MLS protocol version (1.0)
    mls_version: []const u8,
    
    /// Cipher suite ID
    cipher_suite: u16,
    
    /// Serialized MLS KeyPackage data
    mls_data: []const u8,
    
    /// Timestamp when created
    created_at: u64,
    
    pub fn create(
        allocator: std.mem.Allocator,
        user_identity: *const UserIdentity,
        mls_data: []const u8,
    ) !KeyPackage {
        const owned_mls_data = try allocator.dupe(u8, mls_data);
        const timestamp = std.time.timestamp();
        
        return KeyPackage{
            .user_identity = user_identity,
            .mls_version = "1.0",
            .cipher_suite = 0x0001, // MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            .mls_data = owned_mls_data,
            .created_at = @intCast(timestamp),
        };
    }
    
    pub fn deinit(self: KeyPackage, allocator: std.mem.Allocator) void {
        allocator.free(self.mls_data);
    }
    
    pub fn debugPrint(self: KeyPackage) void {
        std.debug.print("KeyPackage for {s}:\n", .{self.user_identity.name});
        std.debug.print("  MLS version: {s}\n", .{self.mls_version});
        std.debug.print("  Cipher suite: 0x{x:0>4}\n", .{self.cipher_suite});
        std.debug.print("  MLS data size: {} bytes\n", .{self.mls_data.len});
        std.debug.print("  Created at: {}\n", .{self.created_at});
    }
};

/// Group state and metadata
pub const GroupState = struct {
    /// MLS group ID (private)
    mls_group_id: GroupID,
    
    /// Nostr group ID (public identifier)
    nostr_group_id: GroupID,
    
    /// Group metadata
    name: []const u8,
    description: []const u8,
    
    /// Current epoch
    epoch: u64,
    
    /// Admin public keys
    admin_pubkeys: []NostrPublicKey,
    
    /// Current exporter secret for NIP-44 encryption
    exporter_secret: ExporterSecret,
    
    /// Group members
    members: []*const UserIdentity,
    
    pub fn create(
        allocator: std.mem.Allocator,
        name: []const u8,
        description: []const u8,
        admin: *const UserIdentity,
    ) !GroupState {
        const owned_name = try allocator.dupe(u8, name);
        const owned_description = try allocator.dupe(u8, description);
        
        var admin_pubkeys = try allocator.alloc(NostrPublicKey, 1);
        admin_pubkeys[0] = admin.nostr_public_key;
        
        var members = try allocator.alloc(*const UserIdentity, 1);
        members[0] = admin;
        
        return GroupState{
            .mls_group_id = GroupID.generate(),
            .nostr_group_id = GroupID.generate(),
            .name = owned_name,
            .description = owned_description,
            .epoch = 0,
            .admin_pubkeys = admin_pubkeys,
            .exporter_secret = ExporterSecret.generate(),
            .members = members,
        };
    }
    
    pub fn deinit(self: GroupState, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.description);
        allocator.free(self.admin_pubkeys);
        allocator.free(self.members);
    }
    
    pub fn debugPrint(self: GroupState) void {
        std.debug.print("Group: {s}\n", .{self.name});
        std.debug.print("  Description: {s}\n", .{self.description});
        std.debug.print("  Nostr group ID: {s}\n", .{self.nostr_group_id.toHex()});
        std.debug.print("  Epoch: {}\n", .{self.epoch});
        std.debug.print("  Members: {}\n", .{self.members.len});
        std.debug.print("  Exporter secret: {s}\n", .{self.exporter_secret.toHex()});
    }
};

/// NIP-EE specific errors
pub const NipEEError = error{
    InvalidNostrKey,
    InvalidMLSKey,
    InvalidGroupState,
    KeyPackageCreationFailed,
    GroupCreationFailed,
    InvitationFailed,
    MessageEncryptionFailed,
    MessageDecryptionFailed,
    OutOfMemory,
};