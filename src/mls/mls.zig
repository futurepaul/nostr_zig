const std = @import("std");

// Export all MLS modules
pub const types = @import("types.zig");
pub const provider = @import("provider.zig");
pub const nip_ee = @import("nip_ee.zig");
pub const key_packages = @import("key_packages.zig");
pub const extension = @import("extension.zig");
pub const groups = @import("groups.zig");
pub const welcomes = @import("welcomes.zig");
pub const messages = @import("messages.zig");
pub const openmls_key_packages = @import("openmls_key_packages.zig");

// Re-export commonly used types
pub const Epoch = types.Epoch;
pub const GroupId = types.GroupId;
pub const Ciphersuite = types.Ciphersuite;
pub const MlsProvider = provider.MlsProvider;
pub const KeyPackageEvent = nip_ee.KeyPackageEvent;
pub const WelcomeEvent = nip_ee.WelcomeEvent;
pub const GroupMessageEvent = nip_ee.GroupMessageEvent;

/// MLS group state (stateless representation)
pub const MlsGroupState = struct {
    /// Group ID
    group_id: GroupId,
    
    /// Current epoch
    epoch: Epoch,
    
    /// Cipher suite in use
    cipher_suite: Ciphersuite,
    
    /// Group context
    group_context: types.GroupContext,
    
    /// Tree hash
    tree_hash: [32]u8,
    
    /// Confirmed transcript hash
    confirmed_transcript_hash: [32]u8,
    
    /// Member list
    members: []const types.MemberInfo,
    
    /// Ratchet tree (serialized)
    ratchet_tree: []const u8,
    
    /// Interim transcript hash
    interim_transcript_hash: [32]u8,
    
    /// Group secrets for current epoch
    epoch_secrets: EpochSecrets,
};

/// Epoch secrets
pub const EpochSecrets = struct {
    /// Sender data secret
    sender_data_secret: [32]u8,
    
    /// Encryption secret
    encryption_secret: [32]u8,
    
    /// Exporter secret (used for NIP-44 encryption)
    exporter_secret: [32]u8,
    
    /// Authentication secret
    authentication_secret: [32]u8,
    
    /// External secret
    external_secret: [32]u8,
    
    /// Confirmation key
    confirmation_key: [32]u8,
    
    /// Membership key
    membership_key: [32]u8,
    
    /// Resumption PSK
    resumption_psk: [32]u8,
    
    /// Init secret for next epoch
    init_secret: [32]u8,
};

/// Result of creating a new group
pub const GroupCreationResult = struct {
    /// The initial group state
    state: MlsGroupState,
    
    /// Welcome messages for initial members
    welcomes: []const types.Welcome,
    
    /// Key packages that were used
    used_key_packages: []const types.KeyPackage,
};

/// Result of adding a member
pub const AddMemberResult = struct {
    /// Updated group state
    state: MlsGroupState,
    
    /// Welcome message for new member
    welcome: types.Welcome,
    
    /// Commit message to broadcast
    commit: types.MLSMessage,
};

/// Result of joining a group
pub const JoinResult = struct {
    /// Initial group state
    state: MlsGroupState,
    
    /// Group metadata from extension
    metadata: GroupMetadata,
};

/// Group metadata (from NostrGroupData extension)
pub const GroupMetadata = struct {
    /// Group name
    name: []const u8,
    
    /// Group description
    description: []const u8,
    
    /// Admin public keys
    admins: []const [32]u8,
    
    /// Relay URLs
    relays: []const []const u8,
    
    /// Optional group image
    image: ?[]const u8,
};

/// Encrypted message ready for broadcasting
pub const EncryptedMessage = struct {
    /// MLS ciphertext
    mls_ciphertext: []const u8,
    
    /// NIP-44 encrypted ciphertext
    nip44_ciphertext: []const u8,
    
    /// Epoch used for encryption
    epoch: Epoch,
    
    /// Message type
    message_type: []const u8,
};

/// Decrypted message
pub const DecryptedMessage = struct {
    /// Decrypted content
    content: []const u8,
    
    /// Sender information
    sender: types.Sender,
    
    /// Whether this message updated the group state
    state_updated: bool,
    
    /// New state if updated
    new_state: ?MlsGroupState,
};

/// Group preview (before joining)
pub const GroupPreview = struct {
    /// Group ID
    group_id: GroupId,
    
    /// Group metadata
    metadata: GroupMetadata,
    
    /// Current epoch
    epoch: Epoch,
    
    /// Number of members
    member_count: usize,
    
    /// Cipher suite
    cipher_suite: Ciphersuite,
};

/// Initialize the MLS library
pub fn init() void {
    // Any global initialization if needed
}

test "mls types" {
    const group_id = GroupId.init([_]u8{0} ** 32);
    const epoch: Epoch = 42;
    
    try std.testing.expectEqual(@as(usize, 32), group_id.data.len);
    try std.testing.expectEqual(@as(u64, 42), epoch);
}

test {
    // Run tests from all MLS modules
    _ = @import("types.zig");
    _ = @import("provider.zig");
    _ = @import("nip_ee.zig");
    _ = @import("key_packages.zig");
    _ = @import("extension.zig");
    _ = @import("groups.zig");
    _ = @import("welcomes.zig");
    _ = @import("messages.zig");
    _ = @import("test_example.zig");
}