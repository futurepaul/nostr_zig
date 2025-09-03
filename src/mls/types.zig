const std = @import("std");

/// MLS epoch counter
pub const Epoch = u64;

/// MLS group ID (32 bytes)
pub const GroupId = struct {
    data: [32]u8,
    
    pub fn init(data: [32]u8) GroupId {
        return .{ .data = data };
    }
    
    pub fn eql(self: GroupId, other: GroupId) bool {
        return std.mem.eql(u8, &self.data, &other.data);
    }
};

/// MLS ciphersuite identifier
pub const Ciphersuite = enum(u16) {
    MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 = 0x0001,
    MLS_128_DHKEMP256_AES128GCM_SHA256_P256 = 0x0002,
    MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 = 0x0003,
    MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448 = 0x0004,
    MLS_256_DHKEMP521_AES256GCM_SHA512_P521 = 0x0005,
    MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 = 0x0006,
    MLS_256_DHKEMP384_AES256GCM_SHA384_P384 = 0x0007,
    _,  // Allow unknown values
    
    pub fn fromInt(value: u16) Ciphersuite {
        return @enumFromInt(value);
    }
};

/// Group member role
pub const MemberRole = enum {
    member,
    admin,
};

/// Group state
pub const GroupState = enum {
    pending,
    active,
    inactive,
};

/// MLS protocol version
pub const ProtocolVersion = enum(u16) {
    reserved = 0x0000,
    draft = 0x0001,  // Seen in wire format
    mls10 = 0x0100,
    _,  // Allow unknown values for forward compatibility
    
    pub fn fromInt(value: u16) ProtocolVersion {
        return @enumFromInt(value);
    }
};

/// MLS wire format
pub const WireFormat = enum(u16) {
    reserved = 0,
    mls_plaintext = 1,
    mls_ciphertext = 2,
    mls_welcome = 3,
    mls_group_info = 4,
    mls_key_package = 5,
    _,  // Allow unknown values
    
    pub fn fromInt(value: u16) WireFormat {
        return @enumFromInt(value);
    }
};

/// MLS content type
pub const ContentType = enum(u8) {
    reserved = 0,
    application = 1,
    proposal = 2,
    commit = 3,
    _,  // Allow unknown values
    
    pub fn fromInt(value: u8) ContentType {
        return @enumFromInt(value);
    }
};

/// MLS sender type
pub const SenderType = enum(u8) {
    reserved = 0,
    member = 1,
    external = 2,
    new_member_proposal = 3,
    new_member_commit = 4,
    _,  // Allow unknown values
    
    pub fn fromInt(value: u8) SenderType {
        return @enumFromInt(value);
    }
};

/// Proposal type
pub const ProposalType = enum(u16) {
    reserved = 0,
    add = 1,
    update = 2,
    remove = 3,
    psk = 4,
    reinit = 5,
    external_init = 6,
    group_context_extensions = 7,
    _,  // Allow unknown values
    
    pub fn fromInt(value: u16) ProposalType {
        return @enumFromInt(value);
    }
};

/// Extension type
pub const ExtensionType = enum(u16) {
    reserved = 0,
    capabilities = 1,
    lifetime = 2,
    key_id = 3,
    parent_hash = 4,
    ratchet_tree = 5,
    required_capabilities = 6,
    external_pub = 7,
    external_senders = 8,
    last_resort = 9,
    // Custom extension for Nostr group data
    nostr_group_data = 0xFF00,
    _,  // Allow unknown values
    
    pub fn fromInt(value: u16) ExtensionType {
        return @enumFromInt(value);
    }
};

/// Credential type
pub const CredentialType = enum(u16) {
    reserved = 0,
    basic = 1,
    x509 = 2,
    _,  // Allow unknown values
    
    pub fn fromInt(value: u16) CredentialType {
        return @enumFromInt(value);
    }
};

/// Basic credential
pub const BasicCredential = struct {
    identity: []const u8,
};

/// Credential
pub const Credential = union(CredentialType) {
    reserved: void,
    basic: BasicCredential,
    x509: []const u8,
};

/// HPKE public key
pub const HPKEPublicKey = struct {
    data: []const u8,
    
    pub fn init(data: []const u8) HPKEPublicKey {
        return .{ .data = data };
    }
    
    pub fn eql(self: HPKEPublicKey, other: HPKEPublicKey) bool {
        return std.mem.eql(u8, self.data, other.data);
    }
};

/// Signature public key
pub const SignaturePublicKey = struct {
    data: []const u8,
    
    pub fn init(data: []const u8) SignaturePublicKey {
        return .{ .data = data };
    }
    
    pub fn eql(self: SignaturePublicKey, other: SignaturePublicKey) bool {
        return std.mem.eql(u8, self.data, other.data);
    }
};

/// MLS capabilities
pub const Capabilities = struct {
    versions: []const ProtocolVersion,
    ciphersuites: []const Ciphersuite,
    extensions: []const ExtensionType,
    proposals: []const ProposalType,
    credentials: []const CredentialType,
};

/// Lifetime extension
pub const Lifetime = struct {
    not_before: u64,
    not_after: u64,
};

/// Extension
pub const Extension = struct {
    extension_type: ExtensionType,
    critical: bool = false,
    extension_data: []const u8,
};

/// Leaf node
pub const LeafNode = struct {
    encryption_key: HPKEPublicKey,
    signature_key: SignaturePublicKey,
    credential: Credential,
    capabilities: Capabilities,
    leaf_node_source: LeafNodeSource,
    extensions: []const Extension,
    signature: []const u8,
};

/// Leaf node source
pub const LeafNodeSource = union(enum) {
    reserved: void,
    key_package: void,
    update: void,
    commit: []const u8,
};

/// Group context
pub const GroupContext = struct {
    version: ProtocolVersion,
    cipher_suite: Ciphersuite,
    group_id: GroupId,
    epoch: Epoch,
    tree_hash: [32]u8,
    confirmed_transcript_hash: [32]u8,
    extensions: []const Extension,
};

/// Member info
pub const MemberInfo = struct {
    index: u32,
    credential: Credential,
    role: MemberRole,
    joined_at_epoch: Epoch,
};

/// Group info
pub const GroupInfo = struct {
    group_context: GroupContext,
    members: []const MemberInfo,
    ratchet_tree: []const u8,
};

/// Welcome message
pub const Welcome = struct {
    cipher_suite: Ciphersuite,
    secrets: []const EncryptedGroupSecrets,
    encrypted_group_info: []const u8,
};

/// Encrypted group secrets
pub const EncryptedGroupSecrets = struct {
    new_member: []const u8,
    encrypted_group_secrets: []const u8,
};

/// Proposal
pub const Proposal = union(ProposalType) {
    reserved: void,
    add: Add,
    update: Update,
    remove: Remove,
    psk: PreSharedKey,
    reinit: ReInit,
    external_init: ExternalInit,
    group_context_extensions: GroupContextExtensions,
};

/// Add proposal
pub const Add = struct {
    // TODO: Replace with flat KeyPackage
    key_package: void, // KeyPackage removed - use mls_zig.key_package_flat.KeyPackage
};

/// Update proposal
pub const Update = struct {
    leaf_node: LeafNode,
};

/// Remove proposal
pub const Remove = struct {
    removed: u32,
};

/// Pre-shared key proposal
pub const PreSharedKey = struct {
    psk: PreSharedKeyID,
};

/// PSK ID
pub const PreSharedKeyID = union(enum) {
    reserved: void,
    external: ExternalPSK,
    resumption: ResumptionPSK,
};

/// External PSK
pub const ExternalPSK = struct {
    psk_id: []const u8,
};

/// Resumption PSK
pub const ResumptionPSK = struct {
    usage: ResumptionPSKUsage,
    psk_group_id: GroupId,
    psk_epoch: Epoch,
};

/// Resumption PSK usage
pub const ResumptionPSKUsage = enum(u8) {
    reserved = 0,
    application = 1,
    reinit = 2,
    branch = 3,
    _,  // Allow unknown values
    
    pub fn fromInt(value: u8) ResumptionPSKUsage {
        return @enumFromInt(value);
    }
};

/// ReInit proposal
pub const ReInit = struct {
    group_id: GroupId,
    version: ProtocolVersion,
    cipher_suite: Ciphersuite,
    extensions: []const Extension,
};

/// External init proposal
pub const ExternalInit = struct {
    kem_output: []const u8,
};

/// Group context extensions proposal
pub const GroupContextExtensions = struct {
    extensions: []const Extension,
};

/// Commit
pub const Commit = struct {
    proposals: []const ProposalOrRef,
    path: ?UpdatePath,
};

/// Proposal or reference
pub const ProposalOrRef = union(enum) {
    proposal: Proposal,
    reference: ProposalRef,
};

/// Proposal reference
pub const ProposalRef = struct {
    data: [32]u8,
    
    pub fn init(data: [32]u8) ProposalRef {
        return .{ .data = data };
    }
    
    pub fn eql(self: ProposalRef, other: ProposalRef) bool {
        return std.mem.eql(u8, &self.data, &other.data);
    }
};

/// Update path
pub const UpdatePath = struct {
    leaf_node: LeafNode,
    nodes: []const UpdatePathNode,
};

/// Update path node
pub const UpdatePathNode = struct {
    public_key: HPKEPublicKey,
    encrypted_path_secret: []const HPKECiphertext,
};

/// HPKE ciphertext
pub const HPKECiphertext = struct {
    kem_output: []const u8,
    ciphertext: []const u8,
};

/// Sender
pub const Sender = union(SenderType) {
    reserved: void,
    member: u32,
    external: u32,
    new_member_proposal: void,
    new_member_commit: void,
};

/// Framed content
pub const FramedContent = struct {
    group_id: GroupId,
    epoch: Epoch,
    sender: Sender,
    authenticated_data: []const u8,
    content_type: ContentType,
    content: Content,
};

/// Content
pub const Content = union(ContentType) {
    reserved: void,
    application: []const u8,
    proposal: Proposal,
    commit: Commit,
};

/// MLS plaintext
pub const MLSPlaintext = struct {
    group_id: GroupId,
    epoch: Epoch,
    sender: Sender,
    authenticated_data: []const u8,
    content_type: ContentType,
    content: Content,
    signature: []const u8,
    confirmation_tag: ?[]const u8,
    membership_tag: ?[]const u8,
};

/// MLS ciphertext
pub const MLSCiphertext = struct {
    group_id: GroupId,
    epoch: Epoch,
    content_type: ContentType,
    authenticated_data: []const u8,
    encrypted_sender_data: []const u8,
    ciphertext: []const u8,
};

/// MLS message
pub const MLSMessage = union(WireFormat) {
    reserved: void,
    mls_plaintext: MLSPlaintext,
    mls_ciphertext: MLSCiphertext,
    mls_welcome: Welcome,
    mls_group_info: GroupInfo,
    // TODO: Replace with flat KeyPackage
    mls_key_package: void, // KeyPackage removed - use mls_zig.key_package_flat.KeyPackage
};

/// Common MLS errors
pub const MLSError = error{
    InvalidCiphersuite,
    InvalidProtocolVersion,
    InvalidWireFormat,
    InvalidContentType,
    InvalidProposalType,
    InvalidExtensionType,
    InvalidCredentialType,
    UnsupportedVersion,
    UnsupportedCiphersuite,
    UnsupportedExtension,
    UnsupportedProposal,
    UnsupportedCredential,
    InvalidSignature,
    InvalidEpoch,
    InvalidGroupId,
    InvalidMember,
    PermissionDenied,
    GroupNotActive,
    MemberNotFound,
    ProposalNotFound,
    PathRequired,
    PathNotRequired,
    InvalidPath,
    InvalidKeyPackage,
    InvalidLeafNode,
    InvalidGroupInfo,
    InvalidWelcome,
    DecryptionFailed,
    EncryptionFailed,
};

/// KeyPackage specific errors
pub const KeyPackageError = error{
    InvalidVersion,
    UnsupportedCipherSuite,
    InvalidKeyLength,
    InvalidLeafNode,
    MalformedExtensions,
    InvalidSignature,
    UnexpectedEndOfStream,
    ProtocolVersionMismatch,
};

/// Group operation errors  
pub const GroupError = error{
    InvalidGroupId,
    MemberNotFound,
    InvalidEpoch,
    StaleMessage,
    InvalidTreeHash,
    GroupNotActive,
    PermissionDenied,
    InvalidProposal,
};

/// Welcome message errors
pub const WelcomeError = error{
    InvalidCipherSuite,
    DecryptionFailed,
    InvalidGroupInfo,
    NoMatchingKeyPackage,
    InvalidSecrets,
};

/// Parsing errors
pub const ParseError = error{
    InvalidWireFormat,
    UnexpectedEndOfStream,
    InvalidLength,
    MalformedData,
    UnsupportedVersion,
};

test "types sizes" {
    // GroupId contains a [32]u8 data field
    const gid = GroupId.init([_]u8{0} ** 32);
    try std.testing.expectEqual(@as(usize, 32), gid.data.len);
    try std.testing.expectEqual(@sizeOf(Epoch), 8);
    // ProposalRef contains a [32]u8 data field
    const ref = ProposalRef.init([_]u8{0} ** 32);
    try std.testing.expectEqual(@as(usize, 32), ref.data.len);
}

test "enum values" {
    try std.testing.expectEqual(@intFromEnum(Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519), 0x0001);
    try std.testing.expectEqual(@intFromEnum(WireFormat.mls_welcome), 3);
    try std.testing.expectEqual(@intFromEnum(ContentType.application), 1);
    try std.testing.expectEqual(@intFromEnum(ProposalType.add), 1);
    try std.testing.expectEqual(@intFromEnum(ExtensionType.nostr_group_data), 0xFF00);
}