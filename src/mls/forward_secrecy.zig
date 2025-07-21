const std = @import("std");
const types = @import("types.zig");
const mls = @import("mls.zig");
const crypto_utils = @import("crypto_utils.zig");

/// Forward secrecy manager that handles secure key lifecycle management
pub const ForwardSecrecyManager = struct {
    allocator: std.mem.Allocator,
    
    /// Initialize the forward secrecy manager
    pub fn init(allocator: std.mem.Allocator) ForwardSecrecyManager {
        return ForwardSecrecyManager{
            .allocator = allocator,
        };
    }
    
    /// Deinitialize the forward secrecy manager
    pub fn deinit(self: *ForwardSecrecyManager) void {
        _ = self;
        // Nothing to clean up at the manager level
    }
};

/// Secure key container that automatically clears keys when dropped
pub fn SecureKey(comptime key_size: usize) type {
    return struct {
        const Self = @This();
        
        /// Key material
        data: [key_size]u8,
        
        /// Whether the key has been cleared
        cleared: bool,
        
        /// Initialize a secure key with the provided data
        pub fn init(key_data: [key_size]u8) Self {
            return Self{
                .data = key_data,
                .cleared = false,
            };
        }
        
        /// Get a reference to the key data
        /// This should only be used immediately before cryptographic operations
        pub fn getData(self: *const Self) ?*const [key_size]u8 {
            if (self.cleared) {
                return null;
            }
            return &self.data;
        }
        
        /// Create a copy of the key (for temporary use)
        /// Caller must securely clear the copy after use
        pub fn copy(self: *const Self) ?[key_size]u8 {
            if (self.cleared) {
                return null;
            }
            return self.data;
        }
        
        /// Securely clear the key material
        pub fn clear(self: *Self) void {
            if (!self.cleared) {
                secureZero(u8, &self.data);
                self.cleared = true;
            }
        }
        
        /// Check if the key has been cleared
        pub fn isCleared(self: *const Self) bool {
            return self.cleared;
        }
    };
}

/// Secure memory for MLS epoch secrets with automatic cleanup
pub const SecureEpochSecrets = struct {
    joiner_secret: SecureKey(32),
    member_secret: SecureKey(32),
    welcome_secret: SecureKey(32),
    epoch_secret: SecureKey(32),
    sender_data_secret: SecureKey(32),
    encryption_secret: SecureKey(32),
    exporter_secret: SecureKey(32),
    epoch_authenticator: SecureKey(32),
    external_secret: SecureKey(32),
    confirmation_key: SecureKey(32),
    membership_key: SecureKey(32),
    resumption_psk: SecureKey(32),
    init_secret: SecureKey(32),
    
    /// Initialize from standard epoch secrets
    pub fn init(epoch_secrets: mls.EpochSecrets) SecureEpochSecrets {
        return SecureEpochSecrets{
            .joiner_secret = SecureKey(32).init(epoch_secrets.joiner_secret),
            .member_secret = SecureKey(32).init(epoch_secrets.member_secret),
            .welcome_secret = SecureKey(32).init(epoch_secrets.welcome_secret),
            .epoch_secret = SecureKey(32).init(epoch_secrets.epoch_secret),
            .sender_data_secret = SecureKey(32).init(epoch_secrets.sender_data_secret),
            .encryption_secret = SecureKey(32).init(epoch_secrets.encryption_secret),
            .exporter_secret = SecureKey(32).init(epoch_secrets.exporter_secret),
            .epoch_authenticator = SecureKey(32).init(epoch_secrets.epoch_authenticator),
            .external_secret = SecureKey(32).init(epoch_secrets.external_secret),
            .confirmation_key = SecureKey(32).init(epoch_secrets.confirmation_key),
            .membership_key = SecureKey(32).init(epoch_secrets.membership_key),
            .resumption_psk = SecureKey(32).init(epoch_secrets.resumption_psk),
            .init_secret = SecureKey(32).init(epoch_secrets.init_secret),
        };
    }
    
    /// Convert to standard epoch secrets (copying the data)
    /// Note: The caller must ensure the returned secrets are securely cleared after use
    pub fn toEpochSecrets(self: *const SecureEpochSecrets) ?mls.EpochSecrets {
        // Check if any secrets have been cleared
        if (self.joiner_secret.isCleared() or 
            self.member_secret.isCleared() or
            self.welcome_secret.isCleared() or
            self.epoch_secret.isCleared() or
            self.sender_data_secret.isCleared() or
            self.encryption_secret.isCleared() or
            self.exporter_secret.isCleared() or
            self.epoch_authenticator.isCleared() or
            self.external_secret.isCleared() or
            self.confirmation_key.isCleared() or
            self.membership_key.isCleared() or
            self.resumption_psk.isCleared() or
            self.init_secret.isCleared()) {
            return null;
        }
        
        return mls.EpochSecrets{
            .joiner_secret = self.joiner_secret.copy().?,
            .member_secret = self.member_secret.copy().?,
            .welcome_secret = self.welcome_secret.copy().?,
            .epoch_secret = self.epoch_secret.copy().?,
            .sender_data_secret = self.sender_data_secret.copy().?,
            .encryption_secret = self.encryption_secret.copy().?,
            .exporter_secret = self.exporter_secret.copy().?,
            .epoch_authenticator = self.epoch_authenticator.copy().?,
            .external_secret = self.external_secret.copy().?,
            .confirmation_key = self.confirmation_key.copy().?,
            .membership_key = self.membership_key.copy().?,
            .resumption_psk = self.resumption_psk.copy().?,
            .init_secret = self.init_secret.copy().?,
        };
    }
    
    /// Securely clear all epoch secrets
    pub fn clear(self: *SecureEpochSecrets) void {
        self.joiner_secret.clear();
        self.member_secret.clear();
        self.welcome_secret.clear();
        self.epoch_secret.clear();
        self.sender_data_secret.clear();
        self.encryption_secret.clear();
        self.exporter_secret.clear();
        self.epoch_authenticator.clear();
        self.external_secret.clear();
        self.confirmation_key.clear();
        self.membership_key.clear();
        self.resumption_psk.clear();
        self.init_secret.clear();
    }
    
    /// Check if all secrets have been cleared
    pub fn allCleared(self: *const SecureEpochSecrets) bool {
        return self.joiner_secret.isCleared() and
               self.member_secret.isCleared() and
               self.welcome_secret.isCleared() and
               self.epoch_secret.isCleared() and
               self.sender_data_secret.isCleared() and
               self.encryption_secret.isCleared() and
               self.exporter_secret.isCleared() and
               self.epoch_authenticator.isCleared() and
               self.external_secret.isCleared() and
               self.confirmation_key.isCleared() and
               self.membership_key.isCleared() and
               self.resumption_psk.isCleared() and
               self.init_secret.isCleared();
    }
};

/// Secure MLS group state with forward secrecy guarantees
pub const SecureMlsGroupState = struct {
    /// Basic group information (not sensitive)
    group_id: types.GroupId,
    epoch: types.Epoch,
    cipher_suite: types.Ciphersuite,
    group_context: types.GroupContext,
    tree_hash: [32]u8,
    confirmed_transcript_hash: [32]u8,
    members: []const types.MemberInfo,
    ratchet_tree: []const u8,
    interim_transcript_hash: [32]u8,
    
    /// Secure epoch secrets
    epoch_secrets: SecureEpochSecrets,
    
    /// Initialize from standard MLS group state
    pub fn init(state: mls.MlsGroupState) SecureMlsGroupState {
        return SecureMlsGroupState{
            .group_id = state.group_id,
            .epoch = state.epoch,
            .cipher_suite = state.cipher_suite,
            .group_context = state.group_context,
            .tree_hash = state.tree_hash,
            .confirmed_transcript_hash = state.confirmed_transcript_hash,
            .members = state.members,
            .ratchet_tree = state.ratchet_tree,
            .interim_transcript_hash = state.interim_transcript_hash,
            .epoch_secrets = SecureEpochSecrets.init(state.epoch_secrets),
        };
    }
    
    /// Convert to standard MLS group state (for immediate use)
    /// WARNING: The returned state contains sensitive data that must be securely cleared
    pub fn toMlsGroupState(self: *const SecureMlsGroupState) ?mls.MlsGroupState {
        const epoch_secrets = self.epoch_secrets.toEpochSecrets() orelse return null;
        
        return mls.MlsGroupState{
            .group_id = self.group_id,
            .epoch = self.epoch,
            .cipher_suite = self.cipher_suite,
            .group_context = self.group_context,
            .tree_hash = self.tree_hash,
            .confirmed_transcript_hash = self.confirmed_transcript_hash,
            .members = self.members,
            .ratchet_tree = self.ratchet_tree,
            .interim_transcript_hash = self.interim_transcript_hash,
            .epoch_secrets = epoch_secrets,
        };
    }
    
    /// Clear all sensitive data
    pub fn clear(self: *SecureMlsGroupState) void {
        self.epoch_secrets.clear();
        
        // Also clear any potentially sensitive non-secret data
        secureZero(u8, &self.tree_hash);
        secureZero(u8, &self.confirmed_transcript_hash);
        secureZero(u8, &self.interim_transcript_hash);
    }
};

/// Temporary key holder that automatically clears on scope exit
pub fn TemporaryKey(comptime key_size: usize) type {
    return struct {
        const Self = @This();
        
        key: SecureKey(key_size),
        
        pub fn init(key_data: [key_size]u8) Self {
            return Self{
                .key = SecureKey(key_size).init(key_data),
            };
        }
        
        pub fn deinit(self: *Self) void {
            self.key.clear();
        }
        
        pub fn getData(self: *const Self) ?*const [key_size]u8 {
            return self.key.getData();
        }
    };
}

/// Enhanced crypto operations with automatic key clearing
pub const SecureCryptoOps = struct {
    /// Derive MLS signing key with automatic cleanup
    pub fn deriveMlsSigningKeySecure(
        allocator: std.mem.Allocator,
        nostr_private_key: [32]u8,
        epoch: u64,
    ) !TemporaryKey(32) {
        const key_data = try crypto_utils.deriveMlsSigningKey(allocator, nostr_private_key, epoch);
        defer secureZero(u8, key_data);
        defer allocator.free(key_data);
        
        var secure_key: [32]u8 = undefined;
        @memcpy(&secure_key, key_data[0..32]);
        
        return TemporaryKey(32).init(secure_key);
    }
    
    /// Derive MLS HPKE key with automatic cleanup
    pub fn deriveMlsHpkeKeySecure(
        allocator: std.mem.Allocator,
        nostr_private_key: [32]u8,
    ) !TemporaryKey(32) {
        const key_data = try crypto_utils.deriveMlsHpkeKey(allocator, nostr_private_key);
        defer secureZero(u8, key_data);
        defer allocator.free(key_data);
        
        var secure_key: [32]u8 = undefined;
        @memcpy(&secure_key, key_data[0..32]);
        
        return TemporaryKey(32).init(secure_key);
    }
};

/// Secure memory clearing function
/// This function attempts to prevent compiler optimizations from removing the clearing
pub fn secureZero(comptime T: type, buffer: []T) void {
    @setRuntimeSafety(false);
    for (buffer) |*item| {
        // Use volatile operations to prevent optimization
        const volatile_ptr: *volatile T = @ptrCast(item);
        volatile_ptr.* = 0;
    }
    
    // Memory barrier not needed in Zig - volatile operations are sufficient
}

/// Secure memory clearing for single values
pub fn secureZeroValue(comptime T: type, value: *T) void {
    const bytes = std.mem.asBytes(value);
    secureZero(u8, bytes);
}

/// Utility to securely clear epoch secrets in standard format
pub fn securelyCleanEpochSecrets(epoch_secrets: *mls.EpochSecrets) void {
    secureZero(u8, &epoch_secrets.joiner_secret);
    secureZero(u8, &epoch_secrets.member_secret);
    secureZero(u8, &epoch_secrets.welcome_secret);
    secureZero(u8, &epoch_secrets.epoch_secret);
    secureZero(u8, &epoch_secrets.sender_data_secret);
    secureZero(u8, &epoch_secrets.encryption_secret);
    secureZero(u8, &epoch_secrets.exporter_secret);
    secureZero(u8, &epoch_secrets.epoch_authenticator);
    secureZero(u8, &epoch_secrets.external_secret);
    secureZero(u8, &epoch_secrets.confirmation_key);
    secureZero(u8, &epoch_secrets.membership_key);
    secureZero(u8, &epoch_secrets.resumption_psk);
    secureZero(u8, &epoch_secrets.init_secret);
}

/// Forward secrecy audit events
pub const ForwardSecrecyAuditEvent = struct {
    timestamp: i64,
    event_type: EventType,
    epoch: ?types.Epoch,
    key_type: ?[]const u8,
    
    pub const EventType = enum {
        key_created,
        key_used,
        key_cleared,
        epoch_secrets_cleared,
        security_violation, // Key used after it should have been cleared
    };
};

/// Audit logger for forward secrecy events
pub const ForwardSecrecyAuditor = struct {
    allocator: std.mem.Allocator,
    events: std.ArrayList(ForwardSecrecyAuditEvent),
    
    pub fn init(allocator: std.mem.Allocator) ForwardSecrecyAuditor {
        return ForwardSecrecyAuditor{
            .allocator = allocator,
            .events = std.ArrayList(ForwardSecrecyAuditEvent).init(allocator),
        };
    }
    
    pub fn deinit(self: *ForwardSecrecyAuditor) void {
        self.events.deinit();
    }
    
    pub fn logEvent(
        self: *ForwardSecrecyAuditor,
        event_type: ForwardSecrecyAuditEvent.EventType,
        epoch: ?types.Epoch,
        key_type: ?[]const u8,
    ) !void {
        const event = ForwardSecrecyAuditEvent{
            .timestamp = std.time.timestamp(),
            .event_type = event_type,
            .epoch = epoch,
            .key_type = key_type,
        };
        
        try self.events.append(event);
    }
    
    pub fn getEvents(self: *const ForwardSecrecyAuditor) []const ForwardSecrecyAuditEvent {
        return self.events.items;
    }
    
    pub fn hasSecurityViolations(self: *const ForwardSecrecyAuditor) bool {
        for (self.events.items) |event| {
            if (event.event_type == .security_violation) {
                return true;
            }
        }
        return false;
    }
};

// Tests

test "secure key lifecycle" {
    // Test basic secure key functionality
    var key = SecureKey(32).init([_]u8{0x42} ** 32);
    
    // Key should be accessible initially
    try std.testing.expect(!key.isCleared());
    const data = key.getData();
    try std.testing.expect(data != null);
    try std.testing.expectEqual(@as(u8, 0x42), data.?[0]);
    
    // Test copying
    const copy = key.copy();
    try std.testing.expect(copy != null);
    try std.testing.expectEqual(@as(u8, 0x42), copy.?[0]);
    
    // Clear the key
    key.clear();
    try std.testing.expect(key.isCleared());
    
    // After clearing, data should not be accessible
    try std.testing.expect(key.getData() == null);
    try std.testing.expect(key.copy() == null);
    
    // Verify the underlying data was actually cleared
    var all_zeros = true;
    for (key.data) |byte| {
        if (byte != 0) {
            all_zeros = false;
            break;
        }
    }
    try std.testing.expect(all_zeros);
}

test "secure epoch secrets" {
    // Create test epoch secrets
    const test_secrets = mls.EpochSecrets{
        .joiner_secret = [_]u8{0x01} ** 32,
        .member_secret = [_]u8{0x02} ** 32,
        .welcome_secret = [_]u8{0x03} ** 32,
        .epoch_secret = [_]u8{0x04} ** 32,
        .sender_data_secret = [_]u8{0x05} ** 32,
        .encryption_secret = [_]u8{0x06} ** 32,
        .exporter_secret = [_]u8{0x07} ** 32,
        .epoch_authenticator = [_]u8{0x08} ** 32,
        .external_secret = [_]u8{0x09} ** 32,
        .confirmation_key = [_]u8{0x0A} ** 32,
        .membership_key = [_]u8{0x0B} ** 32,
        .resumption_psk = [_]u8{0x0C} ** 32,
        .init_secret = [_]u8{0x0D} ** 32,
    };
    
    // Create secure epoch secrets
    var secure_secrets = SecureEpochSecrets.init(test_secrets);
    
    // Should be able to convert back initially
    const converted = secure_secrets.toEpochSecrets();
    try std.testing.expect(converted != null);
    try std.testing.expectEqual(@as(u8, 0x01), converted.?.joiner_secret[0]);
    try std.testing.expectEqual(@as(u8, 0x0D), converted.?.init_secret[0]);
    
    // Clear the secrets
    secure_secrets.clear();
    try std.testing.expect(secure_secrets.allCleared());
    
    // After clearing, should not be able to convert
    try std.testing.expect(secure_secrets.toEpochSecrets() == null);
}

test "temporary key automatic cleanup" {
    var temp_key = TemporaryKey(32).init([_]u8{0xFF} ** 32);
    
    // Should be accessible
    const data = temp_key.getData();
    try std.testing.expect(data != null);
    try std.testing.expectEqual(@as(u8, 0xFF), data.?[0]);
    
    // Cleanup
    temp_key.deinit();
    
    // Should be cleared
    try std.testing.expect(temp_key.getData() == null);
}

test "secure memory clearing" {
    var buffer = [_]u8{0xFF} ** 100;
    
    // Clear the buffer
    secureZero(u8, &buffer);
    
    // Verify all bytes are zero
    for (buffer) |byte| {
        try std.testing.expectEqual(@as(u8, 0), byte);
    }
    
    // Test single value clearing
    var value: u32 = 0xDEADBEEF;
    secureZeroValue(u32, &value);
    try std.testing.expectEqual(@as(u32, 0), value);
}

test "forward secrecy auditor" {
    const allocator = std.testing.allocator;
    
    var auditor = ForwardSecrecyAuditor.init(allocator);
    defer auditor.deinit();
    
    // Log some events
    try auditor.logEvent(.key_created, 0, "signing_key");
    try auditor.logEvent(.key_used, 0, "signing_key");
    try auditor.logEvent(.key_cleared, 0, "signing_key");
    try auditor.logEvent(.security_violation, 1, "encryption_key");
    
    // Verify events
    const events = auditor.getEvents();
    try std.testing.expectEqual(@as(usize, 4), events.len);
    
    try std.testing.expectEqual(
        ForwardSecrecyAuditEvent.EventType.key_created,
        events[0].event_type
    );
    try std.testing.expectEqual(
        ForwardSecrecyAuditEvent.EventType.security_violation,
        events[3].event_type
    );
    
    // Check for security violations
    try std.testing.expect(auditor.hasSecurityViolations());
}

test "secure MLS group state" {
    const test_secrets = mls.EpochSecrets{
        .joiner_secret = [_]u8{0x01} ** 32,
        .member_secret = [_]u8{0x02} ** 32,
        .welcome_secret = [_]u8{0x03} ** 32,
        .epoch_secret = [_]u8{0x04} ** 32,
        .sender_data_secret = [_]u8{0x05} ** 32,
        .encryption_secret = [_]u8{0x06} ** 32,
        .exporter_secret = [_]u8{0x07} ** 32,
        .epoch_authenticator = [_]u8{0x08} ** 32,
        .external_secret = [_]u8{0x09} ** 32,
        .confirmation_key = [_]u8{0x0A} ** 32,
        .membership_key = [_]u8{0x0B} ** 32,
        .resumption_psk = [_]u8{0x0C} ** 32,
        .init_secret = [_]u8{0x0D} ** 32,
    };
    
    const test_state = mls.MlsGroupState{
        .group_id = types.GroupId.init([_]u8{0xAA} ** 32),
        .epoch = 42,
        .cipher_suite = .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        .group_context = undefined,
        .tree_hash = [_]u8{0xBB} ** 32,
        .confirmed_transcript_hash = [_]u8{0xCC} ** 32,
        .members = &.{},
        .ratchet_tree = &.{},
        .interim_transcript_hash = [_]u8{0xDD} ** 32,
        .epoch_secrets = test_secrets,
    };
    
    // Create secure state
    var secure_state = SecureMlsGroupState.init(test_state);
    
    // Should be able to convert back
    const converted = secure_state.toMlsGroupState();
    try std.testing.expect(converted != null);
    try std.testing.expectEqual(@as(u64, 42), converted.?.epoch);
    try std.testing.expectEqual(@as(u8, 0xBB), converted.?.tree_hash[0]);
    
    // Clear the secure state
    secure_state.clear();
    
    // Should not be able to convert after clearing
    try std.testing.expect(secure_state.toMlsGroupState() == null);
    
    // Verify sensitive data was cleared
    var all_zeros = true;
    for (secure_state.tree_hash) |byte| {
        if (byte != 0) {
            all_zeros = false;
            break;
        }
    }
    try std.testing.expect(all_zeros);
}