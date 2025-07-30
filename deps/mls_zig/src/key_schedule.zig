const std = @import("std");
const CipherSuite = @import("cipher_suite.zig").CipherSuite;

const Allocator = std.mem.Allocator;

/// MLS Key Schedule implementation according to RFC 9420 Section 8
pub const KeySchedule = struct {
    cipher_suite: CipherSuite,
    allocator: Allocator,
    
    pub fn init(allocator: Allocator, cipher_suite: CipherSuite) KeySchedule {
        return .{
            .cipher_suite = cipher_suite,
            .allocator = allocator,
        };
    }
    
    /// Derive joiner secret from commit secret and PSK
    /// joiner_secret = Extract(commit_secret, psk_secret || 0...)
    pub fn deriveJoinerSecret(
        self: KeySchedule,
        commit_secret: []const u8,
        psk_secret: ?[]const u8,
    ) !std.ArrayList(u8) {
        // If no PSK, use zeros
        const hash_len = self.cipher_suite.hashLength();
        const zeros = try self.allocator.alloc(u8, hash_len);
        defer self.allocator.free(zeros);
        @memset(zeros, 0);
        
        const salt = psk_secret orelse zeros;
        
        // Extract using HKDF
        var joiner_secret_result = try self.cipher_suite.hkdfExtract(
            self.allocator,
            salt,
            commit_secret,
        );
        defer joiner_secret_result.deinit();
        
        // Transfer to ArrayList
        var result = std.ArrayList(u8).init(self.allocator);
        errdefer result.deinit();
        try result.appendSlice(joiner_secret_result.data);
        return result;
    }
    
    /// Derive member secret from joiner secret
    /// member_secret = DeriveSecret(joiner_secret, "member")
    pub fn deriveMemberSecret(
        self: KeySchedule,
        joiner_secret: []const u8,
        group_context: []const u8,
    ) !std.ArrayList(u8) {
        var secret = try self.cipher_suite.deriveSecret(
            self.allocator,
            joiner_secret,
            "member",
            group_context,
        );
        defer secret.deinit();
        
        // Transfer to ArrayList
        var result = std.ArrayList(u8).init(self.allocator);
        errdefer result.deinit();
        try result.appendSlice(secret.data);
        return result;
    }
    
    /// Derive welcome secret from joiner secret
    /// welcome_secret = DeriveSecret(joiner_secret, "welcome")
    pub fn deriveWelcomeSecret(
        self: KeySchedule,
        joiner_secret: []const u8,
        group_context: []const u8,
    ) !std.ArrayList(u8) {
        var secret = try self.cipher_suite.deriveSecret(
            self.allocator,
            joiner_secret,
            "welcome",
            group_context,
        );
        defer secret.deinit();
        
        // Transfer to ArrayList
        var result = std.ArrayList(u8).init(self.allocator);
        errdefer result.deinit();
        try result.appendSlice(secret.data);
        return result;
    }
    
    /// Derive epoch secret from member secret
    /// epoch_secret = DeriveSecret(member_secret, "epoch", GroupContext)
    pub fn deriveEpochSecret(
        self: KeySchedule,
        member_secret: []const u8,
        group_context: []const u8,
    ) !std.ArrayList(u8) {
        var secret = try self.cipher_suite.deriveSecret(
            self.allocator,
            member_secret,
            "epoch",
            group_context,
        );
        defer secret.deinit();
        
        // Transfer to ArrayList
        var result = std.ArrayList(u8).init(self.allocator);
        errdefer result.deinit();
        try result.appendSlice(secret.data);
        return result;
    }
    
    /// Derive all application secrets from epoch secret
    pub fn deriveApplicationSecrets(
        self: KeySchedule,
        epoch_secret: []const u8,
        group_context: []const u8,
    ) !ApplicationSecrets {
        // Derive all the application secrets
        var sender_data_secret_result = try self.cipher_suite.deriveSecret(
            self.allocator,
            epoch_secret,
            "sender data",
            group_context,
        );
        defer sender_data_secret_result.deinit();
        var sender_data_secret = std.ArrayList(u8).init(self.allocator);
        errdefer sender_data_secret.deinit();
        try sender_data_secret.appendSlice(sender_data_secret_result.data);
        
        var encryption_secret_result = try self.cipher_suite.deriveSecret(
            self.allocator,
            epoch_secret,
            "encryption",
            group_context,
        );
        defer encryption_secret_result.deinit();
        var encryption_secret = std.ArrayList(u8).init(self.allocator);
        errdefer encryption_secret.deinit();
        try encryption_secret.appendSlice(encryption_secret_result.data);
        
        var exporter_secret_result = try self.cipher_suite.deriveSecret(
            self.allocator,
            epoch_secret,
            "exporter",
            group_context,
        );
        defer exporter_secret_result.deinit();
        var exporter_secret = std.ArrayList(u8).init(self.allocator);
        errdefer exporter_secret.deinit();
        try exporter_secret.appendSlice(exporter_secret_result.data);
        
        var epoch_authenticator_result = try self.cipher_suite.deriveSecret(
            self.allocator,
            epoch_secret,
            "authentication",
            group_context,
        );
        defer epoch_authenticator_result.deinit();
        var epoch_authenticator = std.ArrayList(u8).init(self.allocator);
        errdefer epoch_authenticator.deinit();
        try epoch_authenticator.appendSlice(epoch_authenticator_result.data);
        
        var external_secret_result = try self.cipher_suite.deriveSecret(
            self.allocator,
            epoch_secret,
            "external",
            group_context,
        );
        defer external_secret_result.deinit();
        var external_secret = std.ArrayList(u8).init(self.allocator);
        errdefer external_secret.deinit();
        try external_secret.appendSlice(external_secret_result.data);
        
        var confirmation_key_result = try self.cipher_suite.deriveSecret(
            self.allocator,
            epoch_secret,
            "confirm",
            group_context,
        );
        defer confirmation_key_result.deinit();
        var confirmation_key = std.ArrayList(u8).init(self.allocator);
        errdefer confirmation_key.deinit();
        try confirmation_key.appendSlice(confirmation_key_result.data);
        
        var membership_key_result = try self.cipher_suite.deriveSecret(
            self.allocator,
            epoch_secret,
            "membership",
            group_context,
        );
        defer membership_key_result.deinit();
        var membership_key = std.ArrayList(u8).init(self.allocator);
        errdefer membership_key.deinit();
        try membership_key.appendSlice(membership_key_result.data);
        
        var resumption_psk_result = try self.cipher_suite.deriveSecret(
            self.allocator,
            epoch_secret,
            "resumption",
            group_context,
        );
        defer resumption_psk_result.deinit();
        var resumption_psk = std.ArrayList(u8).init(self.allocator);
        errdefer resumption_psk.deinit();
        try resumption_psk.appendSlice(resumption_psk_result.data);
        
        return ApplicationSecrets{
            .sender_data_secret = sender_data_secret,
            .encryption_secret = encryption_secret,
            .exporter_secret = exporter_secret,
            .epoch_authenticator = epoch_authenticator,
            .external_secret = external_secret,
            .confirmation_key = confirmation_key,
            .membership_key = membership_key,
            .resumption_psk = resumption_psk,
        };
    }
    
    /// Derive init secret for next epoch
    /// init_secret[n+1] = DeriveSecret(commit_secret[n], "init")
    pub fn deriveNextInitSecret(
        self: KeySchedule,
        commit_secret: []const u8,
    ) !std.ArrayList(u8) {
        var secret = try self.cipher_suite.deriveSecret(
            self.allocator,
            commit_secret,
            "init",
            &[_]u8{}, // empty context
        );
        defer secret.deinit();
        
        // Transfer to ArrayList
        var result = std.ArrayList(u8).init(self.allocator);
        errdefer result.deinit();
        try result.appendSlice(secret.data);
        return result;
    }
    
    /// Complete epoch secrets derivation following RFC 9420
    pub fn deriveEpochSecrets(
        self: KeySchedule,
        commit_secret: []const u8,
        psk_secret: ?[]const u8,
        group_context: []const u8,
    ) !EpochSecrets {
        // Derive joiner secret
        var joiner_secret = try self.deriveJoinerSecret(commit_secret, psk_secret);
        errdefer joiner_secret.deinit();
        
        // Derive member and welcome secrets
        var member_secret = try self.deriveMemberSecret(joiner_secret.items, group_context);
        errdefer member_secret.deinit();
        
        var welcome_secret = try self.deriveWelcomeSecret(joiner_secret.items, group_context);
        errdefer welcome_secret.deinit();
        
        // Derive epoch secret
        var epoch_secret = try self.deriveEpochSecret(member_secret.items, group_context);
        errdefer epoch_secret.deinit();
        
        // Derive application secrets
        var app_secrets = try self.deriveApplicationSecrets(epoch_secret.items, group_context);
        errdefer {
            app_secrets.sender_data_secret.deinit();
            app_secrets.encryption_secret.deinit();
            app_secrets.exporter_secret.deinit();
            app_secrets.epoch_authenticator.deinit();
            app_secrets.external_secret.deinit();
            app_secrets.confirmation_key.deinit();
            app_secrets.membership_key.deinit();
            app_secrets.resumption_psk.deinit();
        }
        
        // Derive init secret for next epoch
        var init_secret = try self.deriveNextInitSecret(commit_secret);
        errdefer init_secret.deinit();
        
        return EpochSecrets{
            .joiner_secret = joiner_secret,
            .member_secret = member_secret,
            .welcome_secret = welcome_secret,
            .epoch_secret = epoch_secret,
            .sender_data_secret = app_secrets.sender_data_secret,
            .encryption_secret = app_secrets.encryption_secret,
            .exporter_secret = app_secrets.exporter_secret,
            .epoch_authenticator = app_secrets.epoch_authenticator,
            .external_secret = app_secrets.external_secret,
            .confirmation_key = app_secrets.confirmation_key,
            .membership_key = app_secrets.membership_key,
            .resumption_psk = app_secrets.resumption_psk,
            .init_secret = init_secret,
        };
    }
};

/// Application secrets derived from epoch secret
pub const ApplicationSecrets = struct {
    sender_data_secret: std.ArrayList(u8),
    encryption_secret: std.ArrayList(u8),
    exporter_secret: std.ArrayList(u8),
    epoch_authenticator: std.ArrayList(u8),
    external_secret: std.ArrayList(u8),
    confirmation_key: std.ArrayList(u8),
    membership_key: std.ArrayList(u8),
    resumption_psk: std.ArrayList(u8),
};

/// Complete set of epoch secrets
pub const EpochSecrets = struct {
    joiner_secret: std.ArrayList(u8),
    member_secret: std.ArrayList(u8),
    welcome_secret: std.ArrayList(u8),
    epoch_secret: std.ArrayList(u8),
    sender_data_secret: std.ArrayList(u8),
    encryption_secret: std.ArrayList(u8),
    exporter_secret: std.ArrayList(u8),
    epoch_authenticator: std.ArrayList(u8),
    external_secret: std.ArrayList(u8),
    confirmation_key: std.ArrayList(u8),
    membership_key: std.ArrayList(u8),
    resumption_psk: std.ArrayList(u8),
    init_secret: std.ArrayList(u8),
    
    pub fn deinit(self: *EpochSecrets) void {
        self.joiner_secret.deinit();
        self.member_secret.deinit();
        self.welcome_secret.deinit();
        self.epoch_secret.deinit();
        self.sender_data_secret.deinit();
        self.encryption_secret.deinit();
        self.exporter_secret.deinit();
        self.epoch_authenticator.deinit();
        self.external_secret.deinit();
        self.confirmation_key.deinit();
        self.membership_key.deinit();
        self.resumption_psk.deinit();
        self.init_secret.deinit();
    }
    
    /// Convert to fixed-size epoch secrets for use in our codebase
    pub fn toFixed(self: *const EpochSecrets) FixedEpochSecrets {
        var fixed: FixedEpochSecrets = undefined;
        
        // Copy each secret to fixed array, padding or truncating as needed
        copyToFixed(self.joiner_secret.items, &fixed.joiner_secret);
        copyToFixed(self.member_secret.items, &fixed.member_secret);
        copyToFixed(self.welcome_secret.items, &fixed.welcome_secret);
        copyToFixed(self.epoch_secret.items, &fixed.epoch_secret);
        copyToFixed(self.sender_data_secret.items, &fixed.sender_data_secret);
        copyToFixed(self.encryption_secret.items, &fixed.encryption_secret);
        copyToFixed(self.exporter_secret.items, &fixed.exporter_secret);
        copyToFixed(self.epoch_authenticator.items, &fixed.epoch_authenticator);
        copyToFixed(self.external_secret.items, &fixed.external_secret);
        copyToFixed(self.confirmation_key.items, &fixed.confirmation_key);
        copyToFixed(self.membership_key.items, &fixed.membership_key);
        copyToFixed(self.resumption_psk.items, &fixed.resumption_psk);
        copyToFixed(self.init_secret.items, &fixed.init_secret);
        
        return fixed;
    }
    
    fn copyToFixed(src: []const u8, dst: *[32]u8) void {
        if (src.len >= 32) {
            @memcpy(dst, src[0..32]);
        } else {
            @memset(dst, 0);
            @memcpy(dst[0..src.len], src);
        }
    }
};

/// Fixed-size epoch secrets for compatibility with existing code
pub const FixedEpochSecrets = struct {
    joiner_secret: [32]u8,
    member_secret: [32]u8,
    welcome_secret: [32]u8,
    epoch_secret: [32]u8,
    sender_data_secret: [32]u8,
    encryption_secret: [32]u8,
    exporter_secret: [32]u8,
    epoch_authenticator: [32]u8,
    external_secret: [32]u8,
    confirmation_key: [32]u8,
    membership_key: [32]u8,
    resumption_psk: [32]u8,
    init_secret: [32]u8,
};

// Tests
const testing = std.testing;

test "key schedule derivation" {
    const allocator = testing.allocator;
    const cipher_suite = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    
    var key_schedule = KeySchedule.init(allocator, cipher_suite);
    
    // Test with dummy commit secret
    const commit_secret = [_]u8{0x42} ** 32;
    const group_context = "test_group_context";
    
    var epoch_secrets = try key_schedule.deriveEpochSecrets(
        &commit_secret,
        null, // no PSK
        group_context,
    );
    defer epoch_secrets.deinit();
    
    // Verify all secrets are derived
    try testing.expect(epoch_secrets.joiner_secret.items.len > 0);
    try testing.expect(epoch_secrets.member_secret.items.len > 0);
    try testing.expect(epoch_secrets.exporter_secret.items.len > 0);
    
    // Convert to fixed size
    const fixed = epoch_secrets.toFixed();
    try testing.expect(fixed.exporter_secret != [_]u8{0} ** 32);
}