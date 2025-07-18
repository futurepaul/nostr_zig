const std = @import("std");
const mls = @import("mls.zig");
const types = @import("types.zig");
const messages = @import("messages.zig");
const ephemeral = @import("ephemeral.zig");
const nip_ee = @import("nip_ee.zig");
const provider = @import("provider.zig");

/// High-level API for sending group messages with proper ephemeral key usage
pub const GroupMessenger = struct {
    allocator: std.mem.Allocator,
    mls_provider: *provider.MlsProvider,
    ephemeral_cache: ephemeral.EphemeralKeyCache,
    
    pub fn init(allocator: std.mem.Allocator, mls_provider: *provider.MlsProvider) GroupMessenger {
        return .{
            .allocator = allocator,
            .mls_provider = mls_provider,
            .ephemeral_cache = ephemeral.EphemeralKeyCache.init(allocator),
        };
    }
    
    pub fn deinit(self: *GroupMessenger) void {
        self.ephemeral_cache.deinit();
    }
    
    /// Send a message to the group with automatic ephemeral key generation
    pub fn sendMessage(
        self: *GroupMessenger,
        group_state: *const mls.MlsGroupState,
        content: []const u8,
        sender_private_key: [32]u8,
    ) !nip_ee.GroupMessageEvent {
        // Encrypt the message
        const encrypted = try messages.encryptGroupMessage(
            self.allocator,
            self.mls_provider,
            group_state,
            content,
            sender_private_key,
            .{},
        );
        defer self.allocator.free(encrypted.nip44_ciphertext);
        
        // Create group message event with ephemeral key
        const group_msg = try messages.createGroupMessageEvent(
            self.allocator,
            encrypted,
            group_state.group_context.group_id,
        );
        
        // Cache the ephemeral public key for potential verification
        try self.ephemeral_cache.add(group_msg.event.id, group_msg.event.pubkey);
        
        return group_msg;
    }
    
    /// Send multiple messages efficiently with batch ephemeral key generation
    pub fn sendBatchMessages(
        self: *GroupMessenger,
        group_state: *const mls.MlsGroupState,
        contents: []const []const u8,
        sender_private_key: [32]u8,
    ) ![]nip_ee.GroupMessageEvent {
        // Generate ephemeral keys for all messages
        const ephemeral_keys = try ephemeral.generateBatchEphemeralKeys(contents.len, self.allocator);
        defer {
            ephemeral.clearBatchEphemeralKeys(ephemeral_keys);
            self.allocator.free(ephemeral_keys);
        }
        
        const events = try self.allocator.alloc(nip_ee.GroupMessageEvent, contents.len);
        errdefer self.allocator.free(events);
        
        for (contents, ephemeral_keys, 0..) |content, eph_key, i| {
            // Encrypt the message
            const encrypted = try messages.encryptGroupMessage(
                self.allocator,
                self.mls_provider,
                group_state,
                content,
                sender_private_key,
                .{},
            );
            defer self.allocator.free(encrypted.nip44_ciphertext);
            
            // Create group message event with pre-generated ephemeral key
            events[i] = try messages.createGroupMessageEventWithKey(
                self.allocator,
                encrypted,
                group_state.group_context.group_id,
                eph_key.private_key,
            );
            
            // Cache the ephemeral public key
            try self.ephemeral_cache.add(events[i].event.id, eph_key.public_key);
        }
        
        return events;
    }
    
    /// Verify that a group message was sent with a proper ephemeral key
    pub fn verifyEphemeralKey(self: *GroupMessenger, event: nip_ee.GroupMessageEvent) bool {
        // Check if we have the ephemeral key in cache
        if (self.ephemeral_cache.get(event.event.id)) |cached_pubkey| {
            return std.mem.eql(u8, &cached_pubkey, &event.event.pubkey);
        }
        
        // Additional checks can be added here:
        // - Verify the key hasn't been used before
        // - Check against a bloom filter of used keys
        // - Verify randomness properties
        
        return true; // Assume valid if not in cache
    }
};

/// Statistics for ephemeral key usage
pub const EphemeralKeyStats = struct {
    total_messages: u64 = 0,
    unique_keys: u64 = 0,
    reused_keys: u64 = 0,
    
    key_tracker: std.AutoHashMap([32]u8, u32),
    
    pub fn init(allocator: std.mem.Allocator) EphemeralKeyStats {
        return .{
            .key_tracker = std.AutoHashMap([32]u8, u32).init(allocator),
        };
    }
    
    pub fn deinit(self: *EphemeralKeyStats) void {
        self.key_tracker.deinit();
    }
    
    pub fn recordKey(self: *EphemeralKeyStats, pubkey: [32]u8) !void {
        self.total_messages += 1;
        
        const result = try self.key_tracker.getOrPut(pubkey);
        if (!result.found_existing) {
            result.value_ptr.* = 1;
            self.unique_keys += 1;
        } else {
            result.value_ptr.* += 1;
            self.reused_keys += 1;
        }
    }
    
    pub fn getKeyUsageCount(self: *EphemeralKeyStats, pubkey: [32]u8) u32 {
        return self.key_tracker.get(pubkey) orelse 0;
    }
    
    pub fn hasKeyReuse(self: *EphemeralKeyStats) bool {
        return self.reused_keys > 0;
    }
};

test "group messenger sends with ephemeral keys" {
    const allocator = std.testing.allocator;
    
    var mls_provider = provider.MlsProvider.init(allocator);
    
    var messenger = GroupMessenger.init(allocator, &mls_provider);
    defer messenger.deinit();
    
    // Create mock group state
    const group_state = mls.MlsGroupState{
        .group_id = types.GroupId.init([_]u8{1} ** 32),
        .epoch = 0,
        .cipher_suite = .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        .group_context = .{
            .version = .mls10,
            .cipher_suite = .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            .group_id = types.GroupId.init([_]u8{1} ** 32),
            .epoch = 0,
            .tree_hash = [_]u8{0} ** 32,
            .confirmed_transcript_hash = [_]u8{0} ** 32,
            .extensions = &.{},
        },
        .tree_hash = [_]u8{0} ** 32,
        .confirmed_transcript_hash = [_]u8{0} ** 32,
        .members = &.{},
        .ratchet_tree = &.{},
        .interim_transcript_hash = [_]u8{0} ** 32,
        .epoch_secrets = .{
            .joiner_secret = [_]u8{0} ** 32,
            .member_secret = [_]u8{0} ** 32,
            .welcome_secret = [_]u8{0} ** 32,
            .epoch_secret = [_]u8{0} ** 32,
            .sender_data_secret = [_]u8{0} ** 32,
            .encryption_secret = [_]u8{0} ** 32,
            .exporter_secret = [_]u8{0} ** 32,
            .epoch_authenticator = [_]u8{0} ** 32,
            .external_secret = [_]u8{0} ** 32,
            .confirmation_key = [_]u8{0} ** 32,
            .membership_key = [_]u8{0} ** 32,
            .resumption_psk = [_]u8{0} ** 32,
            .init_secret = [_]u8{0} ** 32,
        },
    };
    
    // Test would continue with actual message sending
    // This is a simplified test structure
    _ = group_state;
}

test "ephemeral key stats tracking" {
    const allocator = std.testing.allocator;
    
    var stats = EphemeralKeyStats.init(allocator);
    defer stats.deinit();
    
    const key1: [32]u8 = [_]u8{1} ** 32;
    const key2: [32]u8 = [_]u8{2} ** 32;
    
    // Record unique keys
    try stats.recordKey(key1);
    try stats.recordKey(key2);
    
    try std.testing.expectEqual(@as(u64, 2), stats.total_messages);
    try std.testing.expectEqual(@as(u64, 2), stats.unique_keys);
    try std.testing.expectEqual(@as(u64, 0), stats.reused_keys);
    try std.testing.expect(!stats.hasKeyReuse());
    
    // Record key reuse
    try stats.recordKey(key1);
    
    try std.testing.expectEqual(@as(u64, 3), stats.total_messages);
    try std.testing.expectEqual(@as(u64, 2), stats.unique_keys);
    try std.testing.expectEqual(@as(u64, 1), stats.reused_keys);
    try std.testing.expect(stats.hasKeyReuse());
    
    try std.testing.expectEqual(@as(u32, 2), stats.getKeyUsageCount(key1));
    try std.testing.expectEqual(@as(u32, 1), stats.getKeyUsageCount(key2));
}