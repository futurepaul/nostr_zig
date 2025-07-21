const std = @import("std");
const types = @import("types.zig");
const mls = @import("mls.zig");
const application_messages = @import("application_messages.zig");

/// Error types for message authentication
pub const AuthenticationError = error{
    /// The sender's MLS identity doesn't match the inner event pubkey
    SenderIdentityMismatch,
    /// The sender is not a valid member of the group
    InvalidSender,
    /// The message signature is invalid
    InvalidSignature,
    /// The inner event format is invalid
    InvalidInnerEvent,
    /// Generic authentication failure
    AuthenticationFailed,
};

/// Validate that a decrypted application message has authentic sender identity
/// This prevents identity spoofing by verifying that the MLS sender matches the inner event pubkey
pub fn validateApplicationMessageAuthenticity(
    allocator: std.mem.Allocator,
    group_state: *const mls.MlsGroupState,
    decrypted_message: *const mls.DecryptedMessage,
) !void {
    // Parse the inner event from the decrypted content
    const inner_event = application_messages.InnerEvent.parse(allocator, decrypted_message.content) catch {
        return AuthenticationError.InvalidInnerEvent;
    };
    defer inner_event.deinit(allocator);
    
    // Get the sender's public key from the MLS group state
    const sender_pubkey = getSenderPublicKey(group_state, decrypted_message.sender) catch {
        return AuthenticationError.InvalidSender;
    };
    
    // Verify that the sender's MLS identity matches the inner event pubkey
    if (!std.mem.eql(u8, &sender_pubkey, &inner_event.pubkey)) {
        return AuthenticationError.SenderIdentityMismatch;
    }
    
    // Additional validation: verify inner event structure
    try application_messages.validateInnerEvent(&inner_event);
}

/// Validate a sender's identity when creating an application message
/// This ensures the sender can only create messages with their own pubkey
pub fn validateSenderIdentity(
    sender_private_key: [32]u8,
    inner_event: *const application_messages.InnerEvent,
) !void {
    // Derive the public key from the private key
    const crypto = @import("../crypto.zig");
    const actual_pubkey = try crypto.getPublicKey(sender_private_key);
    
    // Verify that the inner event pubkey matches the sender's actual pubkey
    if (!std.mem.eql(u8, &actual_pubkey, &inner_event.pubkey)) {
        return AuthenticationError.SenderIdentityMismatch;
    }
}

/// Enhanced application message creation with authentication validation
pub fn createAuthenticatedApplicationMessage(
    allocator: std.mem.Allocator,
    mls_provider: *@import("provider.zig").MlsProvider,
    group_state: *const mls.MlsGroupState,
    inner_event: application_messages.InnerEvent,
    sender_private_key: [32]u8,
) !@import("messages.zig").EncryptedMessage {
    // First, validate that the sender can create this message
    try validateSenderIdentity(sender_private_key, &inner_event);
    
    // Proceed with normal message creation
    return try application_messages.createApplicationMessage(
        allocator,
        mls_provider,
        group_state,
        inner_event,
        sender_private_key,
    );
}

/// Enhanced application message parsing with authentication validation
pub fn parseAuthenticatedApplicationMessage(
    allocator: std.mem.Allocator,
    mls_provider: *@import("provider.zig").MlsProvider,
    group_state: *const mls.MlsGroupState,
    encrypted_data: []const u8,
    epoch: types.Epoch,
    recipient_private_key: [32]u8,
) !application_messages.InnerEvent {
    // First decrypt the message normally
    const messages = @import("messages.zig");
    const decrypted_msg = try messages.decryptGroupMessage(
        allocator,
        mls_provider,
        group_state,
        encrypted_data,
        epoch,
        recipient_private_key,
    );
    defer allocator.free(decrypted_msg.content);
    
    // Validate the authenticity of the message
    try validateApplicationMessageAuthenticity(allocator, group_state, &decrypted_msg);
    
    // Parse and return the inner event
    return try application_messages.InnerEvent.parse(allocator, decrypted_msg.content);
}

/// Get the Nostr public key for a sender from the group state
fn getSenderPublicKey(group_state: *const mls.MlsGroupState, sender: types.Sender) ![32]u8 {
    switch (sender) {
        .member => |index| {
            if (index >= group_state.members.len) {
                return AuthenticationError.InvalidSender;
            }
            const member = group_state.members[index];
            switch (member.credential) {
                .basic => |basic| {
                    if (basic.identity.len != 64) {
                        return AuthenticationError.InvalidSender;
                    }
                    var pubkey: [32]u8 = undefined;
                    _ = try std.fmt.hexToBytes(&pubkey, basic.identity);
                    return pubkey;
                },
                else => return AuthenticationError.InvalidSender,
            }
        },
        else => return AuthenticationError.InvalidSender,
    }
}

/// Audit log entry for authentication events
pub const AuthenticationAuditEvent = struct {
    /// Timestamp of the event
    timestamp: i64,
    /// Event type
    event_type: EventType,
    /// Group ID involved
    group_id: types.GroupId,
    /// Sender's pubkey (if available)
    sender_pubkey: ?[32]u8,
    /// Attempted inner event pubkey (if different)
    attempted_pubkey: ?[32]u8,
    /// Error that occurred (if any)
    error_type: ?AuthenticationError,
    
    pub const EventType = enum {
        message_authentication_success,
        message_authentication_failure,
        sender_validation_success, 
        sender_validation_failure,
    };
};

/// Simple audit logger for authentication events
pub const AuthenticationAuditor = struct {
    allocator: std.mem.Allocator,
    events: std.ArrayList(AuthenticationAuditEvent),
    
    pub fn init(allocator: std.mem.Allocator) AuthenticationAuditor {
        return AuthenticationAuditor{
            .allocator = allocator,
            .events = std.ArrayList(AuthenticationAuditEvent).init(allocator),
        };
    }
    
    pub fn deinit(self: *AuthenticationAuditor) void {
        self.events.deinit();
    }
    
    pub fn logEvent(
        self: *AuthenticationAuditor,
        event_type: AuthenticationAuditEvent.EventType,
        group_id: types.GroupId,
        sender_pubkey: ?[32]u8,
        attempted_pubkey: ?[32]u8,
        error_type: ?AuthenticationError,
    ) !void {
        const event = AuthenticationAuditEvent{
            .timestamp = std.time.timestamp(),
            .event_type = event_type,
            .group_id = group_id,
            .sender_pubkey = sender_pubkey,
            .attempted_pubkey = attempted_pubkey,
            .error_type = error_type,
        };
        
        try self.events.append(event);
    }
    
    pub fn getEvents(self: *const AuthenticationAuditor) []const AuthenticationAuditEvent {
        return self.events.items;
    }
    
    pub fn hasFailures(self: *const AuthenticationAuditor) bool {
        for (self.events.items) |event| {
            switch (event.event_type) {
                .message_authentication_failure, .sender_validation_failure => return true,
                else => {},
            }
        }
        return false;
    }
};

// Tests

test "validate sender identity match" {
    const allocator = std.testing.allocator;
    const crypto = @import("../crypto.zig");
    
    // Generate a sender key pair
    const sender_private_key = try crypto.generatePrivateKey();
    const sender_pubkey = try crypto.getPublicKey(sender_private_key);
    
    // Create an inner event with the correct pubkey
    const valid_event = try application_messages.createChatMessage(
        allocator,
        "Valid message",
        sender_pubkey,
        std.time.timestamp(),
    );
    defer valid_event.deinit(allocator);
    
    // Should validate successfully
    try validateSenderIdentity(sender_private_key, &valid_event);
    
    // Create an inner event with wrong pubkey
    const wrong_pubkey: [32]u8 = [_]u8{0xFF} ** 32;
    const invalid_event = try application_messages.createChatMessage(
        allocator,
        "Invalid message",
        wrong_pubkey,
        std.time.timestamp(),
    );
    defer invalid_event.deinit(allocator);
    
    // Should fail validation
    try std.testing.expectError(
        AuthenticationError.SenderIdentityMismatch, 
        validateSenderIdentity(sender_private_key, &invalid_event)
    );
}

test "validate application message authenticity" {
    const allocator = std.testing.allocator;
    const crypto = @import("../crypto.zig");
    
    // Create a test member
    const member_pubkey = try crypto.generatePrivateKey();
    const member_pubkey_hex = try std.fmt.allocPrint(
        allocator,
        "{s}",
        .{std.fmt.fmtSliceHexLower(&member_pubkey)},
    );
    defer allocator.free(member_pubkey_hex);
    
    const members = [_]types.MemberInfo{
        .{
            .index = 0,
            .credential = .{
                .basic = .{
                    .identity = member_pubkey_hex,
                },
            },
            .role = .member,
            .joined_at_epoch = 0,
        },
    };
    
    const state = mls.MlsGroupState{
        .group_id = types.GroupId.init([_]u8{0} ** 32),
        .epoch = 0,
        .cipher_suite = .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        .group_context = undefined,
        .tree_hash = [_]u8{0} ** 32,
        .confirmed_transcript_hash = [_]u8{0} ** 32,
        .members = &members,
        .ratchet_tree = &.{},
        .interim_transcript_hash = [_]u8{0} ** 32,
        .epoch_secrets = undefined,
    };
    
    // Create a valid inner event
    const valid_inner = try application_messages.createChatMessage(
        allocator,
        "Authentic message",
        member_pubkey, // Correct pubkey
        std.time.timestamp(),
    );
    defer valid_inner.deinit(allocator);
    
    const valid_content = try valid_inner.serialize(allocator);
    defer allocator.free(valid_content);
    
    const valid_msg = mls.DecryptedMessage{
        .content = valid_content,
        .sender = types.Sender{ .member = 0 }, // Member at index 0
        .state_updated = false,
        .new_state = null,
    };
    
    // Should validate successfully
    try validateApplicationMessageAuthenticity(allocator, &state, &valid_msg);
    
    // Create an invalid inner event (wrong pubkey)
    const wrong_pubkey: [32]u8 = [_]u8{0xFF} ** 32;
    const invalid_inner = try application_messages.createChatMessage(
        allocator,
        "Spoofed message",
        wrong_pubkey, // Wrong pubkey
        std.time.timestamp(),
    );
    defer invalid_inner.deinit(allocator);
    
    const invalid_content = try invalid_inner.serialize(allocator);
    defer allocator.free(invalid_content);
    
    const invalid_msg = mls.DecryptedMessage{
        .content = invalid_content,
        .sender = types.Sender{ .member = 0 }, // Same sender
        .state_updated = false,
        .new_state = null,
    };
    
    // Should fail validation
    try std.testing.expectError(
        AuthenticationError.SenderIdentityMismatch,
        validateApplicationMessageAuthenticity(allocator, &state, &invalid_msg)
    );
}

test "authentication auditor" {
    const allocator = std.testing.allocator;
    
    var auditor = AuthenticationAuditor.init(allocator);
    defer auditor.deinit();
    
    const group_id = types.GroupId.init([_]u8{1} ** 32);
    const sender_pubkey: [32]u8 = [_]u8{2} ** 32;
    const attempted_pubkey: [32]u8 = [_]u8{3} ** 32;
    
    // Log a success event
    try auditor.logEvent(
        .message_authentication_success,
        group_id,
        sender_pubkey,
        null,
        null,
    );
    
    // Log a failure event
    try auditor.logEvent(
        .sender_validation_failure,
        group_id,
        sender_pubkey,
        attempted_pubkey,
        AuthenticationError.SenderIdentityMismatch,
    );
    
    // Verify events
    const events = auditor.getEvents();
    try std.testing.expectEqual(@as(usize, 2), events.len);
    
    try std.testing.expectEqual(
        AuthenticationAuditEvent.EventType.message_authentication_success,
        events[0].event_type
    );
    try std.testing.expectEqual(
        AuthenticationAuditEvent.EventType.sender_validation_failure,
        events[1].event_type
    );
    
    // Check for failures
    try std.testing.expect(auditor.hasFailures());
}

test "get sender public key from group state" {
    const allocator = std.testing.allocator;
    
    const expected_pubkey: [32]u8 = [_]u8{0xAB} ** 32;
    const pubkey_hex = try std.fmt.allocPrint(
        allocator,
        "{s}",
        .{std.fmt.fmtSliceHexLower(&expected_pubkey)},
    );
    defer allocator.free(pubkey_hex);
    
    const members = [_]types.MemberInfo{
        .{
            .index = 0,
            .credential = .{
                .basic = .{
                    .identity = pubkey_hex,
                },
            },
            .role = .member,
            .joined_at_epoch = 0,
        },
    };
    
    const state = mls.MlsGroupState{
        .group_id = types.GroupId.init([_]u8{0} ** 32),
        .epoch = 0,
        .cipher_suite = .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        .group_context = undefined,
        .tree_hash = [_]u8{0} ** 32,
        .confirmed_transcript_hash = [_]u8{0} ** 32,
        .members = &members,
        .ratchet_tree = &.{},
        .interim_transcript_hash = [_]u8{0} ** 32,
        .epoch_secrets = undefined,
    };
    
    const sender = types.Sender{ .member = 0 };
    const actual_pubkey = try getSenderPublicKey(&state, sender);
    
    try std.testing.expectEqual(expected_pubkey, actual_pubkey);
    
    // Test invalid sender index
    const invalid_sender = types.Sender{ .member = 999 };
    try std.testing.expectError(
        AuthenticationError.InvalidSender,
        getSenderPublicKey(&state, invalid_sender)
    );
}