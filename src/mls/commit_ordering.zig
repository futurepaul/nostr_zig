const std = @import("std");
const types = @import("types.zig");
const Event = @import("../nostr/event.zig").Event;

/// Commit ordering and race condition handling for MLS group events
/// Implements timestamp-based ordering with event ID tiebreakers as per NIP-EE specification

/// A pending commit that needs ordering
pub const PendingCommit = struct {
    /// The commit event ID
    event_id: [32]u8,
    /// Timestamp from the event
    created_at: i64,
    /// The group event content
    event: Event,
    /// The source epoch for the commit
    source_epoch: u64,
    /// Whether this commit has been acknowledged by relays
    relay_acknowledged: bool = false,
    /// The sender of the commit
    sender_pubkey: [32]u8,
    
    /// Compare two commits for ordering
    /// Returns true if self comes before other
    pub fn comesBefore(self: *const PendingCommit, other: *const PendingCommit) bool {
        // Primary ordering: timestamp (earlier first)
        if (self.created_at < other.created_at) {
            return true;
        } else if (self.created_at > other.created_at) {
            return false;
        }
        
        // Tiebreaker: event ID (lexicographically smaller first)
        return std.mem.lessThan(u8, &self.event_id, &other.event_id);
    }
};

/// State for handling commit ordering and race conditions
pub const CommitOrderingState = struct {
    allocator: std.mem.Allocator,
    
    /// Current epoch of the group
    current_epoch: u64,
    
    /// Pending commits waiting for ordering
    pending_commits: std.ArrayList(PendingCommit),
    
    /// Previous group state for fork recovery (opaque pointer)
    previous_state: ?*anyopaque,
    
    /// Timeout for waiting for relay acknowledgments (in seconds)
    relay_timeout: u64 = 30,
    
    /// Whether to wait for relay acknowledgment before applying commits
    require_relay_ack: bool = true,
    
    pub fn init(allocator: std.mem.Allocator, current_epoch: u64) CommitOrderingState {
        return .{
            .allocator = allocator,
            .current_epoch = current_epoch,
            .pending_commits = std.ArrayList(PendingCommit).init(allocator),
            .previous_state = null,
        };
    }
    
    pub fn deinit(self: *CommitOrderingState) void {
        self.pending_commits.deinit();
        // Note: previous_state is now managed externally
        self.previous_state = null;
    }
    
    /// Add a commit to the pending queue
    pub fn addPendingCommit(
        self: *CommitOrderingState,
        event_id: [32]u8,
        created_at: i64,
        event: Event,
        source_epoch: u64,
        sender_pubkey: [32]u8,
    ) !void {
        const commit = PendingCommit{
            .event_id = event_id,
            .created_at = created_at,
            .event = event,
            .source_epoch = source_epoch,
            .sender_pubkey = sender_pubkey,
        };
        
        try self.pending_commits.append(commit);
        
        // Sort pending commits to maintain order
        std.sort.insertion(PendingCommit, self.pending_commits.items, {}, comparePendingCommits);
    }
    
    /// Mark a commit as acknowledged by relays
    pub fn acknowledgeCommit(self: *CommitOrderingState, event_id: [32]u8) !bool {
        for (self.pending_commits.items) |*commit| {
            if (std.mem.eql(u8, &commit.event_id, &event_id)) {
                commit.relay_acknowledged = true;
                return true;
            }
        }
        return false;
    }
    
    /// Get the next commit that should be applied
    /// Returns null if no commits are ready (waiting for acknowledgment or ordering)
    pub fn getNextCommitToApply(self: *CommitOrderingState) ?PendingCommit {
        if (self.pending_commits.items.len == 0) {
            return null;
        }
        
        // Get the earliest commit (already sorted)
        const earliest = &self.pending_commits.items[0];
        
        // If we require relay acknowledgment, check if it's been acknowledged
        if (self.require_relay_ack and !earliest.relay_acknowledged) {
            return null;
        }
        
        // Check if enough time has passed for other commits to arrive
        const current_time = std.time.timestamp();
        const time_since_commit = current_time - earliest.created_at;
        
        // Wait a short time for potential race conditions to resolve
        // This gives other commits with similar timestamps a chance to arrive
        if (time_since_commit < 5) { // 5 second grace period
            return null;
        }
        
        return earliest.*;
    }
    
    /// Remove and return the next commit to apply
    pub fn popNextCommit(self: *CommitOrderingState) ?PendingCommit {
        if (self.getNextCommitToApply()) |_| {
            return self.pending_commits.orderedRemove(0);
        }
        return null;
    }
    
    /// Save current state for potential rollback
    pub fn saveCurrentState(self: *CommitOrderingState, current_state: *anyopaque) !void {
        // Store the state pointer for potential recovery
        // The actual state management is handled by the state machine
        self.previous_state = current_state;
    }
    
    /// Restore previous state in case of fork/conflict
    pub fn restorePreviousState(self: *CommitOrderingState) ?*anyopaque {
        if (self.previous_state) |prev_state| {
            self.previous_state = null;
            return prev_state;
        }
        return null;
    }
    
    /// Check for potential conflicts between commits
    pub fn hasConflicts(self: *CommitOrderingState) bool {
        if (self.pending_commits.items.len < 2) {
            return false;
        }
        
        // Look for commits from the same epoch with similar timestamps
        var i: usize = 0;
        while (i < self.pending_commits.items.len - 1) : (i += 1) {
            const current = &self.pending_commits.items[i];
            const next = &self.pending_commits.items[i + 1];
            
            // If commits are from same epoch and within 10 seconds of each other
            if (current.source_epoch == next.source_epoch and 
                @abs(current.created_at - next.created_at) <= 10) {
                return true;
            }
        }
        
        return false;
    }
    
    /// Get statistics about pending commits
    pub fn getStats(self: *const CommitOrderingState) CommitStats {
        var acknowledged: u32 = 0;
        var oldest_timestamp: i64 = std.math.maxInt(i64);
        var newest_timestamp: i64 = std.math.minInt(i64);
        
        for (self.pending_commits.items) |commit| {
            if (commit.relay_acknowledged) {
                acknowledged += 1;
            }
            if (commit.created_at < oldest_timestamp) {
                oldest_timestamp = commit.created_at;
            }
            if (commit.created_at > newest_timestamp) {
                newest_timestamp = commit.created_at;
            }
        }
        
        return CommitStats{
            .total_pending = @intCast(self.pending_commits.items.len),
            .acknowledged = acknowledged,
            .oldest_timestamp = if (self.pending_commits.items.len > 0) oldest_timestamp else 0,
            .newest_timestamp = if (self.pending_commits.items.len > 0) newest_timestamp else 0,
            .current_epoch = self.current_epoch,
        };
    }
    
    /// Remove commits that are too old (cleanup)
    pub fn cleanupOldCommits(self: *CommitOrderingState, max_age_seconds: u64) !u32 {
        const current_time = std.time.timestamp();
        var removed_count: u32 = 0;
        
        var i: usize = 0;
        while (i < self.pending_commits.items.len) {
            const commit = &self.pending_commits.items[i];
            const age = @as(u64, @intCast(current_time - commit.created_at));
            
            if (age > max_age_seconds) {
                _ = self.pending_commits.orderedRemove(i);
                removed_count += 1;
            } else {
                i += 1;
            }
        }
        
        return removed_count;
    }
};

/// Statistics about commit ordering state
pub const CommitStats = struct {
    total_pending: u32,
    acknowledged: u32,
    oldest_timestamp: i64,
    newest_timestamp: i64,
    current_epoch: u64,
};

/// Comparison function for sorting pending commits
fn comparePendingCommits(context: void, a: PendingCommit, b: PendingCommit) bool {
    _ = context;
    return a.comesBefore(&b);
}

/// Utility function to validate timestamp ordering
pub fn validateTimestampOrdering(commits: []const PendingCommit) bool {
    if (commits.len < 2) {
        return true;
    }
    
    for (commits[0..commits.len-1], commits[1..]) |current, next| {
        if (!current.comesBefore(&next)) {
            return false;
        }
    }
    
    return true;
}

/// Convert event ID from hex string to bytes
pub fn parseEventId(hex_str: []const u8) ![32]u8 {
    if (hex_str.len != 64) {
        return error.InvalidEventIdLength;
    }
    
    var event_id: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&event_id, hex_str);
    return event_id;
}

/// Convert public key from hex string to bytes
pub fn parsePublicKey(hex_str: []const u8) ![32]u8 {
    if (hex_str.len != 64) {
        return error.InvalidPublicKeyLength;
    }
    
    var pubkey: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pubkey, hex_str);
    return pubkey;
}

// Tests
test "commit ordering - timestamp precedence" {
    const allocator = std.testing.allocator;
    
    var ordering = CommitOrderingState.init(allocator, 0);
    defer ordering.deinit();
    
    // Create mock event
    const mock_event = Event{
        .id = "0000000000000000000000000000000000000000000000000000000000000000",
        .pubkey = "0000000000000000000000000000000000000000000000000000000000000000",
        .created_at = 0,
        .kind = 445,
        .tags = &.{},
        .content = "",
        .sig = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    };
    
    // Add commits with different timestamps
    try ordering.addPendingCommit(
        [_]u8{1} ** 32,    // event_id
        1000,              // created_at
        mock_event,
        0,                 // source_epoch
        [_]u8{0x11} ** 32, // sender_pubkey
    );
    
    try ordering.addPendingCommit(
        [_]u8{2} ** 32,    // event_id
        500,               // created_at (earlier)
        mock_event,
        0,                 // source_epoch
        [_]u8{0x22} ** 32, // sender_pubkey
    );
    
    // Earlier timestamp should come first
    const first = ordering.pending_commits.items[0];
    const second = ordering.pending_commits.items[1];
    
    try std.testing.expectEqual(@as(i64, 500), first.created_at);
    try std.testing.expectEqual(@as(i64, 1000), second.created_at);
}

test "commit ordering - event ID tiebreaker" {
    const allocator = std.testing.allocator;
    
    var ordering = CommitOrderingState.init(allocator, 0);
    defer ordering.deinit();
    
    // Create mock event
    const mock_event = Event{
        .id = "0000000000000000000000000000000000000000000000000000000000000000",
        .pubkey = "0000000000000000000000000000000000000000000000000000000000000000",
        .created_at = 0,
        .kind = 445,
        .tags = &.{},
        .content = "",
        .sig = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    };
    
    const same_timestamp: i64 = 1000;
    
    // Add commits with same timestamp but different event IDs
    try ordering.addPendingCommit(
        [_]u8{0xFF} ** 32, // event_id (larger)
        same_timestamp,
        mock_event,
        0,
        [_]u8{0x11} ** 32,
    );
    
    try ordering.addPendingCommit(
        [_]u8{0x01} ** 32, // event_id (smaller)
        same_timestamp,
        mock_event,
        0,
        [_]u8{0x22} ** 32,
    );
    
    // Smaller event ID should come first (lexicographic ordering)
    const first = ordering.pending_commits.items[0];
    const second = ordering.pending_commits.items[1];
    
    try std.testing.expectEqual([_]u8{0x01} ** 32, first.event_id);
    try std.testing.expectEqual([_]u8{0xFF} ** 32, second.event_id);
}

test "commit ordering - relay acknowledgment" {
    const allocator = std.testing.allocator;
    
    var ordering = CommitOrderingState.init(allocator, 0);
    defer ordering.deinit();
    
    // Create mock event
    const mock_event = Event{
        .id = "0000000000000000000000000000000000000000000000000000000000000000",
        .pubkey = "0000000000000000000000000000000000000000000000000000000000000000",
        .created_at = 0,
        .kind = 445,
        .tags = &.{},
        .content = "",
        .sig = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    };
    
    const event_id = [_]u8{1} ** 32;
    
    // Add a commit
    try ordering.addPendingCommit(
        event_id,
        1000,
        mock_event,
        0,
        [_]u8{0x11} ** 32,
    );
    
    // Should not be ready without acknowledgment
    try std.testing.expect(ordering.getNextCommitToApply() == null);
    
    // Acknowledge the commit
    const acknowledged = try ordering.acknowledgeCommit(event_id);
    try std.testing.expect(acknowledged);
    
    // Should still not be ready due to grace period (timestamp too recent)
    try std.testing.expect(ordering.getNextCommitToApply() == null);
    
    // Disable relay requirement for testing
    ordering.require_relay_ack = false;
    
    // Add an old commit
    try ordering.addPendingCommit(
        [_]u8{2} ** 32,
        100, // Very old timestamp
        mock_event,
        0,
        [_]u8{0x22} ** 32,
    );
    
    // Should be ready now (old enough and no relay requirement)
    try std.testing.expect(ordering.getNextCommitToApply() != null);
}

test "commit ordering - conflict detection" {
    const allocator = std.testing.allocator;
    
    var ordering = CommitOrderingState.init(allocator, 0);
    defer ordering.deinit();
    
    // Create mock event
    const mock_event = Event{
        .id = "0000000000000000000000000000000000000000000000000000000000000000",
        .pubkey = "0000000000000000000000000000000000000000000000000000000000000000",
        .created_at = 0,
        .kind = 445,
        .tags = &.{},
        .content = "",
        .sig = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    };
    
    // Add commits from same epoch with similar timestamps
    try ordering.addPendingCommit(
        [_]u8{1} ** 32,
        1000,
        mock_event,
        5, // same epoch
        [_]u8{0x11} ** 32,
    );
    
    try ordering.addPendingCommit(
        [_]u8{2} ** 32,
        1005, // within 10 seconds
        mock_event,
        5, // same epoch
        [_]u8{0x22} ** 32,
    );
    
    // Should detect conflict
    try std.testing.expect(ordering.hasConflicts());
    
    // Add commit from different epoch
    try ordering.addPendingCommit(
        [_]u8{3} ** 32,
        1003,
        mock_event,
        6, // different epoch
        [_]u8{0x33} ** 32,
    );
    
    // Should still detect conflict between first two
    try std.testing.expect(ordering.hasConflicts());
}

test "validate timestamp ordering" {
    const mock_event = Event{
        .id = "0000000000000000000000000000000000000000000000000000000000000000",
        .pubkey = "0000000000000000000000000000000000000000000000000000000000000000",
        .created_at = 0,
        .kind = 445,
        .tags = &.{},
        .content = "",
        .sig = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    };
    
    const commits = [_]PendingCommit{
        .{
            .event_id = [_]u8{1} ** 32,
            .created_at = 100,
            .event = mock_event,
            .source_epoch = 0,
            .sender_pubkey = [_]u8{0x11} ** 32,
        },
        .{
            .event_id = [_]u8{2} ** 32,
            .created_at = 200,
            .event = mock_event,
            .source_epoch = 0,
            .sender_pubkey = [_]u8{0x22} ** 32,
        },
        .{
            .event_id = [_]u8{3} ** 32,
            .created_at = 300,
            .event = mock_event,
            .source_epoch = 0,
            .sender_pubkey = [_]u8{0x33} ** 32,
        },
    };
    
    try std.testing.expect(validateTimestampOrdering(&commits));
    
    // Test invalid ordering
    const invalid_commits = [_]PendingCommit{
        .{
            .event_id = [_]u8{1} ** 32,
            .created_at = 300, // Out of order
            .event = mock_event,
            .source_epoch = 0,
            .sender_pubkey = [_]u8{0x11} ** 32,
        },
        .{
            .event_id = [_]u8{2} ** 32,
            .created_at = 200,
            .event = mock_event,
            .source_epoch = 0,
            .sender_pubkey = [_]u8{0x22} ** 32,
        },
    };
    
    try std.testing.expect(!validateTimestampOrdering(&invalid_commits));
}

test "parse event ID and public key" {
    const valid_event_id = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    const event_id = try parseEventId(valid_event_id);
    try std.testing.expectEqual(@as(u8, 0x12), event_id[0]);
    try std.testing.expectEqual(@as(u8, 0xef), event_id[31]);
    
    const valid_pubkey = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    const pubkey = try parsePublicKey(valid_pubkey);
    try std.testing.expectEqual(@as(u8, 0xde), pubkey[0]);
    try std.testing.expectEqual(@as(u8, 0xef), pubkey[31]);
    
    // Test invalid lengths
    try std.testing.expectError(error.InvalidEventIdLength, parseEventId("short"));
    try std.testing.expectError(error.InvalidPublicKeyLength, parsePublicKey("short"));
}