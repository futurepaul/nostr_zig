//! Nostr Zig library for encoding and decoding Nostr events
const std = @import("std");
const testing = std.testing;

// Export the nostr module
pub const nostr = @import("nostr/event.zig");

// Export main types for convenience
pub const Event = nostr.Event;
pub const Kind = nostr.Kind;

test {
    // Reference all tests
    std.testing.refAllDecls(@This());
    _ = @import("nostr/event.zig");
}
