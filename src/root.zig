//! Nostr Zig library for encoding and decoding Nostr events
const std = @import("std");
const testing = std.testing;

// Export the nostr module
pub const nostr = @import("nostr.zig");
pub const client = @import("client.zig");
pub const crypto = @import("crypto.zig");
pub const bech32 = @import("bech32.zig");
pub const nip44 = @import("nip44/mod.zig");

// Export main types for convenience
pub const Event = nostr.Event;
pub const Kind = nostr.Kind;
pub const Client = client.Client;
pub const Filter = client.Filter;
pub const RelayMessage = client.RelayMessage;

test {
    // Reference all tests
    std.testing.refAllDecls(@This());
    _ = @import("nostr/event.zig");
    _ = @import("nip44/test_vectors.zig");
}
