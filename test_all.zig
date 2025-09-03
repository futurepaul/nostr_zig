// Single entry point for all tests
const std = @import("std");
const nostr = @import("nostr");

test {
    // Import all test files
    _ = @import("tests/test_events.zig");
    _ = @import("tests/test_nip_ee_real.zig");
    _ = @import("tests/test_welcome_events.zig");
    _ = @import("tests/test_welcome_roundtrip.zig");
    _ = @import("tests/test_key_schedule.zig");
    _ = @import("tests/test_keypackage_vectors.zig");
    _ = @import("tests/test_mls_roundtrip.zig");
    _ = @import("tests/test_public_key_derivation.zig");
    _ = @import("tests/test_schnorr_verify.zig");
    
    // Also trigger internal library tests
    std.testing.refAllDecls(nostr);
}