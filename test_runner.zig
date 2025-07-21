const std = @import("std");

// Main test runner that imports all test files
// This allows running all tests with: zig build test-all
test {
    // Core Nostr functionality tests
    _ = @import("tests/test_events.zig");
    
    // MLS/NIP-EE protocol tests  
    _ = @import("tests/test_nip_ee_real.zig");
    _ = @import("tests/test_welcome_events.zig"); // Re-enabled after fixing comment block syntax
    _ = @import("tests/test_mls_state_machine.zig"); // Re-enabling to fix type system issues
    
    // Add new test files here as they are created
    // Comment out tests that are failing or too slow for regular runs
}