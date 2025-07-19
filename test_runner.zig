const std = @import("std");

// Include test files
test {
    // Test files from tests/ directory
    _ = @import("tests/test_nip_ee_real.zig");
    _ = @import("tests/test_welcome_events.zig");
    _ = @import("tests/test_mls_state_machine.zig");
    
    // You can comment out tests you don't want to run
    // or add new test files here
}