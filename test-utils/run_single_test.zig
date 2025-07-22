const std = @import("std");

// This is a template for running single test files
// Usage: 
// 1. Edit this file to import the test file you want to run
// 2. Run: zig build test-single

// EDIT THIS LINE to change which test file to run
test {
    _ = @import("../tests/test_public_key_derivation.zig");
}
