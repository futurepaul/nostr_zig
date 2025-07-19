#!/bin/bash

# Simple script to run a single test file
# Usage: ./run_test.sh tests/test_nip_ee_real.zig

if [ $# -eq 0 ]; then
    echo "Usage: $0 <test_file_path>"
    echo "Example: $0 tests/test_nip_ee_real.zig"
    exit 1
fi

TEST_FILE=$1

# Check if file exists
if [ ! -f "$TEST_FILE" ]; then
    echo "Error: Test file '$TEST_FILE' not found"
    exit 1
fi

# Create a temporary test runner that imports the specified file
cat > run_single_test.zig << EOF
const std = @import("std");

// This is a template for running single test files
// Usage: 
// 1. Edit this file to import the test file you want to run
// 2. Run: zig build test-single

// EDIT THIS LINE to change which test file to run
test {
    _ = @import("$TEST_FILE");
}
EOF

echo "Running test file: $TEST_FILE"
zig build test-single