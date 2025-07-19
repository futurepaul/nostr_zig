# Test Guide for nostr_zig

## Understanding the Test Structure

This project has test files in two locations:
- `src/` - Test files that are part of the source modules
- `tests/` - Standalone test files that test the library as a whole

## The Module Resolution Problem

When running `zig test` directly on a file, the test file doesn't have access to the modules configured in `build.zig`. This is why you get errors like:
```
error: no module named 'nostr' available within module test
```

This happens because:
1. The `zig test` command doesn't know about external dependencies (websocket, secp256k1, bech32, mls_zig)
2. It doesn't know where to find the "nostr" module that test files import
3. It doesn't have the necessary C libraries linked

## Solutions for Running Tests

### 1. Run Specific Test Steps (Recommended)

Individual test files already have build steps configured:
```bash
# Run the NIP-EE real test
zig build test-nip-ee-real

# Run all unit tests
zig build test

# Run roundtrip test
zig build test-roundtrip
```

### 2. Run All Tests in tests/ Directory

Use the new test runner that includes all test files:
```bash
zig build test-all
```

### 3. Run a Single Test File

#### Option A: Using the helper script (Easiest)
```bash
./run_test.sh tests/test_nip_ee_real.zig
./run_test.sh tests/test_mls_state_machine.zig
```

#### Option B: Manual method
1. Edit `run_single_test.zig` and change the import line to your test file:
```zig
test {
    _ = @import("tests/test_mls_state_machine.zig");
}
```

2. Run:
```bash
zig build test-single
```

### 4. Add a New Test File

To add a new test file:

1. Create your test file in `tests/` directory
2. Import it in `test_runner.zig`:
```zig
test {
    // Existing tests...
    _ = @import("tests/your_new_test.zig");
}
```

3. (Optional) Add a dedicated build step in `build.zig`:
```zig
const your_test = b.addTest(.{
    .root_source_file = b.path("tests/your_new_test.zig"),
    .target = target,
    .optimize = optimize,
});
your_test.root_module.addImport("websocket", websocket_mod);
your_test.root_module.addImport("secp256k1", secp256k1_mod);
your_test.root_module.addImport("bech32", bech32_mod);
your_test.root_module.addImport("mls_zig", mls_mod);
your_test.root_module.addImport("nostr", lib_mod);
// Add other dependencies as needed...

const run_your_test = b.addRunArtifact(your_test);
const your_test_step = b.step("test-your", "Run your test");
your_test_step.dependOn(&run_your_test.step);
```

## Why Direct `zig test` Doesn't Work

The `zig test` command doesn't know about the module dependencies configured in `build.zig`. When you use `@import("nostr")` in a test file, it needs to be told where to find that module.

The build system (`build.zig`) configures these module paths and dependencies, which is why tests must be run through `zig build` commands.

## Quick Reference

```bash
# List all available test commands
zig build --help | grep test

# Run all tests
zig build test-all

# Run specific test
zig build test-nip-ee-real
zig build test-roundtrip

# Run single test (after editing run_single_test.zig)
zig build test-single
```