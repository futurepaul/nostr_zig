# Simple Test Guide for Nostr Zig

## Running Tests - Two Commands, That's It!

### Run library unit tests only:
```bash
zig build test
```

### Run ALL tests (unit + integration):
```bash
zig build test-all
```

That's it. No confusion. No guessing.

## Writing Tests

### Simple test file:
```zig
const std = @import("std");
const testing = std.testing;
const nostr = @import("nostr");  // This works because build.zig sets it up

test "my feature works" {
    const result = nostr.someFunction();
    try testing.expect(result == expected);
}
```

### Key points:
1. Import "nostr" not "../src/root.zig" 
2. Use std.testing utilities
3. Tests run with `zig build test` automatically if referenced in root.zig

## Adding a New Test File

1. Create `tests/test_my_feature.zig`
2. Add to `test_all.zig`:
   ```zig
   test {
       // ... existing imports ...
       _ = @import("tests/test_my_feature.zig");
   }
   ```
3. Run with `zig build test-all`

## Running Individual Test Files

Need to run just one test file for debugging?

```bash
# Create a temporary test runner
echo 'test { _ = @import("tests/test_welcome_roundtrip.zig"); }' > test_one.zig

# Run it
zig build-exe test_one.zig \
    --test \
    -I deps/secp256k1/include \
    -L .zig-cache/o/*/  \
    -lsecp256k1 -lbech32 -lc \
    --dep nostr -Mnostr=src/root.zig \
    --dep mls_zig -Mmls_zig=deps/mls_zig/src/root.zig
./test_one

# Clean up
rm test_one test_one.zig
```

## That's it!

Two simple commands:
- `zig build test` - library tests only
- `zig build test-all` - everything
- Individual files - use the snippet above

No magic. No guessing. It just works.