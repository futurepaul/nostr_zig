# Nostr Zig Development Guide

## High-Level Development Strategy

### 1. **Use and Improve mls_zig** 
### 🚨 **IMPORTANT: mls_zig IS OUR LIBRARY - WE WROTE IT, WE CAN MAKE IT BETTER!** 🚨
- The `mls_zig` library (located at `deps/mls_zig`) is **our code** - we have full control
- **When functionality is missing, ADD IT to mls_zig** - don't work around it
- **When APIs don't fit our needs, CHANGE THEM** - it's our library
- **When WASM compatibility is needed, BUILD IT IN** - don't create workarounds
- Examples of improvements we should make directly to mls_zig:
  - Missing serialization? Add `serialize()`/`deserialize()` methods
  - API doesn't work in WASM? Fix the API design
  - Need new functionality? Implement it properly in mls_zig
- Keep `mls_zig` as a clean, reusable MLS implementation that benefits everyone

### 2. **Pure Zig First, Test Early**
- Write core logic in pure Zig modules under `src/`
- Create comprehensive tests in `tests/` that run without WASM
- Ensure adherence to specifications (for NIP-EE, refer to `EE.md`)
- Debug and iterate quickly with native Zig tests before moving to WASM

### 3. **Follow Zig Best Practices**
- Use strongly typed structs for keys and cryptographic data instead of magic `[32]u8` arrays
- Create proper error types for domain-specific failures
- Use comptime for type-safe operations and generic functions
- Prefer explicit error handling over hidden failures
- Make invalid states unrepresentable through the type system

### 4. **Thin WASM Wrapper Pattern**
- Only after pure Zig tests pass, create thin wrappers in `src/wasm_exports.zig`
- WASM exports should be simple function calls to the pure Zig implementation
- Create corresponding tests in `wasm_tests/the_new_feature.ts` that mirror the pure Zig tests
- Avoid business logic in WASM exports - they should only handle memory management and type conversion
- Always use WASM-safe abstractions for time (`wasm_time.zig`) and randomness (`wasm_random.zig`)

### 🚨 **NEVER CREATE FAKE/DUMMY/SIMPLIFIED IMPLEMENTATIONS** 🚨
**This is a critical rule that must never be broken:**

- **NO PLACEHOLDERS**: Never create "dummy", "fake", "simplified", or "minimal" implementations
- **NO SHORTCUTS**: If real cryptography is hard to implement, STOP and ask for help - don't fake it
- **REAL CRYPTO ONLY**: Always use proper cryptographic implementations, never XOR, zeros, or fake data
- **NO STUBS**: Don't create stub functions that return fake data "for now"
- **PROPER RANDOM**: We have `wasm_random.zig` - use it for all randomness, never fake random data
- **PROPER TIME**: We have `wasm_time.zig` - use it for all timestamps, never fake time
- **FIND ROOT CAUSE**: If something doesn't work, debug the real issue, don't work around it with fakes

**Why this matters:**
- Fake implementations are extremely hard to find and remove later
- They create security vulnerabilities and false test results
- They violate the "real cryptography" principle fundamental to this project
- They make it impossible to trust the system's security properties

**What to do instead:**
- If you encounter POSIX issues, fix the abstraction layer (`wasm_random.zig`, `wasm_time.zig`)
- If MLS operations are complex, implement them properly using `mls_zig`
- If something is missing from `mls_zig`, contribute the real implementation there
- If you're stuck, ask for help - never fake your way around the problem

### 5. **Visualizer Last**
- Only update the visualizer after both pure Zig and WASM tests are passing
- This ensures the underlying implementation is solid before adding UI complexity
- The visualizer should be a thin client that calls tested WASM functions

### 6. **Migrate Logic from TypeScript to Zig**
- Over time, move cryptographic and protocol logic from TypeScript and `wasm_exports.zig` into pure Zig
- Use comptime generics to handle WASM-specific differences (buffer sizes, memory layout)
- This centralizes the logic and makes it easier to test and maintain

## Project Architecture

### Core Structure
```
src/
├── nip_ee.zig           # High-level NIP-EE operations
├── nip44/v2.zig         # NIP-44 encryption implementation
├── mls/*.zig            # MLS protocol logic using mls_zig
├── wasm_exports.zig     # Thin WASM wrappers
├── crypto.zig           # Cryptographic utilities
├── wasm_random.zig      # WASM-safe random number generation
├── wasm_time.zig        # WASM-safe timestamp abstraction
└── crypto/
    └── hkdf.zig         # Shared HKDF implementation

tests/                   # Pure Zig tests
wasm_tests/             # WASM-specific tests
../mls_zig/             # MLS protocol library (separate repo)
```

### Key Principles
- **Clean separation**: Pure Zig logic → WASM wrappers → UI
- **Type safety**: Strongly typed keys and data structures
- **Testability**: Every feature tested in pure Zig first
- **Reusability**: Logic usable in both native and WASM contexts

## Development Workflow

### For New Features
1. **Design**: Create types and interfaces in pure Zig
2. **Implement**: Write the core logic using existing libraries
3. **Test**: Create comprehensive tests in `tests/`
4. **Wrap**: Add thin WASM exports in `wasm_exports.zig`
5. **Verify**: Test WASM functionality with `wasm_tests/`
6. **Integrate**: Update visualizer to use new functionality

### For Bug Fixes
1. **Reproduce**: Write a failing test in pure Zig
2. **Fix**: Implement the fix in the pure Zig module
3. **Verify**: Ensure all tests pass
4. **Propagate**: WASM wrappers should automatically work

## Nostr Event Structure

A Nostr event contains these fields:
- `id`: 32-byte hex-encoded SHA256 hash of the serialized event
- `pubkey`: 32-byte hex-encoded public key of the event creator
- `created_at`: Unix timestamp in seconds
- `kind`: Integer (0-65535) indicating event type
- `tags`: Array of tag arrays (string arrays)
- `content`: Arbitrary string content
- `sig`: 64-byte hex-encoded BIP340 signature

## Event Kinds

### Basic Kinds
- **Kind 0**: Metadata (user profiles) - replaceable
- **Kind 1**: Text notes (posts)
- **Kind 3**: Contact lists (following) - replaceable
- **Kind 4**: Encrypted direct messages
- **Kind 5**: Event deletion requests
- **Kind 7**: Reactions (likes, etc.)

### NIP-EE Kinds
- **Kind 443**: KeyPackage events for group discovery
- **Kind 444**: Welcome events for new members (NIP-59 gift-wrapped)
- **Kind 445**: Group events with NIP-44 encrypted MLS messages

### Kind Ranges
- 0-999: Core protocol events
- 1,000-9,999: Regular events
- 10,000-19,999: Replaceable events
- 20,000-29,999: Ephemeral events
- 30,000-39,999: Addressable events

## Cryptographic Requirements

### Current Implementation
- **BIP340 Schnorr**: Using bitcoin-core/secp256k1 library
- **SHA256**: Using `std.crypto.hash.sha2.Sha256`
- **NIP-44 v2**: ChaCha20-Poly1305 with HKDF key derivation
- **MLS Protocol**: Using `mls_zig` for all MLS operations

### Best Practices
- Always verify private keys with `secp256k1_ec_seckey_verify`
- Use `secp256k1_keypair_create` for Schnorr operations
- Handle all error cases from secp256k1 functions explicitly
- Use strongly typed wrappers for keys instead of raw byte arrays

## Testing Strategy

The project has a comprehensive test suite organized into several categories:

### 🏗️ Build Commands for Testing

**Quick Reference:**
```bash
# Run all working tests (recommended for regular development)
zig build test-all

# Run specific test suites  
zig build test-events        # Core Nostr event functionality
zig build test-nip-ee-real   # NIP-EE MLS protocol tests
zig build test               # Basic library tests

# Run single test file (edit test-utils/run_single_test.zig first)
zig build test-single

# List all available test commands
zig build --help | grep test
```

### 📁 Test Organization

```
tests/                          # Pure Zig integration tests
├── test_events.zig            # ✅ Core Nostr events + publish/subscribe
├── test_nip_ee_real.zig       # ✅ NIP-EE protocol implementation  
├── test_welcome_events.zig    # ✅ MLS welcome message handling
└── test_mls_state_machine.zig # ⚠️ MLS state management (disabled)

wasm_tests/                     # TypeScript tests for WASM functionality
├── test_state_machine.ts      # Main WASM integration tests
├── test_crypto_functions.ts   # Cryptographic operations
└── [various other test files] # Specific feature tests

test-utils/                     # Test utilities and helpers  
├── run_single_test.zig        # Single test runner
├── run_test.sh               # Helper script
└── [development test files]   # Temporary test files

test_runner.zig                # Master test file (imports all tests)
```

### ✅ Core Test Suites

#### `test-events` - Event Creation and Publishing
**What it tests:**
- Event creation with proper ID calculation and signing
- BIP340 Schnorr signature generation and verification
- JSON serialization/deserialization round-trips
- Tag handling and validation
- **NEW: Publish-subscribe roundtrip testing**
  - Publishes events to relay via WebSocket
  - Sets up subscriptions to query for specific events
  - Validates received events match published data
  - Tests complete relay integration workflow

**Example Output:**
```
✅ Event created successfully
✅ Event signature verified successfully  
✅ All validations passed!
```

#### `test-nip-ee-real` - NIP-EE Protocol
**What it tests:**
- MLS KeyPackage generation and parsing
- Group creation and member management
- Welcome event handling with NIP-59 gift wrapping
- NIP-44 encryption integration
- Real cryptographic operations (no placeholders)

#### `test-welcome-events` - MLS Welcome Messages
**What it tests:**
- Welcome message creation and processing
- Ephemeral key generation for privacy
- HPKE encryption/decryption operations
- Group state initialization from welcome

### 🌐 WASM Tests (`wasm_tests/`)
- TypeScript integration tests for browser functionality
- WASM-specific memory management verification
- Cross-platform compatibility testing
- Performance benchmarks

### 🔧 Test Configuration

#### Master Test Runner (`test_runner.zig`)
```zig
test {
    // Core Nostr functionality tests
    _ = @import("tests/test_events.zig");
    
    // MLS/NIP-EE protocol tests  
    _ = @import("tests/test_nip_ee_real.zig");
    _ = @import("tests/test_welcome_events.zig");
    // _ = @import("tests/test_mls_state_machine.zig"); // Disabled: compilation errors
}
```

#### Single Test Runner (`test-utils/run_single_test.zig`)
Edit this file to test individual test files:
```zig
test {
    _ = @import("tests/test_events.zig"); // Change this line
}
```

### 🚨 Relay Testing Requirements

**For publish-subscribe tests:**
1. Start a test relay: `nak serve --verbose`
2. Relay runs on `ws://localhost:10547`
3. Tests will skip gracefully if relay is unavailable

**Test Features:**
- ✅ Publishes real Nostr events to relay
- ✅ Sets up REQ subscriptions with filters  
- ✅ Validates event round-trip integrity
- ✅ Proper NIP-01 message format compliance
- ✅ Timeout handling (5 second max wait)
- ✅ Graceful failure if relay unavailable

### 🐛 Debugging Failed Tests

#### Common Issues:
```bash
# Module resolution error (no module 'nostr' available)
# → Always use `zig build test-*` commands, never `zig test` directly

# Connection refused to relay
# → Start relay with: nak serve --verbose

# Compilation errors in MLS tests  
# → Some MLS tests disabled due to type system changes
```

#### Getting More Information:
```bash
# Verbose output
zig build test-events --verbose

# Show all compilation errors
zig build test-all --summary all

# Run tests with more detailed failure info
zig build test-all --summary failures
```

### 📊 Test Coverage Areas

#### ✅ Working & Comprehensive
- **Event Creation**: ID calculation, signing, verification
- **JSON Handling**: Serialization, parsing, validation  
- **Relay Integration**: WebSocket publish/subscribe
- **Cryptography**: BIP340 Schnorr, secp256k1 operations
- **NIP-EE Core**: KeyPackages, Welcome events
- **Performance**: Event creation benchmarks (~1.8ms/event)

#### ⚠️ Partial Coverage  
- **MLS State Machine**: Type system issues with some tests
- **WASM Integration**: Some functions need debugging
- **Error Recovery**: Limited edge case coverage

#### ❌ Missing Coverage
- **Multi-relay Publishing**: Not yet implemented
- **Large Group Support**: >150 members not tested
- **Multi-device Scenarios**: Single client testing only

### 💡 Adding New Tests

1. **Create test file** in `tests/` directory:
```zig
const std = @import("std");
const testing = std.testing;
const nostr = @import("nostr"); // Uses build system modules

test "My new feature" {
    const allocator = testing.allocator;
    // Test implementation...
    try testing.expect(result == expected);
}
```

2. **Add to test_runner.zig**:
```zig
test {
    _ = @import("tests/my_new_test.zig");
}
```

3. **Optional: Add dedicated build step**:
Edit `build.zig` to add `zig build test-my-feature` command.

### 🎯 Test Guidelines

- **Real Cryptography Only**: No fake/placeholder implementations
- **Integration Focus**: Test complete workflows, not just units
- **Error Path Coverage**: Test both success and failure cases  
- **Relay Compatibility**: Use real relay for integration tests
- **Performance Awareness**: Monitor test execution time
- **Documentation**: Document test purpose and expected behavior

## Zig Idioms and Best Practices

### Type Safety
```zig
// Good: Strongly typed
pub const PrivateKey = struct {
    bytes: [32]u8,
    
    pub fn generate() !PrivateKey {
        // ...
    }
};

// Bad: Magic byte arrays
fn processKey(key: [32]u8) void {
    // What kind of key is this?
}
```

### Error Handling
```zig
// Good: Specific error types
const CryptoError = error{
    InvalidPrivateKey,
    InvalidPublicKey,
    SignatureFailed,
};

// Bad: Generic errors
const GenericError = error{
    Failed,
};
```

### Memory Management
```zig
// Good: Explicit allocator parameter
pub fn encrypt(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    // Caller controls memory
}

// Bad: Hidden allocation
pub fn encrypt(data: []const u8) ![]u8 {
    // Where does this memory come from?
}
```

### Tag Allocation Best Practices
```zig
// Good: Use TagBuilder for safe tag allocation
var builder = nostr.TagBuilder.init(allocator);
defer builder.deinit();

try builder.addEventTag("event_id");
try builder.addPubkeyTag("pubkey");
try builder.addRelayTag("wss://relay.example.com");

const tags = try builder.build();
defer allocator.free(tags);

// Bad: Manual tag allocation (error-prone)
const tag = try allocator.alloc([]const u8, 2);
tag[0] = try allocator.dupe(u8, "e");
tag[1] = try allocator.dupe(u8, "event_id");
// Easy to forget cleanup, leak memory
```

### Arena Allocator Pattern
```zig
// Good: Use arena for temporary allocations
var arena = std.heap.ArenaAllocator.init(allocator);
defer arena.deinit();
const arena_alloc = arena.allocator();

// All allocations in this scope use arena
const temp_data = try arena_alloc.alloc(u8, 1024);
const temp_string = try arena_alloc.dupe(u8, "temporary");
// No need to free individually - arena.deinit() handles all

// Bad: Many small allocations without grouping
const data1 = try allocator.alloc(u8, 100);
defer allocator.free(data1);
const data2 = try allocator.alloc(u8, 200);
defer allocator.free(data2);
// Error-prone, easy to miss a defer
```

### Deep Copy When Storing
```zig
// Good: Deep copy when storing in long-lived structures
pub fn cacheEvent(self: *Cache, event: Event) !void {
    const event_copy = try event.deepCopy(self.allocator);
    try self.events.put(event.id, event_copy);
}

// Bad: Store reference that may be freed
pub fn cacheEvent(self: *Cache, event: Event) !void {
    try self.events.put(event.id, event); // Dangerous!
}
```

### Comptime for Generics
```zig
// Handle WASM vs native differences
fn processBuffer(comptime is_wasm: bool, buffer: []u8) void {
    if (is_wasm) {
        // WASM-specific handling
    } else {
        // Native handling
    }
}
```

### WASM-Safe Abstractions
```zig
// Good: Abstract POSIX dependencies
const wasm_time = @import("wasm_time.zig");
const now = wasm_time.timestamp(); // Works in both native and WASM

// Bad: Direct POSIX usage
const now = std.time.timestamp(); // Fails in WASM

// Good: WASM-safe randomness
const wasm_random = @import("wasm_random.zig");
wasm_random.secure_random.bytes(&buffer);

// Bad: std crypto random
std.crypto.random.bytes(&buffer); // Fails in WASM
```

## File Structure

```
src/
├── main.zig           # CLI entry point
├── root.zig           # Library exports
├── nip_ee.zig         # NIP-EE high-level operations
├── crypto.zig         # Cryptographic utilities
├── wasm_exports.zig   # WASM wrapper functions
├── nostr/
│   └── event.zig      # Event structure and parsing
├── nip44/             # NIP-44 encrypted messages
│   ├── v2.zig         # Main NIP-44 implementation
│   └── mod.zig        # Module exports
├── mls/               # MLS/NIP-EE group messaging
│   ├── types.zig      # Core MLS types
│   ├── provider.zig   # MLS crypto provider interface
│   ├── mls_messages.zig # MLS message handling
│   ├── ephemeral.zig  # Ephemeral key generation
│   └── key_packages.zig # KeyPackage management
└── secp256k1/         # Custom secp256k1 wrapper
    ├── secp256k1.zig  # Zig bindings
    └── callbacks.c    # External callback implementations

tests/                 # Pure Zig tests
├── test_nip_ee.zig    # NIP-EE functionality tests
├── test_nip44_raw.zig # NIP-44 encryption tests
└── test_crypto.zig    # Cryptographic operation tests

wasm_tests/            # WASM-specific tests
├── test_send_message.ts
├── test_nip44_raw.ts
└── test_mls_simple.ts

../mls_zig/            # MLS protocol library (separate repo)
```

## Common Pitfalls to Avoid

### Architecture
- Don't duplicate logic between WASM exports and pure Zig
- Don't put business logic in TypeScript or WASM wrappers
- Don't create magic byte arrays without type safety
- Don't skip pure Zig tests when adding WASM functionality

### Memory Management
- Don't shallow copy when you need ownership (leads to double-free)
- Don't store references to data that might be freed (use-after-free)
- Don't manually allocate tags - use TagBuilder
- Don't forget errdefer for cleanup on error paths
- Don't mix allocators - be consistent about which allocator owns what

### Cryptography
- Don't use default secp256k1 ECDH (applies SHA256)
- Don't ignore secp256k1 function return values
- Don't use ECDSA functions for Schnorr signatures
- Don't forget to validate private keys before use
- Don't duplicate HKDF/HMAC implementations - use shared modules

### Memory Ownership Patterns

#### When to Deep Copy
- Storing data in caches or long-lived structures
- Crossing module boundaries where lifetime is unclear
- When the original might be freed before you're done

#### When to Use Arena Allocators
- Temporary operations within a function
- Building complex structures that will be used together
- Test setup/teardown
- MLS operations that create many temporary objects

#### TagBuilder Usage
```zig
// Always prefer TagBuilder for tag creation
var builder = nostr.TagBuilder.init(allocator);
defer builder.deinit();

// Use type-safe methods
try builder.addEventTag(event_id);
try builder.addPubkeyTag(pubkey);

// For custom tags
try builder.add(&.{ "custom", "value1", "value2" });

const tags = try builder.build();
```

### Testing
- Don't rely only on WASM tests for correctness
- Don't skip error path testing
- Don't use fake or placeholder cryptography in tests
- Don't forget to test complete round-trips

### WASM/POSIX Compatibility
- Don't use `std.debug.print` in WASM-compiled code (causes POSIX errors)
- Don't use `std.time.timestamp()` directly - abstract it for WASM
- Don't use `std.crypto.random` - use `wasm_random` module instead
- Don't use `std.Random` PRNG - it depends on POSIX functionality

## Migration Strategy

### Moving Logic from TypeScript to Zig
1. Identify TypeScript functions that contain business logic
2. Create equivalent pure Zig functions with proper types
3. Add comprehensive tests for the Zig implementation
4. Create thin WASM wrappers that call the Zig functions
5. Update TypeScript to use the WASM functions
6. Remove the original TypeScript implementation

### Example Migration
```typescript
// Before: Logic in TypeScript
function processMessage(message: string): string {
    // Complex processing logic
}

// After: Thin wrapper
function processMessage(message: string): string {
    return wasmModule.process_message(message);
}
```

```zig
// New: Logic in Zig
pub fn processMessage(allocator: std.mem.Allocator, message: []const u8) ![]u8 {
    // Complex processing logic with proper error handling
}

// WASM wrapper
export fn wasm_process_message(message: [*]const u8, len: u32, out: [*]u8, out_len: *u32) bool {
    const result = processMessage(allocator, message[0..len]) catch return false;
    // Handle result...
}
```

This approach ensures that the core logic is testable, reusable, and maintainable while keeping the WASM interface simple and reliable.