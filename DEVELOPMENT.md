# Nostr Zig Development Guide

## High-Level Development Strategy

### 1. **Use and Improve mls_zig**
- Leverage the `mls_zig` library (located at `../mls_zig`) for all MLS protocol operations
- When functionality is missing, contribute improvements to `mls_zig` rather than duplicating logic
- Keep `mls_zig` as a clean, reusable MLS implementation that other projects can use

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

### Pure Zig Tests (`tests/`)
- Unit tests for each module
- Integration tests for complete flows
- Cryptographic test vectors
- Error handling verification

### WASM Tests (`wasm_tests/`)
- WASM-specific behavior testing
- Memory management verification
- Browser compatibility testing
- Performance benchmarks

### Guidelines
- Test both success and failure paths
- Use real-world test data when possible
- Verify cryptographic operations with known test vectors
- Test complete round-trips (encrypt → decrypt, serialize → deserialize)

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

### Cryptography
- Don't use default secp256k1 ECDH (applies SHA256)
- Don't ignore secp256k1 function return values
- Don't use ECDSA functions for Schnorr signatures
- Don't forget to validate private keys before use
- Don't duplicate HKDF/HMAC implementations - use shared modules

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