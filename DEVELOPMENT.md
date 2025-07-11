# Nostr Zig Development Guide

## Project Overview

This project implements a Zig library for encoding and decoding Nostr events with proper validation, cryptographic operations, and JSON serialization. The goal is to create an idiomatic Zig implementation that can parse JSON Nostr events into strongly-typed structs and serialize them back to JSON.

## Key Features

- Parse and validate Nostr events from JSON
- Serialize Nostr events to JSON
- Support for basic event kinds (notes, profiles, reactions, etc.)
- **Production-grade BIP340 Schnorr signatures using bitcoin-core/secp256k1**
- Real cryptographic operations verified by live Nostr relays
- Future support for NIP-44 encrypted payloads
- TDD development approach with comprehensive tests

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

### Kind Ranges
- 0-999: Core protocol events
- 1,000-9,999: Regular events
- 10,000-19,999: Replaceable events
- 20,000-29,999: Ephemeral events
- 30,000-39,999: Addressable events

## Available Resources

### Documentation
- `docs/zig-0.14.1/`: Complete Zig language and standard library documentation
- `docs/zig-0.14.1/std/`: Standard library API reference

### Sample Code References

#### Rust Nostr Implementation (`samples/nostr/`)
- Gold standard reference implementation
- Event structures in `crates/nostr/`
- Comprehensive test coverage
- NIP implementations and examples

#### Zig Language Source (`samples/zig/`)
- Idiomatic Zig patterns and conventions
- Standard library implementations
- JSON handling examples in `lib/std/json.zig`
- Testing patterns throughout codebase

#### Existing Zig Nostr Relay (`samples/zig-nostr-relay/`)
- Basic Nostr event structure (may use outdated syntax)
- WebSocket handling patterns
- Event parsing and validation examples

## Development Approach

### Test-Driven Development
1. Find canonical Nostr event examples
2. Write failing tests for parsing these events
3. Implement minimal code to make tests pass
4. Refactor for idiomatic Zig patterns
5. Add validation and error handling
6. Repeat for serialization

### Zig Idioms to Follow
- Use `std.json.parseFromSlice` for JSON parsing
- Use `std.json.stringifyAlloc` for JSON serialization
- Prefer tagged unions over inheritance
- Use `std.testing` for comprehensive test coverage
- Follow Zig naming conventions (snake_case)
- Minimize allocations where possible
- Use comptime for type-safe operations

## Cryptographic Requirements

Zig's standard library provides:
- SHA256 hashing (`std.crypto.hash.sha2.Sha256`) ✅
- Secp256k1 curve operations (`std.crypto.pcurves.secp256k1`) ✅
- ECDSA signatures (`std.crypto.ecdsa.EcdsaSecp256k1Sha256`) ✅
- Random number generation for key generation ✅

**✅ COMPLETED: BIP340 Schnorr Integration**
- Added bitcoin-core/secp256k1 as git submodule (deps/secp256k1/)
- Created custom secp256k1 wrapper (src/secp256k1/secp256k1.zig)
- Configured with all required modules (EXTRAKEYS, SCHNORRSIG, ECDH, RECOVERY)
- Implemented production-grade signing and verification
- Verified working with real Nostr relays

## Future Extensions

- NIP-44 encrypted message support
- Event relay client/server functionality
- WebSocket handling for real-time events
- Database integration for event storage
- Performance optimizations for high-throughput scenarios

## File Structure

```
src/
├── main.zig           # CLI entry point
├── root.zig           # Library exports
├── nostr.zig          # Core Nostr types
├── crypto.zig         # BIP340 cryptographic operations
├── client.zig         # WebSocket relay client
├── bech32.zig         # NIP-19 bech32 encoding/decoding
├── nostr/
│   └── event.zig      # Event structure and parsing
├── nip44/             # NIP-44 encrypted messages
│   ├── hkdf.zig       # HKDF key derivation
│   ├── padding.zig    # Message padding algorithm
│   ├── test_vectors.zig # Test vector runner
│   └── v2.zig         # Main NIP-44 implementation
├── mls/               # MLS/NIP-EE group messaging
│   ├── types.zig      # Core MLS types
│   ├── provider.zig   # MLS crypto provider interface
│   ├── operations.zig # MLS operations
│   ├── events.zig     # NIP-EE event types
│   ├── group.zig      # Group management
│   ├── messages.zig   # Message handling
│   ├── members.zig    # Member management
│   ├── wire.zig       # Wire format serialization
│   └── tests.zig      # MLS tests
├── secp256k1/         # Custom secp256k1 wrapper
│   ├── secp256k1.zig  # Zig bindings for bitcoin-core/secp256k1
│   ├── callbacks.c    # External callback implementations
│   └── libsecp256k1-config.h  # Build configuration
├── test_events.zig    # Test event fixtures
└── test_roundtrip.zig # Integration tests

deps/
├── secp256k1/         # bitcoin-core/secp256k1 git submodule
└── bech32/            # sipa/bech32 reference implementation

debug_scripts/         # Debug and test utilities (not for production)
├── debug_*.zig       # Various debugging tools
├── test_*.zig        # Standalone test scripts
└── verify_*.zig      # Verification utilities
```

## Testing Strategy

- Unit tests for each event kind
- JSON round-trip tests (parse → serialize → parse)
- Signature verification tests
- Error handling tests for malformed events
- Performance benchmarks for large event sets

## Lessons Learned and Patterns

### Zig JSON Handling
- Use `std.json.parseFromSlice` with `json.Value` for flexible parsing
- Always check union types before accessing (e.g., `if (value != .string) return error`)
- Remember to `defer parsed.deinit()` after parsing
- Use separate structs for JSON serialization when field names/types differ

### Error Handling Best Practices
- Define custom error sets for domain-specific errors
- Return errors early with descriptive types (not generic errors)
- Validate all fields during parsing, not just during later use
- Provide clear error messages to help users debug issues

### Memory Management
- Use arena allocators for operations that allocate many small objects
- Always `defer deinit()` or `defer free()` immediately after allocation
- Design APIs that let callers manage memory (pass allocator as parameter)
- Avoid hidden allocations - make them explicit in function signatures

### Testing in Zig
- Put tests in the same file as the implementation for better cohesion
- Use `test {}` block in root.zig to reference all test files
- Use real-world test data (actual Nostr events) for realistic testing
- Test both success and failure paths explicitly

### CLI Design
- Read all stdin at once for simple JSON parsing (with size limits)
- Use buffered writers for better output performance
- Always flush buffered output before program exit
- Format all print statements with explicit arguments (even empty `{}`)

### Project Structure
- `src/root.zig` exports the library's public API
- `src/main.zig` contains the CLI executable entry point
- Keep related functionality together (event.zig contains Event + tests)
- Use `pub const` to export types and functions from modules

### Zig Idioms Applied
- Prefer explicit error handling over exceptions or panics
- Use tagged unions (enums) for type-safe kind handling
- Make invalid states unrepresentable (Kind enum with integer backing)
- Use comptime where possible (will add for crypto operations)
- Keep allocations visible and controllable by the caller

## WebSocket Client Development

### Dependency Management
- Use `zig fetch --save <url>` to add dependencies to build.zig.zon
- Dependencies are added to the `.dependencies` field in build.zig.zon
- In build.zig, use `b.dependency()` to fetch the dependency module
- Add imports to modules with `module.addImport("name", dep_module)`

### WebSocket Connection Issues
- The websocket.zig library requires a Host header in the handshake
- Parse WebSocket URLs carefully - Uri.Component is a union type
- Handle both ws:// (port 80) and wss:// (port 443) default ports
- Always check if path is empty and default to "/" for WebSocket handshake

### Client Architecture Patterns
- Store WebSocket client as optional (`?websocket.Client`)
- Use HashMaps for managing subscriptions and callbacks
- Process messages in a loop with error handling for WouldBlock
- Remember to call `client.done(msg)` after processing each message
- Close and deinit the WebSocket client on disconnect

### Event Publishing Flow
1. Serialize event to JSON
2. Wrap in ["EVENT", <event>] array
3. Send as text frame via WebSocket
4. Store callback in HashMap keyed by event ID
5. Process OK response and invoke callback

### Subscription Management
1. Generate unique subscription ID
2. Create REQ message: ["REQ", <sub_id>, <filter1>, ...]
3. Store subscription with optional callback
4. Process EVENT and EOSE messages for the subscription
5. Send CLOSE message when unsubscribing

### Testing WebSocket Applications
- Use `nak serve --verbose` for a local test relay
- Test with curl to verify WebSocket upgrade works
- Add debug logging to track message flow
- Create both unit tests and integration tests
- Use threads for testing concurrent publish/subscribe

### Common WebSocket Pitfalls
- Not including required headers (especially Host)
- Forgetting to handle WouldBlock errors in read loops
- Not properly closing WebSocket connections
- Memory leaks from not calling deinit on client
- Race conditions in multi-threaded tests

### Nostr-Specific Lessons
- Event IDs are SHA256 of canonical JSON: [0, pubkey, created_at, kind, tags, content]
- Relay responses include: EVENT, OK, EOSE, NOTICE, AUTH, COUNT
- Filters support: ids, authors, kinds, since, until, limit, and tag filters
- Always escape content when calculating event ID (quotes, newlines, etc.)
- Relays validate BIP340 signatures - only real signatures are accepted

## NIP-44 Implementation

### Development Approach
When implementing NIP-44 cryptographic operations, use the reference implementations in `samples/nip44/` to understand the spec and debug issues. Multiple implementations are available, each with different strengths.

### Reference Implementations

#### Go Implementation (`samples/nip44/go/`)
- **Strengths**: Very readable, clear structure, good for understanding the flow
- **Key files**:
  - `nip44.go` - Main implementation with clear function names
  - `nip44_test.go` - Comprehensive test cases
- **Key insights**:
  - Public keys are always prefixed with "02" for even y-coordinate
  - Uses `secp256k1.ParsePubKey()` for public key parsing
  - ECDH uses `secp256k1.GenerateSharedSecret()` followed by HKDF

#### Rust Implementation (`samples/nip44/rust/`)
- **Strengths**: Type-safe, shows proper error handling patterns
- **Key files**:
  - `src/lib.rs` - Core implementation
  - `src/tests.rs` - Test suite
- **Key insights**:
  - Uses `PublicKey::from_x_only_public_key(x_only_public_key_b, Parity::Even)`
  - ECDH returns raw x-coordinate: `ssp.resize(32, 0); // toss the Y part`
  - Clear separation of concerns with `get_shared_point()` and `get_conversation_key()`

#### C Implementation (`samples/nip44/c/`)
- **Strengths**: Most detailed, shows low-level operations, canonical reference
- **Key files**:
  - `src/noscrypt.c` - Core NIP-44 encryption/decryption
  - `src/crypto/nc-crypto.c` - Cryptographic primitives
  - `src/hkdf.c` - HKDF key derivation
- **Key insights**:
  - Custom ECDH callback `_edhHashFuncInternal` returns x-coordinate only
  - No hashing in ECDH - just copies 32-byte x-coordinate
  - Detailed comments explain NIP-44 spec requirements

### Test Vectors
- **Location**: `samples/nip44/nip44.vectors.json`
- **Alternative**: Use paulmillr's test vectors from `https://github.com/paulmillr/nip44`
- **Structure**:
  - `conversation_key` - Tests for ECDH shared secret generation
  - `get_message_keys` - Tests for HKDF key derivation
  - `calc_padded_len` - Tests for padding algorithm
  - `encrypt_decrypt` - End-to-end encryption/decryption tests
- **Usage**: Parse JSON and run each test case to verify implementation

### Common Implementation Pitfalls

1. **ECDH Hash Function**:
   - Default `secp256k1_ecdh` applies SHA256 to shared point
   - NIP-44 requires raw x-coordinate (no hashing)
   - Must provide custom callback function

2. **X-Only Public Keys**:
   - Always use even y-coordinate (0x02) when converting to compressed
   - This is a Nostr/NIP-44 convention, not a secp256k1 requirement

3. **HKDF Parameters**:
   - Extract: `HKDF-Extract(salt="nip44-v2", ikm=shared_secret)`
   - Expand: `HKDF-Expand(conversation_key, nonce, 76_bytes)`
   - Order matters: output buffer, info (nonce), PRK (conversation key)

4. **Padding Algorithm**:
   - Not simple power-of-2 padding
   - Has specific rules for different size ranges
   - Check Rust implementation for exact algorithm

5. **HMAC Calculation**:
   - Must include correct data in correct order
   - Check reference implementations for exact HMAC input structure

### Debugging Strategy

1. **Start with Known Good Tests**:
   - Test conversation key generation with vectors from `conversation_key` section
   - Verify your ECDH produces expected shared secrets

2. **Isolate Components**:
   - Test HKDF separately with `get_message_keys` vectors
   - Test padding with `calc_padded_len` vectors
   - Only then test full encrypt/decrypt

3. **Compare Implementations**:
   - When stuck, implement same test in Go/Rust to compare
   - Use debug output to see intermediate values
   - Cross-reference multiple implementations

4. **Use Reference Test Runners**:
   - Run `go test` in `samples/nip44/go/`
   - Run `cargo test` in `samples/nip44/rust/`
   - See how they handle edge cases

## Bitcoin-core/secp256k1 Integration

### Custom Wrapper Development
- Created dedicated wrapper in `src/secp256k1/` for Zig bindings
- Used git submodule approach for bitcoin-core/secp256k1 (most reliable)
- Avoided third-party wrappers to ensure full module support
- Built static library with all required modules enabled

### Required secp256k1 Modules
- `ENABLE_MODULE_EXTRAKEYS` - Essential for x-only public keys (Nostr format)
- `ENABLE_MODULE_SCHNORRSIG` - Required for BIP340 Schnorr signatures
- `ENABLE_MODULE_ECDH` and `ENABLE_MODULE_RECOVERY` - Additional functionality
- Static precomputation tables for performance

### Build System Integration
- Added secp256k1 compilation to build.zig with proper C flags
- Created external callback functions (callbacks.c) for error handling
- Configured proper include paths and library linking
- Used `@cImport` for C header integration in Zig

### Cryptographic Implementation Best Practices
- Always verify private keys with `secp256k1_ec_seckey_verify`
- Use `secp256k1_keypair_create` for Schnorr operations (not ECDSA functions)
- Extract x-only public keys with `secp256k1_keypair_xonly_pub` 
- Convert hex event IDs to bytes before signing/verification
- Handle all error cases from secp256k1 functions explicitly

### Testing and Integration Verification
- Test signature generation produces non-zero, unique signatures
- Verify signatures locally before sending to relays
- Test complete roundtrip: generate → sign → publish → relay validation
- Use `zig build` approach for integration tests (better than `zig test`)
- Always test with real relay (`nak serve --verbose`) for validation

### Common Pitfalls Avoided
- Don't use Syndica/secp256k1-zig (incomplete module support)
- Don't rely on Zig's standard library crypto (no Schnorr support)
- Don't use ECDSA functions for Schnorr signatures
- Don't forget to link the static library and include paths
- Don't ignore secp256k1 function return values (always check for == 1)

## Project Organization Best Practices

### Debug Scripts Management
- Keep debug and test utilities separate from production code
- Use a dedicated `debug_scripts/` folder for:
  - One-off debugging tools (`debug_*.zig`)
  - Standalone test scripts (`test_*.zig`)
  - Verification utilities (`verify_*.zig`)
- Don't commit temporary planning documents to the main branch
- Keep the root directory clean and focused on essential files

### Documentation Structure
- `README.md` - User-facing documentation and quick start
- `DEVELOPMENT.md` - Developer guidelines and technical details
- `PROGRESS.md` - Current status and todo tracking
- `PROBLEMS.md` - Known issues and solutions
- Avoid creating temporary markdown files for planning

### Debug Scripts Guidelines
- **Always** place debug scripts and test utilities in the `debug_scripts/` directory
- Never leave debug scripts in the root directory
- Follow naming conventions:
  - `debug_*.zig` - For debugging specific features
  - `test_*.zig` - For standalone test scripts
  - `verify_*.zig` - For verification utilities
- These scripts are not part of the production codebase
- They should be self-contained and runnable independently

### Source Code Organization
- `src/` - All production code
- `src/nostr/` - Core Nostr protocol implementations
- `src/nip*/` - Specific NIP implementations as modules
- `src/mls/` - MLS/group messaging features
- Keep related functionality together in modules

### Build System
- Use `zig build` for all build tasks
- Define custom build steps for examples and tests
- Keep build.zig clean and well-documented
- Use git submodules for C dependencies