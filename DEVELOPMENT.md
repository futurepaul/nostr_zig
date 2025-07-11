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
├── secp256k1/         # Custom secp256k1 wrapper
│   ├── secp256k1.zig  # Zig bindings for bitcoin-core/secp256k1
│   ├── callbacks.c    # External callback implementations
│   └── libsecp256k1-config.h  # Build configuration
├── test_events.zig    # Test event fixtures
└── test_roundtrip.zig # Integration tests
deps/
└── secp256k1/         # bitcoin-core/secp256k1 git submodule
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