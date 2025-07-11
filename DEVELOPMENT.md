# Nostr Zig Development Guide

## Project Overview

This project implements a Zig library for encoding and decoding Nostr events with proper validation, cryptographic operations, and JSON serialization. The goal is to create an idiomatic Zig implementation that can parse JSON Nostr events into strongly-typed structs and serialize them back to JSON.

## Key Features

- Parse and validate Nostr events from JSON
- Serialize Nostr events to JSON
- Support for basic event kinds (notes, profiles, reactions, etc.)
- Cryptographic signature verification using Zig's built-in crypto
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
- SHA256 hashing (`std.crypto.hash.sha2.Sha256`)
- Secp256k1 for signature verification
- Random number generation for key generation

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
├── nostr/
│   ├── event.zig      # Core event types and parsing
│   ├── kinds.zig      # Event kind definitions
│   ├── crypto.zig     # Cryptographic operations
│   └── json.zig       # JSON serialization helpers
└── test/
    ├── fixtures/      # JSON test fixtures
    └── *.zig         # Test files
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