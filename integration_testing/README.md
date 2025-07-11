# NIP-44 Cross-Implementation Integration Tests

This directory contains integration tests to verify interoperability between Zig, C, and Rust NIP-44 implementations.

## Structure

- `c/` - C reference implementation wrapper
- `rust/` - Rust reference implementation wrapper  
- `zig/` - Zig implementation wrapper
- `shared/` - Shared test vectors and test runner
- `test_runner.py` - Main test orchestrator

## Test Plan

### 1. Build Phase
- Build C implementation from samples/nip44/c
- Build Rust implementation from samples/nip44/rust
- Build Zig wrapper for our implementation

### 2. Test Scenarios

#### A. Conversation Key Generation
- Test all implementations generate same conversation key from same inputs
- Test with edge cases (all zeros, all ones, etc.)

#### B. Message Key Derivation  
- Verify HKDF produces same keys across implementations
- Test with various nonce values

#### C. Padding Algorithm
- Verify all implementations calculate same padded lengths
- Test edge cases around power-of-2 boundaries

#### D. Encryption/Decryption Interop
- Encrypt with Zig, decrypt with C/Rust
- Encrypt with C, decrypt with Zig/Rust
- Encrypt with Rust, decrypt with Zig/C
- Test with various message lengths

#### E. HMAC Verification
- Ensure all implementations calculate same HMAC
- Test tampering detection

#### F. Error Handling
- Verify all implementations properly reject invalid inputs
- Test malformed payloads, bad HMACs, etc.

### 3. Random Testing
- Generate random keys and messages
- Verify all implementations produce compatible results
- Run 1000+ iterations

## Running Tests

```bash
# Quick start - run everything
./run_tests.sh

# Or use Zig build system directly:
cd integration_testing

# Build all implementations
zig build build-refs

# Run integration tests
zig build test-integration

# Run fuzz tests
zig build fuzz
```

## Fuzz Testing

The fuzz testing suite uses Zig's built-in fuzzing capabilities to test:

1. **Conversation Key Generation** - Random key inputs
2. **Message Key Derivation** - Random conversation keys and nonces
3. **Padding Algorithm** - Random message lengths up to 1MB
4. **Encrypt/Decrypt Roundtrip** - Random keys and messages
5. **Malformed Input Handling** - Invalid base64 and corrupted payloads

Fuzz tests verify:
- Deterministic behavior (same input = same output)
- No crashes on random input
- Proper error handling for invalid data
- Roundtrip correctness (encrypt -> decrypt = original)