# NIP-44 Implementation Plan for Nostr Zig

## Overview

This document outlines the implementation plan for NIP-44 encrypted direct messages in the Nostr Zig library. NIP-44 provides versioned encryption for Nostr with no forward secrecy, designed for the specific requirements of the Nostr protocol.

## Technical Requirements

### NIP-44 v2 Specification
- **Encryption**: ChaCha20 stream cipher
- **Authentication**: HMAC-SHA256  
- **Key Derivation**: HKDF-SHA256
- **ECDH**: secp256k1 (already available in our library)
- **Padding**: Custom power-of-2 padding scheme
- **Encoding**: Base64 for wire format

### Message Structure
```
[version_byte][32_byte_nonce][encrypted_padded_message][32_byte_hmac]
Total: 1 + 32 + len(encrypted) + 32 = 65 + len(encrypted) bytes
```

### Cryptographic Flow
1. **Shared Secret**: ECDH(sender_private_key, recipient_public_key)
2. **Conversation Key**: HKDF-Extract(salt="nip44-v2", ikm=shared_secret)
3. **Message Keys**: HKDF-Expand(conversation_key, nonce, 76_bytes)
   - Bytes 0-31: ChaCha20 key
   - Bytes 32-43: ChaCha20 nonce (12 bytes)
   - Bytes 44-75: HMAC key (32 bytes)
4. **Padding**: Custom algorithm to hide message length
5. **Encryption**: ChaCha20(key, nonce, padded_message)
6. **Authentication**: HMAC-SHA256(hmac_key, encrypted_data)

## Implementation Strategy

### Phase 1: Module Structure
```
src/nip44/
├── mod.zig              # Main API and version handling
├── v2.zig               # NIP-44 v2 implementation
├── crypto.zig           # Crypto utilities specific to NIP-44
├── padding.zig          # Padding algorithm implementation
└── test_vectors.zig     # Test vector runner
```

### Phase 2: Core Components

#### 1. ConversationKey (`src/nip44/v2.zig`)
```zig
const ConversationKey = struct {
    key: [32]u8,
    
    pub fn fromSharedSecret(shared_secret: [32]u8) ConversationKey {
        // HKDF-Extract with salt="nip44-v2"
    }
    
    pub fn deriveMessageKeys(self: ConversationKey, nonce: [32]u8) MessageKeys {
        // HKDF-Expand to derive 76 bytes
    }
};
```

#### 2. MessageKeys (`src/nip44/v2.zig`)
```zig
const MessageKeys = struct {
    chacha_key: [32]u8,
    chacha_nonce: [12]u8, 
    hmac_key: [32]u8,
    
    pub fn fromExpanded(expanded: [76]u8) MessageKeys {
        // Split the 76 bytes into constituent keys
    }
};
```

#### 3. Padding Algorithm (`src/nip44/padding.zig`)
```zig
pub fn calcPaddedLen(content_len: usize) usize {
    // Implement NIP-44 padding calculation
    // Messages ≤32 bytes: pad to 32
    // Messages >32 bytes: pad to next power-of-2 boundary with chunk logic
}

pub fn padMessage(allocator: std.mem.Allocator, content: []const u8) ![]u8 {
    // Return [2_byte_length][message][zero_padding]
}

pub fn unpadMessage(allocator: std.mem.Allocator, padded: []const u8) ![]u8 {
    // Extract original message from padding
}
```

#### 4. Main API (`src/nip44/mod.zig`)
```zig
pub const Nip44Error = error{
    InvalidVersion,
    InvalidLength, 
    InvalidHmac,
    InvalidPadding,
    MessageEmpty,
    MessageTooLong,
    Base64DecodeError,
    HexDecodeError,
    CryptoError,
};

pub fn encrypt(
    allocator: std.mem.Allocator,
    secret_key: [32]u8,
    public_key: [32]u8, 
    content: []const u8,
) Nip44Error![]u8 {
    // High-level encrypt function
    // Returns base64-encoded payload
}

pub fn decrypt(
    allocator: std.mem.Allocator,
    secret_key: [32]u8,
    public_key: [32]u8,
    payload: []const u8,
) Nip44Error![]u8 {
    // High-level decrypt function
    // Accepts base64-encoded payload
}
```

### Phase 3: Crypto Integration

#### Leverage Existing Infrastructure
- ✅ secp256k1 ECDH (already implemented in `src/secp256k1/`)
- ✅ Zig standard library crypto:
  - `std.crypto.stream.chacha.ChaCha20`
  - `std.crypto.auth.hmac.Hmac(std.crypto.hash.sha2.Sha256)`
  - `std.crypto.kdf.hkdf.Hkdf(std.crypto.hash.sha2.Sha256)`
  - `std.base64.standard.Encoder`

#### ECDH Integration (`src/nip44/crypto.zig`)
```zig
pub fn generateSharedSecret(
    secret_key: [32]u8,
    public_key: [32]u8,
) ![32]u8 {
    // Use existing secp256k1 bindings for ECDH
    // Call secp256k1_ecdh with appropriate point format
}
```

### Phase 4: Test Infrastructure

#### Test Vector Integration
- Copy test vectors from https://github.com/paulmillr/nip44/blob/main/nip44.vectors.json
- Implement test runner following MLS Zig patterns found in `~/dev/heavy/mls_zig/`

#### Test Categories
1. **get_conversation_key**: ECDH + HKDF validation
2. **calc_padded_len**: Padding algorithm correctness  
3. **encrypt_decrypt**: End-to-end encryption tests
4. **invalid cases**: Error handling validation

#### Test Structure (`src/nip44/test_vectors.zig`)
```zig
const TestVectorRunner = struct {
    allocator: std.mem.Allocator,
    
    pub fn runAllTests(self: *TestVectorRunner) !void {
        const vectors = try self.loadTestVectors();
        defer vectors.deinit();
        
        try self.runConversationKeyTests(vectors);
        try self.runPaddingTests(vectors);
        try self.runEncryptDecryptTests(vectors);
        try self.runInvalidTests(vectors);
    }
};
```

### Phase 5: Integration

#### Add to Main Library (`src/root.zig`)
```zig
pub const nip44 = @import("nip44/mod.zig");
```

#### CLI Integration (`src/main.zig`)
Add subcommands for NIP-44 operations:
- `encrypt-dm`: Encrypt direct message
- `decrypt-dm`: Decrypt direct message
- `test-nip44`: Run NIP-44 test vectors

## Testing Strategy

### 1. Unit Tests
- Test each component in isolation
- Padding algorithm correctness
- Key derivation validation
- Crypto primitive integration

### 2. Integration Tests  
- Full encrypt/decrypt cycles
- Cross-compatibility with reference implementation
- Error handling edge cases

### 3. Test Vector Validation
- Run against official NIP-44 test vectors
- Validate all test cases (valid and invalid)
- Ensure 100% compatibility with specification

### 4. Property-Based Testing
- Round-trip property: decrypt(encrypt(msg)) == msg
- Randomized key and message testing
- Padding correctness across message sizes

## Dependencies

### Already Available
- ✅ `std.crypto.*` - All required primitives
- ✅ secp256k1 integration with ECDH support
- ✅ JSON parsing utilities
- ✅ Hex conversion utilities
- ✅ Base64 encoding/decoding

### No External Dependencies Required
All cryptographic primitives are available in Zig standard library or existing secp256k1 integration.

## Success Criteria

1. **Specification Compliance**: Pass all official NIP-44 test vectors
2. **Cross-Compatibility**: Encrypt/decrypt interoperability with Rust implementation
3. **Security**: No crypto implementation vulnerabilities
4. **Performance**: Efficient encryption/decryption suitable for real-time messaging
5. **Integration**: Clean API that integrates seamlessly with existing Nostr library
6. **Testing**: Comprehensive test coverage with property-based testing

## Implementation Timeline

1. **Day 1**: Module structure and basic API design
2. **Day 2**: Core crypto components (ConversationKey, MessageKeys)
3. **Day 3**: Padding algorithm implementation and testing
4. **Day 4**: Integration with secp256k1 ECDH and Zig crypto
5. **Day 5**: Test vector runner and validation
6. **Day 6**: CLI integration and documentation
7. **Day 7**: Performance optimization and final testing

## Security Considerations

### Design Limitations (by spec)
- **No forward secrecy**: Keys compromise reveals all past messages
- **No post-compromise security**: Cannot recover from key compromise
- **No deniability**: Signatures provide non-repudiation
- **Metadata leakage**: Timing and frequency analysis possible

### Implementation Security
- Constant-time operations where possible
- Secure random number generation for nonces
- Proper key zeroization after use
- Input validation and bounds checking
- Memory safety through Zig's safety features

### Testing for Security
- Validate against known answer tests
- Cross-implementation compatibility testing
- Fuzzing with invalid inputs
- Side-channel analysis considerations

## Future Extensions

### Potential Improvements
- Streaming encryption for large messages
- Batch operations for multiple messages
- Hardware acceleration where available
- Integration with Nostr event encryption (NIP-59)

### Optimization Opportunities
- Precomputed conversation keys for frequent contacts
- SIMD optimizations for bulk operations
- Memory pool allocation for frequent encrypt/decrypt
- Assembly implementations of hot paths

This plan provides a comprehensive roadmap for implementing NIP-44 in the Nostr Zig library with high security, performance, and compatibility standards.