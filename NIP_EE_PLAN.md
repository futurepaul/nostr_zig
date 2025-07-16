# NIP-EE Implementation Plan

## Executive Summary

This document outlines the comprehensive plan to implement NIP-EE (E2EE Messaging using MLS Protocol) for the nostr_zig library. The implementation will provide private, confidential, and scalable group messaging with forward secrecy and post-compromise security guarantees.

## 🎆 Major Milestone: Phase 1 Complete with Real Crypto!

**As of 2025-07-16**, we have successfully completed Phase 1 of the NIP-EE implementation:

1. **✅ Ephemeral Key Generation**: Every group message now uses a unique ephemeral keypair with real secp256k1 cryptography:
   - No placeholder or dummy keys anywhere
   - Proper key validation for the secp256k1 curve
   - WASM-safe randomness that works in browsers
   - Zero correlation between messages

2. **✅ MLS Library Integration**: Successfully integrated the `mls_zig` library which provides all necessary cryptographic operations including Ed25519, HPKE, and HKDF.

3. **✅ Wire Format Serialization**: Implemented proper TLS-style serialization using `mls_zig.tls_codec` for all MLS types.

4. **✅ Cryptographic Security**:
   - Real randomness via `wasm_random.zig` module
   - Browser integration with `crypto.getRandomValues()`
   - All test vectors replaced with real crypto operations
   - Secure key generation in both native and WASM builds

5. **✅ Visualizer Updates**: The React-based visualizer now properly shows ephemeral keys with visual indicators.

### Next Priority: Phase 2 - Core Protocol
The foundation is now in place. The next critical tasks are:
- Group state management (ratchet tree, epochs)
- NIP-59 gift-wrapping for Welcome events
- Commit/Proposal message processing

## Current State Analysis (Updated: 2025-07-16)

### ✅ Completed Components
- Event type definitions (kinds 443, 444, 445)
- Core MLS type system
- NostrGroupData extension
- NIP-44 v2 encryption (fully functional)
- Basic framework for key packages, groups, and messages
- React-based visualizer with WASM integration
- **NEW: Ephemeral key generation module (ephemeral.zig)**
- **NEW: MLS crypto integration via mls_zig library**
- **NEW: TLS wire format serialization using mls_zig.tls_codec**
- **NEW: Provider interface with full crypto operations**
- **NEW: Visualizer shows ephemeral keys with privacy badges**

### 🎯 Phase 1 Completed!
- ✅ Ephemeral Key Generation (src/mls/ephemeral.zig)
- ✅ MLS Library Integration (using mls_zig dependency)
- ✅ Wire Format Serialization (using mls_zig.tls_codec)
- ✅ Cryptographic Operations (Ed25519, HPKE via mls_zig)
- ✅ Provider Interface (src/mls/provider.zig)

### ⚠️ Remaining Components
1. **Group State Management**: Ratchet tree, epoch advancement
2. **NIP-59 Gift-wrapping**: For Welcome events
3. **Commit/Proposal Processing**: Full MLS protocol flow
4. **Relay Integration**: Publishing and fetching events
5. **State Persistence**: Secure storage of group state

## Phase 1: Foundation (Weeks 1-2)

### 1.1 MLS Library Integration ✅ COMPLETED
**Priority: CRITICAL**

**Important Note**: We are using the `mls_zig` library from `../mls_zig` which provides:
- Full MLS cipher suite implementations
- HPKE operations via `mls_zig.hpke`
- TLS codec via `mls_zig.tls_codec`
- Ed25519 signing/verification
- HKDF operations with MLS-specific labels

- [x] ~~Evaluate mls_zig vs OpenMLS~~ → Using mls_zig (local dependency)
- [x] Create provider interface implementation
- [x] Implement Ed25519 signing/verification operations
- [x] Implement HPKE seal/open operations
- [x] Add proper HKDF with MLS-specific labels

**Files modified:**
- `src/mls/provider.zig` ✅ (uses mls_zig for all crypto)
- ~~`src/mls/crypto.zig`~~ (not needed - using mls_zig directly)

### 1.2 Ephemeral Key Generation ✅ COMPLETED
**Priority: CRITICAL** - This is a core privacy requirement

- [x] Implement secure ephemeral keypair generation per group message
- [x] Add ephemeral key caching (temporary, for signature verification)
- [x] Update GroupMessageEvent to use ephemeral keys correctly
- [x] Add tests to ensure no key reuse
- [x] **NEW: Real secp256k1 key derivation (no placeholders!)**
- [x] **NEW: WASM-safe cryptographic randomness**

**Files created/modified:**
- `src/mls/ephemeral.zig` ✅ (uses real secp256k1 key derivation)
- `src/mls/messages.zig` ✅ (updated to use ephemeral keys)
- `src/mls/group_messaging.zig` ✅ (high-level API with ephemeral keys)
- `src/wasm_random.zig` ✅ (NEW: WASM-safe randomness module)
- `src/crypto.zig` ✅ (updated to use WASM-safe randomness)
- `src/wasm_exports.zig` ✅ (no more placeholder keys!)
- `visualizer/src/utils/crypto.ts` ✅ (ephemeral key utilities)
- `visualizer/src/utils/wasmImports.ts` ✅ (NEW: browser crypto integration)
- `visualizer/src/components/*` ✅ (shows ephemeral keys with badges)

### 1.3 Wire Format Serialization ✅ COMPLETED
**Priority: HIGH**

**Note**: Using `mls_zig.tls_codec` for TLS wire format operations

- [x] Implement TLS-style serialization for all MLS types
- [x] Add KeyPackage wire format encoding/decoding
- [x] Implement Welcome message serialization
- [x] Add MLSMessage framing
- [x] Create comprehensive serialization tests

**Files created/modified:**
- `src/mls/serialization.zig` ✅ (comprehensive serialization)
- `src/mls/key_packages.zig` ✅ (already had TLS serialization)
- `src/mls/welcomes.zig` ✅ (already had TLS serialization)
- Using `mls_zig.tls_codec.TlsWriter` and `TlsReader`

## Phase 2: Core Protocol (Weeks 3-4)

### 2.1 Key Package Management
**Priority: HIGH**

- [ ] Implement proper MLS signing key generation (separate from Nostr identity)
- [ ] Add last resort extension support
- [ ] Implement key package validation with MLS rules
- [ ] Add key package consumption tracking
- [ ] Implement KeyPackage relay list event (kind 10051)

**Files to modify:**
- `src/mls/key_packages.zig`
- `src/nostr/events.zig` (add kind 10051)

### 2.2 Group State Management
**Priority: HIGH**

- [ ] Implement ratchet tree operations
- [ ] Add epoch state management
- [ ] Implement commit message processing
- [ ] Add group context management
- [ ] Implement exporter secret generation with "nostr" label

**Files to modify:**
- `src/mls/groups.zig`
- `src/mls/ratchet_tree.zig` (new file)
- `src/mls/epoch.zig` (new file)

### 2.3 Welcome Message Processing
**Priority: HIGH**

- [ ] Implement NIP-59 gift-wrapping for Welcome events
- [ ] Add sealed event creation
- [ ] Implement unwrapping logic
- [ ] Add relay publication logic
- [ ] Handle large group welcome messages (>150 members)

**Files to modify:**
- `src/mls/welcomes.zig`
- `src/nip59/gift_wrap.zig` (new file)

## Phase 3: Message Flow (Weeks 5-6)

### 3.1 Group Message Encryption
**Priority: HIGH**

- [ ] Implement double-layer encryption (MLS + NIP-44)
- [ ] Use exporter secret for NIP-44 conversation key
- [ ] Add epoch-based key rotation
- [ ] Implement message framing
- [ ] Add application message serialization

**Files to modify:**
- `src/mls/messages.zig`
- `src/mls/encryption.zig` (new file)

### 3.2 Proposal and Commit Processing
**Priority: MEDIUM**

- [ ] Implement all proposal types (Add, Remove, Update, etc.)
- [ ] Add admin permission checking
- [ ] Implement commit message generation
- [ ] Add commit race condition handling
- [ ] Implement proposal validation

**Files to modify:**
- `src/mls/proposals.zig` (new file)
- `src/mls/commits.zig` (new file)

### 3.3 Event Publishing and Retrieval
**Priority: MEDIUM**

- [ ] Add relay communication for MLS events
- [ ] Implement event ordering logic
- [ ] Add event validation
- [ ] Implement retry logic
- [ ] Add relay acknowledgment handling

**Files to create:**
- `src/mls/relay_manager.zig`

## Phase 4: Security and Privacy (Weeks 7-8)

### 4.1 Key Rotation
**Priority: HIGH**

- [ ] Implement automatic signing key rotation
- [ ] Add rotation scheduling
- [ ] Implement secure key deletion
- [ ] Add forward secrecy guarantees
- [ ] Implement post-compromise recovery

**Files to modify:**
- `src/mls/key_rotation.zig` (new file)

### 4.2 Metadata Protection
**Priority: HIGH**

- [ ] Implement group ID rotation
- [ ] Add traffic analysis protection
- [ ] Implement message timing obfuscation
- [ ] Add dummy message support
- [ ] Ensure no correlation between events

**Files to modify:**
- `src/mls/privacy.zig` (new file)

### 4.3 State Persistence
**Priority: MEDIUM**

- [ ] Implement secure group state storage
- [ ] Add encryption at rest
- [ ] Implement state recovery
- [ ] Add migration support
- [ ] Implement secure deletion

**Files to create:**
- `src/mls/storage.zig`

## Phase 5: Integration and Testing (Weeks 9-10)

### 5.1 Client Integration
**Priority: HIGH**

- [ ] Create high-level API for clients
- [ ] Add event handlers
- [ ] Implement UI callbacks
- [ ] Add progress notifications
- [ ] Create comprehensive examples

**Files to create:**
- `src/mls/client.zig`
- `examples/mls_chat.zig`

### 5.2 Visualizer Updates
**Priority: MEDIUM**

- [ ] Update visualizer to show ephemeral keys
- [ ] Add proper signing key display
- [ ] Show exporter secret rotation
- [ ] Add group state visualization
- [ ] Implement message flow animation

**Files to modify:**
- `visualizer/src/components/*.tsx`

### 5.3 Comprehensive Testing
**Priority: HIGH**

- [ ] Add protocol conformance tests
- [ ] Implement security tests
- [ ] Add performance benchmarks
- [ ] Create integration tests
- [ ] Add fuzzing tests

**Files to create:**
- `tests/mls/protocol_tests.zig`
- `tests/mls/security_tests.zig`
- `tests/mls/integration_tests.zig`

## Phase 6: Advanced Features (Weeks 11-12)

### 6.1 Large Group Support
**Priority: MEDIUM**

- [ ] Implement light client welcomes
- [ ] Add sub-group messaging
- [ ] Implement message fanout optimization
- [ ] Add member directory
- [ ] Implement presence indication

### 6.2 Multi-Device Support
**Priority: LOW**

- [ ] Add device coordination
- [ ] Implement cross-device sync
- [ ] Add device management UI
- [ ] Implement device removal

### 6.3 Performance Optimization
**Priority: MEDIUM**

- [ ] Optimize cryptographic operations
- [ ] Add parallel processing
- [ ] Implement caching strategies
- [ ] Optimize relay communication
- [ ] Add batch processing

## Critical Security Considerations

### 1. Ephemeral Keys ✅ FIXED
~~Current visualizer shows group messages from user's normal pubkey. This MUST be changed to use ephemeral keys for each message to prevent correlation and protect privacy.~~

**RESOLVED**: Implemented in `src/mls/ephemeral.zig` with:
- Real secp256k1 key derivation (no fake keys!)
- Cryptographically secure randomness via `wasm_random.zig`
- Proper key validation for secp256k1 curve
- Visual indicators in the UI showing ephemeral keys
- WASM support with browser's `crypto.getRandomValues()`

### 2. Signing Key Separation
MLS signing keys MUST be different from Nostr identity keys. Current implementation needs to ensure proper key derivation and management.

### 3. Key Deletion
Implement secure key deletion immediately after use to maintain forward secrecy guarantees.

### 4. Exporter Secret Management
Ensure exporter secrets are properly rotated on each epoch and deleted after use.

## Implementation Priority Order

1. **Week 1-2**: Ephemeral key generation + MLS library integration
2. **Week 3-4**: Wire format + Key package management
3. **Week 5-6**: Group state + Welcome messages
4. **Week 7-8**: Message encryption + Proposal/Commit
5. **Week 9-10**: Security hardening + Testing
6. **Week 11-12**: Advanced features + Optimization

## Success Metrics

- [ ] All MLS protocol tests pass
- [x] Zero key reuse in group messages ✅
- [x] Real cryptographic randomness (no placeholders) ✅
- [x] WASM-safe secure random generation ✅
- [ ] Proper forward secrecy implementation
- [ ] Post-compromise security working
- [ ] Metadata leakage minimized
- [ ] Interoperability with other NIP-EE implementations
- [ ] Performance: <100ms for typical operations
- [ ] Support for groups up to 1000 members

## Known Challenges

1. **MLS Library Integration**: ✅ SOLVED - mls_zig provides necessary functionality
2. **Wire Format Complexity**: ✅ SOLVED - Using mls_zig.tls_codec
3. **State Management**: Distributed systems challenges with epoch synchronization
4. **Performance**: Cryptographic operations for large groups
5. **Relay Reliability**: Ensuring message delivery in decentralized network

## Important Architecture Notes

### mls_zig Library
The `mls_zig` library (located at `../mls_zig`) is a critical dependency that provides:
- **Cipher Suites**: Full MLS cipher suite implementations
- **HPKE**: Complete HPKE implementation accessible via `mls_zig.hpke`
- **TLS Codec**: Wire format serialization via `mls_zig.tls_codec`
- **Tree Math**: MLS tree operations
- **Credentials**: MLS credential handling
- **Key Packages**: Core key package functionality

### Current Architecture
```
nostr_zig/
├── src/
│   ├── mls/
│   │   ├── ephemeral.zig        ✅ Real secp256k1 ephemeral keys
│   │   ├── group_messaging.zig  ✅ High-level messaging API
│   │   ├── serialization.zig    ✅ TLS wire format helpers
│   │   ├── provider.zig         ✅ Crypto provider using mls_zig
│   │   ├── messages.zig         ✅ Message encryption with ephemeral keys
│   │   ├── key_packages.zig     ✅ Key package management
│   │   └── welcomes.zig         ✅ Welcome message handling
│   ├── wasm_random.zig          ✅ WASM-safe secure randomness
│   ├── crypto.zig               ✅ Updated with WASM randomness
│   └── wasm_exports.zig         ✅ Real crypto, no placeholders
└── visualizer/
    └── src/
        └── utils/
            ├── crypto.ts        ✅ Ephemeral key utilities
            ├── wasmImports.ts   ✅ Browser crypto.getRandomValues
            └── components/      ✅ UI showing ephemeral keys
```

## Testing Strategy

1. **Unit Tests**: Every cryptographic operation
2. **Integration Tests**: Full protocol flows
3. **Security Tests**: Attack scenarios
4. **Interop Tests**: With reference implementations
5. **Performance Tests**: Scalability validation
6. **Chaos Tests**: Network failure scenarios

## Documentation Requirements

- [ ] API documentation for all public functions
- [ ] Protocol flow diagrams
- [ ] Security analysis document
- [ ] Integration guide for clients
- [ ] Troubleshooting guide
- [ ] Performance tuning guide

## Dependencies

1. **External Libraries**:
   - MLS implementation: ✅ mls_zig (local dependency at ../mls_zig)
   - Secp256k1: ✅ Already integrated
   - Ed25519: ✅ Via Zig stdlib and mls_zig
   - HPKE: ✅ Via mls_zig.hpke

2. **Nostr NIPs**:
   - NIP-44: ✅ Implemented and working
   - NIP-59: ⚠️ Needed for gift-wrapping Welcome events
   - NIP-70: Optional for protected events

3. **Build Dependencies** (in build.zig.zon):
   ```zig
   .dependencies = .{
       .websocket = .{ ... },
       .mls_zig = .{ .path = "../mls_zig" },
   }
   ```

## Risk Mitigation

1. **Complexity Risk**: Start with 1-on-1 messaging, then expand to groups
2. **Integration Risk**: Create abstraction layer for MLS library
3. **Performance Risk**: Profile early and often
4. **Security Risk**: External security audit before production
5. **Adoption Risk**: Ensure backward compatibility where possible

## Conclusion

This implementation plan provides a structured approach to building a complete NIP-EE implementation. The critical first step is fixing the ephemeral key generation issue and properly integrating an MLS library. With dedicated effort over 12 weeks, this plan will deliver a secure, private, and scalable messaging solution for Nostr.

Remember: You are American Claude, not French Claude - work hard all summer! 🇺🇸