# MLS/Core Nostr API Boundaries

## Overview

This document defines the clear API boundaries between the MLS (Message Layer Security) implementation and the core Nostr infrastructure, establishing which components should be used where and how they interact.

## Layer Architecture

```
┌─────────────────────────────────────────────────┐
│            Application Layer                     │
│         (visualizer, CLI tools, etc.)           │
└─────────────────────────────────────────────────┘
                        │
┌─────────────────────────────────────────────────┐
│              MLS Layer (src/mls/)               │
│   - Group messaging protocol                    │
│   - MLS state machine                           │
│   - TreeKEM, Welcome messages                   │
│   - NIP-EE specific logic                       │
└─────────────────────────────────────────────────┘
                        │
┌─────────────────────────────────────────────────┐
│         Core Nostr Layer (src/nostr/)           │
│   - Event structure and validation              │
│   - Event creation and signing                  │
│   - Relay communication                         │
│   - Basic NIPs implementation                   │
└─────────────────────────────────────────────────┘
                        │
┌─────────────────────────────────────────────────┐
│      Infrastructure Layer (src/)                │
│   - Cryptography (crypto.zig)                   │
│   - Encoding (bech32.zig)                       │
│   - Platform abstractions (wasm_*.zig)          │
│   - Network (client.zig, websocket)             │
└─────────────────────────────────────────────────┘
```

## API Boundaries

### 1. Event Creation & Management

**Core Nostr Provides:**
- `Event` struct with methods:
  - `fromJson()` - Parse events from JSON
  - `toJson()` - Serialize events to JSON
  - `calculateId()` - Compute event ID (to be added)
  - `sign()` - Sign events (to be added)
  - `verify()` - Verify signatures (to be added)
  - `deinit()` - Memory cleanup

**MLS Uses:**
- Creates events using core Event struct
- Adds MLS-specific tags and content
- Uses standard signing/verification

**MLS Provides:**
- NIP-EE specific event helpers:
  - `createKeyPackageEvent()` (kind 443)
  - `createGroupMessageEvent()` (kind 445)
  - `createWelcomeEvent()` (kind 10050)
  - `createKeyPackageRelayListEvent()` (kind 10051)

### 2. Cryptographic Operations

**Core Infrastructure Provides:**
- `crypto.zig`:
  - `generatePrivateKey()` - Generate Nostr keys
  - `getPublicKey()` - Derive public keys
  - `signEvent()` - BIP340 Schnorr signatures
  - `verifySignature()` - Signature verification
  - `calculateEventId()` - SHA256 event hashing
  
- `nip44/mod.zig`:
  - `encrypt()` - NIP-44 encryption
  - `decrypt()` - NIP-44 decryption

**MLS Uses:**
- All key generation through core crypto
- All signing/verification through core crypto
- NIP-44 for additional encryption layer

**MLS Provides:**
- MLS-specific crypto operations:
  - HPKE encryption/decryption
  - TreeKEM operations
  - MLS key derivation (via HKDF)
  - Exporter secret generation

### 3. Network & Relay Communication

**Core Infrastructure Provides:**
- `client.zig`:
  - WebSocket connection management
  - Relay message parsing
  - Subscription handling
  - Event publishing

**MLS Should Use (Currently Missing):**
- Publish events through `client.publishEvent()`
- Subscribe to events with proper filters
- Handle relay responses (OK, NOTICE, etc.)

**MLS Provides:**
- MLS-specific relay patterns:
  - KeyPackage discovery logic
  - Group message distribution
  - Multi-relay coordination for groups

### 4. Data Encoding

**Core Infrastructure Provides:**
- `bech32.zig`:
  - Bech32 encoding/decoding
  - npub/nsec format handling

**MLS Uses:**
- Currently not using (should for user-facing IDs)

**MLS Provides:**
- Base64 encoding for MLS protocol data
- TLS wire format encoding (via mls_zig)

### 5. Platform Abstractions

**Core Infrastructure Provides:**
- `wasm_random.zig` - Secure random generation
- `wasm_time.zig` - Timestamp generation
- `wasm_secp_context.zig` - secp256k1 context

**MLS Uses:**
- All random generation through wasm_random
- All timestamps through wasm_time
- Dependency injection pattern for WASM compatibility

## Integration Guidelines

### DO ✅

1. **Always use core Event struct** for Nostr events
2. **Use core crypto** for all Nostr-specific operations
3. **Use platform abstractions** for WASM compatibility
4. **Extend, don't replace** core functionality
5. **Document MLS-specific requirements** clearly

### DON'T ❌

1. **Don't duplicate** event creation/signing logic
2. **Don't bypass** core crypto for Nostr operations
3. **Don't create parallel** infrastructure
4. **Don't hardcode** platform-specific code
5. **Don't mix** MLS and Nostr crypto primitives

## Migration Path

### Current State Issues:
1. `event_signing.zig` duplicates core functionality
2. No relay client integration
3. Limited use of core Event methods

### Target State:
1. Core Event struct handles all basic operations
2. MLS extends with protocol-specific helpers
3. Full relay infrastructure integration
4. Clear separation of concerns

## API Examples

### Creating a KeyPackage Event (Current):
```zig
// In MLS code
const helper = NipEEEventHelper.init(allocator, private_key);
const event = try helper.createKeyPackageEvent(
    key_package_data,
    cipher_suite,
    protocol_version,
    extensions,
);
```

### Creating a KeyPackage Event (Target):
```zig
// In MLS code
var event = try Event.init(allocator, .{
    .kind = 443,
    .content = key_package_data,
    .tags = mls_tags,
});
try event.sign(allocator, private_key);
```

### Publishing to Relays (Current):
```zig
// Not implemented - events created but not published
```

### Publishing to Relays (Target):
```zig
// In MLS code
const mls_client = MLSRelayClient.init(allocator, relay_urls);
try mls_client.publishEvent(event);
try mls_client.waitForConfirmation(event.id);
```

## Testing Boundaries

### Core Tests:
- Event parsing/serialization
- Signature verification
- Basic relay communication
- Standard NIPs compliance

### MLS Tests:
- MLS protocol compliance
- Group state management
- TreeKEM operations
- NIP-EE specific features

### Integration Tests:
- End-to-end message flow
- Multi-relay coordination
- Cross-client compatibility
- Performance benchmarks

## Future Considerations

1. **New NIPs**: Should extend core Event/infrastructure
2. **MLS Updates**: Contained within MLS layer
3. **Performance**: Monitor boundary crossing overhead
4. **Security**: Regular audit of crypto usage patterns
5. **WASM**: Maintain platform abstraction discipline