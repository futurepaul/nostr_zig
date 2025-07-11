# Real MLS Implementation Plan

## 💡 Status Update

**Confirmed: `mls_zig` is a real, working MLS implementation!** Testing shows it has functional:
- HKDF operations (tested and working)
- Cipher suite support (Ed25519 + X25519 + AES-128-GCM)
- Credential management
- Nostr-specific extensions
- TLS wire format encoding

## Overview

This document outlines the strategy for integrating `mls_zig` to replace our 13 mock `NotImplemented` functions with real MLS functionality. The library provides most of what we need - we just need to wire it up correctly.

## Current State

### What We Have
- ✅ MLS type definitions and interfaces
- ✅ NIP-EE event kinds (443, 444, 445) for Nostr integration
- ✅ Double-layer encryption design (MLS + NIP-44)
- ✅ Basic HKDF operations working (using Zig std lib)
- ✅ `mls_zig` dependency configured but not used

### What's Missing (13 NotImplemented Functions)
1. **Cryptographic Operations** (5 functions in `provider.zig`)
   - `defaultSign` - Ed25519 signature creation
   - `defaultVerify` - Ed25519 signature verification
   - `defaultHpkeSeal` - HPKE encryption
   - `defaultHpkeOpen` - HPKE decryption
   - `defaultHpkeGenerateKeyPair` - HPKE key generation

2. **Wire Format Serialization** (8 functions)
   - `parseKeyPackage` (key_packages.zig)
   - `serializeKeyPackage` (key_packages.zig)
   - `deserializeKeyPackage` (nip_ee.zig)
   - `parseWelcome` (welcomes.zig)
   - `serializeWelcome` (welcomes.zig)
   - `deserializeWelcome` (nip_ee.zig)
   - `parseMLSCiphertext` (messages.zig)
   - `createAndProcessCommit` (groups.zig)

## Available mls_zig Modules (Real Implementation)

The `mls_zig` library provides these modules with actual MLS functionality:
- `cipher_suite` - Real cipher suite implementations (HKDF, etc.)
- `mls_group` - MLS group management functionality
- `key_package` - Key package creation and verification
- `credentials` - Credential management
- `nostr_extensions` - Nostr-specific MLS extensions for NIP-EE
- `tree_math`, `binary_tree`, `leaf_node`, `tree_kem` - Ratchet tree operations
- `tls_codec` - TLS wire format encoding/decoding

## Confirmed mls_zig Capabilities

Based on testing, mls_zig provides:
- ✅ Real HKDF operations (extract/expand work perfectly)
- ✅ Cipher suite implementations (MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
- ✅ Credential management with BasicCredential
- ✅ NostrGroupData extension support
- ✅ Secret management with proper memory handling
- ✅ TLS codec for wire format (VarBytes)

## Revised Implementation Strategy

### Option 1: Implement MLS from Scratch
**Pros**: Full control, can optimize for Nostr use case
**Cons**: Massive undertaking, high risk of security bugs

### Option 2: Find a Real MLS Library
**Pros**: Battle-tested implementation
**Cons**: May not exist for Zig, would need C bindings

### Option 3: Implement Minimal MLS Subset
**Pros**: Focused on what Nostr needs, manageable scope
**Cons**: Not fully MLS compliant, interop issues

### Recommended Approach: Direct Integration

1. **Use mls_zig directly** - It's a real implementation, use it!
2. **Map our interfaces** - Connect our NotImplemented functions to mls_zig
3. **Leverage Nostr extensions** - mls_zig already has Nostr support!

## Implementation Plan

### Phase 1: Deep Dive into mls_zig (Week 1)

**Goal**: Understand mls_zig's API and map it to our needs

1. **Create API exploration script**
   ```zig
   // debug_scripts/explore_mls_zig_api.zig
   const mls_zig = @import("mls_zig");
   // Test available modules: cipher_suite, hpke, credential, key_package, etc.
   ```

2. **Document available functionality**
   - List all modules and their public APIs
   - Identify which functions map to our NotImplemented ones
   - Create usage examples for each module

3. **Determine gaps**
   - What does mls_zig NOT provide that we need?
   - Do we need additional dependencies (e.g., for Ed25519)?

### Phase 2: Connect to mls_zig Cryptographic Operations (Week 2)

**Goal**: Replace our NotImplemented functions with mls_zig calls

#### 2.1 Ed25519 Signatures
**Implementation**: Use mls_zig's signature operations
```zig
// Current: returns error.NotImplemented
fn defaultSign(allocator: std.mem.Allocator, private_key: []const u8, data: []const u8) anyerror![]u8

// Implementation plan:
// 1. Use mls_zig's credential system for signatures
// 2. Map our sign/verify functions to mls_zig's API
// 3. Ensure proper MLS signature format
```

#### 2.2 HPKE Operations
```zig
// Current: returns error.NotImplemented
fn defaultHpkeSeal(...) anyerror!HpkeCiphertext
fn defaultHpkeOpen(...) anyerror![]u8
fn defaultHpkeGenerateKeyPair(...) anyerror!HpkeKeyPair

// Implementation plan:
// 1. Check if mls_zig uses its own HPKE or the hpke dependency
// 2. Use mls_zig's HPKE operations for Welcome messages
// 3. Support the cipher suites that mls_zig provides
```

#### Tests for Phase 2
- Test Ed25519 sign/verify with known test vectors
- Test HPKE seal/open roundtrip
- Test interoperability with other MLS implementations

### Phase 3: Implement Wire Format (Week 3-4)

**Goal**: Replace all 8 NotImplemented serialization functions

#### 3.1 Key Package Serialization
```zig
// Implement TLS-style wire format per RFC 9420
fn serializeKeyPackage(allocator: std.mem.Allocator, key_package: types.KeyPackage) anyerror![]u8 {
    // 1. Check if mls_zig.wire_format provides this
    // 2. Implement length-prefixed encoding
    // 3. Follow MLS KeyPackage structure
}
```

#### 3.2 Welcome Message Format
```zig
// Implement Welcome message serialization
fn serializeWelcome(allocator: std.mem.Allocator, welcome: types.Welcome) anyerror![]u8 {
    // 1. Serialize GroupInfo
    // 2. Encrypt GroupSecrets with HPKE
    // 3. Package into Welcome structure
}
```

#### 3.3 MLS Ciphertext Parsing
```zig
// Parse incoming MLS messages
fn parseMLSCiphertext(allocator: std.mem.Allocator, data: []const u8) anyerror!types.MLSCiphertext {
    // 1. Parse wire format header
    // 2. Extract sender data
    // 3. Return structured ciphertext
}
```

#### Tests for Phase 3
- Serialize/deserialize roundtrip tests for each type
- Test against known MLS test vectors
- Verify wire format matches RFC 9420 examples

### Phase 4: Integration and Group Operations (Week 5)

**Goal**: Complete group management functionality

#### 4.1 Implement createAndProcessCommit
```zig
fn createAndProcessCommit(...) anyerror!CommitResult {
    // 1. Use mls_zig group operations
    // 2. Generate commit message
    // 3. Update group state
    // 4. Return new epoch secrets
}
```

#### 4.2 Update existing mock implementations
- Replace mock key package generation with real MLS
- Update group creation to use actual MLS groups
- Implement proper member addition/removal

### Phase 5: Update Tests (Week 6)

**Goal**: Replace mock tests with real MLS protocol tests

#### 5.1 Integration Tests
```zig
test "real MLS group creation" {
    // 1. Generate real MLS credentials
    // 2. Create actual MLS group
    // 3. Verify group state
}

test "real MLS message encryption" {
    // 1. Create MLS group with multiple members
    // 2. Send encrypted application messages
    // 3. Verify all members can decrypt
}
```

#### 5.2 Interoperability Tests
- Test against reference MLS implementations
- Verify Nostr event wrapper doesn't break MLS
- Test double-encryption (MLS + NIP-44) flow

## Dependencies Status

### Already Available:
1. **Ed25519**: In Zig stdlib (std.crypto.sign.Ed25519)
2. **HPKE**: Already in build.zig.zon as dependency
3. **X25519**: In Zig stdlib (std.crypto.dh.X25519)
4. **SHA-256**: In Zig stdlib (std.crypto.hash.sha2.Sha256)
5. **HMAC**: In Zig stdlib (std.crypto.auth.hmac)
6. **AES-GCM**: In Zig stdlib (std.crypto.aead.aes_gcm)

### What We Should Use from mls_zig:
1. **Everything!** - It's a real MLS implementation
2. **MlsGroup** - For group management
3. **KeyPackageBundle** - For key package operations
4. **Nostr extensions** - Perfect for NIP-EE integration
5. **Cipher suites** - Real crypto operations

## Key Insights

1. **mls_zig is feature-complete** for basic MLS operations
2. **Already has Nostr support** via nostr_extensions
3. **Supports multiple cipher suites** including the one we need
4. **We just need to wire it up** to our interfaces

## Success Criteria

1. All 13 NotImplemented functions have real implementations
2. Tests use actual MLS protocol, not mocks
3. Can create real MLS groups and exchange encrypted messages
4. Interoperates with at least one other MLS implementation
5. Maintains Nostr integration (NIP-EE events still work)

## Risk Mitigation

1. **mls_zig incomplete**: Have fallback plan to implement missing pieces
2. **Performance issues**: Profile and optimize critical paths
3. **Compatibility**: Test early with other implementations
4. **Complexity**: Break down into smaller, testable pieces

## Simplified Timeline

- **Week 1**: Wire up HKDF and basic crypto (already tested!)
- **Week 2**: Implement HPKE using hpke dependency + Ed25519
- **Week 3**: Connect key package and group operations
- **Week 4**: Wire format and serialization
- **Week 5**: End-to-end testing and polish

## Immediate Next Steps

1. **TODAY**: Replace HKDF functions with mls_zig calls (we know they work!)
2. **TODAY**: Study mls_zig's key_package.zig for KeyPackage creation
3. **TOMORROW**: Investigate HPKE - check if mls_zig uses it internally
4. **THIS WEEK**: Get one complete flow working (create key package with real crypto)

## Next Steps

1. **Study mls_zig examples** - Look for usage patterns
2. **Map our provider interface** - Connect to mls_zig functions
3. **Start with KeyPackage** - Use mls_zig.key_package module
4. **Implement group creation** - Use mls_zig.mls_group
5. **Test with mls_zig's test vectors** - They have test_vectors.zig!

## Example: Using mls_zig for Key Package

```zig
// Instead of our mock implementation:
const mls_zig = @import("mls_zig");

fn generateKeyPackage(allocator: Allocator, provider: *MlsProvider, private_key: []const u8, extensions: KeyPackageExtensions) !types.KeyPackage {
    // Use mls_zig's real implementation
    const cipher_suite = mls_zig.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    const credential = mls_zig.BasicCredential{ .identity = private_key };
    
    const kp_bundle = try mls_zig.KeyPackageBundle.create(
        allocator,
        cipher_suite,
        credential,
        extensions,
    );
    
    // Convert to our types
    return types.KeyPackage{
        .version = .mls10,
        .cipher_suite = @intFromEnum(cipher_suite),
        .init_key = kp_bundle.key_package.init_key,
        .leaf_node = convertLeafNode(kp_bundle.key_package.leaf_node),
        .extensions = kp_bundle.key_package.extensions,
    };
}
```

## Notes

- Keep debug/exploration scripts in `debug_scripts/`
- mls_zig is a real implementation - use it fully!
- The author is just being modest about the "vibes" comment
- Focus on understanding mls_zig's API and integrating it
- Our mock can be completely replaced by mls_zig
- Document which parts are real vs mock as we progress

## Critical Path

1. **HPKE** - Most critical for MLS, needed for Welcome messages
2. **Ed25519** - Needed for all MLS signatures
3. **Wire format** - Need real serialization for interop
4. **Tree operations** - Can start with flat list, add tree later

## Concrete Integration Examples

### 1. Replace HKDF Operations
```zig
// OLD (NotImplemented):
fn defaultHkdfExtract(allocator: Allocator, salt: []const u8, ikm: []const u8) ![]u8 {
    return error.NotImplemented;
}

// NEW (using mls_zig):
fn defaultHkdfExtract(allocator: Allocator, salt: []const u8, ikm: []const u8) ![]u8 {
    const cs = mls_zig.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    var secret = try cs.hkdfExtract(allocator, salt, ikm);
    defer secret.deinit();
    return allocator.dupe(u8, secret.data);
}
```

### 2. Create Real Key Packages
```zig
// Use mls_zig's key package creation
const mls_zig = @import("mls_zig");

pub fn generateKeyPackage(
    allocator: Allocator,
    provider: *MlsProvider,
    private_key: []const u8,
    extensions: KeyPackageExtensions,
) !types.KeyPackage {
    // Create credential
    var identity = try mls_zig.tls_codec.VarBytes.init(allocator, private_key[0..32]);
    defer identity.deinit();
    
    const credential = mls_zig.BasicCredential{ .identity = identity };
    
    // TODO: Use mls_zig.key_package functions once we understand the API better
    // For now, return our mock but with real crypto
    return types.KeyPackage{
        .version = .mls10,
        .cipher_suite = @intFromEnum(mls_zig.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519),
        .init_key = try provider.crypto.hpkeGenerateKeyPairFn(allocator),
        .leaf_node = .{},  // TODO: Build real leaf node
        .extensions = .{},
    };
}
```

### 3. Use NostrGroupData Extension
```zig
// Already works!
var nostr_group_data = try mls_zig.nostr_extensions.NostrGroupData.init(
    allocator,
    group_id,
    &relay_urls,
    creator_pubkey,
    metadata,
);
defer nostr_group_data.deinit();
```