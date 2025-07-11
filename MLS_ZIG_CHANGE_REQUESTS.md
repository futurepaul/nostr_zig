# mls_zig Change Requests

This document outlines the changes needed in the `mls_zig` library to improve its usability and complete our MLS integration.

## 🎯 High Priority Changes

### 1. Expose HPKE Module 
**Priority**: HIGH  
**Current Issue**: Cannot access HPKE functionality from consuming code  
**Current State**: HPKE is imported in mls_zig but not exported  

**Requested Change**:
```zig
// In mls_zig/src/root.zig, add:
pub const hpke = @import("hpke");
```

**Why Needed**: 
- HPKE is critical for MLS Welcome message encryption
- Currently cannot implement `defaultHpkeSeal`, `defaultHpkeOpen`, `defaultHpkeGenerateKeyPair`
- HPKE is already a dependency, just needs to be exposed

**Workaround**: Add direct HPKE dependency to our build.zig (less ideal)

### 2. Add Convenience Signing Methods to CipherSuite
**Priority**: HIGH  
**Current Issue**: CipherSuite has no direct `sign()` or `verify()` methods  
**Current State**: Must use `signWithLabel()` and `verifyWithLabel()` from key_package module  

**Requested Change**:
```zig
// In cipher_suite.zig, add convenience methods:
pub fn sign(self: CipherSuite, allocator: Allocator, private_key: []const u8, data: []const u8) !Signature {
    const key_package = @import("key_package.zig");
    return key_package.signWithLabel(allocator, self, private_key, "", data);
}

pub fn verify(self: CipherSuite, public_key: []const u8, data: []const u8, signature: []const u8) !bool {
    const key_package = @import("key_package.zig");
    return key_package.verifyWithLabel(self, public_key, signature, "", data, null);
}
```

**Why Needed**:
- Simpler API for basic signing operations
- More intuitive for consumers who don't need MLS-specific labels
- Matches expected crypto library interface

**Workaround**: Use `signWithLabel`/`verifyWithLabel` directly (current plan)

### 3. Add KeyPackageBundle Serialization Methods
**Priority**: MEDIUM  
**Current Issue**: No direct serialization methods for KeyPackageBundle  
**Current State**: TLS codec exists but no convenience methods  

**Requested Change**:
```zig
// In key_package.zig, add to KeyPackageBundle:
pub fn serialize(self: *const KeyPackageBundle, allocator: Allocator) ![]u8 {
    // Use tls_codec to serialize the key_package
    return self.key_package.serialize(allocator);
}

pub fn deserialize(allocator: Allocator, data: []const u8) !KeyPackageBundle {
    // Parse using tls_codec and reconstruct bundle
    const key_package = try KeyPackage.deserialize(allocator, data);
    // Note: This would need private key reconstruction logic
    return KeyPackageBundle{ .key_package = key_package, /* ... */ };
}
```

**Why Needed**:
- Need to serialize KeyPackages for Nostr events
- Currently must manually use TLS codec
- Bundle keeps private keys with public key package

**Workaround**: Use tls_codec directly for serialization (current plan)

## 🔧 Medium Priority Changes

### 4. Add Direct MlsGroup Creation from Existing Key
**Priority**: MEDIUM  
**Current Issue**: Complex group creation API  
**Current State**: Need to understand the full group creation flow  

**Requested Change**:
```zig
// In mls_group.zig, add convenience method:
pub fn createFromKeyPackage(
    allocator: Allocator,
    key_package_bundle: *KeyPackageBundle,
    group_extensions: []const Extension
) !MlsGroup {
    // Simplified group creation
}
```

**Why Needed**:
- Easier integration for new group creation
- Less boilerplate for common use case

### 5. Add Nostr Extension Helpers
**Priority**: MEDIUM  
**Current Issue**: NostrGroupData exists but need more helpers  
**Current State**: Basic NostrGroupData extension available  

**Requested Change**:
```zig
// In nostr_extensions.zig, add:
pub fn createNostrGroupExtensions(
    allocator: Allocator,
    group_id: []const u8,
    relay_urls: []const []const u8,
    creator_pubkey: []const u8,
    metadata: ?[]const u8
) ![]Extension {
    // Helper to create standard Nostr group extensions
}
```

**Why Needed**:
- Standardize Nostr-specific extension creation
- Reduce boilerplate for NIP-EE integration

## 📚 Documentation Improvements

### 6. Add Complete API Examples
**Priority**: LOW  
**Current Issue**: Limited usage examples  
**Current State**: Some basic examples exist  

**Requested Change**:
- Add complete KeyPackage creation example
- Add MlsGroup usage example
- Add Nostr integration example
- Document all public APIs

### 7. Add Test Vectors Documentation
**Priority**: LOW  
**Current Issue**: Hard to verify correct implementation  
**Current State**: test_vectors.zig exists but not well documented  

**Requested Change**:
- Document expected inputs/outputs for test vectors
- Add interoperability test examples
- Document wire format compatibility

## 🎬 Implementation Timeline

### Phase 1 (Immediate - Current Blockers)
1. **Expose HPKE module** - Unblocks our HPKE implementation
2. **Add signing convenience methods** - Simplifies crypto integration

### Phase 2 (Short-term - Nice to Have)  
3. **KeyPackage serialization helpers** - Improves wire format handling
4. **MlsGroup creation helpers** - Simplifies group management

### Phase 3 (Long-term - Polish)
5. **Nostr extension helpers** - Better NIP-EE integration
6. **Documentation improvements** - Better developer experience

## 📋 Change Request Summary

**CRITICAL for our integration**:
- ✅ HPKE module exposure (1 line change)
- ✅ CipherSuite signing methods (10 lines)

**HELPFUL for our integration**:
- 📦 KeyPackage serialization (moderate effort)
- 📦 Group creation helpers (moderate effort)

**NICE to have**:
- 📚 Documentation improvements
- 🛠️ Nostr-specific helpers

## 🤝 Contributing Back

Once we have a working integration, we should:
1. **Submit PRs** for the critical changes (HPKE exposure, signing methods)
2. **Share usage examples** from our integration
3. **Report any bugs** we discover during integration
4. **Document integration patterns** for other consumers

## 📞 Contact

If any mls_zig maintainers see this:
- We're actively integrating mls_zig into a Nostr MLS implementation
- Happy to collaborate on API improvements
- Can provide real-world usage feedback
- Willing to contribute back improvements

**Current Integration Repository**: `nostr_zig` (Paul's project)
**Integration Status**: 2/13 functions implemented, actively working on remaining functions