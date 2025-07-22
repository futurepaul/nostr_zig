# FIX_MLS.md - Refactoring Plan to Use mls_zig Library

## Executive Summary

We currently have competing MLS implementations: our custom `state_machine.zig` with its own types, `types.zig` with standard MLS types, and the vendored `mls_zig` library. This creates type conflicts that block Welcome message functionality. 

**Solution**: Refactor to use `mls_zig` directly as the single source of truth for MLS operations.

## Current Problems

### 1. Type System Conflicts
- `state_machine.zig` defines its own `GroupContext` incompatible with `types.zig`
- `MemberInfo` in `types.zig` lacks critical fields needed by state machine
- Type mismatches prevent Welcome message creation/processing
- Can't convert between different type representations

### 2. Duplicate Implementations
- Custom group creation logic vs `mls_zig.MlsGroup.createGroup()`
- Custom key package generation vs `mls_zig.KeyPackageBundle.init()`
- Manual serialization vs `mls_zig.tls_codec`
- Custom crypto utils vs `mls_zig.cipher_suite`

### 3. Blocked Features
- Welcome messages can't be created due to type conflicts
- Bob can't properly join groups (copies state instead)
- Epoch doesn't advance when adding members
- Different exporter secrets derived from same state

## Refactoring Strategy

### Phase 1: Type System Migration (CRITICAL)

#### 1.1 Replace Custom Types with mls_zig Types
```zig
// OLD: state_machine.zig
pub const GroupContext = struct {
    group_id: [32]u8,  // Raw array
    // ...
};

// NEW: Use mls_zig directly
const GroupContext = mls_zig.mls_group.GroupContext;
```

#### 1.2 Update State Machine to Use MlsGroup
```zig
// OLD: Custom state management
pub const MLSStateMachine = struct {
    epoch: u64,
    members: std.ArrayList(Member),
    // ...
};

// NEW: Wrap mls_zig.MlsGroup
pub const MLSStateMachine = struct {
    mls_group: mls_zig.mls_group.MlsGroup,
    allocator: std.mem.Allocator,
    // Nostr-specific additions only
};
```

#### 1.3 Files to Update
- [ ] `src/mls/state_machine.zig` - Replace with thin wrapper around MlsGroup
- [ ] `src/mls/types.zig` - Remove, use mls_zig types directly
- [ ] `src/mls/groups.zig` - Replace createGroup with mls_zig version
- [ ] `src/mls/key_packages.zig` - Use KeyPackageBundle.init()
- [ ] `src/mls/serialization.zig` - Use mls_zig.tls_codec

### Phase 2: Welcome Message Implementation

#### 2.1 Enable Welcome Creation
```zig
// In commitProposals:
const welcome = try self.mls_group.generateWelcome(
    allocator,
    new_member_key_package,
    &mls_provider
);
```

#### 2.2 Enable Welcome Processing
```zig
pub fn joinFromWelcome(welcome_data: []const u8) !MLSStateMachine {
    const mls_group = try mls_zig.mls_group.MlsGroup.processWelcome(
        allocator,
        welcome_data,
        our_key_package,
        &mls_provider
    );
    return .{ .mls_group = mls_group, .allocator = allocator };
}
```

#### 2.3 Update WASM Exports
- [ ] `wasm_state_machine_create_welcome` - Return real Welcome data
- [ ] `wasm_state_machine_process_welcome` - Process real Welcome messages

### Phase 3: Consolidate Duplicate Code

#### 3.1 Key Package Operations
- [ ] Replace `key_packages.zig:generateKeyPackage()` with `mls_zig.KeyPackageBundle.init()`
- [ ] Replace `parseKeyPackage()` with mls_zig TLS codec deserialization
- [ ] Remove custom leaf node creation and signing logic
- [ ] Update tests to use mls_zig key packages

#### 3.2 Serialization 
- [ ] Replace entire `serialization.zig` with `mls_zig.tls_codec` usage
- [ ] Use `TlsWriter` and `TlsReader` for all MLS types
- [ ] Remove manual serialization functions
- [ ] Update all callers to use mls_zig serialization

#### 3.3 Extensions
- [ ] Replace custom `NostrGroupData` with `mls_zig.nostr_extensions.NostrGroupData`
- [ ] Use `mls_zig.nostr_extensions.addNostrGroupData()` helper
- [ ] Use `mls_zig.nostr_extensions.hasLastResort()` for checking
- [ ] Remove duplicate extension serialization code

#### 3.4 Crypto Operations
- [ ] Remove duplicate HKDF from `crypto_utils.zig` - use `mls_zig.cipher_suite`
- [ ] Keep custom Nostr key derivation (`deriveMlsSigningKeyForEpoch`)
- [ ] Verify mls_zig crypto operations work with our secp256k1

#### 3.5 Group Operations
- [ ] Investigate replacing `groups.zig:createGroup()` with `mls_zig.MlsGroup.createGroup()`
- [ ] Ensure Nostr-specific requirements are maintained
- [ ] Remove duplicate group initialization logic

#### 3.6 Tree Operations
- [ ] Continue using `mls_zig.tree_kem` (already doing this correctly)
- [ ] Remove any wrapper functions that don't add value
- [ ] Leverage their binary tree implementation directly

### Phase 4: Testing Strategy

#### 4.1 Unit Tests
- [ ] Test type conversions work correctly
- [ ] Verify Welcome message creation/processing
- [ ] Test epoch advancement on member addition
- [ ] Verify same exporter secrets derived by all members

#### 4.2 Integration Tests
- [ ] Full group lifecycle: create → add → remove → update
- [ ] Cross-compatibility with existing groups
- [ ] WASM integration tests
- [ ] Visualizer end-to-end test

#### 4.3 Migration Tests
- [ ] Ensure existing serialized states can be migrated
- [ ] Test backward compatibility where needed

## Implementation Order

1. **Week 1: Type System Migration**
   - Start with types.zig replacement
   - Update state_machine.zig to use MlsGroup
   - Fix compilation errors
   - Run existing tests

2. **Week 2: Welcome Messages**
   - Enable Welcome creation in commitProposals
   - Implement joinFromWelcome properly
   - Update WASM exports
   - Test with visualizer

3. **Week 3: Code Consolidation**
   - Remove duplicate implementations
   - Adopt mls_zig patterns throughout
   - Clean up unused code

4. **Week 4: Testing & Polish**
   - Comprehensive test coverage
   - Performance testing
   - Documentation updates

## Success Criteria

- [ ] Welcome messages work end-to-end
- [ ] Bob can join groups properly (no state copying)
- [ ] Epoch advances when members are added
- [ ] All members derive same exporter secret
- [ ] Visualizer shows correct MLS flow
- [ ] All tests pass
- [ ] No duplicate MLS implementations remain

## Risks & Mitigations

### Risk 1: mls_zig Has Incomplete Crypto
- **Mitigation**: Verify crypto operations, contribute fixes if needed
- **Fallback**: Keep our crypto layer as adapter

### Risk 2: Breaking Changes
- **Mitigation**: Create migration layer for existing data
- **Fallback**: Version the serialization format

### Risk 3: WASM Compatibility
- **Mitigation**: Test early, test often
- **Fallback**: Keep thin wrapper pattern

## What to Keep Custom

These implementations should remain as they provide Nostr-specific functionality:

1. **Nostr Event Integration** (`event_signing.zig`, `nip_ee.zig`)
   - Creating Nostr events from MLS operations
   - NIP-EE specific event types (443, 444, 445)
   - Integration with Nostr relay system

2. **NIP-44 Encryption Layer** (`nip44/`)
   - Double encryption pattern (MLS + NIP-44)
   - Nostr-specific encryption using exporter secrets

3. **Epoch-based Key Rotation** (`crypto_utils.zig:deriveMlsSigningKeyForEpoch`)
   - Custom signing key derivation per epoch
   - Integration with Nostr identity system

4. **Forward Secrecy Operations** (`forward_secrecy.zig`)
   - Secure memory clearing
   - Key lifecycle management specific to NIP-EE

5. **Relay Client** (`relay_client.zig`)
   - NIP-EE specific relay operations
   - Event filtering and subscription management

## Notes on mls_zig Library

### Strengths
- Complete MLS protocol implementation
- Proper extension system
- Good cipher suite abstraction
- TLS wire format support
- Tree management

### Caveats
- Some crypto is "vibes-based" (needs verification)
- EpochSecrets derivation incomplete
- Welcome encryption/decryption placeholder

### Integration Approach
1. Use their types and structures
2. Verify/fix crypto operations
3. Keep Nostr-specific logic separate
4. Contribute improvements back

## Next Steps

1. Create feature branch: `fix-mls-architecture`
2. Start with smallest change: replace types.zig imports
3. Fix compilation errors incrementally
4. Test each phase thoroughly
5. Update visualizer to match

This refactoring will unblock Welcome messages and create a cleaner, more maintainable architecture using the vendored MLS library as intended.