# Epoch Secrets Derivation Implementation Plan

## Overview
According to RFC 9420, MLS uses a key schedule to derive epoch secrets from commit secrets. Our current implementation is incomplete - it derives secrets directly from init_secret without following the proper key schedule.

## Current State Analysis

### What We Have:
1. **Basic secret derivation** in `groups.zig` that derives all secrets from init_secret
2. **Placeholder epoch secrets** in several places (hardcoded zeros)
3. **CipherSuite support** in mls_zig with `deriveSecret()` and `expandWithLabel()`
4. **Test vectors** in mls_zig for key-schedule validation

### What's Missing:
1. **Proper key schedule implementation** following RFC 9420 Section 8
2. **Joiner secret derivation** from commit_secret and PSK
3. **Member/Welcome secret derivation** from joiner_secret
4. **Epoch secret derivation** from member_secret
5. **Application secrets derivation** from epoch_secret
6. **Confirmation key computation**
7. **Init secret for next epoch**

## RFC 9420 Key Schedule

```
                    commit_secret
                         |
                         V
    psk_secret (or 0) -> Extract = joiner_secret
                         |
                         +--> Derive-Secret(., "member")
                         |    = member_secret
                         |
                         +--> Derive-Secret(., "welcome")
                         |    = welcome_secret  
                         |
                         +--> Derive-Secret(., "epoch")
                              = epoch_secret
                              |
                              +--> Derive-Secret(., "sender data")
                              |    = sender_data_secret
                              |
                              +--> Derive-Secret(., "encryption")
                              |    = encryption_secret
                              |
                              +--> Derive-Secret(., "exporter")
                              |    = exporter_secret
                              |
                              +--> Derive-Secret(., "external")
                              |    = external_secret
                              |
                              +--> Derive-Secret(., "confirm")
                              |    = confirmation_key
                              |
                              +--> Derive-Secret(., "membership")
                              |    = membership_key
                              |
                              +--> Derive-Secret(., "resumption")
                              |    = resumption_psk
                              |
                              +--> Derive-Secret(., "authentication")
                                   = epoch_authenticator
```

## Implementation Tasks

### 1. Create key_schedule.zig module in mls_zig
```zig
// deps/mls_zig/src/key_schedule.zig
pub const KeySchedule = struct {
    cipher_suite: CipherSuite,
    
    pub fn deriveJoinerSecret(
        self: KeySchedule,
        allocator: Allocator,
        commit_secret: []const u8,
        psk_secret: ?[]const u8,
    ) !VarBytes;
    
    pub fn deriveMemberSecret(
        self: KeySchedule,
        allocator: Allocator,
        joiner_secret: []const u8,
        group_context: []const u8,
    ) !VarBytes;
    
    pub fn deriveEpochSecrets(
        self: KeySchedule,
        allocator: Allocator,
        joiner_secret: []const u8,
        commit_secret: []const u8,
        group_context: []const u8,
    ) !EpochSecrets;
};
```

### 2. Update EpochSecrets structure in mls_zig
```zig
pub const EpochSecrets = struct {
    joiner_secret: VarBytes,
    member_secret: VarBytes,
    welcome_secret: VarBytes,
    epoch_secret: VarBytes,
    sender_data_secret: VarBytes,
    encryption_secret: VarBytes,
    exporter_secret: VarBytes,
    epoch_authenticator: VarBytes,
    external_secret: VarBytes,
    confirmation_key: VarBytes,
    membership_key: VarBytes,
    resumption_psk: VarBytes,
    init_secret: VarBytes,
};
```

### 3. Fix deriveEpochSecrets in groups.zig
- Use proper key schedule instead of deriving from init_secret
- Follow the derivation chain: commit_secret → joiner_secret → member_secret → epoch_secret → application secrets

### 4. Implement commit secret generation
- For initial group: derive from random init_secret
- For commits: derive from path secrets and group context

### 5. Add key schedule tests
- Unit tests for each derivation step
- Integration with key-schedule test vectors
- Verify against OpenMLS test vectors

### 6. Update state machine to use proper epoch secrets
- Remove placeholder epoch secrets (zeros)
- Use KeySchedule for all epoch transitions

## Test Strategy

1. **Unit Tests**:
   - Test each derivation function individually
   - Verify against known test vectors
   - Test error cases

2. **Integration Tests**:
   - Full key schedule derivation
   - Group creation with proper secrets
   - Epoch advancement with new secrets

3. **Test Vectors**:
   - Run key-schedule.json test vectors
   - Add debug logging to compare our values
   - Document any incompatibilities

## Priority Order

1. **High Priority** (Required for basic functionality):
   - KeySchedule module structure
   - deriveJoinerSecret implementation
   - deriveEpochSecrets implementation
   - Update groups.zig to use KeySchedule

2. **Medium Priority** (Required for full compliance):
   - Commit secret generation
   - PSK support
   - Confirmation key validation
   - Welcome secret usage

3. **Low Priority** (Nice to have):
   - Resumption PSK
   - External join support
   - Performance optimizations

## Success Criteria

1. All key-schedule test vectors pass
2. Groups created with proper epoch secrets (not zeros)
3. Epoch secrets change correctly on commits
4. Exporter secret works for NIP-44 encryption
5. Welcome messages use proper welcome_secret

## References

- RFC 9420 Section 8: Key Schedule
- OpenMLS key-schedule test vectors
- MLS test vector repository: https://github.com/mlswg/mls-implementations/tree/main/test-vectors