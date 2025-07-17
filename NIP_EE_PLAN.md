# NIP-EE Implementation Plan

## Current Issues

### 1. `generateValidSecp256k1Key` Function is Broken

**Problem**: The `generateValidSecp256k1Key` function in `crypto.zig` is designed to take a seed and derive a valid key from it using SHA256 hashing. However:
- It's being misused throughout the codebase as a "validator" for already-valid keys
- It ALWAYS modifies the input, even if the input is already a valid secp256k1 key
- This causes valid keys to become invalid when passed through NIP-44 encryption

**Evidence**: 
- `wasm_nip44_encrypt` calls this function on the exporter secret, modifying it
- Our debug test shows that keys from `wasm_create_identity` work 80% of the time
- But after passing through `generateValidSecp256k1Key`, they fail 60% of the time

**Root Cause**: The function is not idempotent - it's a key derivation function, not a validation function.

### 2. NIP-44 Encryption Inconsistency

**Problem**: NIP-44 encryption fails intermittently with "InvalidPublicKey" errors
- The `wasm_nip44_encrypt` function modifies the input key before use
- This modification sometimes produces invalid keys

## Solutions

### 1. Replace `generateValidSecp256k1Key` with Proper Functions

We need TWO separate functions:
1. `validateSecp256k1Key(key: [32]u8) bool` - Just checks if a key is valid, doesn't modify
2. `deriveValidKeyFromSeed(seed: [32]u8) ![32]u8` - Derives a valid key from arbitrary seed

### 2. Fix Key Generation Flow

- `generatePrivateKey()` should ALWAYS produce valid secp256k1 keys
- No need for post-processing or "fixing" keys after generation
- If a key fails validation, generate a new one, don't try to "fix" it

### 3. Fix NIP-44 Encryption

- Remove the `generateValidSecp256k1Key` call from `wasm_nip44_encrypt`
- Trust that the input is already a valid key
- Add validation without modification if needed

## Implementation Steps

1. [x] Create `validateSecp256k1Key` function that only validates
2. [x] Rename `generateValidSecp256k1Key` to `deriveValidKeyFromSeed` (kept alias for compatibility)
3. [x] Update `generatePrivateKey` to loop until it generates a valid key (already was doing this)
4. [x] Remove key modification from `wasm_nip44_encrypt` and `wasm_nip44_decrypt`
5. [x] Update nip_ee.zig to use `deriveValidKeyFromSeed` for exporter secrets
6. [x] Test that NIP-44 encryption works consistently

## Results

All tests now pass! The key insights were:
- `generateValidSecp256k1Key` is a key derivation function, not a validation function
- Exporter secrets from SHA256 hashes need to be converted to valid keys using derivation
- Keys from `wasm_create_identity` are already valid and shouldn't be modified
- Added `validateSecp256k1Key` for non-modifying validation
- Fixed `wasm_nip44_encrypt/decrypt` to validate without modifying
- Fixed `encryptWithExporterSecret/decryptWithExporterSecret` to properly derive keys

## Testing Strategy

- Run the same encryption 100 times to ensure consistency
- Test with keys from different sources (generated, derived, imported)
- Verify that valid keys remain valid through all operations