# MLS NotImplemented Functions Summary

Based on my search through the codebase, here are all the `NotImplemented` errors in the MLS implementation:

## 1. **provider.zig** - Cryptographic Provider Functions (5 functions)

### Ed25519 Signature Operations
- **`defaultSign`** (line 115) - Sign data with Ed25519 private key
- **`defaultVerify`** (line 122) - Verify Ed25519 signature

### HPKE (Hybrid Public Key Encryption) Operations
- **`defaultHpkeSeal`** (line 131) - Encrypt data using HPKE
- **`defaultHpkeOpen`** (line 140) - Decrypt data using HPKE
- **`defaultHpkeGenerateKeyPair`** (line 145) - Generate HPKE key pair

Note: HKDF functions (`defaultHkdfExpand` and `defaultHkdfExtract`) are already implemented.

## 2. **nip_ee.zig** - Wire Format Serialization (2 functions)

### Key Package Serialization
- **`deserializeKeyPackage`** (line 322) - Parse MLS key package from wire format
- **`deserializeWelcome`** (line 335) - Parse MLS welcome message from wire format

Note: The corresponding `serialize` functions currently return placeholder data.

## 3. **groups.zig** - Group Operations (1 function)

### Commit Processing
- **`createAndProcessCommit`** (line 418) - Create and process MLS commit messages

## 4. **messages.zig** - Message Parsing (1 function)

### Ciphertext Parsing
- **`parseMLSCiphertext`** (line 481) - Parse MLS ciphertext from wire format

## 5. **welcomes.zig** - Welcome Message Handling (2 functions)

### Welcome Serialization
- **`parseWelcome`** (line 252) - Parse serialized welcome message
- **`serializeWelcome`** (line 260) - Serialize welcome message to wire format

## 6. **key_packages.zig** - Key Package Handling (2 functions)

### Key Package Wire Format
- **`parseKeyPackage`** (line 163) - Parse key package from wire format
- **`serializeKeyPackage`** (line 174) - Serialize key package to wire format

---

## Summary

Total NotImplemented functions: **13**

### By Category:
- **Cryptographic Operations**: 5 (Ed25519 signatures, HPKE)
- **Wire Format Serialization/Parsing**: 8 (key packages, welcomes, messages)

### What mls_zig Can Potentially Provide:

Based on the debug scripts that successfully import mls_zig, we know it provides:
- `cipher_suite` - Including HKDF operations (already being used)
- Potentially HPKE implementations
- Potentially wire format serialization utilities

### Recommended Implementation Order:

1. **Explore mls_zig API** - Determine what functionality is already available
2. **HPKE Operations** - These are critical for MLS group key distribution
3. **Ed25519 Signatures** - Required for MLS authentication
4. **Wire Format Serialization** - Needed for interoperability
5. **Group Commit Processing** - Core MLS group management functionality