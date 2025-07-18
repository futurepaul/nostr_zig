# NIP-EE Implementation Plan

## ✅ Solved Issues (2025-07-18)

### 1. Key Validation Functions Fixed
- Created separate `validateSecp256k1Key` (validation-only) and `deriveValidKeyFromSeed` (key derivation) functions
- Fixed `wasm_nip44_encrypt/decrypt` to validate without modifying keys
- Ensured `generatePrivateKey()` always produces valid secp256k1 keys

### 2. NIP-44 Encryption Working Consistently
- Removed key modification from encryption/decryption functions
- Exporter secrets from SHA256 hashes are properly derived to valid keys
- All encryption tests pass consistently

### 3. UI Improvements Completed
- ✅ Messages box uses correct decryption method
- ✅ Bob gets NIP-44 exporter secret when joining group
- ✅ Exporter secret shown by default (no hide toggle)
- ✅ Messaging panels are wider (4-4-4 layout)
- ✅ Event inspector in center column below Nostr events
- ✅ Message Flow and Protocol State below message decryptor
- ✅ Global toast-style info panel replaces inline tooltips
- ✅ Full width page layout
- ✅ Group IDs match NIP-EE spec (32-byte hex, no prefix)
- ✅ Alice sees when Bob joins the group

## 🚧 TODO: Unimplemented NIP-EE Features

Based on the NIP-EE specification, the following features are not yet implemented:

### 1. Core MLS Protocol Features
- [ ] **MLS Protocol Version Support** - Need to handle `mls_protocol_version` tag (currently hardcoded to "1.0")
- [ ] **Ciphersuite Selection** - Support multiple ciphersuites beyond default (spec mentions "0x0001")
- [ ] **MLS Extensions Support** - Handle arbitrary extension IDs in KeyPackage events
- [ ] **Last Resort KeyPackages** - Implement `last_resort` extension to minimize race conditions

### 2. Group Management
- [ ] **Group Admin Controls** - Implement `admin_pubkeys` from nostr_group_data extension
- [ ] **Group Name/Description** - Store and display group metadata from extension
- [ ] **Relay List Management** - Use relay lists from nostr_group_data extension
- [ ] **Proposal/Commit Ordering** - Handle race conditions with created_at timestamps
- [ ] **Epoch Management** - Properly track and advance group epochs
- [ ] **Member Removal** - Allow admins to remove members from groups

### 3. Key Management
- [ ] **Signing Key Rotation** - Implement automatic rotation for post-compromise security
- [ ] **KeyPackage Deletion** - Delete consumed KeyPackages from relays
- [ ] **Multiple KeyPackages** - Support publishing multiple KeyPackages with different parameters
- [ ] **KeyPackage Relay List Event** - Implement kind 10051 for KeyPackage discovery

### 4. Message Types
- [ ] **Welcome Events (kind: 444)** - Implement NIP-59 gift-wrapped welcome messages
- [ ] **Application Message Types** - Support kind 9 (chat), kind 7 (reactions), etc.
- [ ] **Unsigned Inner Events** - Ensure inner Nostr events remain unsigned
- [ ] **Ephemeral Keypairs** - Use new keypair for each Group Event (kind: 445)

### 5. Security Features
- [ ] **Forward Secrecy** - Delete keys immediately after use
- [ ] **Post-compromise Security** - Regular key rotation
- [ ] **Device Compromise Protection** - Secure storage recommendations
- [ ] **Message Authentication** - Verify sender identity matches inner event pubkey

### 6. Advanced Features
- [ ] **Multi-device Support** - Handle multiple clients per user
- [ ] **Large Group Support** - Handle groups > 150 members (light welcomes)
- [ ] **Cross-client Compatibility** - Support "client" tag for UX improvements
- [ ] **Group State Recovery** - Retain previous states for fork recovery

### 7. Relay Integration
- [ ] **Relay Acknowledgment** - Wait for relay confirmation before applying commits
- [ ] **Multi-relay Publishing** - Publish to multiple relays from relay lists
- [ ] **Protected Events** - Implement NIP-70 protected event support ("-" tag)

## 📝 Implementation Priority

1. **High Priority** - Core functionality needed for basic operation:
   - Welcome Events (kind: 444)
   - Last Resort KeyPackages
   - Signing Key Rotation
   - Group Admin Controls

2. **Medium Priority** - Important for security and UX:
   - Ephemeral Keypairs for Group Events
   - KeyPackage Deletion
   - Epoch Management
   - Application Message Types

3. **Low Priority** - Advanced features:
   - Multi-device Support
   - Large Group Support
   - Cross-client Compatibility