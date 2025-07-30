# NIP-EE Integration Testing

## Overview

This document outlines our integration testing strategy for the nostr_zig NIP-EE (MLS over Nostr) implementation. Our goal is to achieve full interoperability with other NIP-EE implementations, starting with Whitenoise.

## Current Status ✅

### Completed Features
- ✅ **Keypair Generation**: Native Nostr keypair generation with bech32 encoding
- ✅ **KeyPackage Creation**: Real TLS-compliant MLS KeyPackages (242 bytes)
- ✅ **KeyPackage Publishing**: Kind 443 events with proper NIP-EE tags
- ✅ **Relay Integration**: Publishing and fetching events from relays
- ✅ **Roundtrip Testing**: Complete publish/fetch/parse cycle verification
- ✅ **KeyPackage Parsing**: Full TLS deserialization with key extraction

### Test Results
```bash
# Successful roundtrip test output:
✅ Relay is running
✅ Successfully retrieved KeyPackage event from relay!
✅ Content matches!
✅ MLS metadata is correct!
  Protocol version: 0001 (MLS 1.0)
  Cipher suite: 0001 (MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
  Total size: 242 bytes (proper TLS serialization)
```

### Latest Updates (Jan 2025)
- Implemented complete `fetch-keypackage` command with full parsing
- Successfully parses TLS-serialized KeyPackages using `mls_zig.key_package_flat.KeyPackage.tlsDeserialize`
- Extracts and displays all three keys: init_key, encryption_key, signature_key
- **NEW**: Replaced `nak` dependency with native WebSocket client for relay interactions
- **NEW**: Created reusable `relay_utils` module for common relay operations
- Ready for external client integration testing

### Resolved Issues
- ✅ Memory leaks in event parsing (fixed by proper ownership transfer)

## Integration Architecture

### Our Implementation (nostr_zig)
- **Language**: Zig with mls_zig library
- **Architecture**: Flat structs for WASM compatibility
- **Cryptography**: Real X25519/Ed25519 keys, no placeholders
- **Serialization**: TLS-compliant wire format (RFC 9420)
- **Relay Client**: Native WebSocket implementation (no external dependencies)
- **Common Patterns**: `relay_utils` module for reusable relay operations

### External Implementation (Whitenoise)
- **Language**: Rust with OpenMLS
- **Features**: Full MLS group management
- **Testing**: Provides granular commands for debugging

### Test Relay
- **Default**: ws://localhost:10547 (using `nak serve --verbose`)
- **Events**: Kind 443 (KeyPackages), 444 (Welcome), 445 (Group messages)

## Integration Test Plan

### Phase 1: KeyPackage Interoperability ✅ (Current)
1. **Our KeyPackage Publishing** ✅
   - Generate keypair
   - Create MLS KeyPackage
   - Publish as kind 443 event
   - Verify relay storage

2. **External KeyPackage Parsing** 🔄 (Next Step)
   - Fetch Whitenoise KeyPackages from relay
   - Parse TLS serialization
   - Validate MLS structure
   - Extract public keys

### Phase 2: Group Creation (Upcoming)
3. **Create Group with External Member**
   - Use external KeyPackage to add member
   - Generate Welcome message (kind 444)
   - Publish with NIP-59 gift wrapping

4. **Join External Group**
   - Receive Welcome from Whitenoise
   - Process MLS Welcome
   - Initialize group state

### Phase 3: Messaging (Future)
5. **Message Exchange**
   - Send encrypted messages (kind 445)
   - Two-layer encryption (MLS + NIP-44)
   - Verify decryption by external client

## Test Commands

### Current Commands
```bash
# Generate new keypair
./zig-out/bin/nostr_zig generate

# Publish KeyPackage
./zig-out/bin/nostr_zig publish-keypackage --sec <key>

# Fetch and parse KeyPackage (fully implemented with native client!)
./zig-out/bin/nostr_zig fetch-keypackage <npub>

# Example successful fetch:
./zig-out/bin/nostr_zig fetch-keypackage npub1dlc4xrpljk6h07aelzm8ahlndeuwresrzxpv86wnad9hfjjhj64qe5dvgs
# Output: Successfully parses and displays KeyPackage details
```

### Upcoming Commands (Phase 2)
```bash
# Create a group and send welcome to a member
./zig-out/bin/nostr_zig create-welcome <target_npub> --sec <key> [OPTIONS]
# Options:
#   --name <group_name>         Group name (default: "Test Group")
#   --description <desc>        Group description (default: "Test MLS Group")
#   --relay <url>              Relay URL (default: ws://localhost:10547)
#                              Can be specified multiple times

# Example:
./zig-out/bin/nostr_zig create-welcome npub1... --sec 01 --name "Dev Chat" --description "MLS test group" --relay ws://localhost:10547
```

### Test Scripts
```bash
# Full roundtrip test
./test_keypackage_roundtrip.sh

# Parse KeyPackage content
./parse_keypackage.sh <hex_content>
```

## Next Steps

### 1. Test External KeyPackage Parsing (Ready!)
```bash
# After Whitenoise publishes their KeyPackage:
# cargo run --bin external_integration_test -- init

# Fetch and parse their KeyPackage (replace with actual npub)
./zig-out/bin/nostr_zig fetch-keypackage npub1<whitenoise_pubkey>

# Expected output:
# ✅ Successfully parsed KeyPackage!
# KeyPackage Details:
#   Protocol Version: 0x0001 (MLS 1.0)
#   Cipher Suite: 1 (X25519/AES128-GCM/Ed25519)
#   Init Key: <32-byte hex>
#   Encryption Key: <32-byte hex>
#   Signature Key: <32-byte hex>
#   Credential Length: <bytes>
```

### 2. Implement Missing Functionality
- [x] ~~Complete fetch-keypackage command with actual parsing~~
- [ ] Add create-welcome command (create group + send invite)
- [ ] Add join-group command (process welcome messages)
- [ ] Add group messaging commands

### 3. create-welcome Implementation Plan

The `create-welcome` command will use existing MLS functionality to:

1. **Fetch target member's KeyPackage**
   - Use `relay_utils.fetchKeyPackage()` to get the target's KeyPackage
   - Parse it with `mls_zig.key_package_flat.KeyPackage.tlsDeserialize()`

2. **Create MLS Group**
   - Use `mls.groups.createGroup()` with:
     - Creator's private key
     - Group parameters (name, description, relays)
     - Initial members array (just the target's KeyPackage)
   - This returns `GroupCreationResult` with:
     - Initial group state
     - Welcome messages for members
     - Used KeyPackages

3. **Create Welcome Event**
   - Use `mls.welcome_events.WelcomeEvent.create()` to:
     - Create NIP-EE kind 444 event
     - Include MLS Welcome message
     - Reference KeyPackage event ID
     - Apply NIP-59 gift wrapping for metadata protection

4. **Publish Welcome Event**
   - Use `relay_utils.publishEvent()` to send to relay
   - The welcome is encrypted and only readable by the recipient

**Implementation Steps in main.zig:**
```zig
// 1. Add new command enum value
const Command = enum {
    // ... existing commands
    create_welcome,
};

// 2. Add to CLI args parsing
// Parse target npub, group name, description, relays

// 3. Add handler function
fn handleCreateWelcomeCommand(allocator, args, writer) {
    // a. Fetch target's KeyPackage
    // b. Create MLS group with target as initial member
    // c. Create Welcome event (kind 444, NIP-59 wrapped)
    // d. Publish to relay
}
```

**Required Components (Already Implemented):**
- ✅ `relay_utils.fetchKeyPackage()` - Fetch KeyPackages from relay
- ✅ `mls.groups.createGroup()` - Create MLS groups
- ✅ `mls.welcome_events.WelcomeEvent.create()` - Create welcome events
- ✅ `nip59.createGiftWrappedEvent()` - NIP-59 gift wrapping
- ✅ `relay_utils.publishEvent()` - Publish to relay
- ✅ KeyPackage parsing and serialization

The command combines these existing components to provide a simple interface for creating groups and inviting members.

### 4. Create Integration Test Script
```bash
#!/bin/bash
# integration_test_whitenoise.sh

# Start relay
nak serve --verbose &
RELAY_PID=$!

# Initialize Whitenoise
cd ../whitenoise
cargo run --bin external_integration_test -- init
WHITENOISE_PUBKEY=$(cat test-data/test_state.json | jq -r .account_pubkey)
WHITENOISE_NPUB=$(cargo run --bin external_integration_test -- show-npub)

# Initialize nostr_zig
cd ../nostr_zig
NOSTR_ZIG_KEYPAIR=$(./zig-out/bin/nostr_zig generate)
NOSTR_ZIG_PRIVKEY=$(echo "$NOSTR_ZIG_KEYPAIR" | grep "Private key (hex)" | awk '{print $4}')
NOSTR_ZIG_NPUB=$(echo "$NOSTR_ZIG_KEYPAIR" | grep "Public key (npub)" | awk '{print $4}')

# Both publish their KeyPackages
./zig-out/bin/nostr_zig publish-keypackage --sec $NOSTR_ZIG_PRIVKEY
cd ../whitenoise && cargo run --bin external_integration_test -- publish-keypackage

# Test fetching each other's KeyPackages
cd ../nostr_zig
./zig-out/bin/nostr_zig fetch-keypackage $WHITENOISE_NPUB

# Test group creation and welcome
./zig-out/bin/nostr_zig create-welcome $WHITENOISE_NPUB --sec $NOSTR_ZIG_PRIVKEY \
  --name "Integration Test Group" \
  --description "Testing NIP-EE interoperability"

# Whitenoise processes the welcome (when implemented)
cd ../whitenoise
cargo run --bin external_integration_test -- process-welcome

# Further tests...
```

## KeyPackage Format Details

### Our KeyPackages (nostr_zig)
```
Total: 242 bytes
- Protocol Version: 2 bytes (0x0001)
- Cipher Suite: 2 bytes (0x0001)
- Init Key: 1 + 32 bytes (length + X25519 public key)
- LeafNode:
  - Encryption Key: 1 + 32 bytes
  - Signature Key: 1 + 32 bytes
  - Credential: 2 + N bytes (length + data)
  - Capabilities: 2 bytes (empty)
  - Source: 1 byte (0x01 = by_value)
  - Extensions: 2 bytes (empty)
- Extensions: 2 bytes (empty)
- Signature: 2 + 64 bytes (length + Ed25519 signature)
```

### Expected External Format
Should match RFC 9420 Section 7.2 - we need to verify:
- Same protocol version (0x0001)
- Compatible cipher suite
- Valid public keys
- Proper TLS encoding

## Success Criteria

### Phase 1 ✅
- [x] Generate valid keypairs
- [x] Create TLS-compliant KeyPackages
- [x] Publish to relay
- [x] Fetch from relay
- [x] Parse external KeyPackages

### Phase 2
- [ ] Create groups with external members
- [ ] Process external Welcome messages
- [ ] Join external groups

### Phase 3
- [ ] Exchange encrypted messages
- [ ] Maintain forward secrecy
- [ ] Handle epoch updates

## Debugging Tools

### Relay Monitoring
```bash
# Watch all KeyPackage events
nak req -k 443 ws://localhost:10547

# Watch specific author
nak req -k 443 -a <pubkey_hex> ws://localhost:10547

# Pretty print with jq
nak req -k 443 ws://localhost:10547 | jq .
```

### Content Analysis
```bash
# Decode hex KeyPackage
echo <hex> | xxd -r -p | od -t x1

# Check TLS structure
./parse_keypackage.sh <hex>
```

## Known Issues & Solutions

### Issue: Bech32 decoding fails
**Solution**: Ensure npub is exactly 63 characters (npub1 + 58 chars)

### Issue: KeyPackage size mismatch
**Solution**: Verify TLS length prefixes are correct (u8 vs u16)

### Issue: Signature verification fails
**Solution**: Check MLS signature label ("MLS 1.0 KeyPackageTBS")

## References

- [NIP-EE Specification](../EE.md)
- [MLS RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html)
- [Whitenoise Integration Plan](../../whitenoise/EXTERNAL_INTEGRATION_PLAN.md)
- [nostr_zig Development Guide](DEVELOPMENT.md)