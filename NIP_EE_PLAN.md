# NIP-EE Implementation Plan

## ✅ Current Status (2025-07-19) - TreeKEM Complete! 🎉

### **Foundation Complete**
- ✅ **WASM Build System**: All POSIX compatibility issues resolved
- ✅ **Vendored Dependencies**: Self-contained `deps/` structure with `mls_zig`, `zig-hpke`, `secp256k1`, `bech32`
- ✅ **Comptime Generic HPKE**: Fully WASM-compatible, zero runtime function pointers
- ✅ **Random Generation**: WASM-compatible dependency injection pattern throughout
- ✅ **Memory Management**: Proper alignment and cleanup for WASM/JS interop
- ✅ **Test Coverage**: 57/61 tests passing (93.4% success rate)
- ✅ **TreeKEM Implementation**: Full tree-based key agreement using `mls_zig`
  - Test verified: "TreeKEM encryption to members" test passing
  - Ready for integration with MLS state machine for key rotation

### **Core NIP-EE Features Working**
- ✅ **Welcome Events (kind: 444)**: Complete implementation with NIP-59 gift-wrapping
- ✅ **MLS State Machine**: Real implementation with epoch management
- ✅ **Group Operations**: Create, join, member management
- ✅ **Key Generation**: secp256k1 and Ed25519 cryptography
- ✅ **NIP-44 Encryption**: Consistent encryption/decryption with exporter secrets
- ✅ **Visualizer Integration**: Full workflow demonstration in browser

### **Technical Architecture**
- ✅ **Real MLS Types**: Using actual `mls_zig` types (no fake implementations)
- ✅ **WASM State Machine**: Thin wrapper functions in `wasm_state_machine.zig`
- ✅ **TypeScript Integration**: Comprehensive test suite in `test_state_machine.ts`
- ✅ **Shared Crypto**: Consolidated HKDF and crypto utilities

## 🎯 Next Priorities

### **High Priority - Core Features**
1. **✅ TreeKEM Implementation** - Enable full MLS tree-based key agreement
   - ✅ Used vendored `mls_zig` + comptime generic HPKE
   - ✅ Implemented encryption/decryption with proper tree operations
   - ✅ Added Welcome message HPKE operations
   - ✅ Created separate `tree_kem.zig` module to avoid comptime issues

2. **🔄 Last Resort KeyPackages** - Minimize race conditions
   - Implement `last_resort` extension in KeyPackage events
   - Add proper KeyPackage lifecycle management

3. **🔄 Group Admin Controls** - Administrative features
   - Implement `admin_pubkeys` from nostr_group_data extension
   - Add admin-only member removal restrictions

4. **🔄 Signing Key Rotation** - Post-compromise security
   - Implement automatic key rotation
   - Add proper key lifecycle management

### **Medium Priority - Enhanced Features**
1. **🔄 Application Message Types** - Support kind 9 (chat), kind 7 (reactions)
2. **🔄 Ephemeral Keypairs** - Use new keypair for each Group Event (kind: 445)
3. **🔄 KeyPackage Deletion** - Delete consumed KeyPackages from relays
4. **🔄 MLS Protocol Version Support** - Handle `mls_protocol_version` tag

### **Code Consolidation Opportunities**
Replace custom implementations with direct `mls_zig` calls:
1. **`groups.zig:createGroup()`** → `mls_zig.mls_group.MlsGroup.createGroup()`
2. **`key_packages.zig:generateKeyPackage()`** → `mls_zig.key_package.KeyPackageBundle.init()`
3. **`serialization.zig`** → `mls_zig.tls_codec` for proper MLS wire format
4. **`crypto_utils.zig`** → `mls_zig.cipher_suite` HKDF operations

## 🚧 Remaining NIP-EE Features

### **Core MLS Protocol**
- [ ] **Ciphersuite Selection** - Support multiple ciphersuites beyond default
- [ ] **MLS Extensions Support** - Handle arbitrary extension IDs in KeyPackage events

### **Group Management**
- [ ] **Group Name/Description** - Store and display group metadata from extension
- [ ] **Relay List Management** - Use relay lists from nostr_group_data extension
- [ ] **Proposal/Commit Ordering** - Handle race conditions with created_at timestamps

### **Key Management**
- [ ] **Multiple KeyPackages** - Support publishing multiple KeyPackages with different parameters
- [ ] **KeyPackage Relay List Event** - Implement kind 10051 for KeyPackage discovery

### **Security Features**
- [ ] **Forward Secrecy** - Delete keys immediately after use
- [ ] **Post-compromise Security** - Regular key rotation
- [ ] **Message Authentication** - Verify sender identity matches inner event pubkey

### **Advanced Features**
- [ ] **Multi-device Support** - Handle multiple clients per user
- [ ] **Large Group Support** - Handle groups > 150 members (light welcomes)
- [ ] **Cross-client Compatibility** - Support "client" tag for UX improvements
- [ ] **Group State Recovery** - Retain previous states for fork recovery

### **Relay Integration**
- [ ] **Relay Acknowledgment** - Wait for relay confirmation before applying commits
- [ ] **Multi-relay Publishing** - Publish to multiple relays from relay lists
- [ ] **Protected Events** - Implement NIP-70 protected event support ("-" tag)

## 🔧 Technical Details

### **Key Files**
- `src/wasm_state_machine.zig` - Real MLS state machine WASM wrapper
- `wasm_tests/test_state_machine.ts` - Comprehensive test suite
- `deps/mls_zig/` - Vendored MLS implementation with random injection
- `deps/zig-hpke/` - Vendored HPKE with comptime generic architecture
- `src/mls/provider.zig` - Updated to use comptime generic HPKE API
- `src/mls/tree_kem.zig` - TreeKEM operations using real `mls_zig` implementation

### **Build Commands**
- `zig build` - Native build
- `zig build wasm` - WASM build (generates `visualizer/src/nostr_mls.wasm`)
- `zig build test` - Run test suite

### **Current Blockers**
- **None!** 🎉 All major blockers (HPKE, WASM, dependencies) resolved

---

*This plan focuses on current status and next steps. For historical context, see git history.*