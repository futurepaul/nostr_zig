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

2. **✅ Last Resort KeyPackages** - Minimize race conditions
   - ✅ Implemented `last_resort` extension in all KeyPackage events
   - ✅ Added helper function to check for extension presence
   - ✅ Extension included in capabilities list

3. **✅ Group Admin Controls** - Administrative features
   - ✅ Implemented `admin_pubkeys` checking from nostr_group_data extension
   - ✅ Added admin-only restrictions for add/remove proposals
   - ✅ Added admin validation in commit operations

4. **✅ Signing Key Rotation** - Post-compromise security
   - ✅ Implemented automatic key rotation with epoch-based key derivation
   - ✅ Added configurable rotation policies (automatic/manual, rotation intervals)
   - ✅ Integrated automatic rotation triggers into epoch advancement
   - ✅ Created comprehensive tests for key rotation functionality

### **Medium Priority - Enhanced Features**
1. **🔄 Application Message Types** - Support kind 9 (chat), kind 7 (reactions)
2. **🔄 Ephemeral Keypairs** - Use new keypair for each Group Event (kind: 445)
3. **🔄 KeyPackage Deletion** - Delete consumed KeyPackages from relays
4. **🔄 MLS Protocol Version Support** - Handle `mls_protocol_version` tag

### **Low Priority - Code Quality**
1. **🔄 Memory Management Refactor** - Implement clearer ownership model
   - Document ownership in all structs
   - Add separate shallow/deep free functions
   - Consider arena allocators for group-scoped data
2. **🔄 Error Handling Consistency** - Standardize error types across modules
3. **🔄 Documentation** - Add comprehensive API documentation

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

### **Recent Fixes**
- ✅ **Key Generation Issues** - Fixed test failures with proper key generation
- ✅ **Memory Leaks** - Resolved all memory leaks in test suite
- ✅ **Admin Controls** - Implemented permission checks for add/remove operations
- ✅ **Last Resort Extension** - Added to all generated KeyPackages
- ✅ **Automatic Key Rotation** - Implemented epoch-based signing key rotation for post-compromise security

### **Memory Management Improvements Needed**
- **Ownership Clarity** - Current issues discovered while fixing leaks:
  - When `createGroup` consumes KeyPackages, ownership of sub-objects (credentials, etc.) is unclear
  - Some fields are shared between KeyPackage and group state, others are not
  - Led to double-free errors when trying to clean up properly
  
- **Proposed Solutions**:
  1. **Clear Ownership Model** - Document which structures own their data vs. borrow references
  2. **Deep Copy Option** - Add functions to deep-copy credentials when needed
  3. **Separate Free Functions** - Create `freeKeyPackageShallow` vs `freeKeyPackageDeep`
  4. **Reference Counting** - Consider reference counting for shared objects like credentials
  5. **Arena Allocator Pattern** - Use arena allocators for group-lifetime objects
  
- **Best Practices to Adopt**:
  - Always document ownership in struct comments
  - Use consistent naming: `owned_field` vs `borrowed_field`
  - Provide both consuming and non-consuming APIs where appropriate
  - Add debug mode ownership tracking

---

*This plan focuses on current status and next steps. For historical context, see git history.*