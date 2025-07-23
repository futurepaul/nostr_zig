# FIX_WASM.md - Real mls_zig WASM Integration Plan

## Executive Summary

We currently have a **simplified WASM state machine** that demonstrates MLS concepts but doesn't use the real `mls_zig` library due to compilation issues. This plan outlines how to fix the underlying compatibility problems and integrate the full MLS protocol into WASM.

**Goal**: Enable real `mls_zig.MlsGroup` operations in WASM with complete cryptographic functionality.

## Current Status

### ✅ What Works Now
- **Simplified WASM Demo**: 76-byte state format with real crypto validation
- **Core Concepts**: Group init, member addition, epoch advancement, Welcome messages
- **Memory Management**: 32MB buffer allocation working
- **TypeScript Integration**: Complete test coverage for demo functions

### ❌ Current Limitations
- **No Real MLS Protocol**: Using minimal state instead of `mls_zig.MlsGroup`
- **Simplified Welcome Messages**: 44-byte format vs real MLS Welcome with HPKE
- **Missing TreeKEM**: No real tree-based key management
- **No Real Extensions**: Placeholder handling vs actual MLS extensions

## Root Cause Analysis

### 🔍 Compilation Errors Identified

**1. Missing TLS Codec APIs** (`mls_group.zig:267`, `mls_group.zig:273`)
```zig
// BROKEN: These don't exist in Zig 0.14.1
try writer.writeU16(@intFromEnum(self.cipher_suite));
const cipher_suite = @as(CipherSuite, @enumFromInt(try reader.readU16()));
```

**2. POSIX getrandom Unavailable** (`std/posix.zig:608`)
```zig
// BROKEN: getrandom not available in wasm32-freestanding
if (@TypeOf(system.getrandom) != void) {
```

**3. API Compatibility Issues**
- `mls_zig` developed against Zig nightly/master APIs
- Current codebase uses Zig 0.14.1 stable
- WASM target has additional constraints

## Strategic Approach

Following DEVELOPMENT.md principles: **"Use and Improve mls_zig"** rather than working around issues.

### Phase 1: Fix mls_zig Zig 0.14.1 Compatibility
### Phase 2: Resolve WASM-Specific Issues  
### Phase 3: Integrate Real MLS Operations
### Phase 4: Restore Full Functionality

---

## Phase 1: Fix mls_zig Zig 0.14.1 Compatibility

### 🎯 Objective
Make `mls_zig` compile cleanly with Zig 0.14.1 in native environment first.

### 🔧 TLS Codec API Migration

**Problem**: `writeU16`/`readU16` methods don't exist on allocator/slice types.

**Root Cause**: These were likely custom TLS codec methods that got removed or renamed.

**Strategy**: Implement proper TLS codec serialization for MLS wire format.

#### Investigation Steps
```bash
# 1. Find the original TLS codec implementation
cd deps/mls_zig
grep -r "writeU16\|readU16" .
grep -r "TlsWriter\|TlsReader" .

# 2. Check if tls_codec module exists
find . -name "*tls*" -o -name "*codec*"

# 3. Look for serialization patterns
grep -r "serialize\|deserialize" . | head -20
```

#### Implementation Plan
```zig
// Option A: Implement missing TLS codec methods
pub const TlsWriter = struct {
    allocator: std.mem.Allocator,
    buffer: std.ArrayList(u8),
    
    pub fn writeU16(self: *TlsWriter, value: u16) !void {
        const bytes = std.mem.toBytes(std.mem.nativeToBig(u16, value));
        try self.buffer.appendSlice(&bytes);
    }
    
    pub fn writeU32(self: *TlsWriter, value: u32) !void {
        const bytes = std.mem.toBytes(std.mem.nativeToBig(u32, value));
        try self.buffer.appendSlice(&bytes);
    }
};

pub const TlsReader = struct {
    data: []const u8,
    offset: usize = 0,
    
    pub fn readU16(self: *TlsReader) !u16 {
        if (self.offset + 2 > self.data.len) return error.InsufficientData;
        const bytes = self.data[self.offset..self.offset + 2];
        self.offset += 2;
        return std.mem.bigToNative(u16, std.mem.bytesToValue(u16, bytes[0..2]));
    }
    
    pub fn readU32(self: *TlsReader) !u32 {
        if (self.offset + 4 > self.data.len) return error.InsufficientData;
        const bytes = self.data[self.offset..self.offset + 4];
        self.offset += 4;
        return std.mem.bigToNative(u32, std.mem.bytesToValue(u32, bytes[0..4]));
    }
};
```

#### Files to Fix
- `deps/mls_zig/src/mls_group.zig` - Add TLS codec imports/implementations
- `deps/mls_zig/src/tls_codec.zig` - Create if missing
- Any other files using `writeU16`/`readU16`

---

## Phase 2: Resolve WASM-Specific Issues

### 🎯 Objective
Make `mls_zig` compatible with `wasm32-freestanding` target.

### 🔧 Random Number Generation Fix

**Problem**: `std.crypto.random` and `getrandom` not available in WASM.

**Solution**: Use our existing `wasm_random.zig` dependency injection pattern.

#### Implementation Strategy
```zig
// 1. Create WASM-compatible random function
// In src/wasm_random.zig - already exists, enhance it:
pub const WasmRandom = struct {
    pub fn bytes(buf: []u8) void {
        // Use existing getRandomValues from JavaScript
        @import("wasm_exports.zig").getRandomValues(buf.ptr, buf.len);
    }
    
    pub fn int(comptime T: type) T {
        var bytes: [@sizeOf(T)]u8 = undefined;
        self.bytes(&bytes);
        return std.mem.bytesToValue(T, &bytes);
    }
};

// 2. Modify mls_zig to accept random function parameter
// In deps/mls_zig/src/mls_group.zig:
pub fn createGroup(
    allocator: std.mem.Allocator,
    cipher_suite: CipherSuite,
    random_fn: ?*const fn([]u8) void, // NEW: Optional random function
    // ... other params
) !MlsGroup {
    const rng = random_fn orelse std.crypto.random.bytes;
    // Use rng() instead of std.crypto.random.bytes() throughout
}
```

#### Random Function Injection Points
- `MlsGroup.createGroup()` - Group initialization
- `KeyPackageBundle.init()` - KeyPackage generation  
- `MlsGroup.generateWelcome()` - Welcome message creation
- Any HPKE operations requiring randomness

### 🔧 Memory Management Optimization

**Current**: 32MB fixed buffer allocator
**Improvement**: More efficient allocation strategy

```zig
// Enhanced allocator for WASM
pub const WasmAllocator = struct {
    // Keep fixed buffer for small allocations
    small_buffer: [4 * 1024 * 1024]u8 = undefined, // 4MB
    small_fba: std.heap.FixedBufferAllocator,
    
    // Use GeneralPurposeAllocator for larger allocations
    gpa: std.heap.GeneralPurposeAllocator(.{}),
    
    pub fn allocator(self: *WasmAllocator) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .free = free,
            },
        };
    }
    
    fn alloc(ctx: *anyopaque, len: usize, alignment: u8, ret_addr: usize) ?[*]u8 {
        const self: *WasmAllocator = @ptrCast(@alignCast(ctx));
        
        // Small allocations use fixed buffer
        if (len <= 1024) {
            return self.small_fba.allocator().rawAlloc(len, alignment, ret_addr);
        }
        
        // Large allocations use GPA
        return self.gpa.allocator().rawAlloc(len, alignment, ret_addr);
    }
    
    // ... implement resize, free
};
```

---

## Phase 3: Integrate Real MLS Operations

### 🎯 Objective
Replace simplified WASM state machine with real `mls_zig.MlsGroup` operations.

### 🔧 State Machine Architecture

**Current Simplified Format**: 76 bytes (pubkey + group_id + epoch + member_count)
**Target Real Format**: Full `MlsGroup` serialization with TreeKEM state

#### New WASM State Machine Design
```zig
// Enhanced WASM state machine using real MlsGroup
export fn wasm_state_machine_init_group_real(
    group_id: [*]const u8, // 32 bytes
    creator_signing_key: [*]const u8, // 32 bytes
    out_state: [*]u8, // Serialized MlsGroup state
    out_state_len: *u32,
) bool {
    const allocator = wasm_exports.getAllocator();
    
    // Create WASM-compatible random function
    const random_fn = struct {
        fn randomBytes(buf: []u8) void {
            wasm_random.secure_random.bytes(buf);
        }
    }.randomBytes;
    
    // Use real mls_zig KeyPackageBundle creation
    const cipher_suite = mls_zig.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    
    // Create credential from signing key
    const creator_privkey = creator_signing_key[0..32].*;
    const creator_pubkey = crypto.getPublicKey(creator_privkey) catch return false;
    
    // Use mls_zig credential creation
    var credential = mls_zig.BasicCredential.init(
        allocator, 
        std.fmt.fmtSliceHexLower(&creator_pubkey)
    ) catch return false;
    defer credential.deinit();
    
    // Create KeyPackageBundle with WASM-compatible random
    var key_package_bundle = mls_zig.KeyPackageBundle.init(
        allocator,
        cipher_suite,
        credential,
        random_fn, // Use WASM-compatible random
    ) catch return false;
    defer key_package_bundle.deinit();
    
    // Create real MlsGroup
    var mls_group = mls_zig.MlsGroup.createGroup(
        allocator,
        cipher_suite,
        random_fn, // Use WASM-compatible random
        key_package_bundle,
    ) catch return false;
    defer mls_group.deinit();
    
    // Serialize real MlsGroup state
    const serialized = mls_group.serialize(allocator) catch return false;
    defer allocator.free(serialized);
    
    // Return serialized state
    if (out_state_len.* < serialized.len) {
        out_state_len.* = @intCast(serialized.len);
        return false;
    }
    
    @memcpy(out_state[0..serialized.len], serialized);
    out_state_len.* = @intCast(serialized.len);
    
    return true;
}
```

### 🔧 Welcome Message Integration

Replace simplified 44-byte Welcome format with real MLS Welcome messages:

```zig
export fn wasm_state_machine_create_welcome_real(
    state_data: [*]const u8,
    state_data_len: u32,
    new_member_key_package: [*]const u8, // Serialized KeyPackage
    new_member_kp_len: u32,
    out_welcome: [*]u8,
    out_welcome_len: *u32,
) bool {
    const allocator = wasm_exports.getAllocator();
    
    // Deserialize real MlsGroup state
    var mls_group = mls_zig.MlsGroup.deserialize(
        allocator,
        state_data[0..state_data_len],
    ) catch return false;
    defer mls_group.deinit();
    
    // Parse new member KeyPackage
    const new_member_kp = mls_zig.KeyPackage.deserialize(
        new_member_key_package[0..new_member_kp_len],
    ) catch return false;
    defer new_member_kp.deinit();
    
    // Generate real Welcome message with HPKE encryption
    var welcome = mls_group.generateWelcome(
        allocator,
        new_member_kp,
        struct {
            fn randomBytes(buf: []u8) void {
                wasm_random.secure_random.bytes(buf);
            }
        }.randomBytes,
    ) catch return false;
    defer welcome.deinit();
    
    // Serialize Welcome message
    const serialized = welcome.serialize(allocator) catch return false;
    defer allocator.free(serialized);
    
    if (out_welcome_len.* < serialized.len) {
        out_welcome_len.* = @intCast(serialized.len);
        return false;
    }
    
    @memcpy(out_welcome[0..serialized.len], serialized);
    out_welcome_len.* = @intCast(serialized.len);
    
    return true;
}
```

---

## Phase 4: Restore Full Functionality

### 🎯 Objective
Achieve feature parity between native and WASM MLS implementations.

### 🔧 Feature Integration Checklist

**Core MLS Operations:**
- [ ] Group creation with real TreeKEM
- [ ] KeyPackage generation with all extensions
- [ ] Add/Remove proposals with proper validation
- [ ] Commit operations with epoch advancement
- [ ] Welcome message generation with HPKE
- [ ] Welcome message processing for group joining

**Cryptographic Operations:**
- [ ] Real exporter secret derivation
- [ ] HPKE encryption/decryption for Welcome messages
- [ ] TreeKEM path encryption for group updates
- [ ] Proper random number generation for all operations

**Protocol Compliance:**
- [ ] MLS extensions (last_resort, nostr_group_data, etc.)
- [ ] Wire format serialization/deserialization
- [ ] Epoch management and key rotation
- [ ] Forward secrecy implementation

### 🔧 Testing Strategy

**Validation Approach:**
1. **Unit Tests**: Each WASM function matches native behavior
2. **Integration Tests**: Complete group lifecycle works
3. **Interoperability**: WASM and native can interact
4. **Performance**: Memory usage and speed within acceptable limits

```typescript
// Enhanced test suite
describe('Real WASM MLS Integration', () => {
  test('group creation produces identical state', async () => {
    const nativeState = await createGroupNative(groupId, creatorKey);
    const wasmState = await createGroupWasm(groupId, creatorKey);
    
    // Both should have same epoch, member count, tree structure
    expect(nativeState.epoch).toBe(wasmState.epoch);
    expect(nativeState.memberCount).toBe(wasmState.memberCount);
    expect(nativeState.treeHash).toBe(wasmState.treeHash);
  });
  
  test('Welcome messages are interoperable', async () => {
    const aliceGroup = await createGroupWasm(groupId, aliceKey);
    const welcome = await createWelcomeWasm(aliceGroup, bobKeyPackage);
    
    // Bob should be able to join using native implementation
    const bobGroup = await processWelcomeNative(welcome, bobPrivateKey);
    
    // Both should derive same exporter secret
    expect(aliceGroup.exporterSecret).toBe(bobGroup.exporterSecret);
  });
});
```

---

## Implementation Timeline

### Week 1: Phase 1 - mls_zig Compatibility
- **Day 1-2**: Investigate TLS codec issues, implement missing methods
- **Day 3-4**: Fix all Zig 0.14.1 compilation errors
- **Day 5**: Validate native mls_zig builds cleanly

### Week 2: Phase 2 - WASM Compatibility  
- **Day 1-2**: Implement random function injection throughout mls_zig
- **Day 3-4**: Fix POSIX dependencies and WASM target issues
- **Day 5**: Validate WASM compilation succeeds

### Week 3: Phase 3 - Real MLS Integration
- **Day 1-3**: Replace simplified WASM functions with real mls_zig calls
- **Day 4-5**: Implement proper serialization/deserialization

### Week 4: Phase 4 - Full Functionality
- **Day 1-3**: Complete feature integration and testing
- **Day 4-5**: Performance optimization and documentation

## Success Criteria

### ✅ Phase 1 Complete
- `mls_zig` compiles without errors on native Zig 0.14.1
- All existing native tests pass with fixed mls_zig

### ✅ Phase 2 Complete  
- `mls_zig` compiles without errors for WASM target
- Random number generation works in WASM environment

### ✅ Phase 3 Complete
- WASM state machine uses real `mls_zig.MlsGroup` operations
- Welcome messages use real HPKE encryption/decryption

### ✅ Phase 4 Complete
- Feature parity between native and WASM implementations
- All tests pass, performance acceptable
- Visualizer integration working with real MLS protocol

## Risk Mitigation

### Risk 1: Deep mls_zig API Changes Required
- **Mitigation**: Contribute fixes upstream to mls_zig repository
- **Fallback**: Fork mls_zig temporarily with compatibility layer

### Risk 2: WASM Performance Issues
- **Mitigation**: Profile memory usage, optimize allocator strategy  
- **Fallback**: Hybrid approach - heavy operations in native, UI in WASM

### Risk 3: Serialization Complexity
- **Mitigation**: Use existing TLS codec patterns, comprehensive testing
- **Fallback**: Custom serialization format with version management

---

## Critical Discovery: MlsGroup Serialization Gap

### 🚨 Major Blocker Identified (December 2024)

During Phase 3 implementation, we discovered that `mls_zig.MlsGroup` **lacks serialization/deserialization methods**. This is critical because:

1. **WASM Constraint**: WASM functions are stateless - we must serialize state between calls
2. **Missing Methods**: No `serialize()`, `deserialize()`, `toBytes()`, or `fromBytes()` on MlsGroup
3. **Impact**: Cannot pass MlsGroup state between WASM function calls

### Potential Solutions

**Option 1: Add Serialization to mls_zig** (Recommended)
- Implement `serialize()`/`deserialize()` methods on MlsGroup
- Follow MLS protocol wire format for interoperability
- Contribute upstream to mls_zig project

**Option 2: State Handle Pattern**
- Store MlsGroup instances in WASM memory with handles
- Return opaque handles instead of serialized state
- Requires persistent WASM instance (not ideal for browser)

**Option 3: Hybrid Approach** (Current)
- Use simplified state for WASM demonstration
- Use full mls_zig for native implementation
- Document limitations clearly

## Conclusion

The current **simplified WASM demo** remains necessary until mls_zig adds serialization support. The TLS codec and random generation fixes enable native compilation, but full WASM integration requires either:
1. Contributing serialization to mls_zig
2. Architectural changes to maintain persistent WASM state
3. Accepting the simplified demo as sufficient for browser visualization

**Current Status**: Native MLS works fully, WASM uses simplified demonstration.