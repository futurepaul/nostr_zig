# WASM Integration Guide

## Overview
This document explains how our WASM integration works, including memory management, crypto operations, and JavaScript interop.

## Key Insights

### 1. secp256k1 Static Context
The most important discovery: Use the **static context** (`secp256k1_context_no_precomp`) instead of dynamic context creation.

```zig
// In wasm_secp_context.zig
extern const secp256k1_context_no_precomp: secp256k1.secp256k1_context;

pub fn getStaticContext() *const secp256k1.secp256k1_context {
    return &secp256k1_context_no_precomp;
}
```

### 2. Conditional Compilation
Always use different context strategies for WASM vs native:

```zig
const ctx = if (builtin.target.cpu.arch == .wasm32) blk: {
    const wasm_ctx = @import("wasm_secp_context.zig");
    break :blk wasm_ctx.getStaticContext();
} else blk: {
    break :blk secp256k1.secp256k1_context_create(...);
};
```

### 3. JavaScript Access to Static Context
In JavaScript, the static context is exposed as a WebAssembly.Global:

```javascript
const noPrecompGlobal = wasm.secp256k1_context_no_precomp as WebAssembly.Global;
const contextPtr = noPrecompGlobal.value;
```

## Memory Management

### Allocation
We use a fixed buffer allocator in WASM:

```zig
var buffer: [1024 * 1024]u8 = undefined; // 1MB buffer
var fba: ?std.heap.FixedBufferAllocator = null;

export fn wasm_alloc(size: usize) ?[*]u8 {
    const mem = getAllocator().alloc(u8, size) catch return null;
    return mem.ptr;
}

export fn wasm_free(ptr: [*]u8, size: usize) void {
    getAllocator().free(ptr[0..size]);
}
```

### Memory Alignment Issues

**CRITICAL**: JavaScript TypedArrays require proper alignment!

- `Uint32Array` requires 4-byte alignment
- `Float64Array` requires 8-byte alignment

**Problem**: Our `wasm_alloc` doesn't guarantee alignment, causing:
```
RangeError: Byte offset is not aligned
```

**Solution**: Always ensure proper alignment when allocating memory for TypedArrays:

```javascript
// Alignment helper
function ensureAlignment(ptr: number, alignment: number): number {
    const mask = alignment - 1;
    return (ptr + mask) & ~mask;
}

// When allocating for Uint32Array
const outLenPtr = exports.wasm_alloc(8); // Allocate extra
const alignedOutLenPtr = ensureAlignment(outLenPtr, 4);
new Uint32Array(exports.memory.buffer, alignedOutLenPtr, 1)[0] = value;
```

Or better, add an alignment-aware allocator in Zig:

```zig
export fn wasm_alloc_aligned(size: usize, alignment: usize) ?[*]u8 {
    const mem = getAllocator().alignedAlloc(u8, alignment, size) catch return null;
    return mem.ptr;
}
```

## Random Number Generation

WASM doesn't have built-in randomness. We provide it from JavaScript:

```javascript
const imports = {
    env: {
        getRandomValues: (ptr: number, len: number) => {
            const bytes = new Uint8Array(wasmMemory.buffer, ptr, len);
            crypto.getRandomValues(bytes);
        }
    }
};
```

In Zig:
```zig
extern fn getRandomValues(buf: [*]u8, len: usize) void;
```

## Build Configuration

### Build Command
```bash
zig build wasm
```

**✅ Auto-Copy Feature**: The build script automatically copies the WASM file to `visualizer/src/nostr_mls.wasm` - no manual copying needed!

### Key Build Flags
```zig
// In build.zig
wasm_lib.defineCMacro("printf(...)", ""); // Disable printf
wasm_lib.defineCMacro("USE_EXTERNAL_DEFAULT_CALLBACKS", "1");
```

### WASM Output Locations
- **Primary**: `zig-out/visualizer/src/nostr_mls.wasm` (build output)
- **Auto-copied**: `visualizer/src/nostr_mls.wasm` (ready for use)

### Build Process
1. Builds the WASM library with secp256k1 integration
2. Installs to `zig-out/visualizer/src/nostr_mls.wasm`
3. Automatically copies to `visualizer/src/nostr_mls.wasm`
4. Ready for immediate use in the visualizer!

## Testing Strategy

### 1. Create Isolated Test Files
Always test WASM functions in isolation before integrating:

```typescript
// test_feature.ts
import { readFileSync } from 'fs';
import { resolve } from 'path';

const wasmPath = resolve(__dirname, '../visualizer/src/nostr_mls.wasm');
const wasmBuffer = readFileSync(wasmPath);

// Test specific functionality...
```

### 2. Run Tests
```bash
bun test_feature.ts
```

### 3. Common Test Pattern
```typescript
// 1. Load WASM
const wasmModule = new WebAssembly.Module(wasmBuffer);
const wasmInstance = new WebAssembly.Instance(wasmModule, imports);

// 2. Get exports
const exports = wasmInstance.exports as any;

// 3. Allocate memory with proper alignment
const ptr = exports.wasm_alloc(size);
const alignedPtr = ensureAlignment(ptr, 4); // for Uint32Array

// 4. Call function
const success = exports.wasm_function(...);

// 5. Clean up
exports.wasm_free(ptr, size);
```

## Crypto Operations

### Key Generation
```zig
export fn wasm_create_identity(out_private_key: [*]u8, out_public_key: [*]u8) bool {
    const private_key = crypto.generatePrivateKey() catch return false;
    const public_key = crypto.getPublicKey(private_key) catch return false;
    
    @memcpy(out_private_key[0..32], &private_key);
    @memcpy(out_public_key[0..32], &public_key);
    
    return true;
}
```

### Schnorr Signatures
All signing uses real secp256k1 with the static context approach.

### NIP-44 v2 Encryption (✅ IMPLEMENTED)
Real end-to-end encryption using industry-standard cryptography:

```zig
// Real NIP-44 v2 implementation in wasm_send_message
const encrypted_payload = nip44.encrypt(
    allocator,
    sender_priv_key,
    group_secret,
    message_content
) catch return false;
```

**Message Structure:**
- Version byte (0x02 for NIP-44 v2)
- Group hash (SHA256 of group state)
- Sender public key (identity)
- NIP-44 encrypted payload (ChaCha20 + HMAC)
- Schnorr signature (message authenticity)

**Cryptographic Components:**
- **ChaCha20IETF**: Stream cipher encryption
- **HKDF-SHA256**: Key derivation for conversation keys
- **HMAC-SHA256**: Message authentication
- **secp256k1 Schnorr**: Digital signatures
- **Secure random**: Browser crypto.getRandomValues()

**Output:** 261 bytes of properly encrypted data (vs 142 bytes of fake XOR)

## Common Pitfalls

1. **Forgetting alignment** - Always align pointers for TypedArrays
2. **Dynamic context creation** - Always use static context in WASM
3. **Missing randomness** - Ensure getRandomValues is provided
4. **Memory leaks** - Always free allocated memory
5. **Incorrect build** - Ensure WASM is rebuilt after changes

## Debugging Tips

1. **Check alignment first** when getting "Byte offset is not aligned"
2. **Log pointer values** to verify they're reasonable
3. **Use `wasm_test_*` functions** to verify individual components
4. **Check WASM exports** with `console.log(Object.keys(exports))`
5. **Verify static context** is accessible from JavaScript

## Status: ✅ COMPLETE - Full End-to-End Messaging System Working!

### ✅ EVERYTHING IMPLEMENTED AND WORKING
1. **Fixed alignment issues** - Added principled `allocateAlignedU32()` helpers
2. **Real secp256k1 integration** - All crypto operations use real secp256k1 with static context
3. **Group creation working** - Fixed alignment, proper error handling
4. **🔒 REAL NIP-44 v2 ENCRYPTION** - **ChaCha20 + HKDF + HMAC + secp256k1 signatures**
5. **Message flow visualization** - Event-driven state management, no more reset bugs
6. **Ephemeral key generation** - Per-message privacy protection
7. **Comprehensive testing** - Isolated WASM function tests with `test_send_message.ts`

### 🎉 REAL CRYPTOGRAPHY ACHIEVEMENTS
- **ChaCha20 encryption** replaces XOR garbage
- **HKDF key derivation** for secure conversation keys
- **Message padding** per NIP-44 specification for metadata protection
- **HMAC authentication** for message integrity verification
- **secp256k1 Schnorr signatures** for message authenticity
- **Proper random generation** using browser crypto.getRandomValues()

### 📊 Performance Metrics
- **Message encryption**: 142 bytes (fake XOR) → **261 bytes (real NIP-44 v2)**
- **Version byte**: 0x01 (fake) → **0x02 (NIP-44 v2 compliant)**
- **All crypto operations**: Real secp256k1 with static context for WASM compatibility

### 🧪 Testing Infrastructure
- **Isolated WASM testing**: `wasm_tests/test_send_message.ts` for rapid iteration
- **Memory alignment helpers**: Principled TypeScript alignment functions
- **Error handling**: Proper cleanup and meaningful error messages
- **Integration testing**: Full message flow from identity → group → encrypted messaging

### 🔧 Technical Implementation Details
- **Alignment-safe allocators**: `allocateAlignedU32()` and `freeAlignedU32()`
- **WASM-compatible random**: `wasm_random.secure_random.bytes()` for NIP-44
- **Type-safe casting**: Fixed u5/u6 issues in NIP-44 padding calculations
- **Memory management**: Proper cleanup with structured allocation patterns

## References

- [WebAssembly Memory Model](https://webassembly.github.io/spec/core/exec/runtime.html#memory-instances)
- [TypedArray Alignment Requirements](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/TypedArray)
- [secp256k1 Static Context](https://github.com/bitcoin-core/secp256k1/blob/master/include/secp256k1.h)