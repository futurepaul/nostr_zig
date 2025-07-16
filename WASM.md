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

### Key Build Flags
```zig
// In build.zig
wasm_lib.defineCMacro("printf(...)", ""); // Disable printf
wasm_lib.defineCMacro("USE_EXTERNAL_DEFAULT_CALLBACKS", "1");
```

### WASM Output Location
The WASM file is built to: `visualizer/src/nostr_mls.wasm`

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

## Status: create_group Implementation

### ✅ COMPLETED
1. **Fixed alignment issues** - Added `wasm_alloc_u32()` and `wasm_free_u32()` for proper 4-byte alignment
2. **Updated visualizer** - Uses aligned allocation, no more "Byte offset is not aligned" errors
3. **Real secp256k1 integration** - All crypto operations use real secp256k1 with static context

### ❌ CURRENT ISSUE
**Problem**: `wasm_create_group` returns `false`, causing "Failed to create group" error

**What Works:**
- Key generation: `330de1552b8272240ddcd7111538d86cb35d684e1b17b92c60ebac899e24baa9`
- Memory alignment: No more alignment errors
- Function is called: TypeScript properly calls the WASM function

**What Fails:**
- `wasm_create_group` internal logic returns `false`
- Likely the secp256k1 signing step inside the function

### 🔍 DEBUGGING APPROACH
1. **Add debug logging** to see where `wasm_create_group` fails
2. **Test isolated signing** with known good keys
3. **Verify input validation** in the function
4. **Check random generation** for group ID creation

### 🛠️ SOLUTIONS TO TRY
1. **Debug version**: Add logging to each step in `wasm_create_group`
2. **Minimal version**: Skip signing temporarily to test basic structure
3. **Key validation**: Ensure the input keys are valid for secp256k1
4. **Memory check**: Verify all allocations succeed

## References

- [WebAssembly Memory Model](https://webassembly.github.io/spec/core/exec/runtime.html#memory-instances)
- [TypedArray Alignment Requirements](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/TypedArray)
- [secp256k1 Static Context](https://github.com/bitcoin-core/secp256k1/blob/master/include/secp256k1.h)