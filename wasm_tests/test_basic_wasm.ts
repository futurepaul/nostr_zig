import { readFileSync } from "fs";
import { resolve } from "path";

// Load WASM file
const wasmPath = resolve(__dirname, "../visualizer/src/nostr_mls.wasm");
const wasmBuffer = readFileSync(wasmPath);

async function testBasicWasm() {
    console.log("🔧 Loading WASM module...");
    console.log("📦 WASM file size:", wasmBuffer.byteLength, "bytes");
    
    let wasmMemory: WebAssembly.Memory | null = null;
    
    // Create imports for WASM
    const imports = {
        env: {
            getRandomValues: (ptr: number, len: number) => {
                console.log(`  📊 getRandomValues called: ptr=${ptr}, len=${len}`);
                if (!wasmMemory) throw new Error('WASM memory not available');
                const bytes = new Uint8Array(wasmMemory.buffer, ptr, len);
                crypto.getRandomValues(bytes);
                console.log(`  📊 Generated random bytes:`, Array.from(bytes).slice(0, 8).map(b => b.toString(16).padStart(2, '0')).join(' '));
            },
            wasm_log_error: (strPtr: number, len: number) => {
                if (!wasmMemory) throw new Error('WASM memory not available');
                const bytes = new Uint8Array(wasmMemory.buffer, strPtr, len);
                const message = new TextDecoder().decode(bytes);
                console.error('❌ secp256k1 error:', message);
            }
        }
    };
    
    // Compile and instantiate WASM
    const wasmModule = await WebAssembly.compile(wasmBuffer);
    const instance = await WebAssembly.instantiate(wasmModule, imports);
    
    wasmMemory = instance.exports.memory as WebAssembly.Memory;
    const wasm = instance.exports as any;
    
    console.log("✅ WASM module loaded successfully!");
    console.log("📦 Memory size:", wasmMemory.buffer.byteLength, "bytes");
    
    // Test 1: Basic add function
    console.log("\n🧮 Test 1: Basic add function...");
    try {
        const result = wasm.wasm_add(5, 7);
        console.log(`  5 + 7 = ${result}`);
        if (result === 12) {
            console.log("✅ Basic function works!");
        } else {
            console.error("❌ Unexpected result!");
        }
    } catch (e) {
        console.error("❌ Error calling wasm_add:", e);
    }
    
    // Test 2: Memory allocation
    console.log("\n🧮 Test 2: Memory allocation...");
    try {
        const ptr = wasm.wasm_alloc(32);
        console.log(`  Allocated 32 bytes at pointer: ${ptr}`);
        if (ptr) {
            console.log("✅ Memory allocation works!");
            wasm.wasm_free(ptr, 32);
            console.log("  Freed memory");
        } else {
            console.error("❌ Failed to allocate memory!");
        }
    } catch (e) {
        console.error("❌ Error in memory allocation:", e);
    }
    
    // Test 3: Test random generation
    console.log("\n🎲 Test 3: Test random generation...");
    try {
        wasm.wasm_test_random();
        console.log("✅ Random generation test completed!");
    } catch (e) {
        console.error("❌ Error in random test:", e);
    }
    
    // Test 4: bytes_to_hex
    console.log("\n🔤 Test 4: Bytes to hex conversion...");
    try {
        const testBytes = new Uint8Array([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
        const bytesPtr = wasm.wasm_alloc(testBytes.length);
        const hexPtr = wasm.wasm_alloc(testBytes.length * 2);
        
        new Uint8Array(wasmMemory.buffer, bytesPtr, testBytes.length).set(testBytes);
        
        const success = wasm.bytes_to_hex(bytesPtr, testBytes.length, hexPtr, testBytes.length * 2);
        if (success) {
            const hexBytes = new Uint8Array(wasmMemory.buffer, hexPtr, testBytes.length * 2);
            const hexStr = new TextDecoder().decode(hexBytes);
            console.log(`  Hex string: ${hexStr}`);
            console.log("✅ Bytes to hex works!");
        } else {
            console.error("❌ Bytes to hex failed!");
        }
        
        wasm.wasm_free(bytesPtr, testBytes.length);
        wasm.wasm_free(hexPtr, testBytes.length * 2);
    } catch (e) {
        console.error("❌ Error in bytes_to_hex:", e);
    }
    
    console.log("\n✅ Basic tests completed!");
}

// Run the tests
testBasicWasm().catch(console.error);