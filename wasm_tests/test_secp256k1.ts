import { readFileSync } from "fs";
import { resolve } from "path";

// Load WASM file
const wasmPath = resolve(__dirname, "../visualizer/src/nostr_mls.wasm");
const wasmBuffer = readFileSync(wasmPath);

async function testSecp256k1() {
    console.log("🔧 Loading WASM module...");
    
    let wasmMemory: WebAssembly.Memory | null = null;
    
    // Create imports for WASM
    const imports = {
        env: {
            getRandomValues: (ptr: number, len: number) => {
                console.log(`  📊 getRandomValues called: ptr=${ptr}, len=${len}`);
                if (!wasmMemory) throw new Error('WASM memory not available');
                const bytes = new Uint8Array(wasmMemory.buffer, ptr, len);
                crypto.getRandomValues(bytes);
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
    
    console.log("✅ WASM module loaded!");
    
    // Check if the test function exists
    if (!wasm.wasm_test_secp256k1_context) {
        console.log("❌ wasm_test_secp256k1_context function not found!");
        console.log("Available exports:", Object.keys(instance.exports).filter(k => k.includes('test')));
        return;
    }
    
    // Test secp256k1 context creation
    console.log("\n🔧 Testing secp256k1 context creation...");
    try {
        const result = wasm.wasm_test_secp256k1_context();
        console.log(`  Result: ${result}`);
        if (result) {
            console.log("✅ secp256k1 context creation works!");
        } else {
            console.log("❌ secp256k1 context creation returned false!");
        }
    } catch (e) {
        console.error("❌ Error during context creation:", e);
        console.error("   Error type:", e.constructor.name);
    }
}

// Run the test
testSecp256k1().catch(console.error);