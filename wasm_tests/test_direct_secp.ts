import { readFileSync } from "fs";
import { resolve } from "path";

// Load WASM file
const wasmPath = resolve(__dirname, "../visualizer/src/nostr_mls.wasm");
const wasmBuffer = readFileSync(wasmPath);

async function testDirectSecp() {
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
    
    // Test 1: Call secp256k1_selftest
    console.log("\n🧪 Test 1: secp256k1 self test...");
    try {
        const selftestResult = wasm.secp256k1_selftest();
        console.log(`  Self test result: ${selftestResult}`);
        if (selftestResult) {
            console.log("✅ secp256k1 self test passed!");
        } else {
            console.log("❌ secp256k1 self test failed!");
        }
    } catch (e) {
        console.error("❌ Error in self test:", e);
    }
    
    // Test 2: Create context directly
    console.log("\n🧪 Test 2: Creating secp256k1 context directly...");
    try {
        const SECP256K1_CONTEXT_SIGN = 1;
        const ctx = wasm.secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
        console.log(`  Context pointer: ${ctx}`);
        
        if (ctx !== 0) {
            console.log("✅ Context created successfully!");
            
            // Try to verify a simple key
            console.log("\n🔑 Test 3: Verifying a test key...");
            const keyPtr = wasm.wasm_alloc(32);
            const keyBytes = new Uint8Array(wasmMemory.buffer, keyPtr, 32);
            
            // Use a known valid private key (all 0x01)
            keyBytes.fill(0x01);
            
            const verifyResult = wasm.secp256k1_ec_seckey_verify(ctx, keyPtr);
            console.log(`  Verify result: ${verifyResult}`);
            
            if (verifyResult === 1) {
                console.log("✅ Key verification works!");
            } else {
                console.log("❌ Key verification failed!");
            }
            
            wasm.wasm_free(keyPtr, 32);
            wasm.secp256k1_context_destroy(ctx);
        } else {
            console.log("❌ Failed to create context!");
        }
    } catch (e) {
        console.error("❌ Error creating context:", e);
        console.error("   Type:", e.constructor.name);
    }
}

// Run the test
testDirectSecp().catch(console.error);