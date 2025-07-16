import { readFileSync } from "fs";
import { resolve } from "path";

// Load WASM file
const wasmPath = resolve(__dirname, "../visualizer/src/nostr_mls.wasm");
const wasmBuffer = readFileSync(wasmPath);

async function testStaticContext() {
    console.log("🔧 Loading WASM module...");
    
    let wasmMemory: WebAssembly.Memory | null = null;
    let errorMessages: string[] = [];
    
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
                errorMessages.push(message);
            }
        }
    };
    
    // Compile and instantiate WASM
    const wasmModule = await WebAssembly.compile(wasmBuffer);
    const instance = await WebAssembly.instantiate(wasmModule, imports);
    
    wasmMemory = instance.exports.memory as WebAssembly.Memory;
    const wasm = instance.exports as any;
    
    console.log("✅ WASM module loaded!");
    
    // Test if we have the static context
    if (wasm.secp256k1_context_static) {
        console.log("\n🎯 Found static context!");
        const staticCtx = wasm.secp256k1_context_static;
        console.log(`  Static context pointer: ${staticCtx}`);
    } else {
        console.log("\n❌ No static context found");
    }
    
    // Try using no-precomp context
    if (wasm.secp256k1_context_no_precomp) {
        console.log("\n🎯 Found no-precomp context!");
        const noPrecompCtx = wasm.secp256k1_context_no_precomp;
        console.log(`  No-precomp context pointer: ${noPrecompCtx}`);
        
        // Try to verify a key with this context
        console.log("\n🔑 Testing key verification with no-precomp context...");
        const keyPtr = wasm.wasm_alloc(32);
        const keyBytes = new Uint8Array(wasmMemory.buffer, keyPtr, 32);
        
        // Use a valid private key
        const validKey = new Uint8Array([
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
        ]);
        keyBytes.set(validKey);
        
        try {
            const verifyResult = wasm.secp256k1_ec_seckey_verify(noPrecompCtx, keyPtr);
            console.log(`  Verify result: ${verifyResult}`);
            if (verifyResult === 1) {
                console.log("✅ Key verification with static context works!");
            }
        } catch (e) {
            console.error("❌ Error verifying key:", e);
        }
        
        wasm.wasm_free(keyPtr, 32);
    }
    
    // Check for preallocated context functions
    console.log("\n🔍 Checking for preallocated context functions...");
    const contextFuncs = [
        'secp256k1_context_preallocated_size',
        'secp256k1_context_preallocated_create',
        'secp256k1_context_preallocated_clone_size',
        'secp256k1_context_preallocated_clone',
        'secp256k1_context_preallocated_destroy'
    ];
    
    for (const func of contextFuncs) {
        if (wasm[func]) {
            console.log(`  ✅ ${func} available`);
        } else {
            console.log(`  ❌ ${func} NOT available`);
        }
    }
    
    // Try preallocated context approach
    if (wasm.secp256k1_context_preallocated_size && wasm.secp256k1_context_preallocated_create) {
        console.log("\n🚀 Trying preallocated context approach...");
        
        const SECP256K1_CONTEXT_SIGN = 1;
        const SECP256K1_CONTEXT_VERIFY = 2;
        const flags = SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY;
        
        // Get required size
        const size = wasm.secp256k1_context_preallocated_size(flags);
        console.log(`  Required context size: ${size} bytes`);
        
        // Allocate memory for context
        const ctxMemory = wasm.wasm_alloc(size);
        console.log(`  Allocated context memory at: ${ctxMemory}`);
        
        if (ctxMemory) {
            try {
                // Create preallocated context
                const ctx = wasm.secp256k1_context_preallocated_create(ctxMemory, flags);
                console.log(`  Created context: ${ctx}`);
                
                if (ctx) {
                    console.log("✅ Preallocated context created successfully!");
                    
                    // Test key generation with this context
                    console.log("\n🔑 Testing key generation with preallocated context...");
                    const privKeyPtr = wasm.wasm_alloc(32);
                    wasm.getRandomValues(privKeyPtr, 32);
                    
                    const verifyResult = wasm.secp256k1_ec_seckey_verify(ctx, privKeyPtr);
                    console.log(`  Key verify result: ${verifyResult}`);
                    
                    wasm.wasm_free(privKeyPtr, 32);
                    wasm.secp256k1_context_preallocated_destroy(ctx);
                }
            } catch (e) {
                console.error("❌ Error creating preallocated context:", e);
            }
            
            wasm.wasm_free(ctxMemory, size);
        }
    }
    
    console.log("\n📋 Error messages collected:", errorMessages);
}

// Run the test
testStaticContext().catch(console.error);