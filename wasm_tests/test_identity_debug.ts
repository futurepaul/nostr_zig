import { readFileSync } from "fs";
import { resolve } from "path";

// Load WASM file
const wasmPath = resolve(__dirname, "../visualizer/src/nostr_mls.wasm");
const wasmBuffer = readFileSync(wasmPath);

function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function testIdentityDebug() {
    console.log("🔧 Loading WASM module...");
    
    let wasmMemory: WebAssembly.Memory | null = null;
    let randomCallCount = 0;
    
    // Create imports for WASM
    const imports = {
        env: {
            getRandomValues: (ptr: number, len: number) => {
                randomCallCount++;
                console.log(`  📊 getRandomValues call #${randomCallCount}: ptr=${ptr}, len=${len}`);
                if (!wasmMemory) throw new Error('WASM memory not available');
                const bytes = new Uint8Array(wasmMemory.buffer, ptr, len);
                crypto.getRandomValues(bytes);
                console.log(`     Random bytes: ${bytesToHex(bytes).slice(0, 64)}...`);
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
    
    // Test identity creation step by step
    console.log("\n🔑 Testing identity creation...");
    
    console.log("  1️⃣ Allocating memory for keys...");
    const privateKeyPtr = wasm.wasm_alloc(32);
    const publicKeyPtr = wasm.wasm_alloc(32);
    console.log(`     Private key ptr: ${privateKeyPtr}`);
    console.log(`     Public key ptr: ${publicKeyPtr}`);
    
    if (!privateKeyPtr || !publicKeyPtr) {
        throw new Error('Failed to allocate memory for keys');
    }
    
    console.log("\n  2️⃣ Calling wasm_create_identity...");
    try {
        const success = wasm.wasm_create_identity(privateKeyPtr, publicKeyPtr);
        console.log(`     Result: ${success}`);
        
        if (success) {
            console.log("\n  3️⃣ Reading generated keys...");
            const privateKey = new Uint8Array(wasmMemory.buffer, privateKeyPtr, 32);
            const publicKey = new Uint8Array(wasmMemory.buffer, publicKeyPtr, 32);
            
            console.log("     Private key:", bytesToHex(privateKey));
            console.log("     Public key: ", bytesToHex(publicKey));
            
            console.log("\n✅ Identity creation succeeded!");
        } else {
            console.error("❌ Identity creation returned false!");
        }
    } catch (e) {
        console.error("❌ Error during identity creation:", e);
        console.error("   Error type:", e.constructor.name);
        console.error("   Stack:", e.stack);
    }
    
    console.log("\n  4️⃣ Freeing memory...");
    wasm.wasm_free(privateKeyPtr, 32);
    wasm.wasm_free(publicKeyPtr, 32);
    console.log("     Memory freed");
    
    // Now test ephemeral keys
    console.log("\n🔐 Testing ephemeral key generation...");
    
    console.log("  1️⃣ Allocating memory for ephemeral keys...");
    const ephPrivKeyPtr = wasm.wasm_alloc(32);
    const ephPubKeyPtr = wasm.wasm_alloc(32);
    console.log(`     Private key ptr: ${ephPrivKeyPtr}`);
    console.log(`     Public key ptr: ${ephPubKeyPtr}`);
    
    console.log("\n  2️⃣ Calling wasm_generate_ephemeral_keys...");
    try {
        const ephSuccess = wasm.wasm_generate_ephemeral_keys(ephPrivKeyPtr, ephPubKeyPtr);
        console.log(`     Result: ${ephSuccess}`);
        
        if (ephSuccess) {
            console.log("\n  3️⃣ Reading generated ephemeral keys...");
            const ephPrivKey = new Uint8Array(wasmMemory.buffer, ephPrivKeyPtr, 32);
            const ephPubKey = new Uint8Array(wasmMemory.buffer, ephPubKeyPtr, 32);
            
            console.log("     Private key:", bytesToHex(ephPrivKey));
            console.log("     Public key: ", bytesToHex(ephPubKey));
            
            console.log("\n✅ Ephemeral key generation succeeded!");
        } else {
            console.error("❌ Ephemeral key generation returned false!");
        }
    } catch (e) {
        console.error("❌ Error during ephemeral key generation:", e);
        console.error("   Error type:", e.constructor.name);
        console.error("   Stack:", e.stack);
    }
    
    console.log("\n  4️⃣ Freeing memory...");
    wasm.wasm_free(ephPrivKeyPtr, 32);
    wasm.wasm_free(ephPubKeyPtr, 32);
    console.log("     Memory freed");
    
    console.log("\n📊 Total random calls:", randomCallCount);
}

// Run the tests
testIdentityDebug().catch(console.error);