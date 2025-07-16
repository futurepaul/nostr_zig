import { readFileSync } from "fs";
import { resolve } from "path";

// Load WASM file
const wasmPath = resolve(__dirname, "../visualizer/src/nostr_mls.wasm");
const wasmBuffer = readFileSync(wasmPath);

// Simple crypto functions for debugging
function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

async function testKeyPackages() {
    console.log("🔧 Loading WASM module...");
    
    // Create imports for WASM including getRandomValues
    const imports = {
        env: {
            // Provide secure randomness from Node's crypto API
            getRandomValues: (ptr: number, len: number) => {
                const memory = (instance.exports as any).memory;
                const bytes = new Uint8Array(memory.buffer, ptr, len);
                // Use Node's crypto for randomness
                const crypto = require('crypto');
                const randomBytes = crypto.randomBytes(len);
                bytes.set(randomBytes);
                console.log(`  Generated ${len} random bytes`);
            },
            // Error logging function for debugging
            wasm_log_error: (strPtr: number, len: number) => {
                const memory = (instance.exports as any).memory;
                const bytes = new Uint8Array(memory.buffer, strPtr, len);
                const message = new TextDecoder().decode(bytes);
                console.error('  WASM error:', message);
            }
        }
    };
    
    const module = await WebAssembly.compile(wasmBuffer);
    const instance = await WebAssembly.instantiate(module, imports);
    const wasm = instance.exports as any;
    
    console.log("✅ WASM module loaded successfully!");
    
    // Initialize WASM
    if (wasm.wasm_init) {
        wasm.wasm_init();
        console.log("✅ WASM initialized");
    }
    
    console.log("\n🔑 Test 1: Creating identity for key package...");
    const privKeyPtr = wasm.wasm_alloc(32);
    const pubKeyPtr = wasm.wasm_alloc(32);
    
    const identitySuccess = wasm.wasm_create_identity(privKeyPtr, pubKeyPtr);
    if (!identitySuccess) {
        console.error("❌ Failed to create identity");
        return;
    }
    
    const privateKey = new Uint8Array(wasm.memory.buffer, privKeyPtr, 32);
    const publicKey = new Uint8Array(wasm.memory.buffer, pubKeyPtr, 32);
    
    console.log("  Private key:", bytesToHex(privateKey).slice(0, 32) + "...");
    console.log("  Public key: ", bytesToHex(publicKey));
    
    console.log("\n📦 Test 2: Creating key package...");
    
    // Allocate space for key package
    const maxSize = 1024;
    const outDataPtr = wasm.wasm_alloc(maxSize);
    const outLenPtr = wasm.wasm_alloc(4);
    
    if (!outDataPtr || !outLenPtr) {
        console.error("❌ Failed to allocate memory for key package");
        return;
    }
    
    // Set initial length
    const lenView = new Uint32Array(wasm.memory.buffer, outLenPtr, 1);
    lenView[0] = maxSize;
    
    console.log("  Allocated buffers - data ptr:", outDataPtr, "len ptr:", outLenPtr);
    console.log("  Initial buffer size:", lenView[0]);
    
    // Try to create key package
    const keyPackageSuccess = wasm.wasm_create_key_package(
        privKeyPtr,
        outDataPtr,
        outLenPtr
    );
    
    const actualLen = lenView[0];
    console.log("  Key package creation result:", keyPackageSuccess);
    console.log("  Actual data length:", actualLen);
    
    if (keyPackageSuccess) {
        const keyPackageData = new Uint8Array(wasm.memory.buffer, outDataPtr, actualLen);
        console.log("✅ Key package created successfully!");
        console.log("  Size:", actualLen, "bytes");
        console.log("  First 32 bytes:", bytesToHex(keyPackageData.slice(0, 32)));
    } else {
        console.error("❌ Failed to create key package");
        console.log("  This is expected - MLS functionality is not yet implemented in WASM");
        console.log("\n💡 Next steps:");
        console.log("  1. Implement a simplified key package format for the visualizer");
        console.log("  2. Or use mock data for visualization purposes");
        console.log("  3. Full MLS implementation can come later");
    }
    
    // Clean up
    wasm.wasm_free(privKeyPtr, 32);
    wasm.wasm_free(pubKeyPtr, 32);
    wasm.wasm_free(outDataPtr, maxSize);
    wasm.wasm_free(outLenPtr, 4);
    
    console.log("\n🧪 Test 3: Checking other crypto functions...");
    
    // Test if ephemeral key generation is available
    if (wasm.wasm_generate_ephemeral_keys) {
        console.log("✅ Ephemeral key generation is available");
    } else {
        console.log("❌ Ephemeral key generation is NOT exported");
    }
    
    // Test if signing is available
    if (wasm.wasm_sign_schnorr) {
        console.log("✅ Schnorr signing is available");
    } else {
        console.log("❌ Schnorr signing is NOT exported");
    }
    
    // Test if verification is available
    if (wasm.wasm_verify_schnorr) {
        console.log("✅ Schnorr verification is available");
    } else {
        console.log("❌ Schnorr verification is NOT exported");
    }
    
    console.log("\n✅ Test completed!");
}

testKeyPackages().catch(console.error);