import { readFileSync } from 'fs';
import { resolve } from 'path';
import { createHash } from 'crypto';

// Load the WASM module
const wasmPath = resolve(__dirname, '../visualizer/src/nostr_mls.wasm');
const wasmBuffer = readFileSync(wasmPath);

// Create simple imports that don't require browser APIs
const wasmMemory = new WebAssembly.Memory({ initial: 256, maximum: 512 });

const imports = {
    env: {
        memory: wasmMemory,
        getRandomValues: (ptr: number, len: number) => {
            const bytes = new Uint8Array(wasmMemory.buffer, ptr, len);
            // Use Node.js crypto for randomness
            const nodeBytes = require('crypto').randomBytes(len);
            bytes.set(nodeBytes);
        }
    }
};

async function testSha256() {
    console.log("Loading WASM module...");
    const wasmModule = new WebAssembly.Module(wasmBuffer);
    const wasmInstance = new WebAssembly.Instance(wasmModule, imports);
    const exports = wasmInstance.exports as any;
    
    console.log("WASM exports:", Object.keys(exports).filter(k => k.includes('sha256')));
    
    // Test data
    const testData = "hello world";
    const encoder = new TextEncoder();
    const dataBytes = encoder.encode(testData);
    
    // Allocate memory for input and output
    const dataPtr = exports.wasm_alloc(dataBytes.length);
    if (!dataPtr) {
        throw new Error("Failed to allocate memory for data");
    }
    
    const hashPtr = exports.wasm_alloc(32); // SHA-256 produces 32 bytes
    if (!hashPtr) {
        exports.wasm_free(dataPtr, dataBytes.length);
        throw new Error("Failed to allocate memory for hash");
    }
    
    try {
        // Copy test data to WASM memory
        const wasmData = new Uint8Array(exports.memory.buffer, dataPtr, dataBytes.length);
        wasmData.set(dataBytes);
        
        // Call WASM SHA-256 function
        console.log(`\nTesting SHA-256 on: "${testData}"`);
        const success = exports.wasm_sha256(dataPtr, dataBytes.length, hashPtr);
        
        if (!success) {
            throw new Error("SHA-256 function returned false");
        }
        
        // Read the hash from WASM memory
        const hashBytes = new Uint8Array(exports.memory.buffer, hashPtr, 32);
        const hashArray = Array.from(hashBytes);
        
        // Convert to hex string
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        console.log("WASM SHA-256 result:", hashHex);
        
        // Compare with Node.js crypto SHA-256
        const expectedHash = createHash('sha256').update(testData).digest('hex');
        console.log("Expected SHA-256:   ", expectedHash);
        
        if (hashHex === expectedHash) {
            console.log("✅ SHA-256 implementation is correct!");
        } else {
            console.log("❌ SHA-256 implementation differs from expected!");
        }
        
        // Test with empty string
        console.log("\nTesting empty string:");
        const emptyData = new Uint8Array(0);
        const emptyPtr = exports.wasm_alloc(1); // Allocate at least 1 byte
        const emptyHashPtr = exports.wasm_alloc(32);
        
        // SHA-256 of empty string should fail per our validation
        const emptySuccess = exports.wasm_sha256(emptyPtr, 0, emptyHashPtr);
        console.log("Empty string result:", emptySuccess ? "❌ Should have failed!" : "✅ Correctly rejected");
        
        exports.wasm_free(emptyPtr, 1);
        exports.wasm_free(emptyHashPtr, 32);
        
        // Test with longer data
        const longData = "The quick brown fox jumps over the lazy dog";
        const longBytes = encoder.encode(longData);
        const longPtr = exports.wasm_alloc(longBytes.length);
        const longHashPtr = exports.wasm_alloc(32);
        
        const wasmLongData = new Uint8Array(exports.memory.buffer, longPtr, longBytes.length);
        wasmLongData.set(longBytes);
        
        console.log(`\nTesting longer string: "${longData}"`);
        const longSuccess = exports.wasm_sha256(longPtr, longBytes.length, longHashPtr);
        
        if (longSuccess) {
            const longHashBytes = new Uint8Array(exports.memory.buffer, longHashPtr, 32);
            const longHashHex = Array.from(longHashBytes).map(b => b.toString(16).padStart(2, '0')).join('');
            const expectedLongHash = createHash('sha256').update(longData).digest('hex');
            
            console.log("WASM result:    ", longHashHex);
            console.log("Expected result:", expectedLongHash);
            console.log(longHashHex === expectedLongHash ? "✅ Correct!" : "❌ Incorrect!");
        }
        
        exports.wasm_free(longPtr, longBytes.length);
        exports.wasm_free(longHashPtr, 32);
        
    } finally {
        // Clean up
        exports.wasm_free(dataPtr, dataBytes.length);
        exports.wasm_free(hashPtr, 32);
    }
}

// Run the test
testSha256().catch(console.error);