#!/usr/bin/env bun

import { readFileSync } from 'fs';
import { resolve } from 'path';

// Load WASM module
const wasmPath = resolve(__dirname, '../visualizer/src/nostr_mls.wasm');
const wasmBuffer = readFileSync(wasmPath);

// Helper to convert bytes to hex string
function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

// Setup WASM imports
const imports = {
    env: {
        getRandomValues: (ptr: number, len: number) => {
            const bytes = new Uint8Array(wasmMemory.buffer, ptr, len);
            crypto.getRandomValues(bytes);
        },
        getCurrentTimestamp: (): bigint => {
            return BigInt(Math.floor(Date.now() / 1000));
        },
        wasm_log_error: (strPtr: number, len: number) => {
            const bytes = new Uint8Array(wasmMemory.buffer, strPtr, len);
            const message = new TextDecoder().decode(bytes);
            console.error('WASM error:', message);
        }
    }
};

// Instantiate WASM module
const wasmModule = new WebAssembly.Module(wasmBuffer);
const wasmInstance = new WebAssembly.Instance(wasmModule, imports);
const exports = wasmInstance.exports as any;
const wasmMemory = exports.memory as WebAssembly.Memory;

console.log("🔍 Debugging NIP-44 Key Issues...\n");

// Test multiple times to see if it's consistent
for (let i = 0; i < 5; i++) {
    console.log(`\n--- Test ${i + 1} ---`);
    
    // Method 1: Create identity
    const privateKey1Ptr = exports.wasm_alloc(32);
    const publicKey1Ptr = exports.wasm_alloc(32);
    
    if (!exports.wasm_create_identity(privateKey1Ptr, publicKey1Ptr)) {
        console.error("❌ Failed to create identity");
        continue;
    }
    
    const privateKey1 = new Uint8Array(wasmMemory.buffer, privateKey1Ptr, 32);
    const publicKey1 = new Uint8Array(wasmMemory.buffer, publicKey1Ptr, 32);
    console.log(`Identity private key: ${bytesToHex(privateKey1)}`);
    console.log(`Identity public key:  ${bytesToHex(publicKey1)}`);
    
    // Method 2: Generate valid secp256k1 key from the same private key
    const validKeyPtr = exports.wasm_alloc(32);
    if (!exports.wasm_generate_valid_secp256k1_key(privateKey1Ptr, validKeyPtr)) {
        console.error("❌ Failed to generate valid key");
        exports.wasm_free(privateKey1Ptr, 32);
        exports.wasm_free(publicKey1Ptr, 32);
        exports.wasm_free(validKeyPtr, 32);
        continue;
    }
    
    const validKey = new Uint8Array(wasmMemory.buffer, validKeyPtr, 32);
    console.log(`Valid secp256k1 key:  ${bytesToHex(validKey)}`);
    
    // Get public key from the valid key
    const validPubKeyPtr = exports.wasm_alloc(32);
    if (!exports.wasm_secp256k1_get_public_key(validKeyPtr, validPubKeyPtr)) {
        console.error("❌ Failed to get public key from valid key");
        exports.wasm_free(privateKey1Ptr, 32);
        exports.wasm_free(publicKey1Ptr, 32);
        exports.wasm_free(validKeyPtr, 32);
        exports.wasm_free(validPubKeyPtr, 32);
        continue;
    }
    
    const validPubKey = new Uint8Array(wasmMemory.buffer, validPubKeyPtr, 32);
    console.log(`Valid public key:     ${bytesToHex(validPubKey)}`);
    
    // Now try NIP-44 encryption with each key
    const plaintext = "Test message";
    const plaintextBytes = new TextEncoder().encode(plaintext);
    const plaintextPtr = exports.wasm_alloc(plaintextBytes.length);
    new Uint8Array(wasmMemory.buffer, plaintextPtr, plaintextBytes.length).set(plaintextBytes);
    
    const ciphertextPtr = exports.wasm_alloc(256);
    const ciphertextLenPtr = exports.wasm_alloc_u32(1);
    const ciphertextLenView = new Uint32Array(wasmMemory.buffer, ciphertextLenPtr, 1);
    ciphertextLenView[0] = 256;
    
    // Try with original key
    console.log(`\nTrying NIP-44 with original key...`);
    const encryptResult1 = exports.wasm_nip44_encrypt(
        privateKey1Ptr,
        plaintextPtr,
        plaintextBytes.length,
        ciphertextPtr,
        ciphertextLenPtr
    );
    console.log(`Result: ${encryptResult1 ? '✅ Success' : '❌ Failed'}`);
    
    // Try with valid key
    console.log(`Trying NIP-44 with valid key...`);
    ciphertextLenView[0] = 256; // Reset buffer size
    const encryptResult2 = exports.wasm_nip44_encrypt(
        validKeyPtr,
        plaintextPtr,
        plaintextBytes.length,
        ciphertextPtr,
        ciphertextLenPtr
    );
    console.log(`Result: ${encryptResult2 ? '✅ Success' : '❌ Failed'}`);
    
    // Clean up
    exports.wasm_free(privateKey1Ptr, 32);
    exports.wasm_free(publicKey1Ptr, 32);
    exports.wasm_free(validKeyPtr, 32);
    exports.wasm_free(validPubKeyPtr, 32);
    exports.wasm_free(plaintextPtr, plaintextBytes.length);
    exports.wasm_free(ciphertextPtr, 256);
    exports.wasm_free_u32(ciphertextLenPtr, 1);
}

console.log("\n✅ Debug test completed");