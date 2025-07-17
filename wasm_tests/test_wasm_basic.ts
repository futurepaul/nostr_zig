#!/usr/bin/env bun

import { readFileSync } from 'fs';
import { resolve } from 'path';

// Load WASM module
const wasmPath = resolve(__dirname, '../visualizer/src/nostr_mls.wasm');
const wasmBuffer = readFileSync(wasmPath);

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

console.log("🧪 Testing Basic WASM Functionality...\n");

// Test 1: Basic allocation
console.log("1. Testing memory allocation...");
const ptr = exports.wasm_alloc(32);
if (ptr) {
    console.log("✅ Memory allocation successful");
    exports.wasm_free(ptr, 32);
} else {
    console.error("❌ Memory allocation failed");
}

// Test 2: Version check
console.log("\n2. Testing version...");
const version = exports.wasm_get_version();
console.log(`✅ WASM version: ${version}`);

// Test 3: List available exports
console.log("\n3. Available WASM exports:");
const exportNames = Object.keys(exports).filter(name => name.startsWith('wasm_'));
exportNames.sort().forEach(name => {
    console.log(`   - ${name}`);
});

// Test 4: Test identity creation
console.log("\n4. Testing identity creation...");
const privateKeyPtr = exports.wasm_alloc(32);
const publicKeyPtr = exports.wasm_alloc(32);

if (exports.wasm_create_identity(privateKeyPtr, publicKeyPtr)) {
    const privateKey = new Uint8Array(wasmMemory.buffer, privateKeyPtr, 32);
    const publicKey = new Uint8Array(wasmMemory.buffer, publicKeyPtr, 32);
    
    console.log(`✅ Created identity`);
    console.log(`   Private key: ${Array.from(privateKey).map(b => b.toString(16).padStart(2, '0')).join('')}`);
    console.log(`   Public key: ${Array.from(publicKey).map(b => b.toString(16).padStart(2, '0')).join('')}`);
} else {
    console.error("❌ Identity creation failed");
}

exports.wasm_free(privateKeyPtr, 32);
exports.wasm_free(publicKeyPtr, 32);

console.log("\n✅ Basic WASM test completed!");