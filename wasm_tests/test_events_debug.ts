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

console.log("🔍 Debug: Testing individual WASM functions...\n");

// Test the individual crypto functions that work
console.log("1. Testing individual crypto functions...");

// Create a test private key
const privateKeyPtr = exports.wasm_alloc(32);
const privateKey = new Uint8Array(32);
privateKey.fill(1); // Simple test key
new Uint8Array(wasmMemory.buffer, privateKeyPtr, 32).set(privateKey);

// Get public key
const publicKeyPtr = exports.wasm_alloc(32);
if (exports.wasm_get_public_key(privateKeyPtr, publicKeyPtr)) {
    const publicKey = new Uint8Array(wasmMemory.buffer, publicKeyPtr, 32);
    console.log("✅ Got public key:", Array.from(publicKey).map(b => b.toString(16).padStart(2, '0')).join(''));
}

// Test SHA256
console.log("\n2. Testing SHA256...");
const testData = "hello world";
const testBytes = new TextEncoder().encode(testData);
const dataPtr = exports.wasm_alloc(testBytes.length);
new Uint8Array(wasmMemory.buffer, dataPtr, testBytes.length).set(testBytes);

const hashPtr = exports.wasm_alloc(32);
if (exports.wasm_sha256(dataPtr, testBytes.length, hashPtr)) {
    const hash = new Uint8Array(wasmMemory.buffer, hashPtr, 32);
    console.log("✅ SHA256 hash:", Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join(''));
    // Expected: b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
}

// Test signing
console.log("\n3. Testing Schnorr signing...");
const messagePtr = exports.wasm_alloc(32);
const message = new Uint8Array(32);
message.fill(2); // Simple test message
new Uint8Array(wasmMemory.buffer, messagePtr, 32).set(message);

const signaturePtr = exports.wasm_alloc(64);
if (exports.wasm_sign_schnorr(messagePtr, privateKeyPtr, signaturePtr)) {
    const signature = new Uint8Array(wasmMemory.buffer, signaturePtr, 64);
    console.log("✅ Schnorr signature created");
    console.log("   Length:", signature.length, "bytes");
}

// Now test event creation manually
console.log("\n4. Manual event ID calculation test...");

// Create a simple event structure manually
const pubkeyHex = Array.from(new Uint8Array(wasmMemory.buffer, publicKeyPtr, 32))
    .map(b => b.toString(16).padStart(2, '0')).join('');
const createdAt = Math.floor(Date.now() / 1000);
const kind = 1;
const tags: any[] = [];
const content = "Test event";

// Create canonical form for ID calculation
const canonical = JSON.stringify([
    0,
    pubkeyHex,
    createdAt,
    kind,
    tags,
    content
]);

console.log("   Canonical form:", canonical);

// Calculate ID
const canonicalBytes = new TextEncoder().encode(canonical);
const canonicalPtr = exports.wasm_alloc(canonicalBytes.length);
new Uint8Array(wasmMemory.buffer, canonicalPtr, canonicalBytes.length).set(canonicalBytes);

const idHashPtr = exports.wasm_alloc(32);
if (exports.wasm_sha256(canonicalPtr, canonicalBytes.length, idHashPtr)) {
    const idHash = new Uint8Array(wasmMemory.buffer, idHashPtr, 32);
    const eventId = Array.from(idHash).map(b => b.toString(16).padStart(2, '0')).join('');
    console.log("✅ Event ID calculated:", eventId);
}

// Cleanup
exports.wasm_free(privateKeyPtr, 32);
exports.wasm_free(publicKeyPtr, 32);
exports.wasm_free(dataPtr, testBytes.length);
exports.wasm_free(hashPtr, 32);
exports.wasm_free(messagePtr, 32);
exports.wasm_free(signaturePtr, 64);
exports.wasm_free(canonicalPtr, canonicalBytes.length);
exports.wasm_free(idHashPtr, 32);

console.log("\n✅ Debug test completed!");