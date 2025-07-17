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

// Helper to allocate aligned memory for uint32
function allocateAlignedU32(exports: any): { ptr: number; alignedPtr: number } {
    const ptr = exports.wasm_alloc(8); // Allocate extra for alignment
    const alignedPtr = (ptr + 3) & ~3; // Align to 4-byte boundary
    return { ptr, alignedPtr };
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

console.log("🧪 Testing MLS Serialization/Deserialization...\n");

// Create a simple test Nostr event
const testEvent = {
    kind: 9,
    content: "Hello MLS!",
    created_at: Math.floor(Date.now() / 1000),
    pubkey: "be1444fc52079cf9a5e45d7054becfcc13249ec244af6da4e4ab7347ba155baa",
    tags: []
};

const testEventJson = JSON.stringify(testEvent);
console.log(`📝 Test event: ${testEventJson}`);

// Allocate memory for the event
const eventPtr = exports.wasm_alloc(testEventJson.length);
if (!eventPtr) {
    console.error("❌ Failed to allocate memory for event");
    process.exit(1);
}
new Uint8Array(wasmMemory.buffer, eventPtr, testEventJson.length).set(new TextEncoder().encode(testEventJson));

// Allocate memory for output
const serializedPtr = exports.wasm_alloc(4096);
const serializedLenAlloc = allocateAlignedU32(exports);
new Uint32Array(wasmMemory.buffer, serializedLenAlloc.alignedPtr, 1)[0] = 4096;

// Create test parameters
const groupId = new Uint8Array(32).fill(0x42);
const groupIdPtr = exports.wasm_alloc(32);
new Uint8Array(wasmMemory.buffer, groupIdPtr, 32).set(groupId);

const signature = new Uint8Array(64).fill(0xab);
const signaturePtr = exports.wasm_alloc(64);
new Uint8Array(wasmMemory.buffer, signaturePtr, 64).set(signature);

console.log("\n1. Testing MLS serialization...");
const serializeSuccess = exports.wasm_serialize_mls_application_message(
    groupIdPtr,
    BigInt(1), // epoch
    0, // sender_index
    eventPtr,
    testEventJson.length,
    signaturePtr,
    64,
    serializedPtr,
    serializedLenAlloc.alignedPtr
);

if (!serializeSuccess) {
    console.error("❌ Serialization failed");
    process.exit(1);
}

const serializedLen = new Uint32Array(wasmMemory.buffer, serializedLenAlloc.alignedPtr, 1)[0];
const serializedData = new Uint8Array(wasmMemory.buffer, serializedPtr, serializedLen).slice();

console.log(`✅ Serialization successful! Size: ${serializedLen} bytes`);
console.log(`📦 Serialized data (first 32 bytes): ${bytesToHex(serializedData.slice(0, 32))}`);

console.log("\n2. Testing MLS deserialization...");

// Allocate memory for deserialization outputs
const outGroupIdPtr = exports.wasm_alloc(32);
const outEpochPtr = exports.wasm_alloc(16); // Allocate extra for 8-byte alignment
const alignedOutEpochPtr = (outEpochPtr + 7) & ~7; // Align to 8-byte boundary
const outSenderIndexAlloc = allocateAlignedU32(exports);
const outAppDataPtr = exports.wasm_alloc(4096);
const outAppDataLenAlloc = allocateAlignedU32(exports);
const outSigPtr = exports.wasm_alloc(256);
const outSigLenAlloc = allocateAlignedU32(exports);

new Uint32Array(wasmMemory.buffer, outAppDataLenAlloc.alignedPtr, 1)[0] = 4096;
new Uint32Array(wasmMemory.buffer, outSigLenAlloc.alignedPtr, 1)[0] = 256;

const deserializeSuccess = exports.wasm_deserialize_mls_message(
    serializedPtr,
    serializedLen,
    outGroupIdPtr,
    alignedOutEpochPtr,
    outSenderIndexAlloc.alignedPtr,
    outAppDataPtr,
    outAppDataLenAlloc.alignedPtr,
    outSigPtr,
    outSigLenAlloc.alignedPtr
);

if (!deserializeSuccess) {
    console.error("❌ Deserialization failed");
    process.exit(1);
}

// Read back the results
const recoveredGroupId = new Uint8Array(wasmMemory.buffer, outGroupIdPtr, 32).slice();
const recoveredEpoch = new BigUint64Array(wasmMemory.buffer, alignedOutEpochPtr, 1)[0];
const recoveredSenderIndex = new Uint32Array(wasmMemory.buffer, outSenderIndexAlloc.alignedPtr, 1)[0];
const recoveredAppDataLen = new Uint32Array(wasmMemory.buffer, outAppDataLenAlloc.alignedPtr, 1)[0];
const recoveredAppData = new Uint8Array(wasmMemory.buffer, outAppDataPtr, recoveredAppDataLen).slice();
const recoveredSigLen = new Uint32Array(wasmMemory.buffer, outSigLenAlloc.alignedPtr, 1)[0];
const recoveredSig = new Uint8Array(wasmMemory.buffer, outSigPtr, recoveredSigLen).slice();

console.log(`✅ Deserialization successful!`);
console.log(`📊 Recovered data:`);
console.log(`  - Group ID: ${bytesToHex(recoveredGroupId)}`);
console.log(`  - Epoch: ${recoveredEpoch}`);
console.log(`  - Sender Index: ${recoveredSenderIndex}`);
console.log(`  - App Data Length: ${recoveredAppDataLen} bytes`);
console.log(`  - Signature Length: ${recoveredSigLen} bytes`);

// Convert recovered application data back to string
const recoveredEventJson = new TextDecoder().decode(recoveredAppData);
console.log(`  - Recovered Event: ${recoveredEventJson}`);

console.log("\n3. Verifying round-trip integrity...");

// Check group ID
const groupIdMatch = bytesToHex(recoveredGroupId) === bytesToHex(groupId);
console.log(`✅ Group ID match: ${groupIdMatch}`);

// Check epoch
const epochMatch = recoveredEpoch === BigInt(1);
console.log(`✅ Epoch match: ${epochMatch}`);

// Check sender index
const senderIndexMatch = recoveredSenderIndex === 0;
console.log(`✅ Sender index match: ${senderIndexMatch}`);

// Check application data
const eventMatch = recoveredEventJson === testEventJson;
console.log(`✅ Event match: ${eventMatch}`);

// Check signature
const sigMatch = bytesToHex(recoveredSig) === bytesToHex(signature);
console.log(`✅ Signature match: ${sigMatch}`);

if (groupIdMatch && epochMatch && senderIndexMatch && eventMatch && sigMatch) {
    console.log("\n🎉 All tests passed! MLS serialization/deserialization working perfectly!");
} else {
    console.log("\n❌ Some tests failed!");
    process.exit(1);
}

// Cleanup
exports.wasm_free(eventPtr, testEventJson.length);
exports.wasm_free(serializedPtr, 4096);
exports.wasm_free(serializedLenAlloc.ptr, 8);
exports.wasm_free(groupIdPtr, 32);
exports.wasm_free(signaturePtr, 64);
exports.wasm_free(outGroupIdPtr, 32);
exports.wasm_free(outEpochPtr, 16);
exports.wasm_free(outSenderIndexAlloc.ptr, 8);
exports.wasm_free(outAppDataPtr, 4096);
exports.wasm_free(outAppDataLenAlloc.ptr, 8);
exports.wasm_free(outSigPtr, 256);
exports.wasm_free(outSigLenAlloc.ptr, 8);

console.log("\n✅ MLS serialization/deserialization test complete!");