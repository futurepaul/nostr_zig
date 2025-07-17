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

console.log("🧪 Testing NIP-EE Functions Directly...\n");

// Test 1: Generate exporter secret
console.log("1. Testing exporter secret generation...");
const groupState = new Uint8Array(137);
crypto.getRandomValues(groupState);

const statePtr = exports.wasm_alloc(groupState.length);
const secretPtr = exports.wasm_alloc(32);

new Uint8Array(wasmMemory.buffer, statePtr, groupState.length).set(groupState);

const secretResult = exports.wasm_nip_ee_generate_exporter_secret(
    statePtr,
    groupState.length,
    secretPtr
);

if (!secretResult) {
    console.error("❌ Failed to generate exporter secret");
    process.exit(1);
}

const generatedSecret = new Uint8Array(wasmMemory.buffer, secretPtr, 32);
console.log(`✅ Generated exporter secret: ${bytesToHex(generatedSecret)}`);

// Make sure the exporter secret is a valid secp256k1 key
const validSecretPtr = exports.wasm_alloc(32);
if (!exports.wasm_generate_valid_secp256k1_key(secretPtr, validSecretPtr)) {
    console.error("❌ Failed to convert exporter secret to valid secp256k1 key");
    process.exit(1);
}

// Copy back to secretPtr
new Uint8Array(wasmMemory.buffer, secretPtr, 32).set(new Uint8Array(wasmMemory.buffer, validSecretPtr, 32));
exports.wasm_free(validSecretPtr, 32);
console.log(`✅ Converted to valid secp256k1 key: ${bytesToHex(new Uint8Array(wasmMemory.buffer, secretPtr, 32))}`);

// Test 2: Create encrypted group message
console.log("\n2. Testing group message encryption...");

const testMessage = "Hello from NIP-EE test!";
const testMessageBytes = new TextEncoder().encode(testMessage);

// Create test data
const groupId = new Uint8Array(32);
crypto.getRandomValues(groupId);

const signature = new Uint8Array(64);
crypto.getRandomValues(signature);

// Allocate memory
const messagePtr = exports.wasm_alloc(testMessageBytes.length);
const groupIdPtr = exports.wasm_alloc(32);
const signaturePtr = exports.wasm_alloc(64);
const encryptedPtr = exports.wasm_alloc(1024);
const encryptedLenPtr = exports.wasm_alloc_u32(1);

// Copy data to WASM memory
new Uint8Array(wasmMemory.buffer, messagePtr, testMessageBytes.length).set(testMessageBytes);
new Uint8Array(wasmMemory.buffer, groupIdPtr, 32).set(groupId);
new Uint8Array(wasmMemory.buffer, signaturePtr, 64).set(signature);

// Set output buffer size
const encryptedLenView = new Uint32Array(wasmMemory.buffer, encryptedLenPtr, 1);
encryptedLenView[0] = 1024;

// Encrypt
const encryptResult = exports.wasm_nip_ee_create_encrypted_group_message(
    groupIdPtr,        // group_id
    BigInt(0),         // epoch
    0,                 // sender_index
    messagePtr,        // message_content
    testMessageBytes.length,
    signaturePtr,      // mls_signature
    64,                // signature length
    secretPtr,         // exporter_secret (from step 1)
    encryptedPtr,      // out_encrypted
    encryptedLenPtr    // out_len
);

if (!encryptResult) {
    console.error("❌ Failed to create encrypted group message");
    process.exit(1);
}

const encryptedLen = encryptedLenView[0];
const encryptedMessage = new Uint8Array(wasmMemory.buffer, encryptedPtr, encryptedLen);
console.log(`✅ Encrypted message created (${encryptedLen} bytes)`);
console.log(`   First 32 bytes: ${bytesToHex(encryptedMessage.slice(0, 32))}`);

// Test 3: Decrypt group message
console.log("\n3. Testing group message decryption...");

const decryptedPtr = exports.wasm_alloc(1024);
const decryptedLenPtr = exports.wasm_alloc_u32(1);

// Set output buffer size
const decryptedLenView = new Uint32Array(wasmMemory.buffer, decryptedLenPtr, 1);
decryptedLenView[0] = 1024;

// Decrypt
const decryptResult = exports.wasm_nip_ee_decrypt_group_message(
    encryptedPtr,      // encrypted_content
    encryptedLen,      // encrypted_content_len
    secretPtr,         // exporter_secret (same as used for encryption)
    decryptedPtr,      // out_decrypted
    decryptedLenPtr    // out_len
);

if (!decryptResult) {
    console.error("❌ Failed to decrypt group message");
    process.exit(1);
}

const decryptedLen = decryptedLenView[0];
const decryptedMessage = new Uint8Array(wasmMemory.buffer, decryptedPtr, decryptedLen);
const decryptedText = new TextDecoder().decode(decryptedMessage);

console.log(`✅ Message decrypted successfully (${decryptedLen} bytes)`);
console.log(`   Content: "${decryptedText}"`);

// Verify round-trip
if (decryptedText === testMessage) {
    console.log("✅ Round-trip encryption/decryption successful!");
} else {
    console.error(`❌ Round-trip failed: expected "${testMessage}", got "${decryptedText}"`);
    process.exit(1);
}

// Clean up
exports.wasm_free(statePtr, groupState.length);
exports.wasm_free(secretPtr, 32);
exports.wasm_free(messagePtr, testMessageBytes.length);
exports.wasm_free(groupIdPtr, 32);
exports.wasm_free(signaturePtr, 64);
exports.wasm_free(encryptedPtr, 1024);
exports.wasm_free_u32(encryptedLenPtr, 1);
exports.wasm_free(decryptedPtr, 1024);
exports.wasm_free_u32(decryptedLenPtr, 1);

console.log("\n🎉 All NIP-EE tests passed!");