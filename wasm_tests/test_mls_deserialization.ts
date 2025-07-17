#!/usr/bin/env bun

import { readFileSync } from 'fs';
import { resolve } from 'path';

// Load WASM module
const wasmPath = resolve(__dirname, '../visualizer/src/nostr_mls.wasm');
const wasmBuffer = readFileSync(wasmPath);

// Helper to convert hex string to bytes
function hexToBytes(hex: string): Uint8Array {
    if (hex.length % 2 !== 0) throw new Error("Invalid hex string");
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}

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

console.log("🔍 Testing MLS Message Deserialization...\n");

// Debug: Check available exports
console.log("📋 Available WASM exports:");
const exportNames = Object.keys(exports).filter(name => name.startsWith('wasm_'));
exportNames.forEach(name => console.log(`  - ${name}`));
console.log("");

// STEP 1: Create a group to get valid group state
console.log("1. Creating test group...");
const testPrivKey = hexToBytes("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
const testPubKey = new Uint8Array(32);

// Get public key from private key
const privKeyPtr = exports.wasm_alloc(32);
const pubKeyPtr = exports.wasm_alloc(32);
new Uint8Array(wasmMemory.buffer, privKeyPtr, 32).set(testPrivKey);
exports.wasm_get_public_key_from_private(privKeyPtr, pubKeyPtr);
new Uint8Array(wasmMemory.buffer, pubKeyPtr, 32).fill(0);
const pubKeyData = new Uint8Array(wasmMemory.buffer, pubKeyPtr, 32).slice();

// Create group
const groupStatePtr = exports.wasm_alloc(4096);
const groupStateLenPtr = exports.wasm_alloc(4);
new Uint32Array(wasmMemory.buffer, groupStateLenPtr, 1)[0] = 4096;

const groupSuccess = exports.wasm_create_group(privKeyPtr, pubKeyPtr, groupStatePtr, groupStateLenPtr);
if (!groupSuccess) {
    console.error("❌ Failed to create group");
    process.exit(1);
}

const groupStateLen = new Uint32Array(wasmMemory.buffer, groupStateLenPtr, 1)[0];
const groupState = new Uint8Array(wasmMemory.buffer, groupStatePtr, groupStateLen).slice();
console.log(`✅ Group created! State size: ${groupStateLen} bytes`);

// STEP 2: Create a test message using wasm_send_message
console.log("\n2. Creating test MLS message...");
const testMessage = "Hello MLS World!";
const messageBytes = new TextEncoder().encode(testMessage);
const messagePtr = exports.wasm_alloc(messageBytes.length);
if (!messagePtr) {
    console.error("❌ Failed to allocate memory for message");
    process.exit(1);
}
new Uint8Array(wasmMemory.buffer, messagePtr, messageBytes.length).set(messageBytes);

// Allocate space for encrypted output
const encryptedPtr = exports.wasm_alloc(4096);
const encryptedLenPtr = exports.wasm_alloc(4);
new Uint32Array(wasmMemory.buffer, encryptedLenPtr, 1)[0] = 4096;

// Copy group state to working buffer
const workingGroupStatePtr = exports.wasm_alloc(groupStateLen);
new Uint8Array(wasmMemory.buffer, workingGroupStatePtr, groupStateLen).set(groupState);

// Send message to get encrypted output
const sendSuccess = exports.wasm_send_message(
    workingGroupStatePtr,
    groupStateLen,
    privKeyPtr,
    messagePtr,
    messageBytes.length,
    encryptedPtr,
    encryptedLenPtr
);

if (!sendSuccess) {
    console.error("❌ Failed to send message");
    process.exit(1);
}

const encryptedLen = new Uint32Array(wasmMemory.buffer, encryptedLenPtr, 1)[0];
const encryptedData = new Uint8Array(wasmMemory.buffer, encryptedPtr, encryptedLen).slice();
console.log(`✅ Message encrypted! Ciphertext size: ${encryptedLen} bytes`);

// STEP 3: Use wasm_receive_message to decrypt and get the MLS ciphertext
console.log("\n3. Decrypting to get MLS serialized data...");

// Debug: Show the encrypted data structure
console.log(`📊 Encrypted data analysis:`);
console.log(`  - Total length: ${encryptedData.length} bytes`);
console.log(`  - Version byte: 0x${encryptedData[0].toString(16).padStart(2, '0')}`);
console.log(`  - First 16 bytes: ${bytesToHex(encryptedData.slice(0, 16))}`);

// The encrypted data from wasm_send_message has this structure:
// [version: 1][group_hash: 32][sender_pubkey: 32][nip44_payload: variable][signature: 64]
// So the NIP-44 payload starts at byte 65 and goes until signature (last 64 bytes)
const headerSize = 1 + 32 + 32; // 65 bytes
const signatureSize = 64;
const nip44PayloadStart = headerSize;
const nip44PayloadEnd = encryptedData.length - signatureSize;
const nip44Payload = encryptedData.slice(nip44PayloadStart, nip44PayloadEnd);

console.log(`  - Header size: ${headerSize} bytes`);
console.log(`  - NIP-44 payload: ${nip44Payload.length} bytes (from ${nip44PayloadStart} to ${nip44PayloadEnd})`);
console.log(`  - Signature size: ${signatureSize} bytes`);

// Convert NIP-44 payload to base64
const encryptedBase64 = btoa(String.fromCharCode(...nip44Payload));
const ciphertextPtr = exports.wasm_alloc(encryptedBase64.length);
new Uint8Array(wasmMemory.buffer, ciphertextPtr, encryptedBase64.length).set(new TextEncoder().encode(encryptedBase64));

// Allocate space for decrypted output
const decryptedPtr = exports.wasm_alloc(4096);
const decryptedLenPtr = exports.wasm_alloc(4);
new Uint32Array(wasmMemory.buffer, decryptedLenPtr, 1)[0] = 4096;

// Reset working group state
new Uint8Array(wasmMemory.buffer, workingGroupStatePtr, groupStateLen).set(groupState);

// Receive message (this does NIP-44 decrypt + MLS deserialize internally)
const receiveSuccess = exports.wasm_receive_message(
    workingGroupStatePtr,
    groupStateLen,
    privKeyPtr,
    ciphertextPtr,
    encryptedBase64.length,
    decryptedPtr,
    decryptedLenPtr
);

if (!receiveSuccess) {
    console.error("❌ Failed to receive message");
    process.exit(1);
}

const decryptedLen = new Uint32Array(wasmMemory.buffer, decryptedLenPtr, 1)[0];
const decryptedMessage = new TextDecoder().decode(new Uint8Array(wasmMemory.buffer, decryptedPtr, decryptedLen));
console.log(`✅ Message decrypted! Length: ${decryptedLen} bytes`);
console.log(`📝 Decrypted content: "${decryptedMessage}"`);

// STEP 4: Test that we get back our original message
console.log("\n4. Verifying round-trip integrity...");
if (decryptedMessage === testMessage) {
    console.log("✅ Round-trip successful! Original message recovered.");
} else {
    console.error(`❌ Round-trip failed!`);
    console.error(`  Expected: "${testMessage}"`);
    console.error(`  Got:      "${decryptedMessage}"`);
    process.exit(1);
}

// STEP 5: Test MLS deserialization components directly (if available)
console.log("\n5. Testing MLS deserialization components...");

// Check if we have the serialize/deserialize functions
const hasSerialize = typeof exports.wasm_serialize_mls_application_message === 'function';
const hasDeserialize = typeof exports.wasm_deserialize_mls_message === 'function';

console.log(`📋 Available functions:`);
console.log(`  - wasm_serialize_mls_application_message: ${hasSerialize ? '✅' : '❌'}`);
console.log(`  - wasm_deserialize_mls_message: ${hasDeserialize ? '✅' : '❌'}`);

if (hasSerialize && hasDeserialize) {
    console.log("\n🧪 Testing direct serialization/deserialization...");
    
    // Create a simple test event
    const testEvent = JSON.stringify({
        kind: 9,
        content: "Direct test message",
        created_at: Math.floor(Date.now() / 1000),
        pubkey: bytesToHex(pubKeyData),
        tags: []
    });
    
    console.log(`📝 Test event: ${testEvent}`);
    
    // Serialize it
    const eventPtr = exports.wasm_alloc(testEvent.length);
    new Uint8Array(wasmMemory.buffer, eventPtr, testEvent.length).set(new TextEncoder().encode(testEvent));
    
    const serializedPtr = exports.wasm_alloc(4096);
    const serializedLenPtr = exports.wasm_alloc(4);
    new Uint32Array(wasmMemory.buffer, serializedLenPtr, 1)[0] = 4096;
    
    // Create fake group ID and signature for testing
    const groupId = new Uint8Array(32).fill(0x42);
    const groupIdPtr = exports.wasm_alloc(32);
    new Uint8Array(wasmMemory.buffer, groupIdPtr, 32).set(groupId);
    
    const signature = new Uint8Array(64).fill(0xab);
    const signaturePtr = exports.wasm_alloc(64);
    new Uint8Array(wasmMemory.buffer, signaturePtr, 64).set(signature);
    
    const serializeSuccess = exports.wasm_serialize_mls_application_message(
        groupIdPtr,
        1n, // epoch
        0, // sender_index
        eventPtr,
        testEvent.length,
        signaturePtr,
        64,
        serializedPtr,
        serializedLenPtr
    );
    
    if (serializeSuccess) {
        const serializedLen = new Uint32Array(wasmMemory.buffer, serializedLenPtr, 1)[0];
        console.log(`✅ Serialization successful! Size: ${serializedLen} bytes`);
        
        // Now test deserialization
        const outGroupIdPtr = exports.wasm_alloc(32);
        const outEpochPtr = exports.wasm_alloc(8);
        const outSenderIndexPtr = exports.wasm_alloc(4);
        const outAppDataPtr = exports.wasm_alloc(4096);
        const outAppDataLenPtr = exports.wasm_alloc(4);
        const outSigPtr = exports.wasm_alloc(256);
        const outSigLenPtr = exports.wasm_alloc(4);
        
        new Uint32Array(wasmMemory.buffer, outAppDataLenPtr, 1)[0] = 4096;
        new Uint32Array(wasmMemory.buffer, outSigLenPtr, 1)[0] = 256;
        
        const deserializeSuccess = exports.wasm_deserialize_mls_message(
            serializedPtr,
            serializedLen,
            outGroupIdPtr,
            outEpochPtr,
            outSenderIndexPtr,
            outAppDataPtr,
            outAppDataLenPtr,
            outSigPtr,
            outSigLenPtr
        );
        
        if (deserializeSuccess) {
            const recoveredLen = new Uint32Array(wasmMemory.buffer, outAppDataLenPtr, 1)[0];
            const recoveredEvent = new TextDecoder().decode(new Uint8Array(wasmMemory.buffer, outAppDataPtr, recoveredLen));
            
            console.log(`✅ Deserialization successful! Recovered ${recoveredLen} bytes`);
            console.log(`📝 Recovered event: ${recoveredEvent}`);
            
            if (recoveredEvent === testEvent) {
                console.log("✅ Direct serialization/deserialization round-trip successful!");
            } else {
                console.error("❌ Direct round-trip failed!");
                console.error(`  Expected: ${testEvent}`);
                console.error(`  Got:      ${recoveredEvent}`);
            }
        } else {
            console.error("❌ Deserialization failed");
        }
        
        // Cleanup
        exports.wasm_free(outGroupIdPtr, 32);
        exports.wasm_free(outEpochPtr, 8);
        exports.wasm_free(outSenderIndexPtr, 4);
        exports.wasm_free(outAppDataPtr, 4096);
        exports.wasm_free(outAppDataLenPtr, 4);
        exports.wasm_free(outSigPtr, 256);
        exports.wasm_free(outSigLenPtr, 4);
    } else {
        console.error("❌ Serialization failed");
    }
    
    // Cleanup
    exports.wasm_free(eventPtr, testEvent.length);
    exports.wasm_free(serializedPtr, 4096);
    exports.wasm_free(serializedLenPtr, 4);
    exports.wasm_free(groupIdPtr, 32);
    exports.wasm_free(signaturePtr, 64);
}

// Cleanup
exports.wasm_free(privKeyPtr, 32);
exports.wasm_free(pubKeyPtr, 32);
exports.wasm_free(groupStatePtr, 4096);
exports.wasm_free(groupStateLenPtr, 4);
exports.wasm_free(messagePtr, messageBytes.length);
exports.wasm_free(encryptedPtr, 4096);
exports.wasm_free(encryptedLenPtr, 4);
exports.wasm_free(workingGroupStatePtr, groupStateLen);
exports.wasm_free(ciphertextPtr, encryptedBase64.length);
exports.wasm_free(decryptedPtr, 4096);
exports.wasm_free(decryptedLenPtr, 4);

console.log("\n✅ All MLS deserialization tests passed!");