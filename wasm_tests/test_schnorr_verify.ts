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

function hexToBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
}

console.log("🔍 Testing Schnorr Signature Verification...\n");

// Test 1: Create signature and verify it immediately
console.log("1. Testing signature creation and verification...");

// Create a test private key
const privateKeyPtr = exports.wasm_alloc(32);
const privateKey = new Uint8Array(32);
privateKey.fill(1); // Simple test key
new Uint8Array(wasmMemory.buffer, privateKeyPtr, 32).set(privateKey);

// Get public key
const publicKeyPtr = exports.wasm_alloc(32);
if (exports.wasm_get_public_key(privateKeyPtr, publicKeyPtr)) {
    const publicKey = new Uint8Array(wasmMemory.buffer, publicKeyPtr, 32);
    console.log("✅ Public key:", Array.from(publicKey).map(b => b.toString(16).padStart(2, '0')).join(''));
    
    // Create a test message (32 bytes)
    const messagePtr = exports.wasm_alloc(32);
    const message = new Uint8Array(32);
    // Fill with a pattern
    for (let i = 0; i < 32; i++) {
        message[i] = i;
    }
    new Uint8Array(wasmMemory.buffer, messagePtr, 32).set(message);
    console.log("Message:", Array.from(message).map(b => b.toString(16).padStart(2, '0')).join(''));
    
    // Sign the message
    const signaturePtr = exports.wasm_alloc(64);
    if (exports.wasm_sign_schnorr(messagePtr, privateKeyPtr, signaturePtr)) {
        const signature = new Uint8Array(wasmMemory.buffer, signaturePtr, 64);
        console.log("✅ Signature created:", Array.from(signature).map(b => b.toString(16).padStart(2, '0')).join(''));
        
        // Now try to verify using a manual verification function if available
        console.log("\n2. Testing if we have a direct verify function...");
        
        // Check available exports
        const verifyFunctions = Object.keys(exports).filter(name => 
            name.includes('verify') && name.startsWith('wasm_')
        );
        console.log("Available verify functions:", verifyFunctions);
        
        // Test event creation with new WASM exports
        console.log("\n3. Testing wasm_create_event...");
        const content = "Test note for verification";
        const contentBytes = new TextEncoder().encode(content);
        const contentPtr = exports.wasm_alloc(contentBytes.length);
        new Uint8Array(wasmMemory.buffer, contentPtr, contentBytes.length).set(contentBytes);
        
        const tagsJson = "[]";
        const tagsBytes = new TextEncoder().encode(tagsJson);
        const tagsPtr = exports.wasm_alloc(tagsBytes.length);
        new Uint8Array(wasmMemory.buffer, tagsPtr, tagsBytes.length).set(tagsBytes);
        
        const outJsonPtr = exports.wasm_alloc(4096);
        const outLenPtr = exports.wasm_alloc_u32(1);
        new Uint32Array(wasmMemory.buffer, outLenPtr, 1)[0] = 4096;
        
        const success = exports.wasm_create_event(
            privateKeyPtr,
            1,                        // kind 1 = text note
            contentPtr,
            contentBytes.length,
            tagsPtr,
            tagsBytes.length,
            outJsonPtr,
            outLenPtr
        );
        
        if (success) {
            const jsonLen = new Uint32Array(wasmMemory.buffer, outLenPtr, 1)[0];
            const eventJson = new TextDecoder().decode(
                new Uint8Array(wasmMemory.buffer, outJsonPtr, jsonLen)
            );
            console.log("✅ Created event with wasm_create_event");
            const event = JSON.parse(eventJson);
            console.log("Event ID:", event.id);
            console.log("Signature:", event.sig);
            
            // Verify using direct Schnorr verification
            const eventIdBytes = hexToBytes(event.id);
            const pubkeyBytes = hexToBytes(event.pubkey);
            const signatureBytes = hexToBytes(event.sig);
            
            const eventIdPtr = exports.wasm_alloc(32);
            const pubkeyPtr = exports.wasm_alloc(32);
            const sigPtr = exports.wasm_alloc(64);
            
            new Uint8Array(wasmMemory.buffer, eventIdPtr, 32).set(eventIdBytes);
            new Uint8Array(wasmMemory.buffer, pubkeyPtr, 32).set(pubkeyBytes);
            new Uint8Array(wasmMemory.buffer, sigPtr, 64).set(signatureBytes);
            
            const verifyResult = exports.wasm_verify_schnorr(eventIdPtr, sigPtr, pubkeyPtr);
            console.log("Verification result:", verifyResult);
            
            exports.wasm_free(eventIdPtr, 32);
            exports.wasm_free(pubkeyPtr, 32);
            exports.wasm_free(sigPtr, 64);
        } else {
            console.error("❌ Failed to create event");
        }
        
        exports.wasm_free(contentPtr, contentBytes.length);
        exports.wasm_free(tagsPtr, tagsBytes.length);
        exports.wasm_free(outJsonPtr, 4096);
        exports.wasm_free(outLenPtr, 4);
        
    } else {
        console.error("❌ Failed to create signature");
    }
    
    exports.wasm_free(messagePtr, 32);
    exports.wasm_free(signaturePtr, 64);
} else {
    console.error("❌ Failed to get public key");
}

exports.wasm_free(privateKeyPtr, 32);
exports.wasm_free(publicKeyPtr, 32);

// Test 4: Check if there's a signature verification export
console.log("\n4. Looking for signature verification exports...");
const signatureExports = Object.keys(exports).filter(name => 
    (name.includes('verify') || name.includes('signature')) && name.startsWith('wasm_')
);
console.log("Signature-related exports:", signatureExports);

// Test 5: Test wasm_verify_schnorr directly
console.log("\n5. Testing wasm_verify_schnorr directly...");

// Create a simple test
const testPrivKeyPtr = exports.wasm_alloc(32);
const testPrivKey = new Uint8Array(32);
testPrivKey.fill(2); // Different test key
new Uint8Array(wasmMemory.buffer, testPrivKeyPtr, 32).set(testPrivKey);

const testPubKeyPtr = exports.wasm_alloc(32);
if (exports.wasm_get_public_key(testPrivKeyPtr, testPubKeyPtr)) {
    const testPubKey = new Uint8Array(wasmMemory.buffer, testPubKeyPtr, 32);
    
    // Create a test message
    const testMsgPtr = exports.wasm_alloc(32);
    const testMsg = new Uint8Array(32);
    testMsg.fill(42); // Fill with 0x2a
    new Uint8Array(wasmMemory.buffer, testMsgPtr, 32).set(testMsg);
    
    // Sign it
    const testSigPtr = exports.wasm_alloc(64);
    if (exports.wasm_sign_schnorr(testMsgPtr, testPrivKeyPtr, testSigPtr)) {
        const testSig = new Uint8Array(wasmMemory.buffer, testSigPtr, 64);
        console.log("Test signature created");
        
        // Now verify it
        const verifyResult = exports.wasm_verify_schnorr(testMsgPtr, testSigPtr, testPubKeyPtr);
        console.log("Direct verify result:", verifyResult);
        
        // Try with wrong message
        const wrongMsgPtr = exports.wasm_alloc(32);
        const wrongMsg = new Uint8Array(32);
        wrongMsg.fill(99); // Different content
        new Uint8Array(wasmMemory.buffer, wrongMsgPtr, 32).set(wrongMsg);
        
        const wrongVerifyResult = exports.wasm_verify_schnorr(wrongMsgPtr, testSigPtr, testPubKeyPtr);
        console.log("Wrong message verify result:", wrongVerifyResult);
        
        exports.wasm_free(wrongMsgPtr, 32);
    }
    
    exports.wasm_free(testMsgPtr, 32);
    exports.wasm_free(testSigPtr, 64);
}

exports.wasm_free(testPrivKeyPtr, 32);
exports.wasm_free(testPubKeyPtr, 32);

console.log("\n✅ Test complete!");