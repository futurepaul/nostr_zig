#!/usr/bin/env bun

import { readFileSync } from 'fs';
import { resolve } from 'path';
import * as crypto from 'crypto';

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
            console.error('WASM:', message);
        }
    }
};

// Instantiate WASM module
const wasmModule = new WebAssembly.Module(wasmBuffer);
const wasmInstance = new WebAssembly.Instance(wasmModule, imports);
const exports = wasmInstance.exports as any;
const wasmMemory = exports.memory as WebAssembly.Memory;

console.log("🔍 Minimal Schnorr Test...\n");

// Create a known private key (secp256k1 test vector)
const privateKeyHex = "0000000000000000000000000000000000000000000000000000000000000003";
const privateKey = Buffer.from(privateKeyHex, 'hex');

console.log("Using test private key:", privateKeyHex);

// Allocate and set private key
const privKeyPtr = exports.wasm_alloc(32);
new Uint8Array(wasmMemory.buffer, privKeyPtr, 32).set(privateKey);

// Get public key
const pubKeyPtr = exports.wasm_alloc(32);
if (exports.wasm_get_public_key(privKeyPtr, pubKeyPtr)) {
    const publicKey = new Uint8Array(wasmMemory.buffer, pubKeyPtr, 32);
    const publicKeyHex = Buffer.from(publicKey).toString('hex');
    console.log("Public key:", publicKeyHex);
    
    // Expected public key for this private key
    const expectedPubKey = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
    console.log("Expected:  ", expectedPubKey);
    console.log("Match:", publicKeyHex === expectedPubKey);
    
    // Store for later use
    globalThis.expectedPubKey = expectedPubKey;
}

// Create a simple message (32 bytes of zeros)
const messagePtr = exports.wasm_alloc(32);
const message = new Uint8Array(32); // All zeros
new Uint8Array(wasmMemory.buffer, messagePtr, 32).set(message);

console.log("\nMessage (32 zeros):", Buffer.from(message).toString('hex'));

// Sign the message
const sigPtr = exports.wasm_alloc(64);
if (exports.wasm_sign_schnorr(messagePtr, privKeyPtr, sigPtr)) {
    const signature = new Uint8Array(wasmMemory.buffer, sigPtr, 64);
    const signatureHex = Buffer.from(signature).toString('hex');
    console.log("Signature:", signatureHex);
    
    // Try to verify
    console.log("\nVerifying signature...");
    const verifyResult = exports.wasm_verify_schnorr(messagePtr, sigPtr, pubKeyPtr);
    console.log("Verification result:", verifyResult);
    
    // Let's also test wasm_create_text_note_working
    console.log("\n--- Testing wasm_create_text_note_working ---");
    const contentPtr = exports.wasm_alloc(100);
    const content = "Hello, Nostr!";
    const contentBytes = new TextEncoder().encode(content);
    new Uint8Array(wasmMemory.buffer, contentPtr, contentBytes.length).set(contentBytes);
    
    const outJsonPtr = exports.wasm_alloc(4096);
    const outLenPtr = exports.wasm_alloc_u32(1);
    new Uint32Array(wasmMemory.buffer, outLenPtr, 1)[0] = 4096;
    
    if (exports.wasm_create_text_note_working) {
        const success = exports.wasm_create_text_note_working(
            privKeyPtr,
            contentPtr,
            contentBytes.length,
            outJsonPtr,
            outLenPtr
        );
        
        if (success) {
            const jsonLen = new Uint32Array(wasmMemory.buffer, outLenPtr, 1)[0];
            const eventJson = new TextDecoder().decode(
                new Uint8Array(wasmMemory.buffer, outJsonPtr, jsonLen)
            );
            console.log("Created event successfully");
            const event = JSON.parse(eventJson);
            console.log("Event pubkey:", event.pubkey);
            console.log("Expected:    ", globalThis.expectedPubKey);
            console.log("Pubkey match:", event.pubkey === globalThis.expectedPubKey);
            
            // Verify this event
            const eventJsonPtr = exports.wasm_alloc(jsonLen);
            new Uint8Array(wasmMemory.buffer, eventJsonPtr, jsonLen).set(
                new TextEncoder().encode(eventJson)
            );
            
            const eventVerifyResult = exports.wasm_verify_event(eventJsonPtr, jsonLen);
            console.log("Event verification:", eventVerifyResult);
            
            exports.wasm_free(eventJsonPtr, jsonLen);
        }
    }
    
    exports.wasm_free(contentPtr, 100);
    exports.wasm_free(outJsonPtr, 4096);
    exports.wasm_free(outLenPtr, 4);
}

// Cleanup
exports.wasm_free(privKeyPtr, 32);
exports.wasm_free(pubKeyPtr, 32);
exports.wasm_free(messagePtr, 32);
exports.wasm_free(sigPtr, 64);

console.log("\n✅ Test complete!");