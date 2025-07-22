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

// Helper functions
function allocateString(str: string): { ptr: number; len: number } {
    const bytes = new TextEncoder().encode(str);
    const ptr = exports.wasm_alloc(bytes.length);
    if (!ptr) throw new Error('Failed to allocate memory');
    new Uint8Array(wasmMemory.buffer, ptr, bytes.length).set(bytes);
    return { ptr, len: bytes.length };
}

function freeString(ptr: number, len: number) {
    exports.wasm_free(ptr, len);
}

function readString(ptr: number, len: number): string {
    const bytes = new Uint8Array(wasmMemory.buffer, ptr, len);
    return new TextDecoder().decode(bytes);
}

console.log("🔍 Investigating Event Verification Issue...\n");

// Test 1: Create an event and examine its structure
console.log("1. Creating and examining event structure...");
const privateKeyPtr = exports.wasm_alloc(32);
const publicKeyPtr = exports.wasm_alloc(32);

if (exports.wasm_create_identity(privateKeyPtr, publicKeyPtr)) {
    const privateKey = new Uint8Array(wasmMemory.buffer, privateKeyPtr, 32);
    const publicKey = new Uint8Array(wasmMemory.buffer, publicKeyPtr, 32);
    
    // Create a simple event
    const content = "Test event for verification";
    const contentAlloc = allocateString(content);
    const tagsAlloc = allocateString("[]");
    
    const outEventJsonPtr = exports.wasm_alloc(4096);
    const outLenPtr = exports.wasm_alloc_u32(1);
    new Uint32Array(wasmMemory.buffer, outLenPtr, 1)[0] = 4096;
    
    if (exports.wasm_create_event(
        privateKeyPtr,
        1,
        contentAlloc.ptr,
        contentAlloc.len,
        tagsAlloc.ptr,
        tagsAlloc.len,
        outEventJsonPtr,
        outLenPtr
    )) {
        const eventJsonLen = new Uint32Array(wasmMemory.buffer, outLenPtr, 1)[0];
        const eventJson = readString(outEventJsonPtr, eventJsonLen);
        const event = JSON.parse(eventJson);
        
        console.log("✅ Event created");
        console.log("\nEvent structure:");
        console.log(JSON.stringify(event, null, 2));
        
        // Test 2: Verify the canonical form
        console.log("\n2. Checking canonical form for ID...");
        const canonical = JSON.stringify([
            0,
            event.pubkey,
            event.created_at,
            event.kind,
            event.tags,
            event.content
        ]);
        console.log("Canonical form:", canonical);
        
        // Calculate expected ID
        const canonicalBytes = new TextEncoder().encode(canonical);
        const canonicalPtr = exports.wasm_alloc(canonicalBytes.length);
        new Uint8Array(wasmMemory.buffer, canonicalPtr, canonicalBytes.length).set(canonicalBytes);
        
        const idHashPtr = exports.wasm_alloc(32);
        if (exports.wasm_sha256(canonicalPtr, canonicalBytes.length, idHashPtr)) {
            const idHash = new Uint8Array(wasmMemory.buffer, idHashPtr, 32);
            const calculatedId = Array.from(idHash).map(b => b.toString(16).padStart(2, '0')).join('');
            console.log("Calculated ID:", calculatedId);
            console.log("Event ID:     ", event.id);
            console.log("IDs match:", calculatedId === event.id);
        }
        
        // Test 3: Try different verification approaches
        console.log("\n3. Testing verification approaches...");
        
        // Try wasm_verify_event
        const eventJsonAlloc = allocateString(eventJson);
        const verifyResult = exports.wasm_verify_event(eventJsonAlloc.ptr, eventJsonAlloc.len);
        console.log("wasm_verify_event result:", verifyResult);
        
        // Test 4: Manually verify the signature
        console.log("\n4. Manual signature verification test...");
        
        // The message for signing should be the event ID (32 bytes)
        const eventIdBytes = new Uint8Array(32);
        for (let i = 0; i < 32; i++) {
            eventIdBytes[i] = parseInt(event.id.substr(i * 2, 2), 16);
        }
        
        console.log("Message (event ID as bytes):", Array.from(eventIdBytes).map(b => b.toString(16).padStart(2, '0')).join(''));
        console.log("Public key:", event.pubkey);
        console.log("Signature:", event.sig);
        
        // Try to create a known-good event manually
        console.log("\n5. Creating event with known test vector...");
        
        // Use a fixed private key for reproducible results
        const testPrivKey = new Uint8Array(32);
        testPrivKey.fill(1); // All 0x01
        const testPrivKeyPtr = exports.wasm_alloc(32);
        new Uint8Array(wasmMemory.buffer, testPrivKeyPtr, 32).set(testPrivKey);
        
        // Get public key for this test key
        const testPubKeyPtr = exports.wasm_alloc(32);
        if (exports.wasm_get_public_key(testPrivKeyPtr, testPubKeyPtr)) {
            const testPubKey = new Uint8Array(wasmMemory.buffer, testPubKeyPtr, 32);
            console.log("Test public key:", Array.from(testPubKey).map(b => b.toString(16).padStart(2, '0')).join(''));
        }
        
        // Create event with test key
        const testContentAlloc = allocateString("Fixed test content");
        const testTagsAlloc = allocateString("[]");
        const testOutPtr = exports.wasm_alloc(4096);
        const testLenPtr = exports.wasm_alloc_u32(1);
        new Uint32Array(wasmMemory.buffer, testLenPtr, 1)[0] = 4096;
        
        if (exports.wasm_create_event(
            testPrivKeyPtr,
            1,
            testContentAlloc.ptr,
            testContentAlloc.len,
            testTagsAlloc.ptr,
            testTagsAlloc.len,
            testOutPtr,
            testLenPtr
        )) {
            const testEventLen = new Uint32Array(wasmMemory.buffer, testLenPtr, 1)[0];
            const testEventJson = readString(testOutPtr, testEventLen);
            const testEvent = JSON.parse(testEventJson);
            
            console.log("\nTest event created:");
            console.log("ID:", testEvent.id);
            console.log("Signature:", testEvent.sig);
            
            // Verify test event
            const testEventAlloc = allocateString(testEventJson);
            const testVerifyResult = exports.wasm_verify_event(testEventAlloc.ptr, testEventAlloc.len);
            console.log("Test event verification:", testVerifyResult);
            
            freeString(testEventAlloc.ptr, testEventAlloc.len);
        }
        
        // Cleanup
        exports.wasm_free(testPrivKeyPtr, 32);
        exports.wasm_free(testPubKeyPtr, 32);
        freeString(testContentAlloc.ptr, testContentAlloc.len);
        freeString(testTagsAlloc.ptr, testTagsAlloc.len);
        exports.wasm_free(testOutPtr, 4096);
        exports.wasm_free(testLenPtr, 4);
        
        freeString(eventJsonAlloc.ptr, eventJsonAlloc.len);
        exports.wasm_free(canonicalPtr, canonicalBytes.length);
        exports.wasm_free(idHashPtr, 32);
    }
    
    freeString(contentAlloc.ptr, contentAlloc.len);
    freeString(tagsAlloc.ptr, tagsAlloc.len);
    exports.wasm_free(outEventJsonPtr, 4096);
    exports.wasm_free(outLenPtr, 4);
}

exports.wasm_free(privateKeyPtr, 32);
exports.wasm_free(publicKeyPtr, 32);

console.log("\n✅ Investigation complete!");