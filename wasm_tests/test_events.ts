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

function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
}

console.log("🧪 Testing Nostr Event Creation and Verification in WASM...\n");

// Test 1: Create a private key and get public key
console.log("1. Testing key generation...");
const privateKeyPtr = exports.wasm_alloc(32);
const publicKeyPtr = exports.wasm_alloc(32);

if (exports.wasm_create_identity(privateKeyPtr, publicKeyPtr)) {
    const privateKey = new Uint8Array(wasmMemory.buffer, privateKeyPtr, 32);
    const publicKey = new Uint8Array(wasmMemory.buffer, publicKeyPtr, 32);
    
    console.log("✅ Created identity");
    console.log(`   Private key: ${bytesToHex(privateKey)}`);
    console.log(`   Public key: ${bytesToHex(publicKey)}`);
    
    // Test getting public key hex
    const pubkeyHexPtr = exports.wasm_alloc(64);
    if (exports.wasm_get_public_key_hex(privateKeyPtr, pubkeyHexPtr)) {
        const pubkeyHex = readString(pubkeyHexPtr, 64);
        console.log(`   Public key (hex): ${pubkeyHex}`);
        console.log(`   Hex matches: ${pubkeyHex === bytesToHex(publicKey)}`);
        exports.wasm_free(pubkeyHexPtr, 64);
    }
    
    // Test 2: Create a simple text note event
    console.log("\n2. Testing event creation...");
    const content = "Hello from WASM test_events.ts!";
    const contentAlloc = allocateString(content);
    const tagsJson = "[]"; // No tags for simple test
    const tagsAlloc = allocateString(tagsJson);
    
    // Allocate for output (generous size for JSON)
    const outEventJsonPtr = exports.wasm_alloc(4096);
    const outLenPtr = exports.wasm_alloc_u32(1);
    new Uint32Array(wasmMemory.buffer, outLenPtr, 1)[0] = 4096;
    
    const success = exports.wasm_create_event(
        privateKeyPtr,           // private key
        1,                      // kind 1 = text note
        contentAlloc.ptr,       // content
        contentAlloc.len,       // content length
        tagsAlloc.ptr,          // tags JSON
        tagsAlloc.len,          // tags length
        outEventJsonPtr,        // output buffer
        outLenPtr              // output length pointer
    );
    
    if (success) {
        const eventJsonLen = new Uint32Array(wasmMemory.buffer, outLenPtr, 1)[0];
        const eventJson = readString(outEventJsonPtr, eventJsonLen);
        console.log("✅ Event created successfully");
        
        // Parse and display event
        const event = JSON.parse(eventJson);
        console.log(`   ID: ${event.id}`);
        console.log(`   Pubkey: ${event.pubkey}`);
        console.log(`   Created at: ${event.created_at}`);
        console.log(`   Kind: ${event.kind}`);
        console.log(`   Content: ${event.content}`);
        console.log(`   Signature: ${event.sig.substring(0, 32)}...`);
        
        // Test 3: Verify the event
        console.log("\n3. Testing event verification...");
        console.log(`   Event JSON length: ${eventJson.length} chars`);
        const eventJsonAlloc = allocateString(eventJson);
        
        // Try direct Schnorr verification since wasm_verify_event was removed
        console.log("   Using direct Schnorr verification...");
        
        // Convert hex strings to bytes for direct verification
        const eventIdBytes = hexToBytes(event.id);
        const pubkeyBytes = hexToBytes(event.pubkey);
        const signatureBytes = hexToBytes(event.sig);
        
        // Allocate memory for the bytes
        const eventIdPtr = exports.wasm_alloc(32);
        const pubkeyPtr = exports.wasm_alloc(32);
        const signaturePtr = exports.wasm_alloc(64);
        
        new Uint8Array(wasmMemory.buffer, eventIdPtr, 32).set(eventIdBytes);
        new Uint8Array(wasmMemory.buffer, pubkeyPtr, 32).set(pubkeyBytes);
        new Uint8Array(wasmMemory.buffer, signaturePtr, 64).set(signatureBytes);
        
        const verified = exports.wasm_verify_schnorr(eventIdPtr, signaturePtr, pubkeyPtr);
        console.log(`   Schnorr verification result: ${verified}`);
        
        if (verified) {
            console.log("✅ Event signature verified successfully using Schnorr");
        } else {
            console.error("❌ Event signature verification failed");
            console.log("   Event details:");
            console.log(`   - ID: ${event.id}`);
            console.log(`   - Pubkey: ${event.pubkey}`);
            console.log(`   - Signature: ${event.sig}`);
        }
        
        // Clean up direct verification memory
        exports.wasm_free(eventIdPtr, 32);
        exports.wasm_free(pubkeyPtr, 32);
        exports.wasm_free(signaturePtr, 64);
        
        freeString(eventJsonAlloc.ptr, eventJsonAlloc.len);
        
        // Test 4: Create event with tags
        console.log("\n4. Testing event creation with tags...");
        const tagsWithData = JSON.stringify([
            ["e", "abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab"],
            ["p", bytesToHex(publicKey)]
        ]);
        const tagsWithDataAlloc = allocateString(tagsWithData);
        const contentWithTags = "This is a reply with tags";
        const contentWithTagsAlloc = allocateString(contentWithTags);
        
        // Reset output buffer
        new Uint32Array(wasmMemory.buffer, outLenPtr, 1)[0] = 4096;
        
        const taggedSuccess = exports.wasm_create_event(
            privateKeyPtr,
            1,                          // kind 1
            contentWithTagsAlloc.ptr,
            contentWithTagsAlloc.len,
            tagsWithDataAlloc.ptr,
            tagsWithDataAlloc.len,
            outEventJsonPtr,
            outLenPtr
        );
        
        if (taggedSuccess) {
            const taggedEventJsonLen = new Uint32Array(wasmMemory.buffer, outLenPtr, 1)[0];
            const taggedEventJson = readString(outEventJsonPtr, taggedEventJsonLen);
            const taggedEvent = JSON.parse(taggedEventJson);
            
            console.log("✅ Event with tags created successfully");
            console.log(`   Tags: ${taggedEvent.tags.length} tags`);
            taggedEvent.tags.forEach((tag: string[], i: number) => {
                console.log(`   Tag ${i}: [${tag.join(", ")}]`);
            });
            
            // Verify this event too using direct Schnorr verification
            const taggedEventIdBytes = hexToBytes(taggedEvent.id);
            const taggedPubkeyBytes = hexToBytes(taggedEvent.pubkey);
            const taggedSignatureBytes = hexToBytes(taggedEvent.sig);
            
            const taggedEventIdPtr = exports.wasm_alloc(32);
            const taggedPubkeyPtr = exports.wasm_alloc(32);
            const taggedSignaturePtr = exports.wasm_alloc(64);
            
            new Uint8Array(wasmMemory.buffer, taggedEventIdPtr, 32).set(taggedEventIdBytes);
            new Uint8Array(wasmMemory.buffer, taggedPubkeyPtr, 32).set(taggedPubkeyBytes);
            new Uint8Array(wasmMemory.buffer, taggedSignaturePtr, 64).set(taggedSignatureBytes);
            
            if (exports.wasm_verify_schnorr(taggedEventIdPtr, taggedSignaturePtr, taggedPubkeyPtr)) {
                console.log("✅ Tagged event signature verified using Schnorr");
            }
            
            exports.wasm_free(taggedEventIdPtr, 32);
            exports.wasm_free(taggedPubkeyPtr, 32);
            exports.wasm_free(taggedSignaturePtr, 64);
        } else {
            console.error("❌ Failed to create tagged event");
        }
        
        // Cleanup
        freeString(tagsWithDataAlloc.ptr, tagsWithDataAlloc.len);
        freeString(contentWithTagsAlloc.ptr, contentWithTagsAlloc.len);
        
    } else {
        console.error("❌ Failed to create event");
    }
    
    // Cleanup
    freeString(contentAlloc.ptr, contentAlloc.len);
    freeString(tagsAlloc.ptr, tagsAlloc.len);
    exports.wasm_free(outEventJsonPtr, 4096);
    exports.wasm_free(outLenPtr, 4);
    
} else {
    console.error("❌ Failed to create identity");
}

// Final cleanup
exports.wasm_free(privateKeyPtr, 32);
exports.wasm_free(publicKeyPtr, 32);

// Test 5: Performance test
console.log("\n5. Testing event creation performance...");
const perfPrivKeyPtr = exports.wasm_alloc(32);
const perfPubKeyPtr = exports.wasm_alloc(32);

if (exports.wasm_create_identity(perfPrivKeyPtr, perfPubKeyPtr)) {
    const numEvents = 100;
    const startTime = performance.now();
    
    for (let i = 0; i < numEvents; i++) {
        const perfContent = `Performance test event #${i}`;
        const perfContentAlloc = allocateString(perfContent);
        const perfTagsAlloc = allocateString("[]");
        const perfOutPtr = exports.wasm_alloc(4096);
        const perfLenPtr = exports.wasm_alloc_u32(1);
        new Uint32Array(wasmMemory.buffer, perfLenPtr, 1)[0] = 4096;
        
        const created = exports.wasm_create_event(
            perfPrivKeyPtr,
            1,
            perfContentAlloc.ptr,
            perfContentAlloc.len,
            perfTagsAlloc.ptr,
            perfTagsAlloc.len,
            perfOutPtr,
            perfLenPtr
        );
        
        if (created) {
            // Verify each event using direct Schnorr verification
            const eventLen = new Uint32Array(wasmMemory.buffer, perfLenPtr, 1)[0];
            const eventJson = readString(perfOutPtr, eventLen);
            const event = JSON.parse(eventJson);
            
            // Convert and verify using Schnorr directly
            const eventIdBytes = hexToBytes(event.id);
            const pubkeyBytes = hexToBytes(event.pubkey);
            const signatureBytes = hexToBytes(event.sig);
            
            const eventIdPtr = exports.wasm_alloc(32);
            const pubkeyPtr = exports.wasm_alloc(32);
            const signaturePtr = exports.wasm_alloc(64);
            
            new Uint8Array(wasmMemory.buffer, eventIdPtr, 32).set(eventIdBytes);
            new Uint8Array(wasmMemory.buffer, pubkeyPtr, 32).set(pubkeyBytes);
            new Uint8Array(wasmMemory.buffer, signaturePtr, 64).set(signatureBytes);
            
            const verified = exports.wasm_verify_schnorr(eventIdPtr, signaturePtr, pubkeyPtr);
            if (!verified && i === 0) {
                console.log(`   First event verification: ${verified}`);
            }
            
            exports.wasm_free(eventIdPtr, 32);
            exports.wasm_free(pubkeyPtr, 32);
            exports.wasm_free(signaturePtr, 64);
        }
        
        // Cleanup
        freeString(perfContentAlloc.ptr, perfContentAlloc.len);
        freeString(perfTagsAlloc.ptr, perfTagsAlloc.len);
        exports.wasm_free(perfOutPtr, 4096);
        exports.wasm_free(perfLenPtr, 4);
    }
    
    const endTime = performance.now();
    const duration = endTime - startTime;
    
    console.log(`✅ Created and verified ${numEvents} events in ${duration.toFixed(2)}ms`);
    console.log(`   Average: ${(duration / numEvents).toFixed(2)}ms per event`);
}

exports.wasm_free(perfPrivKeyPtr, 32);
exports.wasm_free(perfPubKeyPtr, 32);

console.log("\n✅ All event tests completed!");