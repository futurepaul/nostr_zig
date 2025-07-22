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

function hexToBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
}

console.log("🔧 Debugging Event Verification vs Direct Schnorr Verification\n");

// Create a test event
const privateKeyPtr = exports.wasm_alloc(32);
const publicKeyPtr = exports.wasm_alloc(32);

if (exports.wasm_create_identity(privateKeyPtr, publicKeyPtr)) {
    const content = "Debug test event";
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
        
        console.log("✅ Created test event");
        console.log("Event ID:", event.id);
        console.log("Public Key:", event.pubkey);
        console.log("Signature:", event.sig);
        
        // Test 1: wasm_verify_event
        console.log("\n1. Testing wasm_verify_event...");
        const eventJsonAlloc = allocateString(eventJson);
        const eventVerifyResult = exports.wasm_verify_event(eventJsonAlloc.ptr, eventJsonAlloc.len);
        console.log("wasm_verify_event result:", eventVerifyResult);
        
        // Test 2: Direct wasm_verify_schnorr 
        console.log("\n2. Testing direct wasm_verify_schnorr...");
        
        // Convert event data to bytes for direct verification
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
        
        const schnorrVerifyResult = exports.wasm_verify_schnorr(eventIdPtr, signaturePtr, pubkeyPtr);
        console.log("wasm_verify_schnorr result:", schnorrVerifyResult);
        
        // Test 3: Let's also test if the issue is in JSON parsing
        console.log("\n3. Testing JSON parsing isolation...");
        console.log("Original JSON length:", eventJson.length);
        console.log("First 100 chars:", eventJson.substring(0, 100));
        console.log("Last 100 chars:", eventJson.substring(eventJson.length - 100));
        
        // Test manually parsing the JSON structure we expect
        try {
            const parsedEvent = JSON.parse(eventJson);
            console.log("JSON parsing successful");
            console.log("Required fields present:");
            console.log("- id:", parsedEvent.id ? "✅" : "❌");
            console.log("- pubkey:", parsedEvent.pubkey ? "✅" : "❌");
            console.log("- created_at:", parsedEvent.created_at ? "✅" : "❌");
            console.log("- kind:", parsedEvent.kind !== undefined ? "✅" : "❌");
            console.log("- tags:", Array.isArray(parsedEvent.tags) ? "✅" : "❌");
            console.log("- content:", parsedEvent.content !== undefined ? "✅" : "❌");
            console.log("- sig:", parsedEvent.sig ? "✅" : "❌");
            
            // Test field lengths
            console.log("\nField lengths:");
            console.log("- id length:", parsedEvent.id?.length, "(expected: 64)");
            console.log("- pubkey length:", parsedEvent.pubkey?.length, "(expected: 64)");
            console.log("- sig length:", parsedEvent.sig?.length, "(expected: 128)");
            
        } catch (e) {
            console.log("JSON parsing failed:", e);
        }
        
        // Clean up
        freeString(eventJsonAlloc.ptr, eventJsonAlloc.len);
        exports.wasm_free(eventIdPtr, 32);
        exports.wasm_free(pubkeyPtr, 32);
        exports.wasm_free(signaturePtr, 64);
        
    } else {
        console.log("❌ Failed to create event");
    }
    
    freeString(contentAlloc.ptr, contentAlloc.len);
    freeString(tagsAlloc.ptr, tagsAlloc.len);
    exports.wasm_free(outEventJsonPtr, 4096);
    exports.wasm_free(outLenPtr, 4);
}

exports.wasm_free(privateKeyPtr, 32);
exports.wasm_free(publicKeyPtr, 32);

console.log("\n✅ Debug test complete!");