#!/usr/bin/env bun

import { readFileSync } from 'fs';
import { resolve } from 'path';

// Load WASM file
const wasmPath = resolve(__dirname, 'src/nostr_mls.wasm');
const wasmBuffer = readFileSync(wasmPath);

// Create imports (simplified version)
const imports = {
  env: {
    getRandomValues: (ptr: number, len: number) => {
      const bytes = new Uint8Array((instance.exports as any).memory.buffer, ptr, len);
      crypto.getRandomValues(bytes);
    },
    getCurrentTimestamp: () => {
      return Math.floor(Date.now() / 1000);
    },
    wasm_log_error: (strPtr: number, len: number) => {
      const bytes = new Uint8Array((instance.exports as any).memory.buffer, strPtr, len);
      const message = new TextDecoder().decode(bytes);
      console.error('WASM Error:', message);
    }
  }
};

// Instantiate WASM
const wasmModule = new WebAssembly.Module(wasmBuffer);
const instance = new WebAssembly.Instance(wasmModule, imports);
const exports = instance.exports as any;

// Test our workaround approach - create events using individual WASM functions
function testEventCreationWorkaround() {
  console.log('🧪 Testing event creation workaround...');
  
  // Create a test private key (32 bytes)
  const privateKey = new Uint8Array(32);
  crypto.getRandomValues(privateKey);
  
  console.log('Private key:', Array.from(privateKey).map(b => b.toString(16).padStart(2, '0')).join(''));
  
  // Step 1: Get public key using working WASM function
  const privkeyPtr = exports.wasm_alloc(32);
  new Uint8Array(exports.memory.buffer, privkeyPtr, 32).set(privateKey);
  
  const pubkeyPtr = exports.wasm_alloc(32);
  const pubkeySuccess = exports.wasm_get_public_key(privkeyPtr, pubkeyPtr);
  
  if (!pubkeySuccess) {
    console.error('❌ Failed to get public key');
    return;
  }
  
  const pubkeyBytes = new Uint8Array(exports.memory.buffer, pubkeyPtr, 32);
  const pubkeyHex = Array.from(pubkeyBytes).map(b => b.toString(16).padStart(2, '0')).join('');
  console.log('✅ Public key:', pubkeyHex);
  
  // Step 2: Create event structure
  const content = "Testing WASM workaround!";
  const createdAt = Math.floor(Date.now() / 1000);
  
  const eventForId = {
    pubkey: pubkeyHex,
    created_at: createdAt,
    kind: 1,
    tags: [],
    content: content
  };
  
  // Step 3: Calculate event ID using SHA256 
  const serialized = JSON.stringify([
    0,
    eventForId.pubkey,
    eventForId.created_at,
    eventForId.kind,
    eventForId.tags,
    eventForId.content
  ]);
  
  console.log('Serialized for ID:', serialized);
  
  const encoder = new TextEncoder();
  const serializedBytes = encoder.encode(serialized);
  
  const dataPtr = exports.wasm_alloc(serializedBytes.length);
  new Uint8Array(exports.memory.buffer, dataPtr, serializedBytes.length).set(serializedBytes);
  
  const hashPtr = exports.wasm_alloc(32);
  const hashSuccess = exports.wasm_sha256(dataPtr, serializedBytes.length, hashPtr);
  
  if (!hashSuccess) {
    console.error('❌ Failed to calculate SHA256 hash');
    return;
  }
  
  const eventIdBytes = new Uint8Array(exports.memory.buffer, hashPtr, 32);
  const eventId = Array.from(eventIdBytes).map(b => b.toString(16).padStart(2, '0')).join('');
  console.log('✅ Event ID:', eventId);
  
  // Step 4: Sign the event using Schnorr signature
  const sigPtr = exports.wasm_alloc(64);
  const signSuccess = exports.wasm_sign_schnorr(privkeyPtr, hashPtr, sigPtr);
  
  if (!signSuccess) {
    console.error('❌ Failed to sign event');
    return;
  }
  
  const signatureBytes = new Uint8Array(exports.memory.buffer, sigPtr, 64);
  const signature = Array.from(signatureBytes).map(b => b.toString(16).padStart(2, '0')).join('');
  console.log('✅ Signature:', signature);
  
  // Step 5: Build final event
  const finalEvent = {
    id: eventId,
    pubkey: pubkeyHex,
    created_at: createdAt,
    kind: 1,
    tags: [],
    content: content,
    sig: signature
  };
  
  const eventJson = JSON.stringify(finalEvent);
  console.log('✅ Final event JSON:');
  console.log(eventJson);
  
  // Clean up
  exports.wasm_free(privkeyPtr, 32);
  exports.wasm_free(pubkeyPtr, 32);
  exports.wasm_free(dataPtr, serializedBytes.length);
  exports.wasm_free(hashPtr, 32);
  exports.wasm_free(sigPtr, 64);
  
  console.log('✅ Memory cleaned up successfully!');
  
  return eventJson;
}

// Test the workaround
const eventJson = testEventCreationWorkaround();

if (eventJson) {
  console.log('\n🎉 Workaround successful! Event created using individual WASM functions.');
  console.log('📤 This event can now be published to relays.');
}