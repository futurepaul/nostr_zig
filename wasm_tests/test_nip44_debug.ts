#!/usr/bin/env bun

import { readFileSync } from 'fs';
import { join } from 'path';

console.log('\n=== NIP-44 Debug Test ===\n');

// Load WASM
const wasmPath = join(__dirname, '../zig-out/visualizer/src/nostr_mls.wasm');
const wasmBuffer = readFileSync(wasmPath);
const wasmModule = await WebAssembly.compile(wasmBuffer);

// Track random calls
let randomCallCount = 0;

// Create imports
const imports = {
  env: {
    getRandomValues: (ptr: number, len: number) => {
      randomCallCount++;
      const bytes = new Uint8Array(memory.buffer, ptr, len);
      crypto.getRandomValues(bytes);
      console.log(`getRandomValues called ${randomCallCount}: ${len} bytes`);
    },
    wasm_log_error: (strPtr: number, len: number) => {
      const bytes = new Uint8Array(memory.buffer, strPtr, len);
      const message = new TextDecoder().decode(bytes);
      console.error('WASM Error:', message);
    }
  }
};

const instance = await WebAssembly.instantiate(wasmModule, imports);
const exports = instance.exports as any;
const memory = exports.memory;

if (exports.wasm_init) {
  exports.wasm_init();
}

// Test 1: Just create identity to see if crypto works
console.log('--- Test 1: Create Identity ---');
const identityPrivPtr = exports.wasm_alloc(32);
const identityPubPtr = exports.wasm_alloc(32);

const identitySuccess = exports.wasm_create_identity(identityPrivPtr, identityPubPtr);
console.log('Identity creation:', identitySuccess ? '✅ Success' : '❌ Failed');

if (identitySuccess) {
  const privKey = new Uint8Array(memory.buffer, identityPrivPtr, 32);
  const pubKey = new Uint8Array(memory.buffer, identityPubPtr, 32);
  console.log('Private key (first 8 bytes):', Array.from(privKey.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join(' '));
  console.log('Public key (first 8 bytes):', Array.from(pubKey.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join(' '));
  
  // Test 2: Try NIP-44 with this keypair
  console.log('\n--- Test 2: NIP-44 with Generated Key ---');
  const plaintext = "Test";
  const encoder = new TextEncoder();
  const plaintextBytes = encoder.encode(plaintext);
  const plaintextPtr = exports.wasm_alloc(plaintextBytes.length);
  new Uint8Array(memory.buffer, plaintextPtr, plaintextBytes.length).set(plaintextBytes);
  
  const cipherPtr = exports.wasm_alloc(200);
  const cipherLenPtr = exports.wasm_alloc_u32(1);
  new Uint32Array(memory.buffer, cipherLenPtr, 1)[0] = 200;
  
  console.log('Calling wasm_nip44_encrypt...');
  const encryptSuccess = exports.wasm_nip44_encrypt(
    identityPrivPtr,
    plaintextPtr,
    plaintextBytes.length,
    cipherPtr,
    cipherLenPtr
  );
  
  console.log('Encryption result:', encryptSuccess ? '✅ Success' : '❌ Failed');
  
  if (encryptSuccess) {
    const cipherLen = new Uint32Array(memory.buffer, cipherLenPtr, 1)[0];
    console.log('Ciphertext length:', cipherLen);
  }
  
  // Cleanup
  exports.wasm_free(plaintextPtr, plaintextBytes.length);
  exports.wasm_free(cipherPtr, 200);
  exports.wasm_free_u32(cipherLenPtr, 1);
}

// Cleanup
exports.wasm_free(identityPrivPtr, 32);
exports.wasm_free(identityPubPtr, 32);

console.log('\n=== Debug Test Complete ===');
console.log(`Total random calls: ${randomCallCount}\n`);