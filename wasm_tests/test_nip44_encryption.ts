#!/usr/bin/env bun

import { readFileSync } from 'fs';
import { join } from 'path';

console.log('\n=== NIP-44 Encryption/Decryption Test ===\n');

// Load WASM
const wasmPath = join(__dirname, '../zig-out/visualizer/src/nostr_mls.wasm');
console.log(`Loading WASM from: ${wasmPath}`);

const wasmBuffer = readFileSync(wasmPath);
const wasmModule = await WebAssembly.compile(wasmBuffer);

// Create imports
const imports = {
  env: {
    getRandomValues: (ptr: number, len: number) => {
      const bytes = new Uint8Array(memory.buffer, ptr, len);
      crypto.getRandomValues(bytes);
      console.log(`Generated ${len} random bytes`);
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

// Initialize WASM
if (exports.wasm_init) {
  exports.wasm_init();
  console.log('✅ WASM initialized');
}

// Helper functions
function allocString(str: string): { ptr: number; len: number } {
  const encoder = new TextEncoder();
  const bytes = encoder.encode(str);
  const ptr = exports.wasm_alloc(bytes.length);
  if (!ptr) throw new Error('Failed to allocate memory');
  new Uint8Array(memory.buffer, ptr, bytes.length).set(bytes);
  return { ptr, len: bytes.length };
}

function readString(ptr: number, len: number): string {
  const bytes = new Uint8Array(memory.buffer, ptr, len);
  return new TextDecoder().decode(bytes);
}

function readBytes(ptr: number, len: number): Uint8Array {
  return new Uint8Array(memory.buffer, ptr, len).slice();
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

// Test 1: Generate exporter secret
console.log('\n--- Test 1: Generate Exporter Secret ---');
const groupState = new Uint8Array(64); // Dummy group state
crypto.getRandomValues(groupState);
console.log('Group state:', bytesToHex(groupState).substring(0, 32) + '...');

const statePtr = exports.wasm_alloc(groupState.length);
const secretPtr = exports.wasm_alloc(32);

new Uint8Array(memory.buffer, statePtr, groupState.length).set(groupState);

const genSuccess = exports.wasm_generate_exporter_secret(
  statePtr,
  groupState.length,
  secretPtr
);

let exporterSecret: Uint8Array | null = null;

if (genSuccess) {
  exporterSecret = readBytes(secretPtr, 32);
  console.log('✅ Generated exporter secret:', bytesToHex(exporterSecret));
  
  // Test 2: NIP-44 Encryption
  console.log('\n--- Test 2: NIP-44 Encryption ---');
  const plaintext = "Hello, this is a test message for NIP-44 encryption!";
  console.log('Plaintext:', plaintext);
  
  const secretPtr2 = exports.wasm_alloc(32);
  const plaintextData = allocString(plaintext);
  
  new Uint8Array(memory.buffer, secretPtr2, 32).set(exporterSecret);
  
  const maxCipherSize = plaintextData.len * 2 + 200;
  const cipherPtr = exports.wasm_alloc(maxCipherSize);
  const cipherLenPtr = exports.wasm_alloc_u32(1);
  
  new Uint32Array(memory.buffer, cipherLenPtr, 1)[0] = maxCipherSize;
  
  console.log('Calling wasm_nip44_encrypt with:');
  console.log('- Secret:', bytesToHex(exporterSecret));
  console.log('- Plaintext length:', plaintextData.len);
  console.log('- Max cipher size:', maxCipherSize);
  
  const encSuccess = exports.wasm_nip44_encrypt(
    secretPtr2,
    plaintextData.ptr,
    plaintextData.len,
    cipherPtr,
    cipherLenPtr
  );
  
  if (encSuccess) {
    const cipherLen = new Uint32Array(memory.buffer, cipherLenPtr, 1)[0];
    const ciphertext = readBytes(cipherPtr, cipherLen);
    console.log('✅ Encrypted successfully!');
    console.log('Ciphertext length:', cipherLen);
    console.log('Ciphertext (hex):', bytesToHex(ciphertext).substring(0, 64) + '...');
    
    // Test 3: NIP-44 Decryption
    console.log('\n--- Test 3: NIP-44 Decryption ---');
    const secretPtr3 = exports.wasm_alloc(32);
    const cipherPtr2 = exports.wasm_alloc(ciphertext.length);
    
    new Uint8Array(memory.buffer, secretPtr3, 32).set(exporterSecret);
    new Uint8Array(memory.buffer, cipherPtr2, ciphertext.length).set(ciphertext);
    
    const maxPlainSize = ciphertext.length * 2;
    const plainPtr = exports.wasm_alloc(maxPlainSize);
    const plainLenPtr = exports.wasm_alloc_u32(1);
    
    new Uint32Array(memory.buffer, plainLenPtr, 1)[0] = maxPlainSize;
    
    const decSuccess = exports.wasm_nip44_decrypt(
      secretPtr3,
      cipherPtr2,
      ciphertext.length,
      plainPtr,
      plainLenPtr
    );
    
    if (decSuccess) {
      const plainLen = new Uint32Array(memory.buffer, plainLenPtr, 1)[0];
      const decrypted = readString(plainPtr, plainLen);
      console.log('✅ Decrypted successfully!');
      console.log('Decrypted text:', decrypted);
      console.log('Matches original:', decrypted === plaintext ? '✅ YES' : '❌ NO');
    } else {
      console.log('❌ Decryption failed');
    }
    
    // Cleanup
    exports.wasm_free(cipherPtr2, ciphertext.length);
    exports.wasm_free(plainPtr, maxPlainSize);
    exports.wasm_free_u32(plainLenPtr, 1);
    exports.wasm_free(secretPtr3, 32);
  } else {
    console.log('❌ Encryption failed');
  }
  
  // Cleanup
  exports.wasm_free(secretPtr2, 32);
  exports.wasm_free(plaintextData.ptr, plaintextData.len);
  exports.wasm_free(cipherPtr, maxCipherSize);
  exports.wasm_free_u32(cipherLenPtr, 1);
} else {
  console.log('❌ Failed to generate exporter secret');
}

// Cleanup
exports.wasm_free(statePtr, groupState.length);
exports.wasm_free(secretPtr, 32);

// Test 4: Test with different keys (should fail)
console.log('\n--- Test 4: Decryption with Wrong Key ---');
if (exporterSecret) {
  const wrongSecret = new Uint8Array(32);
  crypto.getRandomValues(wrongSecret);

  // Create a test ciphertext first
  const testPlaintext = "Secret message";
  const testData = allocString(testPlaintext);
  const testSecretPtr = exports.wasm_alloc(32);
  new Uint8Array(memory.buffer, testSecretPtr, 32).set(exporterSecret);

const testCipherPtr = exports.wasm_alloc(1000);
const testCipherLenPtr = exports.wasm_alloc_u32(1);
new Uint32Array(memory.buffer, testCipherLenPtr, 1)[0] = 1000;

const testEncSuccess = exports.wasm_nip44_encrypt(
  testSecretPtr,
  testData.ptr,
  testData.len,
  testCipherPtr,
  testCipherLenPtr
);

if (testEncSuccess) {
  const testCipherLen = new Uint32Array(memory.buffer, testCipherLenPtr, 1)[0];
  const testCiphertext = readBytes(testCipherPtr, testCipherLen);
  
  // Try to decrypt with wrong key
  const wrongSecretPtr = exports.wasm_alloc(32);
  const wrongCipherPtr = exports.wasm_alloc(testCiphertext.length);
  new Uint8Array(memory.buffer, wrongSecretPtr, 32).set(wrongSecret);
  new Uint8Array(memory.buffer, wrongCipherPtr, testCiphertext.length).set(testCiphertext);
  
  const wrongPlainPtr = exports.wasm_alloc(1000);
  const wrongPlainLenPtr = exports.wasm_alloc_u32(1);
  new Uint32Array(memory.buffer, wrongPlainLenPtr, 1)[0] = 1000;
  
  const wrongDecSuccess = exports.wasm_nip44_decrypt(
    wrongSecretPtr,
    wrongCipherPtr,
    testCiphertext.length,
    wrongPlainPtr,
    wrongPlainLenPtr
  );
  
  if (wrongDecSuccess) {
    console.log('❌ SECURITY ISSUE: Decryption succeeded with wrong key!');
  } else {
    console.log('✅ Decryption correctly failed with wrong key');
  }
  
  // Cleanup
  exports.wasm_free(wrongSecretPtr, 32);
  exports.wasm_free(wrongCipherPtr, testCiphertext.length);
  exports.wasm_free(wrongPlainPtr, 1000);
  exports.wasm_free_u32(wrongPlainLenPtr, 1);
  }

  // Final cleanup
  exports.wasm_free(testSecretPtr, 32);
  exports.wasm_free(testData.ptr, testData.len);
  exports.wasm_free(testCipherPtr, 1000);
  exports.wasm_free_u32(testCipherLenPtr, 1);
} else {
  console.log('Skipping test 4 - no exporter secret available');
}

console.log('\n=== NIP-44 Encryption Test Complete ===\n');