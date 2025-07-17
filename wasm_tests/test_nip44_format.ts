#!/usr/bin/env bun

import { readFileSync } from 'fs';
import { join } from 'path';

console.log('\n=== NIP-44 Format Test ===\n');

// Load WASM
const wasmPath = join(__dirname, '../zig-out/visualizer/src/nostr_mls.wasm');
const wasmBuffer = readFileSync(wasmPath);
const wasmModule = await WebAssembly.compile(wasmBuffer);

// Create imports
const imports = {
  env: {
    getRandomValues: (ptr: number, len: number) => {
      const bytes = new Uint8Array(memory.buffer, ptr, len);
      crypto.getRandomValues(bytes);
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

// Helper functions
function allocString(str: string): { ptr: number; len: number } {
  const encoder = new TextEncoder();
  const bytes = encoder.encode(str);
  const ptr = exports.wasm_alloc(bytes.length);
  new Uint8Array(memory.buffer, ptr, bytes.length).set(bytes);
  return { ptr, len: bytes.length };
}

function readBytes(ptr: number, len: number): Uint8Array {
  return new Uint8Array(memory.buffer, ptr, len).slice();
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// Test encryption output format
const secret = new Uint8Array(32);
crypto.getRandomValues(secret);

const plaintext = "Test";
const secretPtr = exports.wasm_alloc(32);
const plaintextData = allocString(plaintext);

new Uint8Array(memory.buffer, secretPtr, 32).set(secret);

const maxSize = 500;
const cipherPtr = exports.wasm_alloc(maxSize);
const lenPtr = exports.wasm_alloc_u32(1);
new Uint32Array(memory.buffer, lenPtr, 1)[0] = maxSize;

const success = exports.wasm_nip44_encrypt(
  secretPtr,
  plaintextData.ptr,
  plaintextData.len,
  cipherPtr,
  lenPtr
);

if (success) {
  const len = new Uint32Array(memory.buffer, lenPtr, 1)[0];
  const ciphertext = readBytes(cipherPtr, len);
  
  console.log('Encrypted length:', len);
  console.log('First 20 bytes (hex):', bytesToHex(ciphertext.slice(0, 20)));
  console.log('First 20 bytes (ASCII):', Array.from(ciphertext.slice(0, 20)).map(b => 
    b >= 32 && b <= 126 ? String.fromCharCode(b) : '.'
  ).join(''));
  
  // Check if it's base64
  const asString = new TextDecoder().decode(ciphertext);
  console.log('As string:', asString.slice(0, 50));
  console.log('Looks like base64?', /^[A-Za-z0-9+/]+=*$/.test(asString));
  
  // Try to decode as base64
  try {
    const decoded = atob(asString);
    console.log('Base64 decoded length:', decoded.length);
    console.log('First byte after decode:', decoded.charCodeAt(0));
    console.log('Version byte (should be 2):', decoded.charCodeAt(0));
  } catch (e) {
    console.log('Failed to decode as base64:', e);
  }
}

// Cleanup
exports.wasm_free(secretPtr, 32);
exports.wasm_free(plaintextData.ptr, plaintextData.len);
exports.wasm_free(cipherPtr, maxSize);
exports.wasm_free_u32(lenPtr, 1);

console.log('\n=== Format Test Complete ===\n');