#!/usr/bin/env bun

import { readFileSync } from 'fs';
import { resolve } from 'path';

// Load WASM file
const wasmPath = resolve(__dirname, 'visualizer/src/nostr_mls.wasm');
const wasmBuffer = readFileSync(wasmPath);

// Create imports
const imports = {
  env: {
    getRandomValues: (ptr: number, len: number) => {
      // Create a view into WASM memory
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

// Test function
function testEventCreation() {
  console.log('🧪 Testing WASM event creation...');

  // Create a test private key (32 bytes of 0x01)
  const privkeyPtr = exports.wasm_alloc(32);
  const privkeyView = new Uint8Array(exports.memory.buffer, privkeyPtr, 32);
  privkeyView.fill(1); // Simple test key

  console.log('Private key:', Array.from(privkeyView).map(b => b.toString(16).padStart(2, '0')).join(''));

  // Create test content
  const content = "Hello from WASM test!";
  const encoder = new TextEncoder();
  const contentBytes = encoder.encode(content);
  const contentPtr = exports.wasm_alloc(contentBytes.length);
  const contentView = new Uint8Array(exports.memory.buffer, contentPtr, contentBytes.length);
  contentView.set(contentBytes);

  // Allocate output buffer for event JSON (fixed 4096 bytes)
  const maxJsonSize = 4096;
  const outJsonPtr = exports.wasm_alloc(maxJsonSize);
  
  // Allocate 4 bytes for output length (u32)
  const outLenPtr = exports.wasm_alloc(4);

  console.log('📞 Checking wasm_create_text_note_working signature...');
  console.log('Function type:', typeof exports.wasm_create_text_note_working);
  console.log('Function length:', exports.wasm_create_text_note_working.length);
  console.log('Function toString():', exports.wasm_create_text_note_working.toString());
  
  // Let's also check wasm_sha256 for comparison
  console.log('📞 For comparison, wasm_sha256 signature:');
  console.log('SHA256 type:', typeof exports.wasm_sha256);
  console.log('SHA256 length:', exports.wasm_sha256.length);
  console.log('SHA256 toString():', exports.wasm_sha256.toString());
  
  let success: boolean;
  try {
    console.log('📞 Calling wasm_create_text_note_working...');
    // Call with regular numbers, similar to wasm_sha256
    success = exports.wasm_create_text_note_working(
      privkeyPtr,
      contentPtr,
      contentBytes.length,
      outJsonPtr,
      outLenPtr
    );
    console.log('Function call result (success):', success);
  } catch (error) {
    console.error('Function call error:', error);
    console.error('Error type:', typeof error);
    return;
  }
  
  // Read the actual length from the output parameter
  const actualLen = new Uint32Array(exports.memory.buffer, outLenPtr, 1)[0];
  
  if (success && actualLen > 0) {
    const jsonBytes = new Uint8Array(exports.memory.buffer, outJsonPtr, actualLen);
    const decoder = new TextDecoder();
    const eventJson = decoder.decode(jsonBytes);
    
    console.log('✅ Event created successfully!');
    console.log('📄 Event JSON:');
    
    try {
      const event = JSON.parse(eventJson);
      console.log('  ID:', event.id);
      console.log('  Pubkey:', event.pubkey);
      console.log('  Content:', event.content);
      console.log('  Kind:', event.kind);
      console.log('  Created at:', event.created_at);
      console.log('  Signature:', event.sig);
    } catch (e) {
      console.log('Raw JSON:', eventJson);
      console.error('❌ JSON parsing failed:', e);
    }
  } else {
    console.error('❌ wasm_create_text_note_working failed - success:', success, 'length:', actualLen);
  }

  // Clean up
  exports.wasm_free(privkeyPtr, 32);
  exports.wasm_free(contentPtr, contentBytes.length);
  exports.wasm_free(outJsonPtr, maxJsonSize);
  exports.wasm_free(outLenPtr, 4);
}

// Test SHA256 function to verify calling convention
function testSHA256() {
  console.log('\n🧪 Testing SHA256 function...');
  
  const testData = "Hello World";
  const encoder = new TextEncoder();
  const dataBytes = encoder.encode(testData);
  
  const dataPtr = exports.wasm_alloc(dataBytes.length);
  const dataView = new Uint8Array(exports.memory.buffer, dataPtr, dataBytes.length);
  dataView.set(dataBytes);
  
  const hashPtr = exports.wasm_alloc(32);
  
  console.log('📞 Calling wasm_sha256...');
  console.log('Data length:', dataBytes.length);
  
  const success = exports.wasm_sha256(dataPtr, dataBytes.length, hashPtr);
  
  if (success) {
    const hashView = new Uint8Array(exports.memory.buffer, hashPtr, 32);
    const hashHex = Array.from(hashView).map(b => b.toString(16).padStart(2, '0')).join('');
    console.log('✅ SHA256 hash:', hashHex);
  } else {
    console.error('❌ wasm_sha256 failed');
  }
  
  exports.wasm_free(dataPtr, dataBytes.length);
  exports.wasm_free(hashPtr, 32);
}

// Test public key derivation too
function testPublicKeyDerivation() {
  console.log('\n🧪 Testing public key derivation...');
  
  // Create a test private key (32 bytes of 0x01)
  const privkeyPtr = exports.wasm_alloc(32);
  const privkeyView = new Uint8Array(exports.memory.buffer, privkeyPtr, 32);
  privkeyView.fill(1); // Simple test key
  
  // Allocate output for public key
  const pubkeyPtr = exports.wasm_alloc(32);
  
  console.log('📞 Calling wasm_get_public_key...');
  const success = exports.wasm_get_public_key(privkeyPtr, pubkeyPtr);
  
  if (success) {
    const pubkeyView = new Uint8Array(exports.memory.buffer, pubkeyPtr, 32);
    const pubkeyHex = Array.from(pubkeyView).map(b => b.toString(16).padStart(2, '0')).join('');
    console.log('✅ Public key derived:', pubkeyHex);
  } else {
    console.error('❌ wasm_get_public_key failed');
  }
  
  // Clean up
  exports.wasm_free(privkeyPtr, 32);
  exports.wasm_free(pubkeyPtr, 32);
}

// Check available exports first
console.log('📋 Available WASM exports:');
console.log(Object.keys(exports).filter(key => key.startsWith('wasm_')).sort());

// Run tests
console.log('\n🚀 Starting WASM event creation tests...\n');
testSHA256();
testPublicKeyDerivation();
testEventCreation();