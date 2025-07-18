import { readFileSync } from 'fs';
import { resolve } from 'path';

// Load WASM module
const wasmPath = resolve(__dirname, '../visualizer/src/nostr_mls.wasm');
const wasmBuffer = readFileSync(wasmPath);

// Need forward reference for memory
let wasmMemory: WebAssembly.Memory;

// Define imports
const imports = {
  env: {
    getRandomValues: (ptr: number, len: number) => {
      const bytes = new Uint8Array(wasmMemory.buffer, ptr, len);
      crypto.getRandomValues(bytes);
    },
    wasm_log_error: (msgPtr: number, msgLen: number) => {
      const decoder = new TextDecoder();
      const msgBytes = new Uint8Array(wasmMemory.buffer, msgPtr, msgLen);
      console.error('[WASM Error]', decoder.decode(msgBytes));
    },
    getCurrentTimestamp: () => {
      return BigInt(Math.floor(Date.now() / 1000));
    }
  }
};

const wasmModule = new WebAssembly.Module(wasmBuffer);
const wasmInstance = new WebAssembly.Instance(wasmModule, imports);
const exports = wasmInstance.exports as any;
wasmMemory = exports.memory;

console.log('WASM exports:', Object.keys(exports).filter(k => k.includes('group_message')));

// Test data
const groupId = new Uint8Array(32);
groupId.fill(0x42);

const epoch = BigInt(1);
const senderIndex = 0;
const message = "Hello, NIP-EE!";
const mlsSignature = new Uint8Array(64);
mlsSignature.fill(0x00);

const exporterSecret = new Uint8Array(32);
exporterSecret.fill(0x42);

// Allocate inputs
const groupIdPtr = exports.wasm_alloc(32);
new Uint8Array(exports.memory.buffer, groupIdPtr, 32).set(groupId);

const messageBytes = new TextEncoder().encode(message);
const messagePtr = exports.wasm_alloc(messageBytes.length);
new Uint8Array(exports.memory.buffer, messagePtr, messageBytes.length).set(messageBytes);

const signaturePtr = exports.wasm_alloc(64);
new Uint8Array(exports.memory.buffer, signaturePtr, 64).set(mlsSignature);

const secretPtr = exports.wasm_alloc(32);
new Uint8Array(exports.memory.buffer, secretPtr, 32).set(exporterSecret);

// Allocate output
const maxSize = 4096;
const outPtr = exports.wasm_alloc(maxSize);
const outLenPtr = exports.wasm_alloc_u32 ? exports.wasm_alloc_u32(1) : exports.wasm_alloc(4);
new Uint32Array(exports.memory.buffer, outLenPtr, 1)[0] = maxSize;

console.log('Calling wasm_nip_ee_create_encrypted_group_message...');
try {
  const success = exports.wasm_nip_ee_create_encrypted_group_message(
    groupIdPtr,
    epoch,
    senderIndex,
    messagePtr,
    messageBytes.length,
    signaturePtr,
    64,
    secretPtr,
    outPtr,
    outLenPtr
  );
  
  console.log('Success:', success);
  
  if (success) {
    const actualLen = new Uint32Array(exports.memory.buffer, outLenPtr, 1)[0];
    console.log('Encrypted length:', actualLen);
    
    const encrypted = new Uint8Array(exports.memory.buffer, outPtr, actualLen);
    console.log('Encrypted data (first 32 bytes):', Array.from(encrypted.slice(0, 32)).map(b => b.toString(16).padStart(2, '0')).join(' '));
  } else {
    console.error('Failed to create encrypted group message');
  }
} catch (error) {
  console.error('Error:', error);
}

// Clean up
exports.wasm_free(groupIdPtr, 32);
exports.wasm_free(messagePtr, messageBytes.length);
exports.wasm_free(signaturePtr, 64);
exports.wasm_free(secretPtr, 32);
exports.wasm_free(outPtr, maxSize);
exports.wasm_free(outLenPtr, 4);