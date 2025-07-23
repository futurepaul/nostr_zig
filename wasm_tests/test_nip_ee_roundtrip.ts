#!/usr/bin/env bun
import { test, expect } from "bun:test";

// WASM interface
interface WasmExports {
  memory: WebAssembly.Memory;
  wasm_alloc: (size: number) => number;
  wasm_free: (ptr: number, size: number) => void;
  wasm_alloc_u32: (count: number) => number;
  wasm_free_u32: (ptr: number, count: number) => void;
  wasm_nip_ee_create_encrypted_group_message: (
    groupId: number, epoch: bigint, senderIndex: number,
    messageContent: number, messageContentLen: number,
    mlsSignature: number, mlsSignatureLen: number,
    exporterSecret: number, outEncrypted: number, outLen: number
  ) => boolean;
  wasm_nip_ee_decrypt_group_message: (
    encryptedContent: number, encryptedContentLen: number,
    exporterSecret: number, outDecrypted: number, outLen: number
  ) => boolean;
  wasm_create_random_bytes: (outPtr: number, len: number) => void;
}

let wasmInstance: WebAssembly.Instance | null = null;
let wasmMemory: WebAssembly.Memory | null = null;

async function initWasm() {
  if (wasmInstance) return wasmInstance.exports as WasmExports;
  
  const wasmBuffer = await Bun.file("../visualizer/src/nostr_mls.wasm").arrayBuffer();
  const wasmModule = new WebAssembly.Module(wasmBuffer);
  
  const imports = {
    env: {
      getRandomValues: (buf: number, len: number) => {
        const array = new Uint8Array((wasmInstance!.exports as any).memory.buffer, buf, len);
        crypto.getRandomValues(array);
      },
      getCurrentTimestamp: () => BigInt(Date.now()),
      wasm_log_error: (str: number, len: number) => {
        const memory = (wasmInstance!.exports as any).memory as WebAssembly.Memory;
        const bytes = new Uint8Array(memory.buffer, str, len);
        const message = new TextDecoder().decode(bytes);
        console.log('🔴 WASM error:', message);
      }
    }
  };
  
  wasmInstance = await WebAssembly.instantiate(wasmModule, imports);
  wasmMemory = (wasmInstance.exports as any).memory;
  
  return wasmInstance.exports as WasmExports;
}

function allocateBytes(exports: WasmExports, data: Uint8Array): number {
  const ptr = exports.wasm_alloc(data.length);
  if (!ptr) throw new Error('Failed to allocate memory');
  new Uint8Array(exports.memory.buffer, ptr, data.length).set(data);
  return ptr;
}

function readBytes(exports: WasmExports, ptr: number, len: number): Uint8Array {
  return new Uint8Array(exports.memory.buffer, ptr, len).slice();
}

test("NIP-EE Encrypt/Decrypt Round Trip", async () => {
  console.log("🧪 Testing NIP-EE End-to-End Encrypt/Decrypt");
  
  const exports = await initWasm();
  
  // Test data - use same exporter secret for both encryption and decryption
  const groupId = new Uint8Array(32);
  crypto.getRandomValues(groupId);
  
  const exporterSecret = new Uint8Array(32);
  crypto.getRandomValues(exporterSecret);
  
  const message = "Hello from NIP-EE test!";
  const messageBytes = new TextEncoder().encode(message);
  
  const signature = new Uint8Array(64);
  crypto.getRandomValues(signature);
  
  console.log("📝 Test parameters:");
  console.log("  Group ID:", Array.from(groupId.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join(' '));
  console.log("  Exporter Secret:", Array.from(exporterSecret.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join(' '));
  console.log("  Message:", message);
  
  // Allocate inputs for encryption
  const groupIdPtr = allocateBytes(exports, groupId);
  const messagePtr = allocateBytes(exports, messageBytes);
  const signaturePtr = allocateBytes(exports, signature);
  const exporterSecretPtr1 = allocateBytes(exports, exporterSecret);
  
  // Allocate output for encryption
  const maxEncryptedSize = 4096;
  const encryptedPtr = exports.wasm_alloc(maxEncryptedSize);
  const encryptedLenPtr = exports.wasm_alloc_u32(1);
  new Uint32Array(exports.memory.buffer, encryptedLenPtr, 1)[0] = maxEncryptedSize;
  
  console.log("🔐 Encrypting message...");
  
  // Encrypt
  const encryptSuccess = exports.wasm_nip_ee_create_encrypted_group_message(
    groupIdPtr,
    1n, // epoch
    0, // sender index
    messagePtr,
    messageBytes.length,
    signaturePtr,
    signature.length,
    exporterSecretPtr1,
    encryptedPtr,
    encryptedLenPtr
  );
  
  if (!encryptSuccess) {
    throw new Error("Encryption failed");
  }
  
  const encryptedLen = new Uint32Array(exports.memory.buffer, encryptedLenPtr, 1)[0];
  const encryptedData = readBytes(exports, encryptedPtr, encryptedLen);
  
  console.log("✅ Encryption successful!");
  console.log("  Encrypted length:", encryptedLen);
  console.log("  Encrypted preview:", Array.from(encryptedData.slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join(' '));
  
  // Now decrypt with the SAME exporter secret
  const exporterSecretPtr2 = allocateBytes(exports, exporterSecret); // Same secret!
  const encryptedPtr2 = allocateBytes(exports, encryptedData);
  
  // Allocate output for decryption
  const maxDecryptedSize = 4096;
  const decryptedPtr = exports.wasm_alloc(maxDecryptedSize);
  const decryptedLenPtr = exports.wasm_alloc_u32(1);
  new Uint32Array(exports.memory.buffer, decryptedLenPtr, 1)[0] = maxDecryptedSize;
  
  console.log("🔓 Decrypting message...");
  
  // Decrypt
  const decryptSuccess = exports.wasm_nip_ee_decrypt_group_message(
    encryptedPtr2,
    encryptedData.length,
    exporterSecretPtr2,
    decryptedPtr,
    decryptedLenPtr
  );
  
  if (!decryptSuccess) {
    throw new Error("Decryption failed");
  }
  
  const decryptedLen = new Uint32Array(exports.memory.buffer, decryptedLenPtr, 1)[0];
  const decryptedData = readBytes(exports, decryptedPtr, decryptedLen);
  const decryptedMessage = new TextDecoder().decode(decryptedData);
  
  console.log("✅ Decryption successful!");
  console.log("  Decrypted length:", decryptedLen);
  console.log("  Decrypted message:", decryptedMessage);
  
  // Verify round trip
  expect(decryptedMessage).toBe(message);
  
  // Clean up
  exports.wasm_free(groupIdPtr, groupId.length);
  exports.wasm_free(messagePtr, messageBytes.length);
  exports.wasm_free(signaturePtr, signature.length);
  exports.wasm_free(exporterSecretPtr1, exporterSecret.length);
  exports.wasm_free(encryptedPtr, maxEncryptedSize);
  exports.wasm_free_u32(encryptedLenPtr, 1);
  exports.wasm_free(exporterSecretPtr2, exporterSecret.length);
  exports.wasm_free(encryptedPtr2, encryptedData.length);
  exports.wasm_free(decryptedPtr, maxDecryptedSize);
  exports.wasm_free_u32(decryptedLenPtr, 1);
  
  console.log("🎉 NIP-EE round trip test PASSED!");
});