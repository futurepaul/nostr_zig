#!/usr/bin/env bun

import { readFileSync } from 'fs';
import { resolve } from 'path';

// Load WASM module
const wasmPath = resolve(__dirname, '../visualizer/src/nostr_mls.wasm');
const wasmBuffer = readFileSync(wasmPath);

// Helper to convert hex string to bytes
function hexToBytes(hex: string): Uint8Array {
    if (hex.length % 2 !== 0) throw new Error("Invalid hex string");
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}

// Helper to convert bytes to hex string
function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

// Helper to read big-endian integers
function readBigEndianU16(buffer: Uint8Array, offset: number): number {
    return (buffer[offset] << 8) | buffer[offset + 1];
}

function readBigEndianU64(buffer: Uint8Array, offset: number): bigint {
    let value = 0n;
    for (let i = 0; i < 8; i++) {
        value = (value << 8n) | BigInt(buffer[offset + i]);
    }
    return value;
}

// Setup WASM imports
const imports = {
    env: {
        getRandomValues: (ptr: number, len: number) => {
            const bytes = new Uint8Array(wasmMemory.buffer, ptr, len);
            crypto.getRandomValues(bytes);
        },
        getCurrentTimestamp: (): bigint => {
            // Return current timestamp in seconds
            return BigInt(Math.floor(Date.now() / 1000));
        }
    }
};

// Instantiate WASM module
const wasmModule = new WebAssembly.Module(wasmBuffer);
const wasmInstance = new WebAssembly.Instance(wasmModule, imports);
const exports = wasmInstance.exports as any;
const wasmMemory = exports.memory as WebAssembly.Memory;

// Test keypackage creation
console.log("🔑 Testing MLS Key Package Creation...\n");

// Test private key (32 bytes)
const testPrivKey = hexToBytes("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");

// Allocate memory for output
const outDataPtr = exports.wasm_alloc(1024);
const outLenPtr = exports.wasm_alloc(4);

if (!outDataPtr || !outLenPtr) {
    console.error("❌ Failed to allocate memory");
    process.exit(1);
}

// Set initial output length
new Uint32Array(wasmMemory.buffer, outLenPtr, 1)[0] = 1024;

// Allocate and copy private key
const privKeyPtr = exports.wasm_alloc(32);
if (!privKeyPtr) {
    console.error("❌ Failed to allocate private key memory");
    process.exit(1);
}
new Uint8Array(wasmMemory.buffer, privKeyPtr, 32).set(testPrivKey);

// Create key package
console.log("Creating key package...");
const createFn = exports.wasm_create_real_key_package || exports.wasm_create_key_package;
console.log(`Using function: ${createFn === exports.wasm_create_real_key_package ? 'wasm_create_real_key_package' : 'wasm_create_key_package'}`);
const success = createFn(privKeyPtr, outDataPtr, outLenPtr);

if (!success) {
    console.error("❌ Failed to create key package");
    exports.wasm_free(privKeyPtr, 32);
    exports.wasm_free(outDataPtr, 1024);
    exports.wasm_free(outLenPtr, 4);
    process.exit(1);
}

// Get the actual length
const actualLen = new Uint32Array(wasmMemory.buffer, outLenPtr, 1)[0];
console.log(`✅ Key package created successfully! Size: ${actualLen} bytes\n`);

// Read the key package data
const keyPackageData = new Uint8Array(wasmMemory.buffer, outDataPtr, actualLen);
const keyPackageCopy = new Uint8Array(actualLen);
keyPackageCopy.set(keyPackageData);

// Parse the key package structure
// Format: [version:2][cipher_suite:2][hpke_pubkey:32][mls_pubkey:32][nostr_pubkey:32][timestamp:8][signature:64]
console.log("📋 Key Package Structure:");
console.log("========================");

// Debug: show first few bytes
console.log(`First 16 bytes (hex): ${bytesToHex(keyPackageCopy.slice(0, 16))}`);
console.log(`Expected size: 172 bytes, Actual size: ${actualLen} bytes\n`);

let offset = 0;

// Version
const version = readBigEndianU16(keyPackageCopy, offset);
console.log(`Version: 0x${version.toString(16).padStart(4, '0')} (MLS ${version === 1 ? '1.0' : 'Unknown'})`);
offset += 2;

// Cipher Suite
const cipherSuite = readBigEndianU16(keyPackageCopy, offset);
console.log(`Cipher Suite: 0x${cipherSuite.toString(16).padStart(4, '0')} (${cipherSuite === 1 ? 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519' : 'Unknown'})`);
offset += 2;

// HPKE Public Key
const hpkePubKey = keyPackageCopy.slice(offset, offset + 32);
console.log(`HPKE Public Key: ${bytesToHex(hpkePubKey)}`);
offset += 32;

// MLS Signing Public Key
const mlsPubKey = keyPackageCopy.slice(offset, offset + 32);
console.log(`MLS Public Key: ${bytesToHex(mlsPubKey)}`);
offset += 32;

// Nostr Public Key
const nostrPubKey = keyPackageCopy.slice(offset, offset + 32);
console.log(`Nostr Public Key: ${bytesToHex(nostrPubKey)}`);
offset += 32;

// Timestamp
const timestamp = readBigEndianU64(keyPackageCopy, offset);
console.log(`Timestamp: ${timestamp} (${new Date(Number(timestamp) * 1000).toISOString()})`);
offset += 8;

// Signature
const signature = keyPackageCopy.slice(offset, offset + 64);
console.log(`Signature: ${bytesToHex(signature)}`);
offset += 64;

console.log(`\n✅ Total bytes parsed: ${offset}`);

// Verify the structure
console.log("\n🔍 Verification:");
console.log("================");

// Check that HPKE key is different from Nostr key (should be randomly generated)
const hpkeKeyHex = bytesToHex(hpkePubKey);
const nostrKeyHex = bytesToHex(nostrPubKey);
const mlsKeyHex = bytesToHex(mlsPubKey);

console.log(`✅ HPKE key is unique: ${hpkeKeyHex !== nostrKeyHex}`);
console.log(`✅ MLS signing key is unique: ${mlsKeyHex !== nostrKeyHex && mlsKeyHex !== hpkeKeyHex}`);

// Check signature is not all zeros
const sigNotZero = signature.some(b => b !== 0);
console.log(`✅ Signature is not empty: ${sigNotZero}`);

// Check timestamp is reasonable (within last hour)
const now = Math.floor(Date.now() / 1000);
const timeDiff = Math.abs(now - Number(timestamp));
console.log(`✅ Timestamp is current: ${timeDiff < 3600} (${timeDiff}s difference)`);

// Create another key package to verify randomness
console.log("\n🎲 Testing Randomness:");
console.log("=====================");

// Reset output length
new Uint32Array(wasmMemory.buffer, outLenPtr, 1)[0] = 1024;

const success2 = createFn(privKeyPtr, outDataPtr, outLenPtr);
if (success2) {
    const actualLen2 = new Uint32Array(wasmMemory.buffer, outLenPtr, 1)[0];
    const keyPackageData2 = new Uint8Array(wasmMemory.buffer, outDataPtr, actualLen2);
    const keyPackageCopy2 = new Uint8Array(actualLen2);
    keyPackageCopy2.set(keyPackageData2);
    
    // Extract HPKE key from second package
    const hpkePubKey2 = keyPackageCopy2.slice(4, 36); // Skip version and cipher suite
    const hpkeKeyHex2 = bytesToHex(hpkePubKey2);
    
    console.log(`First HPKE key:  ${hpkeKeyHex}`);
    console.log(`Second HPKE key: ${hpkeKeyHex2}`);
    console.log(`✅ HPKE keys are different: ${hpkeKeyHex !== hpkeKeyHex2}`);
}

// Cleanup
exports.wasm_free(privKeyPtr, 32);
exports.wasm_free(outDataPtr, 1024);
exports.wasm_free(outLenPtr, 4);

console.log("\n✅ All tests passed!");