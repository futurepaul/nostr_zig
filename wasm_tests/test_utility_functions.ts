import { readFileSync } from 'fs';
import { resolve } from 'path';
import { createHash } from 'crypto';

// Load the WASM module
const wasmPath = resolve(__dirname, '../visualizer/src/nostr_mls.wasm');
const wasmBuffer = readFileSync(wasmPath);

// Create simple imports that don't require browser APIs
const wasmMemory = new WebAssembly.Memory({ initial: 256, maximum: 512 });

const imports = {
    env: {
        memory: wasmMemory,
        getRandomValues: (ptr: number, len: number) => {
            const bytes = new Uint8Array(wasmMemory.buffer, ptr, len);
            // Use Node.js crypto for randomness
            const nodeBytes = require('crypto').randomBytes(len);
            bytes.set(nodeBytes);
        }
    }
};

function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function testUtilityFunctions() {
    console.log("Loading WASM module...");
    const wasmModule = new WebAssembly.Module(wasmBuffer);
    const wasmInstance = new WebAssembly.Instance(wasmModule, imports);
    const exports = wasmInstance.exports as any;
    
    console.log("Available utility functions:", Object.keys(exports).filter(k => 
        k.includes('hex') || k.includes('base64') || k.includes('pad') || k.includes('exporter')
    ));
    
    // === Test 1: Hex conversions ===
    console.log("\n=== Testing Hex Conversions ===");
    
    const testData = new TextEncoder().encode("Hello World");
    const expectedHex = "48656c6c6f20576f726c64";
    
    // Allocate memory for hex conversion
    const dataPtr = exports.wasm_alloc(testData.length);
    const hexPtr = exports.wasm_alloc(testData.length * 2);
    const backBytesPtr = exports.wasm_alloc(testData.length);
    
    // Copy test data to WASM
    new Uint8Array(exports.memory.buffer, dataPtr, testData.length).set(testData);
    
    // Convert to hex
    const hexSuccess = exports.bytes_to_hex(dataPtr, testData.length, hexPtr, testData.length * 2);
    console.log("bytes_to_hex success:", hexSuccess);
    
    if (hexSuccess) {
        const hexResult = new TextDecoder().decode(new Uint8Array(exports.memory.buffer, hexPtr, testData.length * 2));
        console.log("Expected hex:", expectedHex);
        console.log("WASM hex:    ", hexResult);
        console.log("Hex match:", hexResult === expectedHex ? "✅" : "❌");
        
        // Test hex back to bytes
        const hexData = new TextEncoder().encode(hexResult);
        const hexDataPtr = exports.wasm_alloc(hexData.length);
        new Uint8Array(exports.memory.buffer, hexDataPtr, hexData.length).set(hexData);
        
        const backSuccess = exports.hex_to_bytes(hexDataPtr, hexData.length, backBytesPtr, testData.length);
        console.log("hex_to_bytes success:", backSuccess);
        
        if (backSuccess) {
            const backBytes = new Uint8Array(exports.memory.buffer, backBytesPtr, testData.length);
            const backText = new TextDecoder().decode(backBytes);
            console.log("Roundtrip text:", backText);
            console.log("Roundtrip match:", backText === "Hello World" ? "✅" : "❌");
        }
        
        exports.wasm_free(hexDataPtr, hexData.length);
    }
    
    // === Test 2: Base64 ===
    console.log("\n=== Testing Base64 ===");
    
    const base64Expected = Buffer.from(testData).toString('base64');
    const base64Ptr = exports.wasm_alloc(100); // Should be enough for base64
    
    const b64EncodeSuccess = exports.base64_encode(dataPtr, testData.length, base64Ptr, 100);
    console.log("base64_encode success:", b64EncodeSuccess);
    
    if (b64EncodeSuccess) {
        // Calculate the actual encoded length
        const encodedLen = Math.ceil(testData.length / 3) * 4;
        const base64Result = new TextDecoder().decode(new Uint8Array(exports.memory.buffer, base64Ptr, encodedLen));
        console.log("Expected base64:", base64Expected);
        console.log("WASM base64:    ", base64Result);
        console.log("Base64 match:", base64Result === base64Expected ? "✅" : "❌");
        
        // Test decode
        const b64Data = new TextEncoder().encode(base64Result);
        const b64DataPtr = exports.wasm_alloc(b64Data.length);
        const decodedPtr = exports.wasm_alloc(testData.length);
        const decodedLenPtr = exports.wasm_alloc_u32(1);
        
        new Uint8Array(exports.memory.buffer, b64DataPtr, b64Data.length).set(b64Data);
        new Uint32Array(exports.memory.buffer, decodedLenPtr, 1)[0] = testData.length;
        
        const decodeSuccess = exports.base64_decode(b64DataPtr, b64Data.length, decodedPtr, decodedLenPtr);
        console.log("base64_decode success:", decodeSuccess);
        
        if (decodeSuccess) {
            const decodedLen = new Uint32Array(exports.memory.buffer, decodedLenPtr, 1)[0];
            const decodedBytes = new Uint8Array(exports.memory.buffer, decodedPtr, decodedLen);
            const decodedText = new TextDecoder().decode(decodedBytes);
            console.log("Decoded text:", decodedText);
            console.log("Base64 roundtrip:", decodedText === "Hello World" ? "✅" : "❌");
        }
        
        exports.wasm_free(b64DataPtr, b64Data.length);
        exports.wasm_free(decodedPtr, testData.length);
        exports.wasm_free_u32(decodedLenPtr, 1);
    }
    
    // === Test 3: Exporter Secret ===
    console.log("\n=== Testing Exporter Secret Derivation ===");
    
    const groupSecret = new Uint8Array(32);
    groupSecret.fill(0x42); // Test group secret
    const epoch = 5n;
    
    const groupSecretPtr = exports.wasm_alloc(32);
    const exporterSecretPtr = exports.wasm_alloc(32);
    
    new Uint8Array(exports.memory.buffer, groupSecretPtr, 32).set(groupSecret);
    
    const exporterSuccess = exports.wasm_derive_exporter_secret(groupSecretPtr, epoch, exporterSecretPtr);
    console.log("derive_exporter_secret success:", exporterSuccess);
    
    if (exporterSuccess) {
        const exporterSecret = new Uint8Array(exports.memory.buffer, exporterSecretPtr, 32);
        console.log("Exporter secret:", bytesToHex(exporterSecret));
        console.log("Length check:", exporterSecret.length === 32 ? "✅" : "❌");
        
        // Test deterministic - same inputs should give same output
        const exporterSecret2Ptr = exports.wasm_alloc(32);
        const exporterSuccess2 = exports.wasm_derive_exporter_secret(groupSecretPtr, epoch, exporterSecret2Ptr);
        
        if (exporterSuccess2) {
            const exporterSecret2 = new Uint8Array(exports.memory.buffer, exporterSecret2Ptr, 32);
            const isDeterministic = bytesToHex(exporterSecret) === bytesToHex(exporterSecret2);
            console.log("Deterministic:", isDeterministic ? "✅" : "❌");
        }
        
        exports.wasm_free(exporterSecret2Ptr, 32);
    }
    
    // === Test 4: NIP-44 Padding ===
    console.log("\n=== Testing NIP-44 Padding ===");
    
    const testMessage = "short";
    const messageBytes = new TextEncoder().encode(testMessage);
    const messageBytesPtr = exports.wasm_alloc(messageBytes.length);
    new Uint8Array(exports.memory.buffer, messageBytesPtr, messageBytes.length).set(messageBytes);
    
    // Calculate padded length
    const paddedLen = exports.wasm_calc_padded_len(messageBytes.length);
    console.log("Message length:", messageBytes.length);
    console.log("Padded length:", paddedLen);
    console.log("Padding adds:", paddedLen - messageBytes.length, "bytes");
    
    // Test padding
    const totalPaddedLen = 2 + paddedLen; // 2 bytes for length + padded content
    const paddedPtr = exports.wasm_alloc(totalPaddedLen);
    const paddedLenPtr = exports.wasm_alloc_u32(1);
    new Uint32Array(exports.memory.buffer, paddedLenPtr, 1)[0] = totalPaddedLen;
    
    const padSuccess = exports.wasm_pad_message(messageBytesPtr, messageBytes.length, paddedPtr, paddedLenPtr);
    console.log("pad_message success:", padSuccess);
    
    if (padSuccess) {
        const actualPaddedLen = new Uint32Array(exports.memory.buffer, paddedLenPtr, 1)[0];
        const paddedBytes = new Uint8Array(exports.memory.buffer, paddedPtr, actualPaddedLen);
        
        console.log("Padded data:", bytesToHex(paddedBytes));
        console.log("First 2 bytes (length):", bytesToHex(paddedBytes.slice(0, 2)));
        
        // Test unpadding
        const unpaddedPtr = exports.wasm_alloc(messageBytes.length);
        const unpaddedLenPtr = exports.wasm_alloc_u32(1);
        new Uint32Array(exports.memory.buffer, unpaddedLenPtr, 1)[0] = messageBytes.length;
        
        const unpadSuccess = exports.wasm_unpad_message(paddedPtr, actualPaddedLen, unpaddedPtr, unpaddedLenPtr);
        console.log("unpad_message success:", unpadSuccess);
        
        if (unpadSuccess) {
            const actualUnpaddedLen = new Uint32Array(exports.memory.buffer, unpaddedLenPtr, 1)[0];
            const unpaddedBytes = new Uint8Array(exports.memory.buffer, unpaddedPtr, actualUnpaddedLen);
            const unpaddedText = new TextDecoder().decode(unpaddedBytes);
            console.log("Unpadded text:", unpaddedText);
            console.log("Padding roundtrip:", unpaddedText === testMessage ? "✅" : "❌");
        }
        
        exports.wasm_free(unpaddedPtr, messageBytes.length);
        exports.wasm_free_u32(unpaddedLenPtr, 1);
    }
    
    // Clean up main allocations
    exports.wasm_free(dataPtr, testData.length);
    exports.wasm_free(hexPtr, testData.length * 2);
    exports.wasm_free(backBytesPtr, testData.length);
    exports.wasm_free(base64Ptr, 100);
    exports.wasm_free(groupSecretPtr, 32);
    exports.wasm_free(exporterSecretPtr, 32);
    exports.wasm_free(messageBytesPtr, messageBytes.length);
    exports.wasm_free(paddedPtr, totalPaddedLen);
    exports.wasm_free_u32(paddedLenPtr, 1);
    
    console.log("\n🎉 All utility function tests completed!");
}

// Run the test
testUtilityFunctions().catch(console.error);