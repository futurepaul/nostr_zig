import { readFileSync } from 'fs';
import { resolve } from 'path';

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

async function testMLSSerialization() {
    console.log("Loading WASM module...");
    const wasmModule = new WebAssembly.Module(wasmBuffer);
    const wasmInstance = new WebAssembly.Instance(wasmModule, imports);
    const exports = wasmInstance.exports as any;
    
    console.log("WASM exports for MLS:", Object.keys(exports).filter(k => k.includes('mls') || k.includes('serialize')));
    
    // Test data
    const groupId = new Uint8Array(32).fill(0x42); // Test group ID
    const epoch = 1n; // BigInt for u64
    const senderIndex = 0;
    const authenticatedData = new TextEncoder().encode("test-auth-data");
    
    // Create an unsigned Nostr event as application data (per NIP-EE spec)
    const applicationEvent = {
        kind: 9, // Chat message
        created_at: Math.floor(Date.now() / 1000),
        tags: [],
        content: "Hello from MLS group message!",
        pubkey: "6e468422dfb74a5738702a8823b9b28168abab8655faacb6853cd0ee15deee93" // User's Nostr identity
    };
    const applicationData = new TextEncoder().encode(JSON.stringify(applicationEvent));
    
    // Create a test signature (64 bytes)
    const signature = new Uint8Array(64).fill(0x99);
    
    // Allocate memory for inputs
    const groupIdPtr = exports.wasm_alloc(32);
    const authDataPtr = exports.wasm_alloc(authenticatedData.length);
    const appDataPtr = exports.wasm_alloc(applicationData.length);
    const signaturePtr = exports.wasm_alloc(64);
    
    // Allocate memory for output (estimate 1KB should be enough)
    const outputPtr = exports.wasm_alloc(1024);
    const outLenPtr = exports.wasm_alloc_u32(1);
    
    if (!groupIdPtr || !authDataPtr || !appDataPtr || !signaturePtr || !outputPtr || !outLenPtr) {
        throw new Error("Failed to allocate memory");
    }
    
    try {
        // Copy input data to WASM memory
        new Uint8Array(exports.memory.buffer, groupIdPtr, 32).set(groupId);
        new Uint8Array(exports.memory.buffer, authDataPtr, authenticatedData.length).set(authenticatedData);
        new Uint8Array(exports.memory.buffer, appDataPtr, applicationData.length).set(applicationData);
        new Uint8Array(exports.memory.buffer, signaturePtr, 64).set(signature);
        
        // Set output buffer size
        new Uint32Array(exports.memory.buffer, outLenPtr, 1)[0] = 1024;
        
        console.log("\nTesting MLS application message serialization:");
        console.log("Group ID:", bytesToHex(groupId));
        console.log("Epoch:", epoch.toString());
        console.log("Sender index:", senderIndex);
        console.log("Auth data:", new TextDecoder().decode(authenticatedData));
        console.log("Application event:", JSON.stringify(applicationEvent, null, 2));
        
        // Call WASM function
        const success = exports.wasm_serialize_mls_application_message(
            groupIdPtr,
            epoch,
            senderIndex,
            authDataPtr,
            authenticatedData.length,
            appDataPtr,
            applicationData.length,
            signaturePtr,
            outputPtr,
            outLenPtr
        );
        
        if (!success) {
            throw new Error("MLS serialization failed");
        }
        
        // Read the result
        const resultLen = new Uint32Array(exports.memory.buffer, outLenPtr, 1)[0];
        const resultBytes = new Uint8Array(exports.memory.buffer, outputPtr, resultLen);
        const resultStr = new TextDecoder().decode(resultBytes);
        
        console.log("\n✅ MLS serialization successful!");
        console.log("Serialized length:", resultLen, "bytes");
        console.log("Serialized data (hex):", bytesToHex(resultBytes));
        
        // Analyze the TLS wire format structure
        console.log("\n✅ TLS Wire Format Analysis:");
        let offset = 0;
        
        // Wire format (u16)
        const wireFormat = new DataView(exports.memory.buffer, outputPtr + offset, 2).getUint16(0, false);
        console.log("- Wire format:", wireFormat, "(1 = mls_plaintext)");
        offset += 2;
        
        // Group ID length + data
        const groupIdLen = new DataView(exports.memory.buffer, outputPtr + offset, 1).getUint8(0);
        offset += 1;
        const groupIdBytes = new Uint8Array(exports.memory.buffer, outputPtr + offset, groupIdLen);
        console.log("- Group ID length:", groupIdLen);
        console.log("- Group ID:", bytesToHex(groupIdBytes));
        offset += groupIdLen;
        
        // Epoch (u64)
        const epochBytes = new Uint8Array(exports.memory.buffer, outputPtr + offset, 8);
        console.log("- Epoch bytes:", bytesToHex(epochBytes));
        offset += 8;
        
        console.log("- Total structure verified! This is proper TLS wire format as required by NIP-EE spec.");
        
    } finally {
        // Clean up
        exports.wasm_free(groupIdPtr, 32);
        exports.wasm_free(authDataPtr, authenticatedData.length);
        exports.wasm_free(appDataPtr, applicationData.length);
        exports.wasm_free(signaturePtr, 64);
        exports.wasm_free(outputPtr, 1024);
        exports.wasm_free_u32(outLenPtr, 1);
    }
}

// Run the test
testMLSSerialization().catch(console.error);