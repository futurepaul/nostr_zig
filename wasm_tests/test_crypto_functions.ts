import { readFileSync } from 'fs';
import { resolve } from 'path';

// Load WASM module
const wasmPath = resolve(__dirname, '../visualizer/src/nostr_mls.wasm');
const wasmBuffer = readFileSync(wasmPath);

// Define WASM imports
const imports = {
    env: {
        getRandomValues: (ptr: number, len: number) => {
            const bytes = new Uint8Array(exports.memory.buffer, ptr, len);
            crypto.getRandomValues(bytes);
        },
        wasm_log_error: (strPtr: number, len: number) => {
            const bytes = new Uint8Array(exports.memory.buffer, strPtr, len);
            const message = new TextDecoder().decode(bytes);
            console.error('WASM error:', message);
        },
        getCurrentTimestamp: () => BigInt(Math.floor(Date.now() / 1000))
    }
};

// Instantiate WASM
const wasmModule = new WebAssembly.Module(wasmBuffer);
const wasmInstance = new WebAssembly.Instance(wasmModule, imports);
const exports = wasmInstance.exports as any;

// Initialize WASM
if (exports.wasm_init) {
    exports.wasm_init();
}

// Helper functions
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

async function testSHA256() {
    console.log('\n🔒 Testing SHA-256 function');
    
    const testData = new TextEncoder().encode('Hello, Nostr!');
    const dataPtr = exports.wasm_alloc(testData.length);
    const hashPtr = exports.wasm_alloc(32);
    
    new Uint8Array(exports.memory.buffer, dataPtr, testData.length).set(testData);
    
    const success = exports.wasm_sha256(dataPtr, testData.length, hashPtr);
    
    if (success) {
        const hash = new Uint8Array(exports.memory.buffer, hashPtr, 32);
        console.log('✅ SHA-256 hash:', bytesToHex(hash));
        
        // Compare with browser's SHA-256
        const browserHash = await crypto.subtle.digest('SHA-256', testData);
        const browserHashHex = bytesToHex(new Uint8Array(browserHash));
        console.log('Browser SHA-256:', browserHashHex);
        console.log('Match:', bytesToHex(hash) === browserHashHex ? '✅' : '❌');
    } else {
        console.log('❌ SHA-256 failed');
    }
    
    exports.wasm_free(dataPtr, testData.length);
    exports.wasm_free(hashPtr, 32);
}

async function testNostrEventId() {
    console.log('\n🎫 Testing Nostr Event ID generation');
    
    // Create test event
    const pubkey = 'a'.repeat(64); // 64 hex chars
    const created_at = BigInt(Math.floor(Date.now() / 1000));
    const kind = 1;
    const tags = [['e', 'test'], ['p', 'test']];
    const content = 'Hello, Nostr!';
    
    // Allocate memory
    const pubkeyPtr = exports.wasm_alloc(64);
    const pubkeyBytes = new TextEncoder().encode(pubkey);
    new Uint8Array(exports.memory.buffer, pubkeyPtr, 64).set(pubkeyBytes);
    
    const tagsJson = JSON.stringify(tags);
    const tagsBytes = new TextEncoder().encode(tagsJson);
    const tagsPtr = exports.wasm_alloc(tagsBytes.length);
    new Uint8Array(exports.memory.buffer, tagsPtr, tagsBytes.length).set(tagsBytes);
    
    const contentBytes = new TextEncoder().encode(content);
    const contentPtr = exports.wasm_alloc(contentBytes.length);
    new Uint8Array(exports.memory.buffer, contentPtr, contentBytes.length).set(contentBytes);
    
    const eventIdPtr = exports.wasm_alloc(32);
    
    const success = exports.wasm_create_nostr_event_id(
        pubkeyPtr,
        created_at,
        kind,
        tagsPtr,
        tagsBytes.length,
        contentPtr,
        contentBytes.length,
        eventIdPtr
    );
    
    if (success) {
        const eventId = new Uint8Array(exports.memory.buffer, eventIdPtr, 32);
        console.log('✅ Event ID:', bytesToHex(eventId));
        
        // Manually verify by creating the serialized event
        const serialized = JSON.stringify([
            0,
            pubkey,
            Number(created_at),
            kind,
            tags,
            content
        ]);
        const manualHash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(serialized));
        const manualHashHex = bytesToHex(new Uint8Array(manualHash));
        console.log('Manual hash:', manualHashHex);
        console.log('Match:', bytesToHex(eventId) === manualHashHex ? '✅' : '❌');
    } else {
        console.log('❌ Event ID generation failed');
    }
    
    exports.wasm_free(pubkeyPtr, 64);
    exports.wasm_free(tagsPtr, tagsBytes.length);
    exports.wasm_free(contentPtr, contentBytes.length);
    exports.wasm_free(eventIdPtr, 32);
}

async function testNIP44WithBase64() {
    console.log('\n🔐 Testing NIP-44 encryption/decryption with base64');
    
    // Generate an identity
    const privateKeyPtr = exports.wasm_alloc(32);
    const publicKeyPtr = exports.wasm_alloc(32);
    
    const identitySuccess = exports.wasm_create_identity(privateKeyPtr, publicKeyPtr);
    if (!identitySuccess) {
        console.log('❌ Failed to create identity');
        return;
    }
    
    const privateKey = new Uint8Array(exports.memory.buffer, privateKeyPtr, 32).slice();
    const publicKey = new Uint8Array(exports.memory.buffer, publicKeyPtr, 32).slice();
    console.log('✅ Created identity:', bytesToHex(publicKey));
    
    // Test message
    const plaintext = 'Hello from NIP-44 v2!';
    const plaintextBytes = new TextEncoder().encode(plaintext);
    const plaintextPtr = exports.wasm_alloc(plaintextBytes.length);
    new Uint8Array(exports.memory.buffer, plaintextPtr, plaintextBytes.length).set(plaintextBytes);
    
    // Use the private key as the exporter secret (for testing)
    const exporterSecretPtr = exports.wasm_alloc(32);
    new Uint8Array(exports.memory.buffer, exporterSecretPtr, 32).set(privateKey);
    
    // Encrypt
    const maxCiphertextSize = 4096;
    const ciphertextPtr = exports.wasm_alloc(maxCiphertextSize);
    const ciphertextLenPtr = exports.wasm_alloc_u32(1);
    new Uint32Array(exports.memory.buffer, ciphertextLenPtr, 1)[0] = maxCiphertextSize;
    
    const encryptSuccess = exports.wasm_nip44_encrypt(
        exporterSecretPtr,
        plaintextPtr,
        plaintextBytes.length,
        ciphertextPtr,
        ciphertextLenPtr
    );
    
    if (!encryptSuccess) {
        console.log('❌ NIP-44 encryption failed');
        return;
    }
    
    const ciphertextLen = new Uint32Array(exports.memory.buffer, ciphertextLenPtr, 1)[0];
    const ciphertext = new Uint8Array(exports.memory.buffer, ciphertextPtr, ciphertextLen).slice();
    const ciphertextBase64 = new TextDecoder().decode(ciphertext);
    console.log('✅ Encrypted (base64):', ciphertextBase64.substring(0, 50) + '...');
    
    // Decrypt
    const decryptInputPtr = exports.wasm_alloc(ciphertext.length);
    new Uint8Array(exports.memory.buffer, decryptInputPtr, ciphertext.length).set(ciphertext);
    
    const maxPlaintextSize = 4096;
    const decryptedPtr = exports.wasm_alloc(maxPlaintextSize);
    const decryptedLenPtr = exports.wasm_alloc_u32(1);
    new Uint32Array(exports.memory.buffer, decryptedLenPtr, 1)[0] = maxPlaintextSize;
    
    const decryptSuccess = exports.wasm_nip44_decrypt(
        exporterSecretPtr,
        decryptInputPtr,
        ciphertext.length,
        decryptedPtr,
        decryptedLenPtr
    );
    
    if (!decryptSuccess) {
        console.log('❌ NIP-44 decryption failed');
        return;
    }
    
    const decryptedLen = new Uint32Array(exports.memory.buffer, decryptedLenPtr, 1)[0];
    const decrypted = new Uint8Array(exports.memory.buffer, decryptedPtr, decryptedLen);
    const decryptedText = new TextDecoder().decode(decrypted);
    console.log('✅ Decrypted:', decryptedText);
    console.log('Match:', plaintext === decryptedText ? '✅' : '❌');
    
    // Clean up
    exports.wasm_free(privateKeyPtr, 32);
    exports.wasm_free(publicKeyPtr, 32);
    exports.wasm_free(plaintextPtr, plaintextBytes.length);
    exports.wasm_free(exporterSecretPtr, 32);
    exports.wasm_free(ciphertextPtr, maxCiphertextSize);
    exports.wasm_free_u32(ciphertextLenPtr, 1);
    exports.wasm_free(decryptInputPtr, ciphertext.length);
    exports.wasm_free(decryptedPtr, maxPlaintextSize);
    exports.wasm_free_u32(decryptedLenPtr, 1);
}

// Run tests
async function runAllTests() {
    console.log('🧪 Testing WASM crypto functions\n');
    
    await testSHA256();
    await testNostrEventId();
    await testNIP44WithBase64();
    
    console.log('\n✅ All tests completed!');
}

runAllTests();