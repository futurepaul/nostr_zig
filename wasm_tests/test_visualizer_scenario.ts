import { readFileSync } from 'fs';
import { resolve } from 'path';

console.log('🧪 Testing Visualizer Encryption/Decryption Scenario...\n');

// Load WASM module
const wasmPath = resolve(__dirname, '../visualizer/src/nostr_mls.wasm');
const wasmBuffer = readFileSync(wasmPath);

const imports = {
    env: {
        getRandomValues: (ptr: number, len: number) => {
            const bytes = new Uint8Array(exports.memory.buffer, ptr, len);
            crypto.getRandomValues(bytes);
        },
        wasm_log_error: (strPtr: number, len: number) => {
            const bytes = new Uint8Array(exports.memory.buffer, strPtr, len);
            const message = new TextDecoder().decode(bytes);
            console.error('🔴 WASM error:', message);
        },
        getCurrentTimestamp: () => BigInt(Math.floor(Date.now() / 1000))
    }
};

let exports: any;

// Initialize WASM
WebAssembly.instantiate(wasmBuffer, imports).then(result => {
    exports = result.instance.exports;
    runVisualizerTest();
});

function allocateBytes(data: Uint8Array): number {
    const ptr = exports.wasm_alloc(data.length);
    new Uint8Array(exports.memory.buffer, ptr, data.length).set(data);
    return ptr;
}

function readBytes(ptr: number, len: number): Uint8Array {
    return new Uint8Array(exports.memory.buffer, ptr, len).slice();
}

function runVisualizerTest() {
    console.log('🎯 Simulating Visualizer Encryption/Decryption Flow\n');
    
    try {
        // Step 1: Create MLS group (like visualizer does)
        console.log('1. Creating MLS group...');
        const creatorIdentity = new Uint8Array(32);
        const creatorSigningKey = new Uint8Array(32);
        crypto.getRandomValues(creatorIdentity);
        crypto.getRandomValues(creatorSigningKey);
        
        const maxStateSize = 4096;
        const statePtr = exports.wasm_alloc(maxStateSize);
        const stateLenPtr = exports.wasm_alloc_u32(1);
        new Uint32Array(exports.memory.buffer, stateLenPtr, 1)[0] = maxStateSize;
        
        const creatorIdentityPtr = allocateBytes(creatorIdentity);
        const creatorSigningKeyPtr = allocateBytes(creatorSigningKey);
        
        const initSuccess = exports.wasm_mls_init_group(
            creatorIdentityPtr, // group_id
            creatorIdentityPtr, // creator_identity  
            creatorSigningKeyPtr, // creator_signing_key
            statePtr,
            stateLenPtr
        );
        
        if (!initSuccess) {
            throw new Error('Failed to create MLS group');
        }
        
        const stateLen = new Uint32Array(exports.memory.buffer, stateLenPtr, 1)[0];
        const groupState = readBytes(statePtr, stateLen);
        console.log('✅ MLS group created, state size:', stateLen);
        
        // Step 2: Generate exporter secret from group state (like both encryption and decryption should do)
        console.log('\n2. Generating exporter secret from group state...');
        const statePtr2 = allocateBytes(groupState);
        const secretPtr = exports.wasm_alloc(32);
        
        const secretSuccess = exports.wasm_nip_ee_generate_exporter_secret(
            statePtr2,
            groupState.length,
            secretPtr
        );
        
        if (!secretSuccess) {
            throw new Error('Failed to generate exporter secret');
        }
        
        const exporterSecret = readBytes(secretPtr, 32);
        console.log('✅ Exporter secret:', Array.from(exporterSecret.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join(' '));
        
        // Step 3: Encrypt message (like MessageComposer does)
        console.log('\n3. Encrypting message...');
        const message = "Hello from visualizer test!";
        const messageBytes = new TextEncoder().encode(message);
        
        const groupId = new Uint8Array(32);
        crypto.getRandomValues(groupId);
        
        const signature = new Uint8Array(64);
        crypto.getRandomValues(signature);
        
        const groupIdPtr = allocateBytes(groupId);
        const messagePtr = allocateBytes(messageBytes);
        const signaturePtr = allocateBytes(signature);
        const exporterSecretPtr1 = allocateBytes(exporterSecret); // Same secret
        
        const maxEncryptedSize = 4096;
        const encryptedPtr = exports.wasm_alloc(maxEncryptedSize);
        const encryptedLenPtr = exports.wasm_alloc_u32(1);
        new Uint32Array(exports.memory.buffer, encryptedLenPtr, 1)[0] = maxEncryptedSize;
        
        const encryptSuccess = exports.wasm_nip_ee_create_encrypted_group_message(
            groupIdPtr,
            1n, // epoch (should match group epoch)
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
            throw new Error('Encryption failed');
        }
        
        const encryptedLen = new Uint32Array(exports.memory.buffer, encryptedLenPtr, 1)[0];
        const encryptedData = readBytes(encryptedPtr, encryptedLen);
        console.log('✅ Encrypted message, length:', encryptedLen);
        console.log('   Preview:', Array.from(encryptedData.slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join(' '));
        
        // Step 4: Decrypt message using SAME exporter secret generation method
        console.log('\n4. Decrypting message with same exporter secret...');
        
        // Generate exporter secret again (simulating what decryption does)
        const statePtr3 = allocateBytes(groupState); // Same group state
        const secretPtr2 = exports.wasm_alloc(32);
        
        const secretSuccess2 = exports.wasm_nip_ee_generate_exporter_secret(
            statePtr3,
            groupState.length,
            secretPtr2
        );
        
        if (!secretSuccess2) {
            throw new Error('Failed to generate exporter secret for decryption');
        }
        
        const exporterSecret2 = readBytes(secretPtr2, 32);
        console.log('✅ Decryption exporter secret:', Array.from(exporterSecret2.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join(' '));
        
        // Verify secrets match
        const secretsMatch = exporterSecret.every((byte, index) => byte === exporterSecret2[index]);
        console.log('✅ Exporter secrets match:', secretsMatch);
        
        if (!secretsMatch) {
            throw new Error('Exporter secrets do not match between encryption and decryption!');
        }
        
        // Decrypt
        const encryptedPtr2 = allocateBytes(encryptedData);
        const exporterSecretPtr2 = allocateBytes(exporterSecret2);
        
        const maxDecryptedSize = 4096;
        const decryptedPtr = exports.wasm_alloc(maxDecryptedSize);
        const decryptedLenPtr = exports.wasm_alloc_u32(1);
        new Uint32Array(exports.memory.buffer, decryptedLenPtr, 1)[0] = maxDecryptedSize;
        
        const decryptSuccess = exports.wasm_nip_ee_decrypt_group_message(
            encryptedPtr2,
            encryptedData.length,
            exporterSecretPtr2,
            decryptedPtr,
            decryptedLenPtr
        );
        
        if (!decryptSuccess) {
            throw new Error('Decryption failed');
        }
        
        const decryptedLen = new Uint32Array(exports.memory.buffer, decryptedLenPtr, 1)[0];
        const decryptedData = readBytes(decryptedPtr, decryptedLen);
        const decryptedMessage = new TextDecoder().decode(decryptedData);
        
        console.log('✅ Decrypted message length:', decryptedLen);
        console.log('✅ Decrypted message:', decryptedMessage);
        
        // Verify round trip
        if (decryptedMessage === message) {
            console.log('\n🎉 VISUALIZER SCENARIO TEST PASSED!');
            console.log('   ✅ Same exporter secret generated for encryption and decryption');
            console.log('   ✅ Message encrypted and decrypted successfully');
            console.log('   ✅ Round trip successful');
        } else {
            console.log('\n❌ VISUALIZER SCENARIO TEST FAILED!');
            console.log('   Expected:', message);
            console.log('   Got:', decryptedMessage);
        }
        
    } catch (error) {
        console.error('\n❌ VISUALIZER SCENARIO TEST FAILED!');
        console.error('Error:', error);
    }
}