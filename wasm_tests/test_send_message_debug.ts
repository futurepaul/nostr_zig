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
            console.log('Generated random bytes:', len);
        },
        wasm_log_error: (strPtr: number, len: number) => {
            const bytes = new Uint8Array(exports.memory.buffer, strPtr, len);
            const message = new TextDecoder().decode(bytes);
            console.error('🔴 WASM error:', message);
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

async function testSendMessage() {
    console.log('\n📤 Testing wasm_send_message with debugging');
    
    // Step 1: Create identity
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
    
    // Step 2: Create group
    console.log('\n🏠 Creating group...');
    const maxGroupStateSize = 4096;
    const groupStatePtr = exports.wasm_alloc(maxGroupStateSize);
    const groupStateLenPtr = exports.wasm_alloc_u32(1);
    new Uint32Array(exports.memory.buffer, groupStateLenPtr, 1)[0] = maxGroupStateSize;
    
    const groupSuccess = exports.wasm_create_group(
        privateKeyPtr,
        publicKeyPtr,
        groupStatePtr,
        groupStateLenPtr
    );
    
    if (!groupSuccess) {
        console.log('❌ Failed to create group');
        exports.wasm_free(privateKeyPtr, 32);
        exports.wasm_free(publicKeyPtr, 32);
        exports.wasm_free(groupStatePtr, maxGroupStateSize);
        exports.wasm_free_u32(groupStateLenPtr, 1);
        return;
    }
    
    const groupStateLen = new Uint32Array(exports.memory.buffer, groupStateLenPtr, 1)[0];
    const groupState = new Uint8Array(exports.memory.buffer, groupStatePtr, groupStateLen).slice();
    console.log('✅ Created group, state length:', groupStateLen);
    
    // Step 3: Send message
    console.log('\n💬 Sending message...');
    const message = 'Hello from debug test!';
    const messageBytes = new TextEncoder().encode(message);
    const messagePtr = exports.wasm_alloc(messageBytes.length);
    new Uint8Array(exports.memory.buffer, messagePtr, messageBytes.length).set(messageBytes);
    
    const maxCiphertextSize = 4096;
    const ciphertextPtr = exports.wasm_alloc(maxCiphertextSize);
    const ciphertextLenPtr = exports.wasm_alloc_u32(1);
    new Uint32Array(exports.memory.buffer, ciphertextLenPtr, 1)[0] = maxCiphertextSize;
    
    // Copy group state to new location (in case function modifies it)
    const groupStateCopyPtr = exports.wasm_alloc(groupState.length);
    new Uint8Array(exports.memory.buffer, groupStateCopyPtr, groupState.length).set(groupState);
    
    console.log('Calling wasm_send_message with:');
    console.log('- group_state_len:', groupState.length);
    console.log('- message_len:', messageBytes.length);
    console.log('- max output size:', maxCiphertextSize);
    
    const sendSuccess = exports.wasm_send_message(
        groupStateCopyPtr,
        groupState.length,
        privateKeyPtr,
        messagePtr,
        messageBytes.length,
        ciphertextPtr,
        ciphertextLenPtr
    );
    
    const actualCiphertextLen = new Uint32Array(exports.memory.buffer, ciphertextLenPtr, 1)[0];
    
    if (!sendSuccess) {
        console.log('❌ wasm_send_message failed');
        console.log('Actual ciphertext length returned:', actualCiphertextLen);
    } else {
        const ciphertext = new Uint8Array(exports.memory.buffer, ciphertextPtr, actualCiphertextLen).slice();
        const ciphertextBase64 = new TextDecoder().decode(ciphertext);
        console.log('✅ Message sent successfully!');
        console.log('Ciphertext length:', actualCiphertextLen);
        console.log('Ciphertext (base64):', ciphertextBase64.substring(0, 50) + '...');
    }
    
    // Clean up
    exports.wasm_free(privateKeyPtr, 32);
    exports.wasm_free(publicKeyPtr, 32);
    exports.wasm_free(groupStatePtr, maxGroupStateSize);
    exports.wasm_free_u32(groupStateLenPtr, 1);
    exports.wasm_free(messagePtr, messageBytes.length);
    exports.wasm_free(ciphertextPtr, maxCiphertextSize);
    exports.wasm_free_u32(ciphertextLenPtr, 1);
    exports.wasm_free(groupStateCopyPtr, groupState.length);
}

// Run test
async function runDebugTest() {
    console.log('🧪 Testing wasm_send_message with debugging\n');
    
    await testSendMessage();
    
    console.log('\n✅ Debug test completed!');
}

runDebugTest();