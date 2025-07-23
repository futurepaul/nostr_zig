import { readFileSync } from 'fs';
import { resolve } from 'path';

console.log('🧪 Testing Core WASM Functions...\n');

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
    runTests();
});

function runTests() {
    console.log('Available exports:', Object.keys(exports).filter(key => key.startsWith('wasm_')));
    
    // Test 1: Memory functions
    console.log('\n1. Testing memory allocation...');
    const testPtr = exports.wasm_alloc(64);
    if (testPtr !== 0) {
        console.log('✅ Memory allocation successful');
        exports.wasm_free(testPtr, 64);
        console.log('✅ Memory deallocation successful');
    } else {
        console.log('❌ Memory allocation failed');
    }
    
    // Test 2: Version
    console.log('\n2. Testing version...');
    const version = exports.wasm_get_version();
    console.log(`✅ WASM version: ${version}`);
    
    // Test 3: Identity creation
    console.log('\n3. Testing identity creation...');
    const privateKeyPtr = exports.wasm_alloc(32);
    const publicKeyPtr = exports.wasm_alloc(32);
    
    if (exports.wasm_create_identity(privateKeyPtr, publicKeyPtr)) {
        const privateKey = new Uint8Array(exports.memory.buffer, privateKeyPtr, 32);
        const publicKey = new Uint8Array(exports.memory.buffer, publicKeyPtr, 32);
        
        console.log(`✅ Private key: ${Array.from(privateKey.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join('')}...`);
        console.log(`✅ Public key: ${Array.from(publicKey.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join('')}...`);
    } else {
        console.log('❌ Identity creation failed');
    }
    
    // Test 4: SHA256
    console.log('\n4. Testing SHA256...');
    const testData = new TextEncoder().encode('Hello WASM!');
    const dataPtr = exports.wasm_alloc(testData.length);
    new Uint8Array(exports.memory.buffer, dataPtr, testData.length).set(testData);
    
    const hashPtr = exports.wasm_alloc(32);
    if (exports.wasm_sha256(dataPtr, testData.length, hashPtr)) {
        const hash = new Uint8Array(exports.memory.buffer, hashPtr, 32);
        console.log(`✅ SHA256: ${Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join('')}`);
    } else {
        console.log('❌ SHA256 failed');
    }
    
    // Test 5: MLS functions
    console.log('\n5. Testing MLS functions...');
    const mlsExports = Object.keys(exports).filter(key => key.startsWith('wasm_mls_'));
    console.log(`✅ Available MLS functions: ${mlsExports.join(', ')}`);
    
    // Test 6: NIP-EE functions
    console.log('\n6. Testing NIP-EE functions...');
    const nipEeExports = Object.keys(exports).filter(key => key.includes('nip_ee'));
    console.log(`✅ Available NIP-EE functions: ${nipEeExports.join(', ')}`);
    
    // Clean up
    exports.wasm_free(privateKeyPtr, 32);
    exports.wasm_free(publicKeyPtr, 32);
    exports.wasm_free(dataPtr, testData.length);
    exports.wasm_free(hashPtr, 32);
    
    console.log('\n🎉 Core function tests completed!');
}