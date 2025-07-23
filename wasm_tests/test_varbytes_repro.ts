import { readFileSync } from 'fs';
import { resolve } from 'path';

// Minimal VarBytes memory corruption reproduction test
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
            console.error('🔴 WASM:', message);
        },
        getCurrentTimestamp: () => BigInt(Math.floor(Date.now() / 1000))
    }
};

const wasmModule = new WebAssembly.Module(wasmBuffer);
const wasmInstance = new WebAssembly.Instance(wasmModule, imports);
const exports = wasmInstance.exports as any;

if (exports.wasm_init) {
    exports.wasm_init();
}

console.log('🧪 Testing VarBytes Memory Corruption Reproduction');
console.log('=================================================');

// Helper to allocate aligned memory for u32 pointers
function allocateAlignedU32(): { alignedPtr: number, view: Uint32Array } {
    const size = 4;
    const alignment = 4;
    const rawPtr = exports.wasm_alloc(size + alignment);
    const alignedPtr = exports.wasm_align_ptr(rawPtr, alignment);
    const view = new Uint32Array(exports.memory.buffer, alignedPtr, 1);
    return { alignedPtr, view };
}

// Test if we can reproduce the VarBytes corruption with just KeyPackageBundle creation
async function testVarBytesCorruption() {
    console.log('\n🎯 Testing VarBytes corruption reproduction');
    
    try {
        // Create basic inputs
        const privateKeyPtr = exports.wasm_alloc(32);
        const publicKeyPtr = exports.wasm_alloc(32);
        
        // Generate a keypair
        const success = exports.wasm_create_identity(privateKeyPtr, publicKeyPtr);
        if (!success) {
            console.error('❌ Failed to create identity');
            return false;
        }
        
        // Read the keys to verify they're valid
        const privateKey = new Uint8Array(exports.memory.buffer, privateKeyPtr, 32);
        const publicKey = new Uint8Array(exports.memory.buffer, publicKeyPtr, 32);
        
        console.log('Private key (first 8 bytes):', Array.from(privateKey.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join(''));
        console.log('Public key (first 8 bytes):', Array.from(publicKey.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join(''));
        
        // Now test the MLS KeyPackageBundle creation step that's failing
        console.log('\n🔧 Testing MLS KeyPackageBundle creation...');
        
        // Create hex string version of public key for BasicCredential
        const pubkeyHex = Array.from(publicKey).map(b => b.toString(16).padStart(2, '0')).join('');
        console.log('Public key hex length:', pubkeyHex.length);
        
        // Try to reproduce the issue by calling just the problematic steps
        const groupIdPtr = exports.wasm_alloc(32);
        const groupId = new Uint8Array(exports.memory.buffer, groupIdPtr, 32);
        crypto.getRandomValues(groupId);
        
        // Test the exact same pattern as wasm_mls_init_group
        const maxStateSize = 10240;
        const outStatePtr = exports.wasm_alloc(maxStateSize);
        const outStateLenAlloc = allocateAlignedU32();
        outStateLenAlloc.view[0] = maxStateSize;
        
        console.log('Calling wasm_mls_init_group with valid inputs...');
        const mlsSuccess = exports.wasm_mls_init_group(
            groupIdPtr,
            publicKeyPtr,  // creator_identity_pubkey
            privateKeyPtr, // creator_signing_key
            outStatePtr,
            outStateLenAlloc.alignedPtr
        );
        
        if (mlsSuccess) {
            console.log('✅ MLS group creation succeeded!');
            const stateLen = outStateLenAlloc.view[0];
            console.log('State length:', stateLen);
        } else {
            console.log('❌ MLS group creation failed (expected - this is the bug we\'re reproducing)');
        }
        
        // Clean up
        exports.wasm_free(privateKeyPtr, 32);
        exports.wasm_free(publicKeyPtr, 32);
        exports.wasm_free(groupIdPtr, 32);
        exports.wasm_free(outStatePtr, maxStateSize);
        
        return mlsSuccess;
        
    } catch (error) {
        console.error('❌ Test error:', error);
        return false;
    }
}

// Test with minimal MLS test function
async function testMinimalMLS() {
    console.log('\n🎯 Testing minimal MLS test function');
    
    if (typeof exports.wasm_mls_test === 'function') {
        console.log('Calling wasm_mls_test()...');
        const result = exports.wasm_mls_test();
        console.log('Result:', result);
        return result;
    } else {
        console.log('wasm_mls_test function not available');
        return false;
    }
}

// Test with minimal VarBytes reproduction
async function testMinimalVarBytes() {
    console.log('\n🎯 Testing minimal VarBytes reproduction');
    
    if (typeof exports.wasm_test_varbytes_minimal === 'function') {
        console.log('Calling wasm_test_varbytes_minimal()...');
        const result = exports.wasm_test_varbytes_minimal();
        console.log('Result:', result);
        return result;
    } else {
        console.log('wasm_test_varbytes_minimal function not available');
        return false;
    }
}

// Run tests
async function runTests() {
    console.log('Available exports:', Object.keys(exports).filter(name => name.includes('test') || name.includes('mls')));
    
    const test1 = await testMinimalMLS();
    const test2 = await testMinimalVarBytes(); 
    const test3 = await testVarBytesCorruption();
    
    console.log('\n📋 Results:');
    console.log('Minimal MLS test:', test1 ? '✅ PASS' : '❌ FAIL');
    console.log('Minimal VarBytes test:', test2 ? '✅ PASS' : '❌ FAIL');
    console.log('Full corruption test:', test3 ? '✅ UNEXPECTED PASS' : '❌ FAIL (expected)');
    
    if (!test1 && !test2 && !test3) {
        console.log('\n🎯 Successfully reproduced the VarBytes memory corruption issue!');
        console.log('All tests fail, confirming the issue exists in WASM but not in native.');
    } else if (test2) {
        console.log('\n🎉 VarBytes are working correctly in the isolated test!');
        console.log('The issue might be specific to the full MLS integration.');
    }
}

runTests().catch(console.error);