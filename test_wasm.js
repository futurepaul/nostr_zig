const fs = require('fs');
const crypto = require('crypto');

async function testWasm() {
    // Read WASM file
    const wasmBuffer = fs.readFileSync('./visualizer/src/nostr_mls.wasm');
    
    // Create imports
    let wasmMemory;
    const imports = {
        env: {
            getRandomValues: (ptr, len) => {
                console.log('getRandomValues called with ptr:', ptr, 'len:', len);
                const bytes = new Uint8Array(wasmMemory.buffer, ptr, len);
                crypto.randomFillSync(bytes);
                console.log('Generated random bytes:', Array.from(bytes).slice(0, 8).map(b => b.toString(16).padStart(2, '0')).join(' '));
            },
            wasm_log_error: (strPtr, len) => {
                const bytes = new Uint8Array(wasmMemory.buffer, strPtr, len);
                const message = new TextDecoder().decode(bytes);
                console.error('secp256k1 error:', message);
            }
        }
    };
    
    // Instantiate WASM
    const wasmModule = await WebAssembly.compile(wasmBuffer);
    
    // Check exports
    const moduleExports = WebAssembly.Module.exports(wasmModule);
    console.log('Module exports:', moduleExports.map(e => `${e.name} (${e.kind})`));
    
    const wasmInstance = await WebAssembly.instantiate(wasmModule, imports);
    
    // Get memory reference
    wasmMemory = wasmInstance.exports.memory;
    const exports = wasmInstance.exports;
    
    // Initialize WASM
    console.log('Available exports:', Object.keys(exports));
    
    if (exports.wasm_init) {
        exports.wasm_init();
        console.log('WASM initialized');
    }
    
    // Test the random function directly
    if (exports.wasm_test_random) {
        console.log('Testing random function...');
        exports.wasm_test_random();
        console.log('Random function called');
    } else {
        console.log('wasm_test_random not found in exports');
    }
    
    // Test identity creation
    const privateKeyPtr = exports.wasm_alloc(32);
    const publicKeyPtr = exports.wasm_alloc(32);
    const privateKeyPtr2 = exports.wasm_alloc(32);
    const publicKeyPtr2 = exports.wasm_alloc(32);
    
    if (!privateKeyPtr || !publicKeyPtr || !privateKeyPtr2 || !publicKeyPtr2) {
        console.error('Failed to allocate memory');
        return;
    }
    
    console.log('About to call wasm_create_identity with privateKeyPtr:', privateKeyPtr, 'publicKeyPtr:', publicKeyPtr);
    
    // Check memory before call
    const privateKeyBefore = new Uint8Array(wasmMemory.buffer, privateKeyPtr, 32);
    const publicKeyBefore = new Uint8Array(wasmMemory.buffer, publicKeyPtr, 32);
    console.log('Private key before call:', Array.from(privateKeyBefore).slice(0, 8).map(b => b.toString(16).padStart(2, '0')).join(''));
    console.log('Public key before call:', Array.from(publicKeyBefore).slice(0, 8).map(b => b.toString(16).padStart(2, '0')).join(''));
    
    const success = exports.wasm_create_identity(privateKeyPtr, publicKeyPtr);
    console.log('wasm_create_identity returned:', success);
    
    if (success) {
        const privateKey = new Uint8Array(wasmMemory.buffer, privateKeyPtr, 32);
        const publicKey = new Uint8Array(wasmMemory.buffer, publicKeyPtr, 32);
        
        console.log('Identity created successfully!');
        console.log('Private key after call:', Array.from(privateKey).map(b => b.toString(16).padStart(2, '0')).join(''));
        console.log('Public key after call:', Array.from(publicKey).map(b => b.toString(16).padStart(2, '0')).join(''));
        
        // Test multiple identities to ensure randomness
        console.log('\nCreating second identity to verify randomness...');
        const success2 = exports.wasm_create_identity(privateKeyPtr2, publicKeyPtr2);
        if (success2) {
            const privateKey2 = new Uint8Array(wasmMemory.buffer, privateKeyPtr2, 32);
            const publicKey2 = new Uint8Array(wasmMemory.buffer, publicKeyPtr2, 32);
            console.log('Private key 2:', Array.from(privateKey2).map(b => b.toString(16).padStart(2, '0')).join(''));
            console.log('Public key 2:', Array.from(publicKey2).map(b => b.toString(16).padStart(2, '0')).join(''));
            
            // Check they're different
            const keysAreDifferent = !privateKey.every((v, i) => v === privateKey2[i]);
            console.log('\nKeys are different:', keysAreDifferent ? 'YES ✓' : 'NO ✗');
        }
    } else {
        console.error('Failed to create identity');
    }
    
    exports.wasm_free(privateKeyPtr, 32);
    exports.wasm_free(publicKeyPtr, 32);
}

testWasm().catch(console.error);