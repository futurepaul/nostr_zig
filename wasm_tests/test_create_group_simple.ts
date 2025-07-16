import { readFileSync } from 'fs';
import { resolve } from 'path';

const wasmPath = resolve(__dirname, '../visualizer/src/nostr_mls.wasm');
const wasmBuffer = readFileSync(wasmPath);
const wasmModule = new WebAssembly.Module(wasmBuffer);

const memory = new WebAssembly.Memory({ initial: 256, maximum: 256 });

let callCount = 0;

const imports = {
    env: {
        memory: memory,
        __linear_memory: memory,
        __indirect_function_table: new WebAssembly.Table({ initial: 0, element: "anyfunc" }),
        getRandomValues: (ptr: number, len: number) => {
            callCount++;
            if (callCount > 10) {
                console.error('Too many random calls, stopping test');
                throw new Error('Infinite loop detected');
            }
            
            const bytes = new Uint8Array(memory.buffer, ptr, len);
            // Use Web Crypto API (available in Bun)
            crypto.getRandomValues(bytes);
            console.log(`Random call ${callCount}: ${len} bytes`);
        },
        wasm_log_error: (strPtr: number, len: number) => {
            const bytes = new Uint8Array(memory.buffer, strPtr, len);
            const message = new TextDecoder().decode(bytes);
            console.error('secp256k1 error:', message);
        }
    }
};

const wasmInstance = new WebAssembly.Instance(wasmModule, imports);
const exports = wasmInstance.exports as any;

console.log('Available exports:', Object.keys(exports).filter(key => key.startsWith('wasm_')));

// Test byte alignment fix
function ensureAlignment(ptr: number, alignment: number): number {
    const mask = alignment - 1;
    return (ptr + mask) & ~mask;
}

async function testCreateGroupSimple() {
    console.log('Testing wasm_create_group directly...\n');

    try {
        // Generate a real keypair using wasm_create_identity
        console.log('Generating real secp256k1 keypair...');
        const privKeyPtr = exports.wasm_alloc(32);
        const pubKeyPtr = exports.wasm_alloc(32);
        
        if (!privKeyPtr || !pubKeyPtr) {
            console.error('Failed to allocate memory for keys');
            return;
        }
        
        // Use wasm_create_identity to generate a proper keypair
        const identityResult = exports.wasm_create_identity(privKeyPtr, pubKeyPtr);
        
        if (!identityResult) {
            console.error('Failed to create identity');
            return;
        }

        const privKey = new Uint8Array(memory.buffer, privKeyPtr, 32);
        const pubKey = new Uint8Array(memory.buffer, pubKeyPtr, 32);

        console.log('Using real keys:');
        console.log('   Private key:', Array.from(privKey).map(b => b.toString(16).padStart(2, '0')).join(''));
        console.log('   Public key:', Array.from(pubKey).map(b => b.toString(16).padStart(2, '0')).join(''));

        // Test create_group with proper alignment
        const maxGroupSize = 4096;
        
        // Allocate output buffer
        const outPtr = exports.wasm_alloc(maxGroupSize);
        
        // Use aligned allocation for u32 if available
        let outLenPtr;
        if (exports.wasm_alloc_u32) {
            outLenPtr = exports.wasm_alloc_u32(1); // Allocate 1 u32
            console.log('Using wasm_alloc_u32 for aligned allocation');
        } else {
            // Fallback to manual alignment
            const rawPtr = exports.wasm_alloc(8);
            outLenPtr = exports.wasm_align_ptr ? 
                exports.wasm_align_ptr(rawPtr, 4) : 
                ensureAlignment(rawPtr, 4);
            console.log('Using manual alignment');
        }
        
        console.log('\nMemory allocation:');
        console.log('   Output buffer ptr:', outPtr);
        console.log('   Output length ptr:', outLenPtr);
        
        // Initialize the length
        const lengthView = new Uint32Array(memory.buffer, outLenPtr, 1);
        lengthView[0] = maxGroupSize;
        
        console.log('\nCalling wasm_create_group...');
        const success = exports.wasm_create_group(
            privKeyPtr,
            pubKeyPtr,
            outPtr,
            outLenPtr
        );
        
        if (success) {
            const actualLength = lengthView[0];
            console.log('✅ Group created successfully!');
            console.log('   Group data length:', actualLength);
            
            // Show first few bytes of group data
            const groupData = new Uint8Array(memory.buffer, outPtr, Math.min(actualLength, 64));
            console.log('   Group data (first 64 bytes):', 
                Array.from(groupData).map(b => b.toString(16).padStart(2, '0')).join(' ')
            );
        } else {
            console.error('❌ Failed to create group');
        }
        
        // Clean up
        exports.wasm_free(privKeyPtr, 32);
        exports.wasm_free(pubKeyPtr, 32);
        exports.wasm_free(outPtr, maxGroupSize);
        if (exports.wasm_alloc_u32 && exports.wasm_free_u32) {
            exports.wasm_free_u32(outLenPtr, 1);
        } else {
            exports.wasm_free(outLenPtr, 8);
        }
        
    } catch (err) {
        console.error('Error:', err);
        if (err instanceof Error) {
            console.error('Stack:', err.stack);
        }
    }
}

testCreateGroupSimple();