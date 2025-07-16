import { readFileSync } from 'fs';

const wasmBuffer = readFileSync('../zig-out/wasm/nip_ee_wasm.wasm');
const wasmModule = new WebAssembly.Module(wasmBuffer);

const memory = new WebAssembly.Memory({ initial: 256, maximum: 256 });

const imports = {
    env: {
        memory: memory,
        __linear_memory: memory,
        __indirect_function_table: new WebAssembly.Table({ initial: 0, element: "anyfunc" }),
        printhex: (ptr: number, len: number) => {
            const bytes = new Uint8Array(memory.buffer, ptr, len);
            console.log('printhex:', Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(''));
        },
        printint: (val: number) => {
            console.log('printint:', val);
        },
        log_message: (ptr: number, len: number) => {
            const bytes = new Uint8Array(memory.buffer, ptr, len);
            const message = new TextDecoder().decode(bytes);
            console.log('log:', message);
        }
    }
};

const wasmInstance = new WebAssembly.Instance(wasmModule, imports);
const exports = wasmInstance.exports as any;

// Test byte alignment fix
function ensureAlignment(ptr: number, alignment: number): number {
    const mask = alignment - 1;
    return (ptr + mask) & ~mask;
}

async function testCreateGroup() {
    console.log('Testing wasm_create_group with proper alignment...\n');

    try {
        // 1. First create an identity for the group creator
        const privKeyPtr = exports.wasm_alloc(32);
        const pubKeyPtr = exports.wasm_alloc(32);
        
        console.log('Creating identity...');
        const identityResult = exports.wasm_create_identity(privKeyPtr, pubKeyPtr);
        
        if (!identityResult) {
            console.error('Failed to create identity');
            return;
        }

        const privKey = new Uint8Array(memory.buffer, privKeyPtr, 32);
        const pubKey = new Uint8Array(memory.buffer, pubKeyPtr, 32);
        
        console.log('✅ Identity created');
        console.log('   Private key:', Array.from(privKey).map(b => b.toString(16).padStart(2, '0')).join(''));
        console.log('   Public key:', Array.from(pubKey).map(b => b.toString(16).padStart(2, '0')).join(''));

        // 2. Test create_group with proper alignment
        const maxGroupSize = 4096;
        
        // Allocate output buffer and length pointer with proper alignment
        const outPtr = exports.wasm_alloc(maxGroupSize);
        const outLenPtr = exports.wasm_alloc(8); // Allocate more than needed to ensure we can align
        
        // Ensure the length pointer is 4-byte aligned
        const alignedOutLenPtr = ensureAlignment(outLenPtr, 4);
        
        console.log('\nMemory allocation:');
        console.log('   Output buffer ptr:', outPtr);
        console.log('   Output length ptr (raw):', outLenPtr);
        console.log('   Output length ptr (aligned):', alignedOutLenPtr);
        console.log('   Alignment offset:', alignedOutLenPtr - outLenPtr);
        
        // Initialize the length
        const lengthView = new Uint32Array(memory.buffer, alignedOutLenPtr, 1);
        lengthView[0] = maxGroupSize;
        
        console.log('\nCalling wasm_create_group...');
        const success = exports.wasm_create_group(
            privKeyPtr,
            pubKeyPtr,
            outPtr,
            alignedOutLenPtr
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
        exports.wasm_free(outLenPtr, 8);
        
    } catch (err) {
        console.error('Error:', err);
        if (err instanceof Error) {
            console.error('Stack:', err.stack);
        }
    }
}

// Also test that our WASM exports the alignment helper if needed
if (exports.wasm_align_ptr) {
    console.log('WASM exports alignment helper');
    const testPtr = 13; // Intentionally misaligned
    const aligned = exports.wasm_align_ptr(testPtr, 4);
    console.log(`Alignment test: ${testPtr} -> ${aligned} (should be 16)\n`);
}

testCreateGroup();