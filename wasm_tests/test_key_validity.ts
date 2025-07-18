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

async function testKeyGeneration() {
    console.log('\n🔑 Testing key generation consistency\n');
    
    let successCount = 0;
    let failureCount = 0;
    const iterations = 100;
    
    for (let i = 0; i < iterations; i++) {
        try {
            // Test 1: Generate ephemeral keys
            const ephPrivPtr = exports.wasm_alloc(32);
            const ephPubPtr = exports.wasm_alloc(32);
            
            const ephSuccess = exports.wasm_generate_ephemeral_keys(ephPrivPtr, ephPubPtr);
            if (!ephSuccess) {
                console.log(`❌ Iteration ${i}: Failed to generate ephemeral keys`);
                failureCount++;
                continue;
            }
            
            const ephPrivKey = new Uint8Array(exports.memory.buffer, ephPrivPtr, 32).slice();
            const ephPubKey = new Uint8Array(exports.memory.buffer, ephPubPtr, 32).slice();
            
            // Test 2: Validate the private key
            const validationPtr = exports.wasm_alloc(32);
            const validationSuccess = exports.wasm_generate_valid_secp256k1_key(ephPrivPtr, validationPtr);
            
            if (!validationSuccess) {
                console.log(`❌ Iteration ${i}: Failed to validate ephemeral private key`);
                console.log(`   Private key: ${bytesToHex(ephPrivKey)}`);
                failureCount++;
            } else {
                // Check if the key was modified
                const validatedKey = new Uint8Array(exports.memory.buffer, validationPtr, 32);
                const wasModified = !ephPrivKey.every((byte, idx) => byte === validatedKey[idx]);
                
                if (wasModified) {
                    console.log(`⚠️  Iteration ${i}: Key was modified during validation`);
                    console.log(`   Original:  ${bytesToHex(ephPrivKey)}`);
                    console.log(`   Modified:  ${bytesToHex(validatedKey)}`);
                }
                
                // Test 3: Use the key for NIP-44 encryption
                const testMessage = "Test message";
                const messageBytes = new TextEncoder().encode(testMessage);
                const messagePtr = exports.wasm_alloc(messageBytes.length);
                new Uint8Array(exports.memory.buffer, messagePtr, messageBytes.length).set(messageBytes);
                
                const ciphertextPtr = exports.wasm_alloc(1024);
                const ciphertextLenPtr = exports.wasm_alloc_u32(1);
                new Uint32Array(exports.memory.buffer, ciphertextLenPtr, 1)[0] = 1024;
                
                const encryptSuccess = exports.wasm_nip44_encrypt(
                    validationPtr, // Use the validated key
                    messagePtr,
                    messageBytes.length,
                    ciphertextPtr,
                    ciphertextLenPtr
                );
                
                if (!encryptSuccess) {
                    console.log(`❌ Iteration ${i}: NIP-44 encryption failed with validated key`);
                    failureCount++;
                } else {
                    successCount++;
                }
                
                exports.wasm_free(validationPtr, 32);
                exports.wasm_free(messagePtr, messageBytes.length);
                exports.wasm_free(ciphertextPtr, 1024);
                exports.wasm_free_u32(ciphertextLenPtr, 1);
            }
            
            exports.wasm_free(ephPrivPtr, 32);
            exports.wasm_free(ephPubPtr, 32);
            
        } catch (error) {
            console.log(`❌ Iteration ${i}: Exception - ${error}`);
            failureCount++;
        }
    }
    
    console.log(`\n📊 Results after ${iterations} iterations:`);
    console.log(`✅ Success: ${successCount} (${(successCount/iterations*100).toFixed(1)}%)`);
    console.log(`❌ Failure: ${failureCount} (${(failureCount/iterations*100).toFixed(1)}%)`);
}

async function testExporterSecretGeneration() {
    console.log('\n\n🔐 Testing exporter secret generation\n');
    
    // Create a dummy group state
    const groupState = new Uint8Array(137);
    crypto.getRandomValues(groupState);
    
    let successCount = 0;
    let failureCount = 0;
    const iterations = 100;
    
    for (let i = 0; i < iterations; i++) {
        try {
            const statePtr = exports.wasm_alloc(groupState.length);
            new Uint8Array(exports.memory.buffer, statePtr, groupState.length).set(groupState);
            
            const secretPtr = exports.wasm_alloc(32);
            
            // Generate exporter secret
            const genSuccess = exports.wasm_nip_ee_generate_exporter_secret(
                statePtr,
                groupState.length,
                secretPtr
            );
            
            if (!genSuccess) {
                console.log(`❌ Iteration ${i}: Failed to generate exporter secret`);
                failureCount++;
                continue;
            }
            
            const exporterSecret = new Uint8Array(exports.memory.buffer, secretPtr, 32).slice();
            
            // Try to use it for encryption
            const testMessage = "Test";
            const messageBytes = new TextEncoder().encode(testMessage);
            const messagePtr = exports.wasm_alloc(messageBytes.length);
            new Uint8Array(exports.memory.buffer, messagePtr, messageBytes.length).set(messageBytes);
            
            const ciphertextPtr = exports.wasm_alloc(1024);
            const ciphertextLenPtr = exports.wasm_alloc_u32(1);
            new Uint32Array(exports.memory.buffer, ciphertextLenPtr, 1)[0] = 1024;
            
            const encryptSuccess = exports.wasm_nip44_encrypt(
                secretPtr,
                messagePtr,
                messageBytes.length,
                ciphertextPtr,
                ciphertextLenPtr
            );
            
            if (!encryptSuccess) {
                console.log(`❌ Iteration ${i}: NIP-44 encryption failed with exporter secret`);
                console.log(`   Secret: ${bytesToHex(exporterSecret)}`);
                failureCount++;
            } else {
                successCount++;
            }
            
            exports.wasm_free(statePtr, groupState.length);
            exports.wasm_free(secretPtr, 32);
            exports.wasm_free(messagePtr, messageBytes.length);
            exports.wasm_free(ciphertextPtr, 1024);
            exports.wasm_free_u32(ciphertextLenPtr, 1);
            
        } catch (error) {
            console.log(`❌ Iteration ${i}: Exception - ${error}`);
            failureCount++;
        }
    }
    
    console.log(`\n📊 Results after ${iterations} iterations:`);
    console.log(`✅ Success: ${successCount} (${(successCount/iterations*100).toFixed(1)}%)`);
    console.log(`❌ Failure: ${failureCount} (${(failureCount/iterations*100).toFixed(1)}%)`);
}

// Run tests
async function runAllTests() {
    console.log('🧪 Testing Key Validity Issues\n');
    
    await testKeyGeneration();
    await testExporterSecretGeneration();
    
    console.log('\n✅ Testing completed!');
}

runAllTests();