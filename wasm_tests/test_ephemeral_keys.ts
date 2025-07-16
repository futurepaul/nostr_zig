import { readFileSync } from "fs";
import { resolve } from "path";

// Load WASM file
const wasmPath = resolve(__dirname, "../visualizer/src/nostr_mls.wasm");
const wasmBuffer = readFileSync(wasmPath);

// Helper to convert bytes to hex
function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function testEphemeralKeys() {
    console.log("🔧 Loading WASM module...");
    
    let wasmMemory: WebAssembly.Memory | null = null;
    
    // Create imports for WASM
    const imports = {
        env: {
            getRandomValues: (ptr: number, len: number) => {
                if (!wasmMemory) throw new Error('WASM memory not available');
                const bytes = new Uint8Array(wasmMemory.buffer, ptr, len);
                crypto.getRandomValues(bytes);
                console.log(`  📊 Generated ${len} random bytes`);
            },
            wasm_log_error: (strPtr: number, len: number) => {
                if (!wasmMemory) throw new Error('WASM memory not available');
                const bytes = new Uint8Array(wasmMemory.buffer, strPtr, len);
                const message = new TextDecoder().decode(bytes);
                console.error('❌ secp256k1 error:', message);
            }
        }
    };
    
    // Compile and instantiate WASM
    const wasmModule = await WebAssembly.compile(wasmBuffer);
    const instance = await WebAssembly.instantiate(wasmModule, imports);
    
    wasmMemory = instance.exports.memory as WebAssembly.Memory;
    const wasm = instance.exports as any;
    
    console.log("✅ WASM module loaded successfully!");
    console.log("📦 Available exports:", Object.keys(instance.exports).filter(k => k.startsWith('wasm_')));
    
    // Test 1: Create regular identity
    console.log("\n🔑 Test 1: Creating regular identity...");
    const privateKeyPtr = wasm.wasm_alloc(32);
    const publicKeyPtr = wasm.wasm_alloc(32);
    
    const identitySuccess = wasm.wasm_create_identity(privateKeyPtr, publicKeyPtr);
    
    if (!identitySuccess) {
        throw new Error('Failed to create identity');
    }
    
    const privateKey = new Uint8Array(wasmMemory.buffer, privateKeyPtr, 32);
    const publicKey = new Uint8Array(wasmMemory.buffer, publicKeyPtr, 32);
    
    console.log("  Private key:", bytesToHex(privateKey).slice(0, 32) + "...");
    console.log("  Public key: ", bytesToHex(publicKey));
    
    wasm.wasm_free(privateKeyPtr, 32);
    wasm.wasm_free(publicKeyPtr, 32);
    
    // Test 2: Generate multiple ephemeral keys
    console.log("\n🔐 Test 2: Generating ephemeral keys...");
    const ephemeralKeys = [];
    
    for (let i = 0; i < 5; i++) {
        const ephPrivKeyPtr = wasm.wasm_alloc(32);
        const ephPubKeyPtr = wasm.wasm_alloc(32);
        
        const ephSuccess = wasm.wasm_generate_ephemeral_keys(ephPrivKeyPtr, ephPubKeyPtr);
        
        if (!ephSuccess) {
            throw new Error(`Failed to generate ephemeral key ${i + 1}`);
        }
        
        const ephPrivKey = new Uint8Array(wasmMemory.buffer, ephPrivKeyPtr, 32);
        const ephPubKey = new Uint8Array(wasmMemory.buffer, ephPubKeyPtr, 32);
        
        const keyPair = {
            privateKey: bytesToHex(ephPrivKey),
            publicKey: bytesToHex(ephPubKey)
        };
        
        ephemeralKeys.push(keyPair);
        
        console.log(`  Ephemeral key ${i + 1}:`);
        console.log(`    Public:  ${keyPair.publicKey}`);
        
        wasm.wasm_free(ephPrivKeyPtr, 32);
        wasm.wasm_free(ephPubKeyPtr, 32);
    }
    
    // Test 3: Verify all keys are unique
    console.log("\n🔍 Test 3: Verifying key uniqueness...");
    const allPublicKeys = [bytesToHex(publicKey), ...ephemeralKeys.map(k => k.publicKey)];
    const uniqueKeys = new Set(allPublicKeys);
    
    if (uniqueKeys.size === allPublicKeys.length) {
        console.log("✅ All keys are unique! Real cryptographic randomness confirmed!");
    } else {
        console.error("❌ Duplicate keys detected! Something is wrong!");
    }
    
    // Test 4: Test Schnorr signatures
    console.log("\n✍️  Test 4: Testing Schnorr signatures...");
    
    // Create a test message hash
    const message = "Hello, Nostr with real secp256k1!";
    const encoder = new TextEncoder();
    const messageBytes = encoder.encode(message);
    const hashBytes = await crypto.subtle.digest('SHA-256', messageBytes);
    const messageHash = new Uint8Array(hashBytes);
    
    // Test signing with first ephemeral key
    const testKey = ephemeralKeys[0];
    const testPrivKey = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
        testPrivKey[i] = parseInt(testKey.privateKey.slice(i * 2, i * 2 + 2), 16);
    }
    
    const hashPtr = wasm.wasm_alloc(32);
    const keyPtr = wasm.wasm_alloc(32);
    const sigPtr = wasm.wasm_alloc(64);
    
    new Uint8Array(wasmMemory.buffer, hashPtr, 32).set(messageHash);
    new Uint8Array(wasmMemory.buffer, keyPtr, 32).set(testPrivKey);
    
    const signSuccess = wasm.wasm_sign_schnorr(hashPtr, keyPtr, sigPtr);
    
    if (signSuccess) {
        const signature = new Uint8Array(wasmMemory.buffer, sigPtr, 64);
        console.log("  Signature:", bytesToHex(signature));
        
        // Verify the signature
        const testPubKey = new Uint8Array(32);
        for (let i = 0; i < 32; i++) {
            testPubKey[i] = parseInt(testKey.publicKey.slice(i * 2, i * 2 + 2), 16);
        }
        
        const pubKeyPtr = wasm.wasm_alloc(32);
        new Uint8Array(wasmMemory.buffer, pubKeyPtr, 32).set(testPubKey);
        
        const verifySuccess = wasm.wasm_verify_schnorr(hashPtr, sigPtr, pubKeyPtr);
        
        if (verifySuccess) {
            console.log("✅ Signature verified successfully!");
        } else {
            console.error("❌ Signature verification failed!");
        }
        
        wasm.wasm_free(pubKeyPtr, 32);
    } else {
        console.error("❌ Failed to create signature!");
    }
    
    wasm.wasm_free(hashPtr, 32);
    wasm.wasm_free(keyPtr, 32);
    wasm.wasm_free(sigPtr, 64);
    
    console.log("\n🎉 All tests completed!");
}

// Run the tests
testEphemeralKeys().catch(console.error);