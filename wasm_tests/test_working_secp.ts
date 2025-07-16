import { readFileSync } from "fs";
import { resolve } from "path";

// Load WASM file
const wasmPath = resolve(__dirname, "../visualizer/src/nostr_mls.wasm");
const wasmBuffer = readFileSync(wasmPath);

function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function testWorkingSecp() {
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
    
    console.log("✅ WASM module loaded!");
    
    // Get the static context value (it's a WebAssembly.Global)
    const noPrecompGlobal = wasm.secp256k1_context_no_precomp as WebAssembly.Global;
    const contextPtr = noPrecompGlobal.value;
    console.log(`\n📍 Static context pointer: ${contextPtr}`);
    
    // Test 1: Verify a private key
    console.log("\n🔑 Test 1: Verify private key...");
    const privKeyPtr = wasm.wasm_alloc(32);
    
    // Generate random private key
    const privKeyBytes = new Uint8Array(wasmMemory.buffer, privKeyPtr, 32);
    crypto.getRandomValues(privKeyBytes);
    
    // Make sure it's not all zeros or all FFs
    privKeyBytes[0] = Math.max(1, Math.min(0xFE, privKeyBytes[0]));
    
    console.log(`  Private key: ${bytesToHex(privKeyBytes)}`);
    
    const verifyResult = wasm.secp256k1_ec_seckey_verify(contextPtr, privKeyPtr);
    console.log(`  Verify result: ${verifyResult}`);
    
    if (verifyResult === 1) {
        console.log("✅ Private key is valid!");
        
        // Test 2: Create public key
        console.log("\n🔑 Test 2: Create public key...");
        const pubKeyPtr = wasm.wasm_alloc(64); // secp256k1_pubkey is 64 bytes
        
        const createResult = wasm.secp256k1_ec_pubkey_create(contextPtr, pubKeyPtr, privKeyPtr);
        console.log(`  Create result: ${createResult}`);
        
        if (createResult === 1) {
            console.log("✅ Public key created!");
            
            // Test 3: Serialize public key (compressed)
            console.log("\n🔑 Test 3: Serialize public key...");
            const serializedPtr = wasm.wasm_alloc(33); // Compressed pubkey is 33 bytes
            const lenPtr = wasm.wasm_alloc(4); // size_t on wasm32 is 4 bytes
            
            // Set initial length (use DataView for unaligned access)
            const lenView = new DataView(wasmMemory.buffer, lenPtr, 4);
            lenView.setUint32(0, 33, true); // little-endian
            
            const SECP256K1_EC_COMPRESSED = 0x0102;
            const serializeResult = wasm.secp256k1_ec_pubkey_serialize(
                contextPtr, 
                serializedPtr, 
                lenPtr, 
                pubKeyPtr, 
                SECP256K1_EC_COMPRESSED
            );
            
            if (serializeResult === 1) {
                const actualLen = lenView.getUint32(0, true);
                const serializedBytes = new Uint8Array(wasmMemory.buffer, serializedPtr, actualLen);
                console.log(`  Serialized public key (${actualLen} bytes): ${bytesToHex(serializedBytes)}`);
                console.log("✅ Public key serialized!");
                
                // Test 4: Create x-only pubkey for Schnorr/Nostr
                console.log("\n🔑 Test 4: Create x-only public key...");
                
                // First create a keypair
                const keypairPtr = wasm.wasm_alloc(96); // secp256k1_keypair is 96 bytes
                const keypairResult = wasm.secp256k1_keypair_create(contextPtr, keypairPtr, privKeyPtr);
                
                if (keypairResult === 1) {
                    console.log("✅ Keypair created!");
                    
                    // Extract x-only pubkey
                    const xonlyPtr = wasm.wasm_alloc(64); // secp256k1_xonly_pubkey
                    const parityPtr = wasm.wasm_alloc(4); // int for parity
                    
                    const xonlyResult = wasm.secp256k1_keypair_xonly_pub(
                        contextPtr,
                        xonlyPtr,
                        parityPtr,
                        keypairPtr
                    );
                    
                    if (xonlyResult === 1) {
                        console.log("✅ X-only pubkey extracted!");
                        
                        // Serialize x-only pubkey (always 32 bytes)
                        const xonlySerializedPtr = wasm.wasm_alloc(32);
                        const xonlySerializeResult = wasm.secp256k1_xonly_pubkey_serialize(
                            contextPtr,
                            xonlySerializedPtr,
                            xonlyPtr
                        );
                        
                        if (xonlySerializeResult === 1) {
                            const xonlyBytes = new Uint8Array(wasmMemory.buffer, xonlySerializedPtr, 32);
                            console.log(`  X-only public key: ${bytesToHex(xonlyBytes)}`);
                            console.log("✅ X-only public key serialized!");
                            
                            // This is the format Nostr uses!
                            console.log("\n🎉 SUCCESS! We have working secp256k1 in WASM!");
                            console.log("   Private key: " + bytesToHex(privKeyBytes));
                            console.log("   Public key:  " + bytesToHex(xonlyBytes));
                        }
                        
                        wasm.wasm_free(xonlySerializedPtr, 32);
                    }
                    
                    wasm.wasm_free(xonlyPtr, 64);
                    wasm.wasm_free(parityPtr, 4);
                }
                
                wasm.wasm_free(keypairPtr, 96);
            }
            
            wasm.wasm_free(serializedPtr, 33);
            wasm.wasm_free(lenPtr, 4);
        }
        
        wasm.wasm_free(pubKeyPtr, 64);
    } else {
        console.log("❌ Private key is invalid!");
    }
    
    wasm.wasm_free(privKeyPtr, 32);
}

// Run the test
testWorkingSecp().catch(console.error);