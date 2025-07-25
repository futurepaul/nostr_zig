import { readFileSync } from 'fs';
import { resolve } from 'path';

// Test vectors from external NIP-EE implementations (from keypackage_vectors.jsonl)
const EXTERNAL_KEYPACKAGE = "00010001208ee582bffdbab7ae4d1f4797df5a8bb93c5d28b94c88c3cf5f8bde5c40e079df20ee02802fc23ac37e7c99dc29a88bce3c8330b959e5e950b2e3cd5b6e825e9962201b19bb43636f57b1e7b0f73e2fa29b3fd85e88d013b2dd7b0e36e9c1187bbeb01404339616635316266306162326666333465373863643263363561626165376335613731376231383739646133313662396136653139343764626635656337373530000200010020ff0001203a0ec7b92ee61ccc30ab87b7a3f8c73c6c2fb1c5f99e673971cbec529cf01e860040bbed685f6bf21a26b99c3a50df1bb64e31b5dc5a38b23dd87cc1ee4f8f8e088bdf926f7e08dc94c2a6e0ba8ba8797c46fa3fb926fc85d9b079c07c0e7e602";

async function testKeyPackageInterop() {
  console.log('🧪 Testing KeyPackage Interoperability...\n');
  
  // Load WASM module
  const wasmPath = resolve(__dirname, '../visualizer/src/nostr_mls.wasm');
  const wasmBuffer = readFileSync(wasmPath);

  let exports: any;
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
      getCurrentTimestamp: () => BigInt(Date.now()),
    },
  };

  const module = await WebAssembly.instantiate(wasmBuffer, imports);
  exports = module.instance.exports;

  // Initialize WASM
  if (exports.wasm_init) {
    exports.wasm_init();
  }
  
  console.log('📦 External KeyPackage Test Vector:');
  console.log(`   Length: ${EXTERNAL_KEYPACKAGE.length} chars (${EXTERNAL_KEYPACKAGE.length/2} bytes)`);
  console.log(`   First 64 chars: ${EXTERNAL_KEYPACKAGE.substring(0, 64)}...`);
  console.log('');
  
  // Create our own KeyPackage for comparison
  const privateKey = new Uint8Array(32);
  crypto.getRandomValues(privateKey);
  
  const publicKeyPtr = exports.wasm_alloc(32);
  const privateKeyPtr = exports.wasm_alloc(32);
  
  new Uint8Array(exports.memory.buffer, privateKeyPtr, 32).set(privateKey);
  
  const success = exports.wasm_get_public_key_from_private(privateKeyPtr, publicKeyPtr);
  if (!success) {
    console.error('❌ Failed to derive public key');
    return;
  }
  
  const publicKey = new Uint8Array(exports.memory.buffer, publicKeyPtr, 32);
  const pubkeyHex = Array.from(publicKey).map(b => b.toString(16).padStart(2, '0')).join('');
  
  // Create our KeyPackage
  const identityBytes = new TextEncoder().encode(pubkeyHex);
  const identityPtr = exports.wasm_alloc(identityBytes.length);
  new Uint8Array(exports.memory.buffer, identityPtr, identityBytes.length).set(identityBytes);
  
  const maxHexSize = 2048;
  const hexOutPtr = exports.wasm_alloc(maxHexSize);
  const hexLenPtr = exports.wasm_alloc_u32(1);
  new Uint32Array(exports.memory.buffer, hexLenPtr, 1)[0] = maxHexSize;
  
  console.log('🔨 Creating our TLS-compliant KeyPackage...');
  const hexSuccess = exports.wasm_create_keypackage_hex(
    privateKeyPtr,
    identityPtr,
    identityBytes.length,
    hexOutPtr,
    hexLenPtr
  );
  
  if (!hexSuccess) {
    console.error('❌ Failed to create our KeyPackage');
    return;
  }
  
  const actualHexLen = new Uint32Array(exports.memory.buffer, hexLenPtr, 1)[0];
  const ourKeyPackage = new TextDecoder().decode(
    new Uint8Array(exports.memory.buffer, hexOutPtr, actualHexLen)
  );
  
  console.log(`✅ Created our KeyPackage: ${ourKeyPackage.length} chars (${ourKeyPackage.length/2} bytes)`);
  console.log(`   First 64 chars: ${ourKeyPackage.substring(0, 64)}...`);
  console.log('');
  
  // Compare structures
  console.log('📊 Structure Comparison:');
  
  function parseKeyPackageHeader(hex: string) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    
    return {
      protocolVersion: (bytes[0] << 8) | bytes[1],
      cipherSuite: (bytes[2] << 8) | bytes[3],
      initKeyLen: bytes[4],
      structurePreview: hex.substring(0, 20) + '...'
    };
  }
  
  const externalHeader = parseKeyPackageHeader(EXTERNAL_KEYPACKAGE);
  const ourHeader = parseKeyPackageHeader(ourKeyPackage);
  
  console.log('External KeyPackage:');
  console.log(`   Protocol: 0x${externalHeader.protocolVersion.toString(16).padStart(4, '0')}`);
  console.log(`   Cipher: 0x${externalHeader.cipherSuite.toString(16).padStart(4, '0')}`);
  console.log(`   Init Key Len: ${externalHeader.initKeyLen}`);
  console.log(`   Structure: ${externalHeader.structurePreview}`);
  console.log('');
  
  console.log('Our KeyPackage:');
  console.log(`   Protocol: 0x${ourHeader.protocolVersion.toString(16).padStart(4, '0')}`);
  console.log(`   Cipher: 0x${ourHeader.cipherSuite.toString(16).padStart(4, '0')}`);
  console.log(`   Init Key Len: ${ourHeader.initKeyLen}`);
  console.log(`   Structure: ${ourHeader.structurePreview}`);
  console.log('');
  
  // Check compatibility
  console.log('✅ Compatibility Check:');
  console.log(`   Protocol Match: ${externalHeader.protocolVersion === ourHeader.protocolVersion ? '✅' : '❌'}`);
  console.log(`   Cipher Match: ${externalHeader.cipherSuite === ourHeader.cipherSuite ? '✅' : '❌'}`);
  console.log(`   Init Key Len Match: ${externalHeader.initKeyLen === ourHeader.initKeyLen ? '✅' : '❌'}`);
  
  // Cleanup
  exports.wasm_free(privateKeyPtr, 32);
  exports.wasm_free(publicKeyPtr, 32);
  exports.wasm_free(identityPtr, identityBytes.length);
  exports.wasm_free(hexOutPtr, maxHexSize);
  exports.wasm_free_u32(hexLenPtr, 1);
  
  console.log('\n🎉 Interoperability test completed!');
}

testKeyPackageInterop().catch(console.error);