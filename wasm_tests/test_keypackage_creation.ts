import { readFileSync } from 'fs';
import { resolve } from 'path';

async function testKeyPackageCreation() {
  console.log('🧪 Testing Real KeyPackage Creation...\n');
  
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
  
  // Test the new KeyPackage creation functions
  if (!exports.wasm_create_keypackage || !exports.wasm_create_keypackage_hex) {
    console.error('❌ KeyPackage creation functions not found in WASM exports');
    return;
  }
  
  console.log('✅ Found KeyPackage creation functions\n');
  
  // Create test identity
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
  
  console.log('📝 Test Identity:');
  console.log('   Public Key:', pubkeyHex);
  console.log('');
  
  // Test hex KeyPackage creation
  const identityBytes = new TextEncoder().encode(pubkeyHex);
  const identityPtr = exports.wasm_alloc(identityBytes.length);
  new Uint8Array(exports.memory.buffer, identityPtr, identityBytes.length).set(identityBytes);
  
  const maxHexSize = 2048;
  const hexOutPtr = exports.wasm_alloc(maxHexSize);
  const hexLenPtr = exports.wasm_alloc_u32(1);
  new Uint32Array(exports.memory.buffer, hexLenPtr, 1)[0] = maxHexSize;
  
  console.log('🔨 Creating TLS-compliant KeyPackage...');
  const hexSuccess = exports.wasm_create_keypackage_hex(
    privateKeyPtr,
    identityPtr,
    identityBytes.length,
    hexOutPtr,
    hexLenPtr
  );
  
  if (!hexSuccess) {
    const neededLen = new Uint32Array(exports.memory.buffer, hexLenPtr, 1)[0];
    console.error(`❌ Failed to create hex KeyPackage. Needed ${neededLen} bytes`);
    return;
  }
  
  const actualHexLen = new Uint32Array(exports.memory.buffer, hexLenPtr, 1)[0];
  const hexKeyPackage = new TextDecoder().decode(
    new Uint8Array(exports.memory.buffer, hexOutPtr, actualHexLen)
  );
  
  console.log(`✅ Created hex KeyPackage: ${actualHexLen} chars (${actualHexLen/2} bytes)`);
  console.log(`   First 64 chars: ${hexKeyPackage.substring(0, 64)}...`);
  console.log('');
  
  // Parse the hex to check structure
  const keyPackageBytes = new Uint8Array(hexKeyPackage.length / 2);
  for (let i = 0; i < hexKeyPackage.length; i += 2) {
    keyPackageBytes[i / 2] = parseInt(hexKeyPackage.substr(i, 2), 16);
  }
  
  // Check basic TLS structure
  console.log('🔍 Analyzing KeyPackage structure:');
  
  // Protocol version (should be 0x0001)
  const protocolVersion = (keyPackageBytes[0] << 8) | keyPackageBytes[1];
  console.log(`   Protocol Version: 0x${protocolVersion.toString(16).padStart(4, '0')} ${protocolVersion === 0x0001 ? '✅' : '❌'}`);
  
  // Cipher suite (should be 0x0001)
  const cipherSuite = (keyPackageBytes[2] << 8) | keyPackageBytes[3];
  console.log(`   Cipher Suite: 0x${cipherSuite.toString(16).padStart(4, '0')} ${cipherSuite === 0x0001 ? '✅' : '❌'}`);
  
  // Init key length (should be 32 with single byte prefix)
  const initKeyLen = keyPackageBytes[4];
  console.log(`   Init Key Length: ${initKeyLen} bytes ${initKeyLen === 32 ? '✅' : '❌'}`);
  
  console.log('');
  console.log('📋 NIP-EE Event Format:');
  console.log('```json');
  console.log(JSON.stringify({
    kind: 443,
    tags: [
      ['mls_protocol_version', '1.0'],
      ['mls_ciphersuite', '1'],
      ['mls_extensions', 'LastResort,RequiredCapabilities'],
      ['relays', 'ws://localhost:10547']
    ],
    content: hexKeyPackage.substring(0, 100) + '...',
  }, null, 2));
  console.log('```');
  
  // Cleanup
  exports.wasm_free(privateKeyPtr, 32);
  exports.wasm_free(publicKeyPtr, 32);
  exports.wasm_free(identityPtr, identityBytes.length);
  exports.wasm_free(hexOutPtr, maxHexSize);
  exports.wasm_free_u32(hexLenPtr, 1);
  
  console.log('\n🎉 KeyPackage creation test completed!');
}

testKeyPackageCreation().catch(console.error);