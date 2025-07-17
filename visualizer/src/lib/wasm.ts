export interface WasmExports {
  memory: WebAssembly.Memory;
  wasm_init: () => void;
  wasm_add: (a: number, b: number) => number;
  wasm_alloc: (size: number) => number;
  wasm_alloc_u32: (count: number) => number;
  wasm_free: (ptr: number, size: number) => void;
  wasm_free_u32: (ptr: number, count: number) => void;
  wasm_align_ptr: (ptr: number, alignment: number) => number;
  bytes_to_hex: (bytes: number, bytesLen: number, outHex: number, outHexLen: number) => boolean;
  wasm_create_identity: (outPrivateKey: number, outPublicKey: number) => boolean;
  wasm_get_public_key_from_private: (privateKey: number, outPublicKey: number) => boolean;
  wasm_generate_ephemeral_keys: (outPrivateKey: number, outPublicKey: number) => boolean;
  wasm_generate_mls_signing_keys: (outPrivateKey: number, outPublicKey: number) => boolean;
  wasm_sign_schnorr: (messageHash: number, privateKey: number, outSignature: number) => boolean;
  wasm_verify_schnorr: (messageHash: number, signature: number, publicKey: number) => boolean;
  wasm_create_key_package: (
    privateKey: number,
    outData: number,
    outLenPtr: number
  ) => boolean;
  wasm_create_group: (
    creatorPrivateKey: number,
    creatorPublicKey: number,
    outState: number,
    outStateLenPtr: number
  ) => boolean;
  wasm_generate_exporter_secret: (
    groupState: number,
    groupStateLen: number,
    outSecret: number
  ) => boolean;
  wasm_nip44_encrypt: (
    exporterSecret: number,
    plaintext: number,
    plaintextLen: number,
    outCiphertext: number,
    outLenPtr: number
  ) => boolean;
  wasm_nip44_decrypt: (
    exporterSecret: number,
    ciphertext: number,
    ciphertextLen: number,
    outPlaintext: number,
    outLenPtr: number
  ) => boolean;
  wasm_send_message: (
    groupState: number,
    groupStateLen: number,
    senderPrivateKey: number,
    message: number,
    messageLen: number,
    outCiphertext: number,
    outLenPtr: number
  ) => boolean;
  wasm_receive_message: (
    groupState: number,
    groupStateLen: number,
    receiverPrivateKey: number,
    nip44Ciphertext: number,
    nip44CiphertextLen: number,
    outPlaintext: number,
    outLenPtr: number
  ) => boolean;
  wasm_deserialize_mls_message: (
    serializedData: number,
    serializedLen: number,
    outGroupId: number,
    outEpoch: number,
    outSenderIndex: number,
    outApplicationData: number,
    outApplicationDataLen: number,
    outSignature: number,
    outSignatureLen: number
  ) => boolean;
}

class WasmWrapper {
  private instance: WebAssembly.Instance | null = null;
  private exports: WasmExports | null = null;

  async init() {
    try {
      console.log('Fetching WASM file...');
      const wasmResponse = await fetch(`/src/nostr_mls.wasm?v=${Date.now()}`);
      if (!wasmResponse.ok) {
        throw new Error(`Failed to fetch WASM: ${wasmResponse.status} ${wasmResponse.statusText}`);
      }
      
      console.log('Compiling WASM module...');
      const wasmBuffer = await wasmResponse.arrayBuffer();
      const wasmModule = await WebAssembly.compile(wasmBuffer);
      
      console.log('Instantiating WASM module...');
      
      // Create a reference that will be updated after instantiation
      let wasmMemory: WebAssembly.Memory | null = null;
      
      // Create imports for WASM including getRandomValues
      const imports = {
        env: {
          // Provide secure randomness from the browser's crypto API
          getRandomValues: (ptr: number, len: number) => {
            if (!wasmMemory) {
              throw new Error('WASM memory not available');
            }
            const bytes = new Uint8Array(wasmMemory.buffer, ptr, len);
            crypto.getRandomValues(bytes);
            console.log('Generated random bytes:', Array.from(bytes).slice(0, 8).map(b => b.toString(16).padStart(2, '0')).join(' '));
          },
          // Error logging function for secp256k1
          wasm_log_error: (strPtr: number, len: number) => {
            if (!wasmMemory) {
              throw new Error('WASM memory not available');
            }
            const bytes = new Uint8Array(wasmMemory.buffer, strPtr, len);
            const message = new TextDecoder().decode(bytes);
            console.error('secp256k1 error:', message);
          },
          // Current Unix timestamp in seconds
          getCurrentTimestamp: () => {
            return BigInt(Math.floor(Date.now() / 1000));
          }
        }
      };
      
      this.instance = await WebAssembly.instantiate(wasmModule, imports);
      
      // Now set the memory reference
      wasmMemory = (this.instance.exports as any).memory;
      
      this.exports = this.instance.exports as WasmExports;
      console.log('Available exports:', Object.keys(this.exports));
      console.log('Export details:', this.exports);
      
      // Check if wasm_init exists
      if (typeof this.exports.wasm_init === 'function') {
        this.exports.wasm_init();
        console.log('WASM initialized successfully');
      } else {
        console.warn('wasm_init is not a function, skipping initialization');
      }
    } catch (error) {
      console.error('Failed to initialize WASM:', error);
      throw error;
    }
  }

  private ensureInitialized(): WasmExports {
    if (!this.exports) {
      throw new Error('WASM not initialized. Call init() first.');
    }
    return this.exports;
  }

  private allocateString(str: string): { ptr: number; len: number } {
    const exports = this.ensureInitialized();
    const encoder = new TextEncoder();
    const bytes = encoder.encode(str);
    const ptr = exports.wasm_alloc(bytes.length);
    if (!ptr) throw new Error('Failed to allocate memory');
    new Uint8Array(exports.memory.buffer, ptr, bytes.length).set(bytes);
    return { ptr, len: bytes.length };
  }

  private readString(ptr: number, len: number): string {
    const exports = this.ensureInitialized();
    const bytes = new Uint8Array(exports.memory.buffer, ptr, len);
    return new TextDecoder().decode(bytes);
  }

  private readBytes(ptr: number, len: number): Uint8Array {
    const exports = this.ensureInitialized();
    return new Uint8Array(exports.memory.buffer, ptr, len).slice();
  }

  private allocateAlignedU32(count: number = 1): { ptr: number; alignedPtr: number; size: number } {
    const exports = this.ensureInitialized();
    
    // Try to use native aligned allocation first
    if (exports.wasm_alloc_u32 && exports.wasm_free_u32) {
      const ptr = exports.wasm_alloc_u32(count);
      return { ptr, alignedPtr: ptr, size: count * 4 };
    }
    
    // Fallback: allocate extra space and align manually
    const extraSize = count * 4 + 4; // Extra 4 bytes for alignment
    const ptr = exports.wasm_alloc(extraSize);
    const alignedPtr = (ptr + 3) & ~3; // Align to 4-byte boundary
    
    return { ptr, alignedPtr, size: extraSize };
  }

  private freeAlignedU32(allocation: { ptr: number; alignedPtr: number; size: number }, count: number = 1) {
    const exports = this.ensureInitialized();
    
    if (exports.wasm_alloc_u32 && exports.wasm_free_u32 && allocation.ptr === allocation.alignedPtr) {
      exports.wasm_free_u32(allocation.ptr, count);
    } else {
      exports.wasm_free(allocation.ptr, allocation.size);
    }
  }

  createIdentity(): { privateKey: Uint8Array; publicKey: Uint8Array } {
    const exports = this.ensureInitialized();
    const privateKeyPtr = exports.wasm_alloc(32);
    const publicKeyPtr = exports.wasm_alloc(32);
    
    if (!privateKeyPtr || !publicKeyPtr) {
      throw new Error('Failed to allocate memory for keys');
    }

    const success = exports.wasm_create_identity(privateKeyPtr, publicKeyPtr);
    if (!success) {
      exports.wasm_free(privateKeyPtr, 32);
      exports.wasm_free(publicKeyPtr, 32);
      throw new Error('Failed to create identity');
    }

    const privateKey = this.readBytes(privateKeyPtr, 32);
    const publicKey = this.readBytes(publicKeyPtr, 32);
    
    console.log('Created identity:', {
      privateKey: Array.from(privateKey).slice(0, 8).map(b => b.toString(16).padStart(2, '0')).join(' '),
      publicKey: Array.from(publicKey).map(b => b.toString(16).padStart(2, '0')).join('')
    });

    exports.wasm_free(privateKeyPtr, 32);
    exports.wasm_free(publicKeyPtr, 32);

    return { privateKey, publicKey };
  }

  generateEphemeralKeys(): { privateKey: Uint8Array; publicKey: Uint8Array } {
    const exports = this.ensureInitialized();
    const privateKeyPtr = exports.wasm_alloc(32);
    const publicKeyPtr = exports.wasm_alloc(32);
    
    if (!privateKeyPtr || !publicKeyPtr) {
      throw new Error('Failed to allocate memory for ephemeral keys');
    }

    const success = exports.wasm_generate_ephemeral_keys(privateKeyPtr, publicKeyPtr);
    if (!success) {
      exports.wasm_free(privateKeyPtr, 32);
      exports.wasm_free(publicKeyPtr, 32);
      throw new Error('Failed to generate ephemeral keys');
    }

    const privateKey = this.readBytes(privateKeyPtr, 32);
    const publicKey = this.readBytes(publicKeyPtr, 32);
    
    console.log('Generated ephemeral keys:', {
      publicKey: Array.from(publicKey).map(b => b.toString(16).padStart(2, '0')).join('')
    });

    exports.wasm_free(privateKeyPtr, 32);
    exports.wasm_free(publicKeyPtr, 32);

    return { privateKey, publicKey };
  }

  generateMLSSigningKeys(): { privateKey: Uint8Array; publicKey: Uint8Array } {
    const exports = this.ensureInitialized();
    const privateKeyPtr = exports.wasm_alloc(32);
    const publicKeyPtr = exports.wasm_alloc(32);
    
    if (!privateKeyPtr || !publicKeyPtr) {
      throw new Error('Failed to allocate memory for MLS signing keys');
    }

    const success = exports.wasm_generate_mls_signing_keys(privateKeyPtr, publicKeyPtr);
    if (!success) {
      exports.wasm_free(privateKeyPtr, 32);
      exports.wasm_free(publicKeyPtr, 32);
      throw new Error('Failed to generate MLS signing keys');
    }

    const privateKey = this.readBytes(privateKeyPtr, 32);
    const publicKey = this.readBytes(publicKeyPtr, 32);
    
    console.log('Generated MLS signing keys:', {
      publicKey: Array.from(publicKey).map(b => b.toString(16).padStart(2, '0')).join('')
    });

    exports.wasm_free(privateKeyPtr, 32);
    exports.wasm_free(publicKeyPtr, 32);

    return { privateKey, publicKey };
  }

  signSchnorr(messageHash: Uint8Array, privateKey: Uint8Array): Uint8Array {
    const exports = this.ensureInitialized();
    
    if (messageHash.length !== 32) {
      throw new Error('Message hash must be 32 bytes');
    }
    if (privateKey.length !== 32) {
      throw new Error('Private key must be 32 bytes');
    }

    const hashPtr = exports.wasm_alloc(32);
    const keyPtr = exports.wasm_alloc(32);
    const sigPtr = exports.wasm_alloc(64);
    
    if (!hashPtr || !keyPtr || !sigPtr) {
      throw new Error('Failed to allocate memory');
    }

    new Uint8Array(exports.memory.buffer, hashPtr, 32).set(messageHash);
    new Uint8Array(exports.memory.buffer, keyPtr, 32).set(privateKey);

    const success = exports.wasm_sign_schnorr(hashPtr, keyPtr, sigPtr);
    if (!success) {
      exports.wasm_free(hashPtr, 32);
      exports.wasm_free(keyPtr, 32);
      exports.wasm_free(sigPtr, 64);
      throw new Error('Failed to sign');
    }

    const signature = this.readBytes(sigPtr, 64);

    exports.wasm_free(hashPtr, 32);
    exports.wasm_free(keyPtr, 32);
    exports.wasm_free(sigPtr, 64);

    return signature;
  }

  verifySchnorr(messageHash: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean {
    const exports = this.ensureInitialized();
    
    if (messageHash.length !== 32) {
      throw new Error('Message hash must be 32 bytes');
    }
    if (signature.length !== 64) {
      throw new Error('Signature must be 64 bytes');
    }
    if (publicKey.length !== 32) {
      throw new Error('Public key must be 32 bytes');
    }

    const hashPtr = exports.wasm_alloc(32);
    const sigPtr = exports.wasm_alloc(64);
    const keyPtr = exports.wasm_alloc(32);
    
    if (!hashPtr || !sigPtr || !keyPtr) {
      throw new Error('Failed to allocate memory');
    }

    new Uint8Array(exports.memory.buffer, hashPtr, 32).set(messageHash);
    new Uint8Array(exports.memory.buffer, sigPtr, 64).set(signature);
    new Uint8Array(exports.memory.buffer, keyPtr, 32).set(publicKey);

    const valid = exports.wasm_verify_schnorr(hashPtr, sigPtr, keyPtr);

    exports.wasm_free(hashPtr, 32);
    exports.wasm_free(sigPtr, 64);
    exports.wasm_free(keyPtr, 32);

    return valid;
  }

  createKeyPackage(privateKey: Uint8Array): Uint8Array {
    const exports = this.ensureInitialized();
    
    // Allocate space for private key
    const privateKeyPtr = exports.wasm_alloc(32);
    if (!privateKeyPtr) throw new Error('Failed to allocate memory');
    new Uint8Array(exports.memory.buffer, privateKeyPtr, 32).set(privateKey);

    // Allocate space for output
    const maxSize = 1024; // Assume max key package size
    const outPtr = exports.wasm_alloc(maxSize);
    
    // Use aligned allocation for the length pointer
    const outLenPtr = exports.wasm_alloc_u32 ? 
      exports.wasm_alloc_u32(1) : 
      exports.wasm_alloc(8); // Allocate extra and align manually
    
    if (!outPtr || !outLenPtr) {
      exports.wasm_free(privateKeyPtr, 32);
      throw new Error('Failed to allocate memory');
    }

    // Set initial length using aligned pointer
    const alignedLenPtr = exports.wasm_align_ptr ? 
      exports.wasm_align_ptr(outLenPtr, 4) : 
      outLenPtr;
    new Uint32Array(exports.memory.buffer, alignedLenPtr, 1)[0] = maxSize;

    const success = exports.wasm_create_key_package(
      privateKeyPtr,
      outPtr,
      alignedLenPtr
    );

    const actualLen = new Uint32Array(exports.memory.buffer, alignedLenPtr, 1)[0];
    
    if (!success) {
      exports.wasm_free(privateKeyPtr, 32);
      exports.wasm_free(outPtr, maxSize);
      exports.wasm_free(outLenPtr, exports.wasm_alloc_u32 ? 4 : 8);
      throw new Error('Failed to create key package');
    }

    const keyPackage = this.readBytes(outPtr, actualLen);

    exports.wasm_free(privateKeyPtr, 32);
    exports.wasm_free(outPtr, maxSize);
    exports.wasm_free(outLenPtr, exports.wasm_alloc_u32 ? 4 : 8);

    return keyPackage;
  }

  createGroup(creatorPrivateKey: Uint8Array, creatorPublicKey: Uint8Array): Uint8Array {
    const exports = this.ensureInitialized();
    
    // Allocate space for keys
    const privateKeyPtr = exports.wasm_alloc(32);
    const publicKeyPtr = exports.wasm_alloc(32);
    if (!privateKeyPtr || !publicKeyPtr) throw new Error('Failed to allocate memory');
    
    new Uint8Array(exports.memory.buffer, privateKeyPtr, 32).set(creatorPrivateKey);
    new Uint8Array(exports.memory.buffer, publicKeyPtr, 32).set(creatorPublicKey);

    // Allocate space for output
    const maxSize = 4096; // Assume max state size
    const outPtr = exports.wasm_alloc(maxSize);
    
    // Use aligned allocation for the length pointer
    const outLenPtr = exports.wasm_alloc_u32 ? 
      exports.wasm_alloc_u32(1) : 
      exports.wasm_alloc(8); // Allocate extra and align manually
    
    if (!outPtr || !outLenPtr) {
      exports.wasm_free(privateKeyPtr, 32);
      exports.wasm_free(publicKeyPtr, 32);
      throw new Error('Failed to allocate memory');
    }

    // Set initial length using aligned pointer
    const alignedLenPtr = exports.wasm_align_ptr ? 
      exports.wasm_align_ptr(outLenPtr, 4) : 
      outLenPtr;
    new Uint32Array(exports.memory.buffer, alignedLenPtr, 1)[0] = maxSize;

    const success = exports.wasm_create_group(
      privateKeyPtr,
      publicKeyPtr,
      outPtr,
      alignedLenPtr
    );

    const actualLen = new Uint32Array(exports.memory.buffer, alignedLenPtr, 1)[0];
    
    if (!success) {
      exports.wasm_free(privateKeyPtr, 32);
      exports.wasm_free(publicKeyPtr, 32);
      exports.wasm_free(outPtr, maxSize);
      if (exports.wasm_alloc_u32 && exports.wasm_free_u32) {
        exports.wasm_free_u32(outLenPtr, 1);
      } else {
        exports.wasm_free(outLenPtr, 8);
      }
      throw new Error('Failed to create group');
    }

    const groupState = this.readBytes(outPtr, actualLen);

    exports.wasm_free(privateKeyPtr, 32);
    exports.wasm_free(publicKeyPtr, 32);
    exports.wasm_free(outPtr, maxSize);
    if (exports.wasm_alloc_u32 && exports.wasm_free_u32) {
      exports.wasm_free_u32(outLenPtr, 1);
    } else {
      exports.wasm_free(outLenPtr, 8);
    }

    return groupState;
  }

  generateExporterSecret(groupState: Uint8Array): Uint8Array {
    const exports = this.ensureInitialized();
    
    // Allocate space for group state
    const statePtr = exports.wasm_alloc(groupState.length);
    const secretPtr = exports.wasm_alloc(32);
    
    if (!statePtr || !secretPtr) {
      throw new Error('Failed to allocate memory');
    }

    new Uint8Array(exports.memory.buffer, statePtr, groupState.length).set(groupState);

    const success = exports.wasm_generate_exporter_secret(
      statePtr,
      groupState.length,
      secretPtr
    );

    if (!success) {
      exports.wasm_free(statePtr, groupState.length);
      exports.wasm_free(secretPtr, 32);
      throw new Error('Failed to generate exporter secret');
    }

    const secret = this.readBytes(secretPtr, 32);

    exports.wasm_free(statePtr, groupState.length);
    exports.wasm_free(secretPtr, 32);

    return secret;
  }

  nip44Encrypt(exporterSecret: Uint8Array, plaintext: string): Uint8Array {
    const exports = this.ensureInitialized();
    
    // Allocate space for inputs
    const secretPtr = exports.wasm_alloc(32);
    const plaintextData = this.allocateString(plaintext);
    
    if (!secretPtr) {
      throw new Error('Failed to allocate memory');
    }

    new Uint8Array(exports.memory.buffer, secretPtr, 32).set(exporterSecret);

    // Allocate space for output
    // NIP-44 overhead: 1 (version) + 32 (nonce) + 32 (hmac) + padding + base64 encoding (~33% increase)
    const maxSize = Math.max(1024, (plaintextData.len * 2 + 65) * 2); // Much more generous buffer
    const outPtr = exports.wasm_alloc(maxSize);
    const lenAllocation = this.allocateAlignedU32(1);
    
    if (!outPtr || !lenAllocation.ptr) {
      exports.wasm_free(secretPtr, 32);
      exports.wasm_free(plaintextData.ptr, plaintextData.len);
      throw new Error('Failed to allocate memory');
    }

    // Set initial length
    new Uint32Array(exports.memory.buffer, lenAllocation.alignedPtr, 1)[0] = maxSize;
    
    const success = exports.wasm_nip44_encrypt(
      secretPtr,
      plaintextData.ptr,
      plaintextData.len,
      outPtr,
      lenAllocation.alignedPtr
    );

    const actualLen = new Uint32Array(exports.memory.buffer, lenAllocation.alignedPtr, 1)[0];
    
    if (!success) {
      exports.wasm_free(secretPtr, 32);
      exports.wasm_free(plaintextData.ptr, plaintextData.len);
      exports.wasm_free(outPtr, maxSize);
      this.freeAlignedU32(lenAllocation);
      throw new Error('Failed to encrypt with NIP-44');
    }

    const ciphertext = this.readBytes(outPtr, actualLen);

    exports.wasm_free(secretPtr, 32);
    exports.wasm_free(plaintextData.ptr, plaintextData.len);
    exports.wasm_free(outPtr, maxSize);
    this.freeAlignedU32(lenAllocation);

    return ciphertext;
  }

  nip44Decrypt(exporterSecret: Uint8Array, ciphertext: Uint8Array): string {
    const exports = this.ensureInitialized();
    
    console.log('[WASM] nip44Decrypt called with:', {
      secretLength: exporterSecret.length,
      ciphertextLength: ciphertext.length,
      secretPreview: Array.from(exporterSecret.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join(' '),
      ciphertextPreview: Array.from(ciphertext.slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join(' ')
    });
    
    // Allocate space for inputs
    const secretPtr = exports.wasm_alloc(32);
    const ciphertextPtr = exports.wasm_alloc(ciphertext.length);
    
    if (!secretPtr || !ciphertextPtr) {
      throw new Error('Failed to allocate memory');
    }

    new Uint8Array(exports.memory.buffer, secretPtr, 32).set(exporterSecret);
    new Uint8Array(exports.memory.buffer, ciphertextPtr, ciphertext.length).set(ciphertext);

    // Allocate space for output
    const maxSize = ciphertext.length * 2; // Generous buffer
    const outPtr = exports.wasm_alloc(maxSize);
    const lenAllocation = this.allocateAlignedU32(1);
    
    if (!outPtr || !lenAllocation.ptr) {
      exports.wasm_free(secretPtr, 32);
      exports.wasm_free(ciphertextPtr, ciphertext.length);
      throw new Error('Failed to allocate memory');
    }

    // Set initial length
    new Uint32Array(exports.memory.buffer, lenAllocation.alignedPtr, 1)[0] = maxSize;
    
    console.log('[WASM] Calling wasm_nip44_decrypt...');
    const success = exports.wasm_nip44_decrypt(
      secretPtr,
      ciphertextPtr,
      ciphertext.length,
      outPtr,
      lenAllocation.alignedPtr
    );

    const actualLen = new Uint32Array(exports.memory.buffer, lenAllocation.alignedPtr, 1)[0];
    console.log('[WASM] wasm_nip44_decrypt returned:', { success, actualLen });
    
    if (!success) {
      exports.wasm_free(secretPtr, 32);
      exports.wasm_free(ciphertextPtr, ciphertext.length);
      exports.wasm_free(outPtr, maxSize);
      this.freeAlignedU32(lenAllocation);
      throw new Error('Failed to decrypt with NIP-44');
    }

    const plaintext = this.readString(outPtr, actualLen);

    exports.wasm_free(secretPtr, 32);
    exports.wasm_free(ciphertextPtr, ciphertext.length);
    exports.wasm_free(outPtr, maxSize);
    this.freeAlignedU32(lenAllocation);

    return plaintext;
  }

  nip44DecryptBytes(exporterSecret: Uint8Array, ciphertext: Uint8Array): Uint8Array {
    const exports = this.ensureInitialized();
    
    console.log('[WASM] nip44DecryptBytes called with:', {
      secretLength: exporterSecret.length,
      ciphertextLength: ciphertext.length,
      secretPreview: Array.from(exporterSecret.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join(' '),
      ciphertextPreview: Array.from(ciphertext.slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join(' ')
    });
    
    // Allocate space for inputs
    const secretPtr = exports.wasm_alloc(32);
    const ciphertextPtr = exports.wasm_alloc(ciphertext.length);
    
    if (!secretPtr || !ciphertextPtr) {
      throw new Error('Failed to allocate memory');
    }

    new Uint8Array(exports.memory.buffer, secretPtr, 32).set(exporterSecret);
    new Uint8Array(exports.memory.buffer, ciphertextPtr, ciphertext.length).set(ciphertext);

    // Allocate space for output
    const maxSize = ciphertext.length * 2; // Generous buffer
    const outPtr = exports.wasm_alloc(maxSize);
    const lenAllocation = this.allocateAlignedU32(1);
    
    if (!outPtr || !lenAllocation.ptr) {
      exports.wasm_free(secretPtr, 32);
      exports.wasm_free(ciphertextPtr, ciphertext.length);
      throw new Error('Failed to allocate memory');
    }

    // Set initial length
    new Uint32Array(exports.memory.buffer, lenAllocation.alignedPtr, 1)[0] = maxSize;
    
    console.log('[WASM] Calling wasm_nip44_decrypt...');
    const success = exports.wasm_nip44_decrypt(
      secretPtr,
      ciphertextPtr,
      ciphertext.length,
      outPtr,
      lenAllocation.alignedPtr
    );

    const actualLen = new Uint32Array(exports.memory.buffer, lenAllocation.alignedPtr, 1)[0];
    console.log('[WASM] wasm_nip44_decrypt returned:', { success, actualLen });
    
    if (!success) {
      exports.wasm_free(secretPtr, 32);
      exports.wasm_free(ciphertextPtr, ciphertext.length);
      exports.wasm_free(outPtr, maxSize);
      this.freeAlignedU32(lenAllocation);
      throw new Error('Failed to decrypt with NIP-44');
    }

    const decryptedBytes = this.readBytes(outPtr, actualLen);

    exports.wasm_free(secretPtr, 32);
    exports.wasm_free(ciphertextPtr, ciphertext.length);
    exports.wasm_free(outPtr, maxSize);
    this.freeAlignedU32(lenAllocation);

    return decryptedBytes;
  }

  sendMessage(
    groupState: Uint8Array,
    senderPrivateKey: Uint8Array,
    message: string
  ): Uint8Array {
    const exports = this.ensureInitialized();
    
    console.log('[WASM] sendMessage called with:', {
      groupStateLength: groupState.length,
      privateKeyLength: senderPrivateKey.length,
      messageLength: message.length,
      message: message.substring(0, 50) + (message.length > 50 ? '...' : '')
    });
    
    // Allocate space for inputs
    const statePtr = exports.wasm_alloc(groupState.length);
    const privateKeyPtr = exports.wasm_alloc(32);
    const messageData = this.allocateString(message);
    
    if (!statePtr || !privateKeyPtr) {
      throw new Error('Failed to allocate memory for sendMessage inputs');
    }

    new Uint8Array(exports.memory.buffer, statePtr, groupState.length).set(groupState);
    new Uint8Array(exports.memory.buffer, privateKeyPtr, 32).set(senderPrivateKey);

    // Allocate space for output
    const maxSize = 4096;
    const outPtr = exports.wasm_alloc(maxSize);
    const lenAllocation = this.allocateAlignedU32(1);
    
    if (!outPtr || !lenAllocation.ptr) {
      exports.wasm_free(statePtr, groupState.length);
      exports.wasm_free(privateKeyPtr, 32);
      exports.wasm_free(messageData.ptr, messageData.len);
      throw new Error('Failed to allocate memory for sendMessage output');
    }

    // Set initial length
    new Uint32Array(exports.memory.buffer, lenAllocation.alignedPtr, 1)[0] = maxSize;
    
    console.log('[WASM] Calling wasm_send_message...');
    const success = exports.wasm_send_message(
      statePtr,
      groupState.length,
      privateKeyPtr,
      messageData.ptr,
      messageData.len,
      outPtr,
      lenAllocation.alignedPtr
    );

    const actualLen = new Uint32Array(exports.memory.buffer, lenAllocation.alignedPtr, 1)[0];
    console.log('[WASM] wasm_send_message returned:', { success, actualLen });
    
    if (!success) {
      exports.wasm_free(statePtr, groupState.length);
      exports.wasm_free(privateKeyPtr, 32);
      exports.wasm_free(messageData.ptr, messageData.len);
      exports.wasm_free(outPtr, maxSize);
      this.freeAlignedU32(lenAllocation);
      throw new Error(`Failed to send message (wasm_send_message returned false, actualLen: ${actualLen})`);
    }

    const ciphertext = this.readBytes(outPtr, actualLen);

    exports.wasm_free(statePtr, groupState.length);
    exports.wasm_free(privateKeyPtr, 32);
    exports.wasm_free(messageData.ptr, messageData.len);
    exports.wasm_free(outPtr, maxSize);
    this.freeAlignedU32(lenAllocation);

    return ciphertext;
  }

  receiveMessage(
    groupState: Uint8Array,
    receiverPrivateKey: Uint8Array,
    nip44Ciphertext: string // Base64 encoded
  ): string {
    const exports = this.ensureInitialized();
    
    console.log('[WASM] receiveMessage called with:', {
      groupStateLength: groupState.length,
      privateKeyLength: receiverPrivateKey.length,
      ciphertextLength: nip44Ciphertext.length,
      ciphertextPreview: nip44Ciphertext.substring(0, 50) + '...'
    });
    
    // Allocate space for inputs
    const statePtr = exports.wasm_alloc(groupState.length);
    const privateKeyPtr = exports.wasm_alloc(32);
    const ciphertextData = this.allocateString(nip44Ciphertext);
    
    if (!statePtr || !privateKeyPtr) {
      throw new Error('Failed to allocate memory for receiveMessage inputs');
    }

    new Uint8Array(exports.memory.buffer, statePtr, groupState.length).set(groupState);
    new Uint8Array(exports.memory.buffer, privateKeyPtr, 32).set(receiverPrivateKey);

    // Allocate space for output
    const maxSize = 4096;
    const outPtr = exports.wasm_alloc(maxSize);
    const lenAllocation = this.allocateAlignedU32(1);
    
    if (!outPtr || !lenAllocation.ptr) {
      exports.wasm_free(statePtr, groupState.length);
      exports.wasm_free(privateKeyPtr, 32);
      exports.wasm_free(ciphertextData.ptr, ciphertextData.len);
      throw new Error('Failed to allocate memory for receiveMessage output');
    }

    // Set initial length
    new Uint32Array(exports.memory.buffer, lenAllocation.alignedPtr, 1)[0] = maxSize;
    
    console.log('[WASM] Calling wasm_receive_message...');
    const success = exports.wasm_receive_message(
      statePtr,
      groupState.length,
      privateKeyPtr,
      ciphertextData.ptr,
      ciphertextData.len,
      outPtr,
      lenAllocation.alignedPtr
    );

    const actualLen = new Uint32Array(exports.memory.buffer, lenAllocation.alignedPtr, 1)[0];
    console.log('[WASM] wasm_receive_message returned:', { success, actualLen });
    
    if (!success) {
      exports.wasm_free(statePtr, groupState.length);
      exports.wasm_free(privateKeyPtr, 32);
      exports.wasm_free(ciphertextData.ptr, ciphertextData.len);
      exports.wasm_free(outPtr, maxSize);
      this.freeAlignedU32(lenAllocation);
      throw new Error(`Failed to receive message (wasm_receive_message returned false, actualLen: ${actualLen})`);
    }

    const plaintext = this.readString(outPtr, actualLen);

    exports.wasm_free(statePtr, groupState.length);
    exports.wasm_free(privateKeyPtr, 32);
    exports.wasm_free(ciphertextData.ptr, ciphertextData.len);
    exports.wasm_free(outPtr, maxSize);
    this.freeAlignedU32(lenAllocation);

    return plaintext;
  }

  deserializeMLSMessage(serializedData: Uint8Array): {
    groupId: Uint8Array;
    epoch: bigint;
    senderIndex: number;
    applicationData: string;
    signature: Uint8Array;
  } {
    const exports = this.ensureInitialized();
    
    console.log('[WASM] deserializeMLSMessage called with:', {
      dataLength: serializedData.length,
      dataPreview: Array.from(serializedData.slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join(' ')
    });
    
    // Check if the WASM function exists
    if (typeof exports.wasm_deserialize_mls_message !== 'function') {
      throw new Error('wasm_deserialize_mls_message function not available');
    }
    
    // Allocate space for input
    const dataPtr = exports.wasm_alloc(serializedData.length);
    if (!dataPtr) {
      throw new Error('Failed to allocate memory for serialized data');
    }
    console.log('[WASM] Allocated input data ptr:', dataPtr);
    new Uint8Array(exports.memory.buffer, dataPtr, serializedData.length).set(serializedData);
    
    // Allocate space for outputs
    const outGroupIdPtr = exports.wasm_alloc(32);
    const outEpochPtr = exports.wasm_alloc(16); // Extra for 8-byte alignment
    const alignedOutEpochPtr = (outEpochPtr + 7) & ~7;
    const outSenderIndexAlloc = this.allocateAlignedU32(1);
    const outAppDataPtr = exports.wasm_alloc(4096);
    const outAppDataLenAlloc = this.allocateAlignedU32(1);
    const outSigPtr = exports.wasm_alloc(256);
    const outSigLenAlloc = this.allocateAlignedU32(1);
    
    if (!outGroupIdPtr || !outEpochPtr || !outSenderIndexAlloc.ptr || 
        !outAppDataPtr || !outAppDataLenAlloc.ptr || !outSigPtr || !outSigLenAlloc.ptr) {
      exports.wasm_free(dataPtr, serializedData.length);
      throw new Error('Failed to allocate memory for outputs');
    }
    
    // Set initial lengths
    new Uint32Array(exports.memory.buffer, outAppDataLenAlloc.alignedPtr, 1)[0] = 4096;
    new Uint32Array(exports.memory.buffer, outSigLenAlloc.alignedPtr, 1)[0] = 256;
    
    console.log('[WASM] Calling wasm_deserialize_mls_message...');
    console.log('[WASM] Function call arguments:', {
      dataPtr,
      dataLength: serializedData.length,
      outGroupIdPtr,
      alignedOutEpochPtr,
      outSenderIndex: outSenderIndexAlloc.alignedPtr,
      outAppDataPtr,
      outAppDataLen: outAppDataLenAlloc.alignedPtr,
      outSigPtr,
      outSigLen: outSigLenAlloc.alignedPtr
    });
    
    let success;
    try {
      success = exports.wasm_deserialize_mls_message(
        dataPtr,
        serializedData.length,
        outGroupIdPtr,
        alignedOutEpochPtr,
        outSenderIndexAlloc.alignedPtr,
        outAppDataPtr,
        outAppDataLenAlloc.alignedPtr,
        outSigPtr,
        outSigLenAlloc.alignedPtr
      );
      console.log('[WASM] wasm_deserialize_mls_message returned:', success);
    } catch (wasmError) {
      console.error('[WASM] Error calling wasm_deserialize_mls_message:', wasmError);
      throw wasmError;
    }
    
    if (!success) {
      // Cleanup on failure
      exports.wasm_free(dataPtr, serializedData.length);
      exports.wasm_free(outGroupIdPtr, 32);
      exports.wasm_free(outEpochPtr, 16);
      this.freeAlignedU32(outSenderIndexAlloc);
      exports.wasm_free(outAppDataPtr, 4096);
      this.freeAlignedU32(outAppDataLenAlloc);
      exports.wasm_free(outSigPtr, 256);
      this.freeAlignedU32(outSigLenAlloc);
      throw new Error('Failed to deserialize MLS message');
    }
    
    // Read results
    const groupId = this.readBytes(outGroupIdPtr, 32);
    const epoch = new BigUint64Array(exports.memory.buffer, alignedOutEpochPtr, 1)[0];
    const senderIndex = new Uint32Array(exports.memory.buffer, outSenderIndexAlloc.alignedPtr, 1)[0];
    const appDataLen = new Uint32Array(exports.memory.buffer, outAppDataLenAlloc.alignedPtr, 1)[0];
    const applicationData = this.readString(outAppDataPtr, appDataLen);
    const sigLen = new Uint32Array(exports.memory.buffer, outSigLenAlloc.alignedPtr, 1)[0];
    const signature = this.readBytes(outSigPtr, sigLen);
    
    console.log('[WASM] wasm_deserialize_mls_message returned:', {
      success,
      groupIdLength: groupId.length,
      epoch: epoch.toString(),
      senderIndex,
      appDataLength: applicationData.length,
      signatureLength: signature.length
    });
    
    // Cleanup
    exports.wasm_free(dataPtr, serializedData.length);
    exports.wasm_free(outGroupIdPtr, 32);
    exports.wasm_free(outEpochPtr, 16);
    this.freeAlignedU32(outSenderIndexAlloc);
    exports.wasm_free(outAppDataPtr, 4096);
    this.freeAlignedU32(outAppDataLenAlloc);
    exports.wasm_free(outSigPtr, 256);
    this.freeAlignedU32(outSigLenAlloc);
    
    return {
      groupId,
      epoch,
      senderIndex,
      applicationData,
      signature
    };
  }

  // Crypto utilities
  bytesToHex(bytes: Uint8Array): string {
    const exports = this.ensureInitialized();
    const bytesPtr = exports.wasm_alloc(bytes.length);
    const hexPtr = exports.wasm_alloc(bytes.length * 2);
    
    if (!bytesPtr || !hexPtr) throw new Error('Failed to allocate memory');
    
    new Uint8Array(exports.memory.buffer, bytesPtr, bytes.length).set(bytes);
    
    const success = exports.bytes_to_hex(bytesPtr, bytes.length, hexPtr, bytes.length * 2);
    if (!success) {
      exports.wasm_free(bytesPtr, bytes.length);
      exports.wasm_free(hexPtr, bytes.length * 2);
      throw new Error('Failed to convert bytes to hex');
    }
    
    const hexStr = this.readString(hexPtr, bytes.length * 2);
    exports.wasm_free(bytesPtr, bytes.length);
    exports.wasm_free(hexPtr, bytes.length * 2);
    
    return hexStr;
  }

  // Test function
  add(a: number, b: number): number {
    const exports = this.ensureInitialized();
    return exports.wasm_add(a, b);
  }
}

export const wasm = new WasmWrapper();