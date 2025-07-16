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
  wasm_send_message: (
    groupState: number,
    groupStateLen: number,
    senderPrivateKey: number,
    message: number,
    messageLen: number,
    outCiphertext: number,
    outLenPtr: number
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

  sendMessage(
    groupState: Uint8Array,
    senderPrivateKey: Uint8Array,
    message: string
  ): Uint8Array {
    const exports = this.ensureInitialized();
    
    // Allocate space for inputs
    const statePtr = exports.wasm_alloc(groupState.length);
    const privateKeyPtr = exports.wasm_alloc(32);
    const messageData = this.allocateString(message);
    
    if (!statePtr || !privateKeyPtr) {
      throw new Error('Failed to allocate memory');
    }

    new Uint8Array(exports.memory.buffer, statePtr, groupState.length).set(groupState);
    new Uint8Array(exports.memory.buffer, privateKeyPtr, 32).set(senderPrivateKey);

    // Allocate space for output
    const maxSize = 4096;
    const outPtr = exports.wasm_alloc(maxSize);
    
    // Allocate extra space for alignment
    const rawOutLenPtr = exports.wasm_alloc(8);
    
    if (!outPtr || !rawOutLenPtr) {
      exports.wasm_free(statePtr, groupState.length);
      exports.wasm_free(privateKeyPtr, 32);
      exports.wasm_free(messageData.ptr, messageData.len);
      throw new Error('Failed to allocate memory');
    }

    // Manually align to 4-byte boundary
    const alignedLenPtr = (rawOutLenPtr + 3) & ~3;
    new Uint32Array(exports.memory.buffer, alignedLenPtr, 1)[0] = maxSize;

    const success = exports.wasm_send_message(
      statePtr,
      groupState.length,
      privateKeyPtr,
      messageData.ptr,
      messageData.len,
      outPtr,
      alignedLenPtr
    );

    const actualLen = new Uint32Array(exports.memory.buffer, alignedLenPtr, 1)[0];
    
    if (!success) {
      exports.wasm_free(statePtr, groupState.length);
      exports.wasm_free(privateKeyPtr, 32);
      exports.wasm_free(messageData.ptr, messageData.len);
      exports.wasm_free(outPtr, maxSize);
      exports.wasm_free(rawOutLenPtr, 8);
      throw new Error('Failed to send message');
    }

    const ciphertext = this.readBytes(outPtr, actualLen);

    exports.wasm_free(statePtr, groupState.length);
    exports.wasm_free(privateKeyPtr, 32);
    exports.wasm_free(messageData.ptr, messageData.len);
    exports.wasm_free(outPtr, maxSize);
    exports.wasm_free(rawOutLenPtr, 8);

    return ciphertext;
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