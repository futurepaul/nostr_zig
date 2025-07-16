export interface WasmExports {
  memory: WebAssembly.Memory;
  wasm_init: () => void;
  wasm_add: (a: number, b: number) => number;
  wasm_alloc: (size: number) => number;
  wasm_free: (ptr: number, size: number) => void;
  wasm_create_identity: (outPrivateKey: number, outPublicKey: number) => boolean;
  wasm_create_key_package: (
    privateKey: number,
    outData: number,
    outLenPtr: number
  ) => boolean;
  wasm_create_group: (
    creatorPrivateKey: number,
    groupId: number,
    groupIdLen: number,
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
      this.instance = await WebAssembly.instantiate(wasmModule, {
        env: {
          // Add any imports required by the WASM module
        }
      });
      
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

    exports.wasm_free(privateKeyPtr, 32);
    exports.wasm_free(publicKeyPtr, 32);

    return { privateKey, publicKey };
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
    const outLenPtr = exports.wasm_alloc(4);
    if (!outPtr || !outLenPtr) {
      exports.wasm_free(privateKeyPtr, 32);
      throw new Error('Failed to allocate memory');
    }

    // Set initial length
    new Uint32Array(exports.memory.buffer, outLenPtr, 1)[0] = maxSize;

    const success = exports.wasm_create_key_package(
      privateKeyPtr,
      outPtr,
      outLenPtr
    );

    const actualLen = new Uint32Array(exports.memory.buffer, outLenPtr, 1)[0];
    
    if (!success) {
      exports.wasm_free(privateKeyPtr, 32);
      exports.wasm_free(outPtr, maxSize);
      exports.wasm_free(outLenPtr, 4);
      throw new Error('Failed to create key package');
    }

    const keyPackage = this.readBytes(outPtr, actualLen);

    exports.wasm_free(privateKeyPtr, 32);
    exports.wasm_free(outPtr, maxSize);
    exports.wasm_free(outLenPtr, 4);

    return keyPackage;
  }

  createGroup(creatorPrivateKey: Uint8Array, groupId: string): Uint8Array {
    const exports = this.ensureInitialized();
    
    // Allocate space for private key
    const privateKeyPtr = exports.wasm_alloc(32);
    if (!privateKeyPtr) throw new Error('Failed to allocate memory');
    new Uint8Array(exports.memory.buffer, privateKeyPtr, 32).set(creatorPrivateKey);

    // Allocate space for group ID
    const groupIdData = this.allocateString(groupId);

    // Allocate space for output
    const maxSize = 4096; // Assume max state size
    const outPtr = exports.wasm_alloc(maxSize);
    const outLenPtr = exports.wasm_alloc(4);
    if (!outPtr || !outLenPtr) {
      exports.wasm_free(privateKeyPtr, 32);
      exports.wasm_free(groupIdData.ptr, groupIdData.len);
      throw new Error('Failed to allocate memory');
    }

    // Set initial length
    new Uint32Array(exports.memory.buffer, outLenPtr, 1)[0] = maxSize;

    const success = exports.wasm_create_group(
      privateKeyPtr,
      groupIdData.ptr,
      groupIdData.len,
      outPtr,
      outLenPtr
    );

    const actualLen = new Uint32Array(exports.memory.buffer, outLenPtr, 1)[0];
    
    if (!success) {
      exports.wasm_free(privateKeyPtr, 32);
      exports.wasm_free(groupIdData.ptr, groupIdData.len);
      exports.wasm_free(outPtr, maxSize);
      exports.wasm_free(outLenPtr, 4);
      throw new Error('Failed to create group');
    }

    const groupState = this.readBytes(outPtr, actualLen);

    exports.wasm_free(privateKeyPtr, 32);
    exports.wasm_free(groupIdData.ptr, groupIdData.len);
    exports.wasm_free(outPtr, maxSize);
    exports.wasm_free(outLenPtr, 4);

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
    const outLenPtr = exports.wasm_alloc(4);
    if (!outPtr || !outLenPtr) {
      exports.wasm_free(statePtr, groupState.length);
      exports.wasm_free(privateKeyPtr, 32);
      exports.wasm_free(messageData.ptr, messageData.len);
      throw new Error('Failed to allocate memory');
    }

    // Set initial length
    new Uint32Array(exports.memory.buffer, outLenPtr, 1)[0] = maxSize;

    const success = exports.wasm_send_message(
      statePtr,
      groupState.length,
      privateKeyPtr,
      messageData.ptr,
      messageData.len,
      outPtr,
      outLenPtr
    );

    const actualLen = new Uint32Array(exports.memory.buffer, outLenPtr, 1)[0];
    
    if (!success) {
      exports.wasm_free(statePtr, groupState.length);
      exports.wasm_free(privateKeyPtr, 32);
      exports.wasm_free(messageData.ptr, messageData.len);
      exports.wasm_free(outPtr, maxSize);
      exports.wasm_free(outLenPtr, 4);
      throw new Error('Failed to send message');
    }

    const ciphertext = this.readBytes(outPtr, actualLen);

    exports.wasm_free(statePtr, groupState.length);
    exports.wasm_free(privateKeyPtr, 32);
    exports.wasm_free(messageData.ptr, messageData.len);
    exports.wasm_free(outPtr, maxSize);
    exports.wasm_free(outLenPtr, 4);

    return ciphertext;
  }

  // Test function
  add(a: number, b: number): number {
    const exports = this.ensureInitialized();
    return exports.wasm_add(a, b);
  }
}

export const wasm = new WasmWrapper();