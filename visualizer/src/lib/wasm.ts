export interface WasmExports {
  memory: WebAssembly.Memory;
  wasm_init: () => void;
  wasm_get_version: () => number;
  wasm_alloc: (size: number) => number;
  wasm_alloc_u32: (count: number) => number;
  wasm_free: (ptr: number, size: number) => void;
  wasm_free_u32: (ptr: number, count: number) => void;
  wasm_align_ptr: (ptr: number, alignment: number) => number;
  wasm_create_identity: (outPrivateKey: number, outPublicKey: number) => boolean;
  wasm_get_public_key_from_private: (privateKey: number, outPublicKey: number) => boolean;
  wasm_get_public_key_hex: (privateKey: number, outPubkeyHex: number) => boolean;
  wasm_sign_schnorr: (messageHash: number, privateKey: number, outSignature: number) => boolean;
  wasm_verify_schnorr: (messageHash: number, signature: number, publicKey: number) => boolean;
  wasm_sha256: (data: number, dataLen: number, outHash: number) => boolean;
  wasm_create_event: (
    privateKey: number,
    kind: number,
    content: number,
    contentLen: number,
    tagsJson: number,
    tagsJsonLen: number,
    outEventJson: number,
    outLenPtr: number
  ) => boolean;
  wasm_create_nostr_event_id: (
    pubkey: number,
    createdAt: bigint,
    kind: number,
    tagsJson: number,
    tagsJsonLen: number,
    content: number,
    contentLen: number,
    outEventId: number
  ) => boolean;
  wasm_nip_ee_create_encrypted_group_message: (
    groupId: number,
    epoch: bigint,
    senderIndex: number,
    messageContent: number,
    messageContentLen: number,
    mlsSignature: number,
    mlsSignatureLen: number,
    exporterSecret: number,
    outEncrypted: number,
    outLen: number
  ) => boolean;
  wasm_nip_ee_decrypt_group_message: (
    encryptedContent: number,
    encryptedContentLen: number,
    exporterSecret: number,
    outDecrypted: number,
    outLen: number
  ) => boolean;
  wasm_nip_ee_generate_exporter_secret: (
    groupState: number,
    groupStateLen: number,
    outSecret: number
  ) => boolean;
  wasm_create_gift_wrap: (
    innerEvent: number,
    innerEventLen: number,
    recipientPubkey: number,
    outGiftWrap: number,
    outLen: number
  ) => boolean;
  wasm_unwrap_gift_wrap: (
    giftWrapEvent: number,
    giftWrapEventLen: number,
    recipientPrivkey: number,
    outInnerEvent: number,
    outLen: number
  ) => boolean;
  // MLS State Machine Functions (DEPRECATED - Use wasm_mls_* instead)
  wasm_state_machine_init_group: (
    groupId: number,
    creatorIdentityPubkey: number,
    creatorSigningKey: number,
    outState: number,
    outStateLenPtr: number
  ) => boolean;
  
  // MLS Functions
  wasm_mls_init_group: (
    groupId: number,
    creatorIdentityPubkey: number,
    creatorSigningKey: number,
    outState: number,
    outStateLenPtr: number
  ) => boolean;
  
  wasm_mls_get_info: (
    stateData: number,
    stateDataLen: number,
    outEpoch: number,
    outMemberCount: number,
    outPendingProposals: number,
    outExporterSecret: number,
    outTreeHash: number
  ) => boolean;
  
  wasm_mls_test: () => boolean;
  wasm_state_machine_propose_add: (
    state: number,
    stateLen: number,
    memberKeyPackage: number,
    memberKeyPackageLen: number,
    outState: number,
    outStateLenPtr: number
  ) => boolean;
  wasm_state_machine_commit_proposals: (
    state: number,
    stateLen: number,
    outState: number,
    outStateLenPtr: number
  ) => boolean;
  wasm_state_machine_get_info: (
    state: number,
    stateLen: number,
    outEpoch: number,
    outMemberCount: number,
    outPendingProposals: number,
    outExporterSecret: number,
    outTreeHash: number
  ) => boolean;
  
  // Utility functions
  bytes_to_hex: (bytes: number, bytesLen: number, outHex: number, outHexLen: number) => boolean;
  hex_to_bytes: (hex: number, hexLen: number, outBytes: number, outBytesLen: number) => boolean;
  base64_encode: (bytes: number, bytesLen: number, outBase64: number, outBase64Len: number) => boolean;
  base64_decode: (base64: number, base64Len: number, outBytes: number, outBytesLen: number) => boolean;
  
  // Additional Nostr functions
  wasm_create_text_note_working: (
    privateKey: number,
    content: number,
    contentLen: number,
    outEventJson: number,
    outLen: number
  ) => boolean;
  wasm_create_reply_note: (
    privateKey: number,
    content: number,
    contentLen: number,
    replyToEventId: number,
    outEventJson: number,
    outLen: number
  ) => boolean;
  wasm_verify_event: (eventJson: number, eventJsonLen: number) => boolean;
  wasm_get_public_key: (privateKey: number, outPublicKey: number) => boolean;
  wasm_pubkey_to_hex: (publicKey: number, outHex: number) => void;
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
            console.error('[WASM ERROR]:', message);
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
      
      // Test real MLS functions
      if (typeof this.exports.wasm_mls_test === 'function') {
        console.log('Testing real MLS functions...');
        const testResult = this.exports.wasm_mls_test();
        console.log('MLS test result:', testResult);
      } else {
        console.warn('wasm_mls_test not available');
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
    // Use the same identity creation function for ephemeral keys
    const identity = this.createIdentity();
    console.log('Generated ephemeral keys:', {
      publicKey: Array.from(identity.publicKey).map(b => b.toString(16).padStart(2, '0')).join('')
    });
    return identity;
  }

  generateMLSSigningKeys(): { privateKey: Uint8Array; publicKey: Uint8Array } {
    // Use the same identity creation function for MLS signing keys
    const identity = this.createIdentity();
    console.log('Generated MLS signing keys:', {
      publicKey: Array.from(identity.publicKey).map(b => b.toString(16).padStart(2, '0')).join('')
    });
    return identity;
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

    // Key packages are now created internally by the state machine
    // For compatibility, we'll create a simplified structure that includes
    // the public key derived from the private key
    const publicKeyPtr = exports.wasm_alloc(32);
    if (!publicKeyPtr) {
      exports.wasm_free(privateKeyPtr, 32);
      exports.wasm_free(outPtr, maxSize);
      exports.wasm_free(outLenPtr, exports.wasm_alloc_u32 ? 4 : 8);
      throw new Error('Failed to allocate memory for public key');
    }

    // Get public key from private key
    const pubKeySuccess = exports.wasm_get_public_key_from_private(privateKeyPtr, publicKeyPtr);
    if (!pubKeySuccess) {
      exports.wasm_free(privateKeyPtr, 32);
      exports.wasm_free(publicKeyPtr, 32);
      exports.wasm_free(outPtr, maxSize);
      exports.wasm_free(outLenPtr, exports.wasm_alloc_u32 ? 4 : 8);
      throw new Error('Failed to derive public key');
    }

    // Create a simplified key package structure for visualization
    // Real key packages are created internally by the state machine
    const keyPackage = new Uint8Array(64);
    keyPackage.set(this.readBytes(publicKeyPtr, 32), 0); // Public key
    keyPackage.set(privateKey, 32); // Private key for later use

    exports.wasm_free(privateKeyPtr, 32);
    exports.wasm_free(publicKeyPtr, 32);
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

  // REMOVED: generateExporterSecret is obsolete - use generateExporterSecretForEpoch instead

  // REMOVED: NIP-44 functions are obsolete - use NIP-EE functions with proper MLS context instead

  // DEPRECATED: Send message functionality is now handled through NIP-EE functions
  sendMessage(
    groupState: Uint8Array,
    senderPrivateKey: Uint8Array,
    message: string
  ): Uint8Array {
    throw new Error('sendMessage is deprecated. Use createEncryptedGroupMessage from NIP-EE instead.');
  }

  // DEPRECATED: Receive message functionality is now handled through NIP-EE functions
  receiveMessage(
    groupState: Uint8Array,
    receiverPrivateKey: Uint8Array,
    nip44Ciphertext: string // Base64 encoded
  ): string {
    throw new Error('receiveMessage is deprecated. Use decryptGroupMessage from NIP-EE instead.');
  }

  // DEPRECATED: MLS message deserialization is no longer exposed
  deserializeMLSMessage(serializedData: Uint8Array): {
    groupId: Uint8Array;
    epoch: bigint;
    senderIndex: number;
    applicationData: string;
    signature: Uint8Array;
  } {
    throw new Error('deserializeMLSMessage is deprecated. MLS messages are handled internally.');
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

  // SHA-256 hash function
  sha256(data: Uint8Array): Uint8Array {
    const exports = this.ensureInitialized();
    const dataPtr = exports.wasm_alloc(data.length);
    const hashPtr = exports.wasm_alloc(32);
    
    if (!dataPtr || !hashPtr) {
      throw new Error('Failed to allocate memory for SHA-256');
    }
    
    new Uint8Array(exports.memory.buffer, dataPtr, data.length).set(data);
    
    const success = exports.wasm_sha256(dataPtr, data.length, hashPtr);
    if (!success) {
      exports.wasm_free(dataPtr, data.length);
      exports.wasm_free(hashPtr, 32);
      throw new Error('Failed to compute SHA-256');
    }
    
    const hash = this.readBytes(hashPtr, 32);
    exports.wasm_free(dataPtr, data.length);
    exports.wasm_free(hashPtr, 32);
    
    return hash;
  }

  // Create Nostr event ID
  createNostrEventId(
    pubkey: string,
    createdAt: number,
    kind: number,
    tags: string[][],
    content: string
  ): Uint8Array {
    const exports = this.ensureInitialized();
    
    // Validate pubkey is 64 hex chars
    if (pubkey.length !== 64) {
      throw new Error('Pubkey must be 64 hex characters');
    }
    
    // Allocate for pubkey hex string
    const pubkeyPtr = exports.wasm_alloc(64);
    if (!pubkeyPtr) throw new Error('Failed to allocate memory');
    
    // Copy pubkey hex string
    const encoder = new TextEncoder();
    const pubkeyBytes = encoder.encode(pubkey);
    new Uint8Array(exports.memory.buffer, pubkeyPtr, 64).set(pubkeyBytes);
    
    // Convert tags to JSON
    const tagsJson = JSON.stringify(tags);
    const tagsData = this.allocateString(tagsJson);
    
    // Allocate content
    const contentData = this.allocateString(content);
    
    // Allocate output
    const eventIdPtr = exports.wasm_alloc(32);
    if (!eventIdPtr) {
      exports.wasm_free(pubkeyPtr, 64);
      exports.wasm_free(tagsData.ptr, tagsData.len);
      exports.wasm_free(contentData.ptr, contentData.len);
      throw new Error('Failed to allocate memory for event ID');
    }
    
    const success = exports.wasm_create_nostr_event_id(
      pubkeyPtr,
      BigInt(createdAt),
      kind,
      tagsData.ptr,
      tagsData.len,
      contentData.ptr,
      contentData.len,
      eventIdPtr
    );
    
    if (!success) {
      exports.wasm_free(pubkeyPtr, 64);
      exports.wasm_free(tagsData.ptr, tagsData.len);
      exports.wasm_free(contentData.ptr, contentData.len);
      exports.wasm_free(eventIdPtr, 32);
      throw new Error('Failed to create Nostr event ID');
    }
    
    const eventId = this.readBytes(eventIdPtr, 32);
    
    exports.wasm_free(pubkeyPtr, 64);
    exports.wasm_free(tagsData.ptr, tagsData.len);
    exports.wasm_free(contentData.ptr, contentData.len);
    exports.wasm_free(eventIdPtr, 32);
    
    return eventId;
  }

  // Create encrypted group message using NIP-EE
  createEncryptedGroupMessage(
    groupId: Uint8Array,
    epoch: bigint,
    senderIndex: number,
    messageContent: string,
    mlsSignature: Uint8Array,
    exporterSecret: Uint8Array
  ): Uint8Array {
    const exports = this.ensureInitialized();
    
    // Allocate inputs
    const groupIdPtr = exports.wasm_alloc(32);
    new Uint8Array(exports.memory.buffer, groupIdPtr, 32).set(groupId);
    
    const messageData = this.allocateString(messageContent);
    
    const signaturePtr = exports.wasm_alloc(mlsSignature.length);
    new Uint8Array(exports.memory.buffer, signaturePtr, mlsSignature.length).set(mlsSignature);
    
    const secretPtr = exports.wasm_alloc(32);
    new Uint8Array(exports.memory.buffer, secretPtr, 32).set(exporterSecret);
    
    // Allocate output
    const maxSize = 4096;
    const outPtr = exports.wasm_alloc(maxSize);
    const outLenPtr = exports.wasm_alloc_u32(1);
    new Uint32Array(exports.memory.buffer, outLenPtr, 1)[0] = maxSize;
    
    const success = exports.wasm_nip_ee_create_encrypted_group_message(
      groupIdPtr,
      epoch,
      senderIndex,
      messageData.ptr,
      messageData.len,
      signaturePtr,
      mlsSignature.length,
      secretPtr,
      outPtr,
      outLenPtr
    );
    
    const actualLen = new Uint32Array(exports.memory.buffer, outLenPtr, 1)[0];
    
    if (!success) {
      exports.wasm_free(groupIdPtr, 32);
      exports.wasm_free(messageData.ptr, messageData.len);
      exports.wasm_free(signaturePtr, mlsSignature.length);
      exports.wasm_free(secretPtr, 32);
      exports.wasm_free(outPtr, maxSize);
      exports.wasm_free_u32(outLenPtr, 1);
      throw new Error('Failed to create encrypted group message');
    }
    
    const result = this.readBytes(outPtr, actualLen);
    
    // Clean up
    exports.wasm_free(groupIdPtr, 32);
    exports.wasm_free(messageData.ptr, messageData.len);
    exports.wasm_free(signaturePtr, mlsSignature.length);
    exports.wasm_free(secretPtr, 32);
    exports.wasm_free(outPtr, maxSize);
    exports.wasm_free_u32(outLenPtr, 1);
    
    return result;
  }

  // Decrypt group message using NIP-EE
  decryptGroupMessage(
    exporterSecret: Uint8Array,
    encryptedData: Uint8Array
  ): Uint8Array {
    const exports = this.ensureInitialized();
    
    console.log('[WASM] decryptGroupMessage called with:', {
      exporterSecretLength: exporterSecret.length,
      exporterSecretPreview: Array.from(exporterSecret.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join(' '),
      encryptedDataLength: encryptedData.length,
      encryptedDataPreview: Array.from(encryptedData.slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join(' ')
    });
    
    // Allocate inputs
    const encryptedPtr = exports.wasm_alloc(encryptedData.length);
    new Uint8Array(exports.memory.buffer, encryptedPtr, encryptedData.length).set(encryptedData);
    
    const secretPtr = exports.wasm_alloc(32);
    new Uint8Array(exports.memory.buffer, secretPtr, 32).set(exporterSecret);
    
    // Allocate output
    const maxSize = 4096;
    const outPtr = exports.wasm_alloc(maxSize);
    const outLenPtr = exports.wasm_alloc_u32(1);
    new Uint32Array(exports.memory.buffer, outLenPtr, 1)[0] = maxSize;
    
    console.log('[WASM] Calling wasm_nip_ee_decrypt_group_message...');
    const success = exports.wasm_nip_ee_decrypt_group_message(
      encryptedPtr,
      encryptedData.length,
      secretPtr,
      outPtr,
      outLenPtr
    );
    
    const actualLen = new Uint32Array(exports.memory.buffer, outLenPtr, 1)[0];
    console.log('[WASM] Decryption result:', { success, actualLen });
    
    if (!success) {
      exports.wasm_free(encryptedPtr, encryptedData.length);
      exports.wasm_free(secretPtr, 32);
      exports.wasm_free(outPtr, maxSize);
      exports.wasm_free_u32(outLenPtr, 1);
      throw new Error(`Failed to decrypt group message (success=${success}, actualLen=${actualLen})`);
    }
    
    const result = this.readBytes(outPtr, actualLen);
    
    // Clean up
    exports.wasm_free(encryptedPtr, encryptedData.length);
    exports.wasm_free(secretPtr, 32);
    exports.wasm_free(outPtr, maxSize);
    exports.wasm_free_u32(outLenPtr, 1);
    
    return result;
  }

  // Create a text note event (kind 1)
  createTextNote(privateKey: Uint8Array, content: string): string {
    const exports = this.ensureInitialized();
    
    // Use the new wasm_create_event function for clean event creation
    const contentBytes = new TextEncoder().encode(content);
    const tagsJson = "[]"; // Empty tags for simple text note
    const tagsBytes = new TextEncoder().encode(tagsJson);
    
    // Allocate memory
    const privateKeyPtr = exports.wasm_alloc(32);
    const contentPtr = exports.wasm_alloc(contentBytes.length);
    const tagsPtr = exports.wasm_alloc(tagsBytes.length);
    const outEventPtr = exports.wasm_alloc(4096); // Generous buffer for JSON
    const outLenPtr = exports.wasm_alloc_u32(1);
    
    if (!privateKeyPtr || !contentPtr || !tagsPtr || !outEventPtr || !outLenPtr) {
      throw new Error('Failed to allocate WASM memory');
    }
    
    try {
      // Copy data to WASM memory
      new Uint8Array(exports.memory.buffer, privateKeyPtr, 32).set(privateKey);
      new Uint8Array(exports.memory.buffer, contentPtr, contentBytes.length).set(contentBytes);
      new Uint8Array(exports.memory.buffer, tagsPtr, tagsBytes.length).set(tagsBytes);
      new Uint32Array(exports.memory.buffer, outLenPtr, 1)[0] = 4096;
      
      // Create the event
      const success = exports.wasm_create_event(
        privateKeyPtr,
        1,                          // kind 1 = text note
        contentPtr,
        contentBytes.length,
        tagsPtr,
        tagsBytes.length,
        outEventPtr,
        outLenPtr
      );
      
      if (!success) {
        throw new Error('Failed to create event');
      }
      
      // Read the result
      const eventJsonLen = new Uint32Array(exports.memory.buffer, outLenPtr, 1)[0];
      const eventJsonBytes = new Uint8Array(exports.memory.buffer, outEventPtr, eventJsonLen);
      const eventJson = new TextDecoder().decode(eventJsonBytes);
      
      console.log('Created text note event:', JSON.parse(eventJson));
      return eventJson;
      
    } finally {
      // Clean up memory
      exports.wasm_free(privateKeyPtr, 32);
      exports.wasm_free(contentPtr, contentBytes.length);
      exports.wasm_free(tagsPtr, tagsBytes.length);
      exports.wasm_free(outEventPtr, 4096);
      exports.wasm_free_u32(outLenPtr, 1);
    }
  }

  // Get public key from private key
  getPublicKey(privateKey: Uint8Array): Uint8Array {
    const exports = this.ensureInitialized();
    
    const privkeyPtr = exports.wasm_alloc(32);
    new Uint8Array(exports.memory.buffer, privkeyPtr, 32).set(privateKey);
    
    const pubkeyPtr = exports.wasm_alloc(32);
    
    const success = exports.wasm_get_public_key(privkeyPtr, pubkeyPtr);
    
    if (!success) {
      exports.wasm_free(privkeyPtr, 32);
      exports.wasm_free(pubkeyPtr, 32);
      throw new Error('Failed to get public key');
    }
    
    const result = this.readBytes(pubkeyPtr, 32);
    
    exports.wasm_free(privkeyPtr, 32);
    exports.wasm_free(pubkeyPtr, 32);
    
    return result;
  }

  // Convert public key to hex
  pubkeyToHex(publicKey: Uint8Array): string {
    const exports = this.ensureInitialized();
    
    const pubkeyPtr = exports.wasm_alloc(32);
    new Uint8Array(exports.memory.buffer, pubkeyPtr, 32).set(publicKey);
    
    const hexPtr = exports.wasm_alloc(64);
    
    exports.wasm_pubkey_to_hex(pubkeyPtr, hexPtr);
    
    const hexBytes = new Uint8Array(exports.memory.buffer, hexPtr, 64);
    const decoder = new TextDecoder();
    const result = decoder.decode(hexBytes);
    
    exports.wasm_free(pubkeyPtr, 32);
    exports.wasm_free(hexPtr, 64);
    
    return result;
  }

  // Verify event signature
  verifyEvent(eventJson: string): boolean {
    const exports = this.ensureInitialized();
    
    const encoder = new TextEncoder();
    const jsonBytes = encoder.encode(eventJson);
    const jsonPtr = exports.wasm_alloc(jsonBytes.length);
    new Uint8Array(exports.memory.buffer, jsonPtr, jsonBytes.length).set(jsonBytes);
    
    const isValid = exports.wasm_verify_event(jsonPtr, jsonBytes.length);
    
    exports.wasm_free(jsonPtr, jsonBytes.length);
    
    return isValid;
  }

  // Real MLS State Machine Functions
  initGroup(groupId: Uint8Array, creatorIdentityPubkey: Uint8Array, creatorSigningKey: Uint8Array): { state: Uint8Array; epoch: bigint; memberCount: number } {
    const exports = this.ensureInitialized();
    
    // Allocate inputs
    const groupIdPtr = exports.wasm_alloc(32);
    const pubkeyPtr = exports.wasm_alloc(32);
    const signingKeyPtr = exports.wasm_alloc(32);
    
    if (!groupIdPtr || !pubkeyPtr || !signingKeyPtr) {
      throw new Error('Failed to allocate memory for state machine init');
    }

    new Uint8Array(exports.memory.buffer, groupIdPtr, 32).set(groupId);
    new Uint8Array(exports.memory.buffer, pubkeyPtr, 32).set(creatorIdentityPubkey);
    new Uint8Array(exports.memory.buffer, signingKeyPtr, 32).set(creatorSigningKey);

    // Allocate outputs
    const maxStateSize = 4096;
    const outStatePtr = exports.wasm_alloc(maxStateSize);
    const outStateLenPtr = exports.wasm_alloc_u32(1);
    
    if (!outStatePtr || !outStateLenPtr) {
      exports.wasm_free(groupIdPtr, 32);
      exports.wasm_free(pubkeyPtr, 32);
      exports.wasm_free(signingKeyPtr, 32);
      throw new Error('Failed to allocate memory for state output');
    }

    new Uint32Array(exports.memory.buffer, outStateLenPtr, 1)[0] = maxStateSize;

    const success = exports.wasm_mls_init_group(
      groupIdPtr,
      pubkeyPtr,
      signingKeyPtr,
      outStatePtr,
      outStateLenPtr
    );

    const actualStateLen = new Uint32Array(exports.memory.buffer, outStateLenPtr, 1)[0];

    if (!success) {
      exports.wasm_free(groupIdPtr, 32);
      exports.wasm_free(pubkeyPtr, 32);
      exports.wasm_free(signingKeyPtr, 32);
      exports.wasm_free(outStatePtr, maxStateSize);
      exports.wasm_free_u32(outStateLenPtr, 1);
      throw new Error('Failed to initialize MLS group');
    }

    const state = this.readBytes(outStatePtr, actualStateLen);
    console.log('State successfully created, length:', actualStateLen);
    console.log('State first 10 bytes:', Array.from(state.slice(0, 10)).map(b => b.toString(16).padStart(2, '0')).join(' '));

    // Get group info (pass groupId since it's not in the state)
    console.log('Calling getGroupInfo with state length:', state.length);
    const { epoch, memberCount } = this.getGroupInfo(state, groupId);

    // Cleanup
    exports.wasm_free(groupIdPtr, 32);
    exports.wasm_free(pubkeyPtr, 32);
    exports.wasm_free(signingKeyPtr, 32);
    exports.wasm_free(outStatePtr, maxStateSize);
    exports.wasm_free_u32(outStateLenPtr, 1);

    return { state, epoch, memberCount };
  }

  proposeAddMember(state: Uint8Array, memberKeyPackage: Uint8Array): { newState: Uint8Array; epoch: bigint; memberCount: number } {
    const exports = this.ensureInitialized();
    
    // Allocate inputs
    const statePtr = exports.wasm_alloc(state.length);
    const keyPackagePtr = exports.wasm_alloc(memberKeyPackage.length);
    
    if (!statePtr || !keyPackagePtr) {
      throw new Error('Failed to allocate memory for propose add');
    }

    new Uint8Array(exports.memory.buffer, statePtr, state.length).set(state);
    new Uint8Array(exports.memory.buffer, keyPackagePtr, memberKeyPackage.length).set(memberKeyPackage);

    // Allocate outputs
    const maxStateSize = 4096;
    const outStatePtr = exports.wasm_alloc(maxStateSize);
    const outStateLenPtr = exports.wasm_alloc_u32(1);
    
    if (!outStatePtr || !outStateLenPtr) {
      exports.wasm_free(statePtr, state.length);
      exports.wasm_free(keyPackagePtr, memberKeyPackage.length);
      throw new Error('Failed to allocate memory for new state output');
    }

    new Uint32Array(exports.memory.buffer, outStateLenPtr, 1)[0] = maxStateSize;

    const success = exports.wasm_state_machine_propose_add(
      statePtr,
      state.length,
      keyPackagePtr,
      memberKeyPackage.length,
      outStatePtr,
      outStateLenPtr
    );

    const actualStateLen = new Uint32Array(exports.memory.buffer, outStateLenPtr, 1)[0];

    if (!success) {
      exports.wasm_free(statePtr, state.length);
      exports.wasm_free(keyPackagePtr, memberKeyPackage.length);
      exports.wasm_free(outStatePtr, maxStateSize);
      exports.wasm_free_u32(outStateLenPtr, 1);
      throw new Error('Failed to propose add member');
    }

    const newState = this.readBytes(outStatePtr, actualStateLen);

    // Get updated group info  
    const { epoch, memberCount } = this.getGroupInfo(newState);

    // Cleanup
    exports.wasm_free(statePtr, state.length);
    exports.wasm_free(keyPackagePtr, memberKeyPackage.length);
    exports.wasm_free(outStatePtr, maxStateSize);
    exports.wasm_free_u32(outStateLenPtr, 1);

    return { newState, epoch, memberCount };
  }

  commitProposals(state: Uint8Array): { newState: Uint8Array; epoch: bigint; memberCount: number; secretsRotated: boolean } {
    const exports = this.ensureInitialized();
    
    // Allocate inputs
    const statePtr = exports.wasm_alloc(state.length);
    
    if (!statePtr) {
      throw new Error('Failed to allocate memory for commit proposals');
    }

    new Uint8Array(exports.memory.buffer, statePtr, state.length).set(state);

    // Allocate outputs
    const maxStateSize = 4096;
    const outStatePtr = exports.wasm_alloc(maxStateSize);
    const outStateLenPtr = exports.wasm_alloc_u32(1);
    
    if (!outStatePtr || !outStateLenPtr) {
      exports.wasm_free(statePtr, state.length);
      throw new Error('Failed to allocate memory for commit output');
    }

    new Uint32Array(exports.memory.buffer, outStateLenPtr, 1)[0] = maxStateSize;

    const oldInfo = this.getGroupInfo(state);

    const success = exports.wasm_state_machine_commit_proposals(
      statePtr,
      state.length,
      outStatePtr,
      outStateLenPtr
    );

    const actualStateLen = new Uint32Array(exports.memory.buffer, outStateLenPtr, 1)[0];

    if (!success) {
      exports.wasm_free(statePtr, state.length);
      exports.wasm_free(outStatePtr, maxStateSize);
      exports.wasm_free_u32(outStateLenPtr, 1);
      throw new Error('Failed to commit proposals');
    }

    const newState = this.readBytes(outStatePtr, actualStateLen);

    // Get updated group info
    const { epoch, memberCount } = this.getGroupInfo(newState);
    
    // Check if secrets were rotated (epoch advanced)
    const secretsRotated = epoch > oldInfo.epoch;

    // Cleanup
    exports.wasm_free(statePtr, state.length);
    exports.wasm_free(outStatePtr, maxStateSize);
    exports.wasm_free_u32(outStateLenPtr, 1);

    return { newState, epoch, memberCount, secretsRotated };
  }

  getGroupInfo(state: Uint8Array, groupId?: Uint8Array): { groupId: Uint8Array; epoch: bigint; memberCount: number; exporterSecret?: Uint8Array } {
    const exports = this.ensureInitialized();
    console.log('getGroupInfo called with state length:', state.length);
    
    // Allocate inputs
    const statePtr = exports.wasm_alloc(state.length);
    
    if (!statePtr) {
      throw new Error('Failed to allocate memory for group info');
    }

    new Uint8Array(exports.memory.buffer, statePtr, state.length).set(state);
    console.log('State copied to WASM memory at ptr:', statePtr);

    // Allocate outputs - Note: get_info no longer returns groupId
    // IMPORTANT: Use proper 8-byte alignment for epoch (u64)
    const outEpochPtr = exports.wasm_alloc(16); // Extra space for alignment
    const alignedEpochPtr = (outEpochPtr + 7) & ~7; // Align to 8-byte boundary
    
    const outMemberCountPtr = exports.wasm_alloc_u32(1);
    const outPendingProposalsPtr = exports.wasm_alloc_u32(1);
    const outExporterSecretPtr = exports.wasm_alloc(32);
    const outTreeHashPtr = exports.wasm_alloc(32);
    
    if (!outEpochPtr || !outMemberCountPtr || !outPendingProposalsPtr || !outExporterSecretPtr || !outTreeHashPtr) {
      exports.wasm_free(statePtr, state.length);
      throw new Error('Failed to allocate memory for group info outputs');
    }

    console.log('Calling wasm_state_machine_get_info with:', {
      statePtr,
      stateLen: state.length,
      alignedEpochPtr,
      outMemberCountPtr,
      outPendingProposalsPtr,
      outExporterSecretPtr,
      outTreeHashPtr
    });

    const success = exports.wasm_mls_get_info(
      statePtr,
      state.length,
      alignedEpochPtr,
      outMemberCountPtr,
      outPendingProposalsPtr,
      outExporterSecretPtr,
      outTreeHashPtr
    );

    if (!success) {
      exports.wasm_free(statePtr, state.length);
      exports.wasm_free(outEpochPtr, 16);
      exports.wasm_free_u32(outMemberCountPtr, 1);
      exports.wasm_free_u32(outPendingProposalsPtr, 1);
      exports.wasm_free(outExporterSecretPtr, 32);
      exports.wasm_free(outTreeHashPtr, 32);
      throw new Error('Failed to get group info');
    }

    // Note: groupId is passed in, not returned from get_info
    const returnGroupId = groupId || new Uint8Array(32); // Use provided groupId or empty array
    
    // Read epoch with proper alignment
    const epoch = new BigUint64Array(exports.memory.buffer, alignedEpochPtr, 1)[0];
    const memberCount = new Uint32Array(exports.memory.buffer, outMemberCountPtr, 1)[0];
    
    // Read exporter secret
    const exporterSecret = this.readBytes(outExporterSecretPtr, 32);

    console.log('Group info retrieved:', {
      epoch: epoch.toString(),
      memberCount,
      exporterSecretPreview: Array.from(exporterSecret.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join(' ')
    });

    // Cleanup
    exports.wasm_free(statePtr, state.length);
    exports.wasm_free(outEpochPtr, 16);
    exports.wasm_free_u32(outMemberCountPtr, 1);
    exports.wasm_free_u32(outPendingProposalsPtr, 1);
    exports.wasm_free(outExporterSecretPtr, 32);
    exports.wasm_free(outTreeHashPtr, 32);

    return { groupId: returnGroupId, epoch, memberCount, exporterSecret };
  }

  // Generate exporter secret for current epoch (with forward secrecy)
  generateExporterSecretForEpoch(state: Uint8Array): Uint8Array {
    const exports = this.ensureInitialized();
    
    // Allocate space for group state
    const statePtr = exports.wasm_alloc(state.length);
    const secretPtr = exports.wasm_alloc(32);
    
    if (!statePtr || !secretPtr) {
      throw new Error('Failed to allocate memory');
    }

    new Uint8Array(exports.memory.buffer, statePtr, state.length).set(state);

    const success = exports.wasm_nip_ee_generate_exporter_secret(
      statePtr,
      state.length,
      secretPtr
    );

    if (!success) {
      exports.wasm_free(statePtr, state.length);
      exports.wasm_free(secretPtr, 32);
      throw new Error('Failed to generate exporter secret from state machine');
    }

    const secret = this.readBytes(secretPtr, 32);

    exports.wasm_free(statePtr, state.length);
    exports.wasm_free(secretPtr, 32);

    return secret;
  }
}

export const wasm = new WasmWrapper();