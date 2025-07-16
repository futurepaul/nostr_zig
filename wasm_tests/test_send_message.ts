import { readFileSync } from 'fs';
import { resolve } from 'path';

const wasmPath = resolve(__dirname, '../visualizer/src/nostr_mls.wasm');
const wasmBuffer = readFileSync(wasmPath);

async function testSendMessage() {
  console.log('🧪 Testing WASM send_message function...\n');

  // Create imports for WASM
  const imports = {
    env: {
      getRandomValues: (ptr: number, len: number) => {
        const bytes = new Uint8Array(wasmMemory.buffer, ptr, len);
        crypto.getRandomValues(bytes);
      },
      wasm_log_error: (strPtr: number, len: number) => {
        const bytes = new Uint8Array(wasmMemory.buffer, strPtr, len);
        const message = new TextDecoder().decode(bytes);
        console.error('WASM error:', message);
      }
    }
  };

  // Load and instantiate WASM
  const wasmModule = new WebAssembly.Module(wasmBuffer);
  const wasmInstance = new WebAssembly.Instance(wasmModule, imports);
  const wasmMemory = wasmInstance.exports.memory as WebAssembly.Memory;
  const exports = wasmInstance.exports as any;

  console.log('✅ WASM loaded successfully');

  // Helper functions
  function allocateAlignedU32(count: number = 1): { ptr: number; alignedPtr: number; size: number } {
    if (exports.wasm_alloc_u32 && exports.wasm_free_u32) {
      const ptr = exports.wasm_alloc_u32(count);
      return { ptr, alignedPtr: ptr, size: count * 4 };
    }
    
    const extraSize = count * 4 + 4;
    const ptr = exports.wasm_alloc(extraSize);
    const alignedPtr = (ptr + 3) & ~3;
    
    return { ptr, alignedPtr, size: extraSize };
  }

  function freeAlignedU32(allocation: { ptr: number; alignedPtr: number; size: number }, count: number = 1) {
    if (exports.wasm_alloc_u32 && exports.wasm_free_u32 && allocation.ptr === allocation.alignedPtr) {
      exports.wasm_free_u32(allocation.ptr, count);
    } else {
      exports.wasm_free(allocation.ptr, allocation.size);
    }
  }

  function allocateString(str: string): { ptr: number; len: number } {
    const encoder = new TextEncoder();
    const bytes = encoder.encode(str);
    const ptr = exports.wasm_alloc(bytes.length);
    if (!ptr) throw new Error('Failed to allocate memory');
    new Uint8Array(exports.memory.buffer, ptr, bytes.length).set(bytes);
    return { ptr, len: bytes.length };
  }

  function readBytes(ptr: number, len: number): Uint8Array {
    return new Uint8Array(exports.memory.buffer, ptr, len).slice();
  }

  try {
    // Step 1: Create identity for group creator
    console.log('1. Creating identity...');
    const privateKeyPtr = exports.wasm_alloc(32);
    const publicKeyPtr = exports.wasm_alloc(32);
    
    if (!exports.wasm_create_identity(privateKeyPtr, publicKeyPtr)) {
      throw new Error('Failed to create identity');
    }

    const privateKey = readBytes(privateKeyPtr, 32);
    const publicKey = readBytes(publicKeyPtr, 32);
    
    console.log('✅ Identity created:', {
      privateKey: Array.from(privateKey).slice(0, 8).map(b => b.toString(16).padStart(2, '0')).join(' '),
      publicKey: Array.from(publicKey).slice(0, 8).map(b => b.toString(16).padStart(2, '0')).join(' ')
    });

    // Step 2: Create group
    console.log('2. Creating group...');
    const maxGroupSize = 4096;
    const groupOutPtr = exports.wasm_alloc(maxGroupSize);
    const groupLenAllocation = allocateAlignedU32(1);
    
    new Uint32Array(exports.memory.buffer, groupLenAllocation.alignedPtr, 1)[0] = maxGroupSize;

    const groupSuccess = exports.wasm_create_group(
      privateKeyPtr,
      publicKeyPtr,
      groupOutPtr,
      groupLenAllocation.alignedPtr
    );

    if (!groupSuccess) {
      throw new Error('Failed to create group');
    }

    const groupStateLen = new Uint32Array(exports.memory.buffer, groupLenAllocation.alignedPtr, 1)[0];
    const groupState = readBytes(groupOutPtr, groupStateLen);
    
    console.log('✅ Group created:', {
      stateLength: groupStateLen,
      statePreview: Array.from(groupState).slice(0, 8).map(b => b.toString(16).padStart(2, '0')).join(' ')
    });

    // Step 3: Test send message
    console.log('3. Testing send message...');
    const message = "Hello, World!";
    const messageData = allocateString(message);
    
    // Allocate space for inputs
    const statePtr = exports.wasm_alloc(groupState.length);
    const msgPrivateKeyPtr = exports.wasm_alloc(32);
    
    // Copy data to WASM memory
    new Uint8Array(exports.memory.buffer, statePtr, groupState.length).set(groupState);
    new Uint8Array(exports.memory.buffer, msgPrivateKeyPtr, 32).set(privateKey);
    
    // Allocate space for output
    const maxCipherSize = 4096;
    const cipherOutPtr = exports.wasm_alloc(maxCipherSize);
    const cipherLenAllocation = allocateAlignedU32(1);
    
    new Uint32Array(exports.memory.buffer, cipherLenAllocation.alignedPtr, 1)[0] = maxCipherSize;
    
    console.log('Calling wasm_send_message with:', {
      statePtr,
      stateLength: groupState.length,
      privateKeyPtr: msgPrivateKeyPtr,
      messagePtr: messageData.ptr,
      messageLength: messageData.len,
      outPtr: cipherOutPtr,
      lenPtr: cipherLenAllocation.alignedPtr
    });

    const sendSuccess = exports.wasm_send_message(
      statePtr,
      groupState.length,
      msgPrivateKeyPtr,
      messageData.ptr,
      messageData.len,
      cipherOutPtr,
      cipherLenAllocation.alignedPtr
    );

    const actualCipherLen = new Uint32Array(exports.memory.buffer, cipherLenAllocation.alignedPtr, 1)[0];
    
    console.log('wasm_send_message result:', { sendSuccess, actualCipherLen });

    if (!sendSuccess) {
      throw new Error('WASM sendMessage returned false');
    }

    const ciphertext = readBytes(cipherOutPtr, actualCipherLen);
    
    console.log('✅ Message sent successfully:', {
      originalMessage: message,
      ciphertextLength: actualCipherLen,
      ciphertextPreview: Array.from(ciphertext).slice(0, 16).map(b => b.toString(16).padStart(2, '0')).join(' ')
    });

    // Cleanup
    exports.wasm_free(privateKeyPtr, 32);
    exports.wasm_free(publicKeyPtr, 32);
    exports.wasm_free(groupOutPtr, maxGroupSize);
    freeAlignedU32(groupLenAllocation);
    exports.wasm_free(messageData.ptr, messageData.len);
    exports.wasm_free(statePtr, groupState.length);
    exports.wasm_free(msgPrivateKeyPtr, 32);
    exports.wasm_free(cipherOutPtr, maxCipherSize);
    freeAlignedU32(cipherLenAllocation);

    console.log('\n🎉 Send message test completed successfully!');

  } catch (error) {
    console.error('❌ Test failed:', error);
    console.error('Error details:', {
      message: error.message,
      stack: error.stack
    });
  }
}

testSendMessage();