#!/usr/bin/env bun

// Test publishing an event to the local relay at ws://localhost:10547
// This simulates what the publish interface should do

import { readFileSync } from 'fs';
import { resolve } from 'path';

// Load WASM file and create event (using our working workaround)
const wasmPath = resolve(__dirname, 'src/nostr_mls.wasm');
const wasmBuffer = readFileSync(wasmPath);

const imports = {
  env: {
    getRandomValues: (ptr: number, len: number) => {
      const bytes = new Uint8Array((instance.exports as any).memory.buffer, ptr, len);
      crypto.getRandomValues(bytes);
    },
    getCurrentTimestamp: () => Math.floor(Date.now() / 1000),
    wasm_log_error: (strPtr: number, len: number) => {
      const bytes = new Uint8Array((instance.exports as any).memory.buffer, strPtr, len);
      const message = new TextDecoder().decode(bytes);
      console.error('WASM Error:', message);
    }
  }
};

const wasmModule = new WebAssembly.Module(wasmBuffer);
const instance = new WebAssembly.Instance(wasmModule, imports);
const exports = instance.exports as any;

function createTestEvent(content: string) {
  // Create a test private key
  const privateKey = new Uint8Array(32);
  crypto.getRandomValues(privateKey);
  
  // Get public key
  const privkeyPtr = exports.wasm_alloc(32);
  new Uint8Array(exports.memory.buffer, privkeyPtr, 32).set(privateKey);
  
  const pubkeyPtr = exports.wasm_alloc(32);
  const pubkeySuccess = exports.wasm_get_public_key(privkeyPtr, pubkeyPtr);
  
  if (!pubkeySuccess) {
    throw new Error('Failed to get public key');
  }
  
  const pubkeyBytes = new Uint8Array(exports.memory.buffer, pubkeyPtr, 32);
  const pubkeyHex = Array.from(pubkeyBytes).map(b => b.toString(16).padStart(2, '0')).join('');
  
  // Create event structure
  const createdAt = Math.floor(Date.now() / 1000);
  const eventForId = {
    pubkey: pubkeyHex,
    created_at: createdAt,
    kind: 1,
    tags: [],
    content: content
  };
  
  // Calculate event ID
  const serialized = JSON.stringify([0, eventForId.pubkey, eventForId.created_at, eventForId.kind, eventForId.tags, eventForId.content]);
  const encoder = new TextEncoder();
  const serializedBytes = encoder.encode(serialized);
  
  const dataPtr = exports.wasm_alloc(serializedBytes.length);
  new Uint8Array(exports.memory.buffer, dataPtr, serializedBytes.length).set(serializedBytes);
  
  const hashPtr = exports.wasm_alloc(32);
  const hashSuccess = exports.wasm_sha256(dataPtr, serializedBytes.length, hashPtr);
  
  if (!hashSuccess) {
    throw new Error('Failed to calculate SHA256 hash');
  }
  
  const eventIdBytes = new Uint8Array(exports.memory.buffer, hashPtr, 32);
  const eventId = Array.from(eventIdBytes).map(b => b.toString(16).padStart(2, '0')).join('');
  
  // Sign the event
  const sigPtr = exports.wasm_alloc(64);
  const signSuccess = exports.wasm_sign_schnorr(privkeyPtr, hashPtr, sigPtr);
  
  if (!signSuccess) {
    throw new Error('Failed to sign event');
  }
  
  const signatureBytes = new Uint8Array(exports.memory.buffer, sigPtr, 64);
  const signature = Array.from(signatureBytes).map(b => b.toString(16).padStart(2, '0')).join('');
  
  // Clean up
  exports.wasm_free(privkeyPtr, 32);
  exports.wasm_free(pubkeyPtr, 32);
  exports.wasm_free(dataPtr, serializedBytes.length);
  exports.wasm_free(hashPtr, 32);
  exports.wasm_free(sigPtr, 64);
  
  return {
    id: eventId,
    pubkey: pubkeyHex,
    created_at: createdAt,
    kind: 1,
    tags: [],
    content: content,
    sig: signature
  };
}

async function publishToRelay(event: any, relayUrl: string) {
  console.log(`📡 Connecting to relay: ${relayUrl}`);
  
  try {
    const ws = new WebSocket(relayUrl);
    
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        ws.close();
        reject(new Error('Connection timeout'));
      }, 5000);
      
      ws.onopen = () => {
        clearTimeout(timeout);
        console.log('✅ Connected to relay');
        
        // Send event to relay
        const message = JSON.stringify(["EVENT", event]);
        console.log('📤 Sending event:', message);
        ws.send(message);
        
        // Wait for response
        setTimeout(() => {
          ws.close();
          resolve('Event sent successfully');
        }, 1000);
      };
      
      ws.onmessage = (msg) => {
        console.log('📥 Relay response:', msg.data);
      };
      
      ws.onerror = (error) => {
        clearTimeout(timeout);
        console.error('❌ WebSocket error:', error);
        reject(error);
      };
      
      ws.onclose = () => {
        console.log('🔌 Connection closed');
      };
    });
  } catch (error) {
    console.error('❌ Failed to connect to relay:', error);
    throw error;
  }
}

// Test the complete flow
async function testCompleteFlow() {
  console.log('🧪 Testing complete event creation and publishing flow...\n');
  
  // Create a test event
  const event = createTestEvent('Hello from WASM + Relay integration test! 🚀');
  
  console.log('✅ Event created successfully:');
  console.log('   ID:', event.id);
  console.log('   Pubkey:', event.pubkey);
  console.log('   Content:', event.content);
  console.log('   Signature:', event.sig);
  console.log();
  
  // Test with the default relay set
  const relays = [
    'ws://localhost:10547',  // Local test relay
    'wss://relay.damus.io',  // Public relay
    'wss://nos.lol',         // Public relay  
    'wss://relay.primal.net' // Public relay
  ];
  
  for (const relayUrl of relays) {
    try {
      console.log(`\n📡 Testing ${relayUrl}...`);
      await publishToRelay(event, relayUrl);
      console.log(`✅ ${relayUrl} - Success!`);
    } catch (error) {
      console.log(`❌ ${relayUrl} - Failed: ${error}`);
    }
  }
  
  console.log('\n🎉 Test completed!');
}

// Run the test
testCompleteFlow().catch(console.error);