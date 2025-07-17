import { readFileSync } from 'fs';
import { resolve } from 'path';
import { createHash } from 'crypto';

// Load the WASM module
const wasmPath = resolve(__dirname, '../visualizer/src/nostr_mls.wasm');
const wasmBuffer = readFileSync(wasmPath);

// Create simple imports that don't require browser APIs
const wasmMemory = new WebAssembly.Memory({ initial: 256, maximum: 512 });

const imports = {
    env: {
        memory: wasmMemory,
        getRandomValues: (ptr: number, len: number) => {
            const bytes = new Uint8Array(wasmMemory.buffer, ptr, len);
            // Use Node.js crypto for randomness
            const nodeBytes = require('crypto').randomBytes(len);
            bytes.set(nodeBytes);
        }
    }
};

function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function testNostrEventId() {
    console.log("Loading WASM module...");
    const wasmModule = new WebAssembly.Module(wasmBuffer);
    const wasmInstance = new WebAssembly.Instance(wasmModule, imports);
    const exports = wasmInstance.exports as any;
    
    console.log("WASM exports for event ID:", Object.keys(exports).filter(k => k.includes('event_id')));
    
    // Test event data
    const pubkeyHex = "6e468422dfb74a5738702a8823b9b28168abab8655faacb6853cd0ee15deee93";
    const createdAt = 1673347337;
    const kind = 1;
    const tags = [["e", "3da979448d9ba263864c4d6f14984c423a3838364ec255f03c7904b1ae77f206"]];
    const content = "Walled gardens became prisons, and nostr is the first step towards tearing down the prison walls.";
    
    // Encode strings
    const encoder = new TextEncoder();
    const pubkeyBytes = encoder.encode(pubkeyHex);
    const tagsJson = JSON.stringify(tags);
    const tagsBytes = encoder.encode(tagsJson);
    const contentBytes = encoder.encode(content);
    
    // Allocate memory
    const pubkeyPtr = exports.wasm_alloc(pubkeyBytes.length);
    const tagsPtr = exports.wasm_alloc(tagsBytes.length);
    const contentPtr = exports.wasm_alloc(contentBytes.length);
    const eventIdPtr = exports.wasm_alloc(32); // SHA-256 produces 32 bytes
    
    if (!pubkeyPtr || !tagsPtr || !contentPtr || !eventIdPtr) {
        throw new Error("Failed to allocate memory");
    }
    
    try {
        // Copy data to WASM memory
        const wasmPubkey = new Uint8Array(exports.memory.buffer, pubkeyPtr, pubkeyBytes.length);
        wasmPubkey.set(pubkeyBytes);
        
        const wasmTags = new Uint8Array(exports.memory.buffer, tagsPtr, tagsBytes.length);
        wasmTags.set(tagsBytes);
        
        const wasmContent = new Uint8Array(exports.memory.buffer, contentPtr, contentBytes.length);
        wasmContent.set(contentBytes);
        
        console.log("\nTesting Nostr event ID creation:");
        console.log("Pubkey:", pubkeyHex);
        console.log("Created at:", createdAt);
        console.log("Kind:", kind);
        console.log("Tags:", tagsJson);
        console.log("Content:", content);
        
        // Call WASM function
        const success = exports.wasm_create_nostr_event_id(
            pubkeyPtr,
            BigInt(createdAt), // Use BigInt for u64
            kind,
            tagsPtr,
            tagsBytes.length,
            contentPtr,
            contentBytes.length,
            eventIdPtr
        );
        
        if (!success) {
            throw new Error("Event ID creation failed");
        }
        
        // Read the event ID from WASM memory
        const eventIdBytes = new Uint8Array(exports.memory.buffer, eventIdPtr, 32);
        const eventIdHex = bytesToHex(eventIdBytes);
        console.log("\nWASM Event ID:", eventIdHex);
        
        // Calculate expected event ID manually
        const eventArray = [
            0,
            pubkeyHex,
            createdAt,
            kind,
            tags,
            content
        ];
        const serialized = JSON.stringify(eventArray);
        const expectedHash = createHash('sha256').update(serialized).digest('hex');
        console.log("Expected ID:  ", expectedHash);
        
        if (eventIdHex === expectedHash) {
            console.log("✅ Event ID calculation is correct!");
        } else {
            console.log("❌ Event ID calculation differs!");
            console.log("\nDebug info:");
            console.log("Serialized event:", serialized);
        }
        
        // Test with empty content
        console.log("\n--- Testing with empty content ---");
        const emptyContentPtr = exports.wasm_alloc(1);
        const emptyEventIdPtr = exports.wasm_alloc(32);
        
        const emptySuccess = exports.wasm_create_nostr_event_id(
            pubkeyPtr,
            BigInt(createdAt),
            kind,
            tagsPtr,
            tagsBytes.length,
            emptyContentPtr,
            0, // empty content
            emptyEventIdPtr
        );
        
        if (emptySuccess) {
            const emptyEventIdBytes = new Uint8Array(exports.memory.buffer, emptyEventIdPtr, 32);
            const emptyEventIdHex = bytesToHex(emptyEventIdBytes);
            
            const emptyEventArray = [0, pubkeyHex, createdAt, kind, tags, ""];
            const emptyExpectedHash = createHash('sha256').update(JSON.stringify(emptyEventArray)).digest('hex');
            
            console.log("WASM Event ID:", emptyEventIdHex);
            console.log("Expected ID:  ", emptyExpectedHash);
            console.log(emptyEventIdHex === emptyExpectedHash ? "✅ Correct!" : "❌ Incorrect!");
        }
        
        exports.wasm_free(emptyContentPtr, 1);
        exports.wasm_free(emptyEventIdPtr, 32);
        
    } finally {
        // Clean up
        exports.wasm_free(pubkeyPtr, pubkeyBytes.length);
        exports.wasm_free(tagsPtr, tagsBytes.length);
        exports.wasm_free(contentPtr, contentBytes.length);
        exports.wasm_free(eventIdPtr, 32);
    }
}

// Run the test
testNostrEventId().catch(console.error);