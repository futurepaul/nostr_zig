import { readFileSync } from 'fs';
import { resolve } from 'path';

// Load WASM module
const wasmPath = resolve(__dirname, '../visualizer/src/nostr_mls.wasm');
const wasmBuffer = readFileSync(wasmPath);

// Define WASM imports
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
        getCurrentTimestamp: () => BigInt(Math.floor(Date.now() / 1000))
    }
};

// Instantiate WASM
const wasmModule = new WebAssembly.Module(wasmBuffer);
const wasmInstance = new WebAssembly.Instance(wasmModule, imports);
const exports = wasmInstance.exports as any;

console.log('Available WASM exports:');
console.log('======================');

const allExports = Object.keys(exports).sort();
console.log(`Total exports: ${allExports.length}`);

// Group exports by category
const categories = {
    state_machine: allExports.filter(name => name.includes('state_machine')),
    mls: allExports.filter(name => name.includes('mls')),
    nip_ee: allExports.filter(name => name.includes('nip_ee')),
    crypto: allExports.filter(name => name.includes('crypto') || name.includes('identity')),
    memory: allExports.filter(name => name.includes('alloc') || name.includes('free') || name === 'memory'),
    other: allExports.filter(name => 
        !name.includes('state_machine') && 
        !name.includes('mls') && 
        !name.includes('nip_ee') && 
        !name.includes('crypto') && 
        !name.includes('identity') &&
        !name.includes('alloc') && 
        !name.includes('free') && 
        name !== 'memory'
    )
};

console.log('\n📦 State Machine Exports:');
categories.state_machine.forEach(name => console.log(`  - ${name}`));

console.log('\n🔐 MLS Exports:');
categories.mls.forEach(name => console.log(`  - ${name}`));

console.log('\n📝 NIP-EE Exports:');
categories.nip_ee.forEach(name => console.log(`  - ${name}`));

console.log('\n🔑 Crypto Exports:');
categories.crypto.forEach(name => console.log(`  - ${name}`));

console.log('\n💾 Memory Exports:');
categories.memory.forEach(name => console.log(`  - ${name}`));

console.log('\n🔧 Other Exports:');
categories.other.forEach(name => console.log(`  - ${name}`));