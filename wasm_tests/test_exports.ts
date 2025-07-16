import { readFileSync } from "fs";
import { resolve } from "path";

// Load WASM file
const wasmPath = resolve(__dirname, "../visualizer/src/nostr_mls.wasm");
const wasmBuffer = readFileSync(wasmPath);

async function testExports() {
    console.log("🔧 Loading WASM module...");
    
    let wasmMemory: WebAssembly.Memory | null = null;
    
    // Create imports for WASM
    const imports = {
        env: {
            getRandomValues: (ptr: number, len: number) => {
                if (!wasmMemory) throw new Error('WASM memory not available');
                const bytes = new Uint8Array(wasmMemory.buffer, ptr, len);
                crypto.getRandomValues(bytes);
            },
            wasm_log_error: (strPtr: number, len: number) => {
                if (!wasmMemory) throw new Error('WASM memory not available');
                const bytes = new Uint8Array(wasmMemory.buffer, strPtr, len);
                const message = new TextDecoder().decode(bytes);
                console.error('secp256k1 error:', message);
            }
        }
    };
    
    // Compile and instantiate WASM
    const wasmModule = await WebAssembly.compile(wasmBuffer);
    const instance = await WebAssembly.instantiate(wasmModule, imports);
    
    wasmMemory = instance.exports.memory as WebAssembly.Memory;
    
    console.log("\n📦 All exports:");
    const exports = Object.keys(instance.exports).sort();
    exports.forEach(name => {
        const exp = instance.exports[name];
        const type = typeof exp === 'function' ? 'function' : 'other';
        console.log(`  ${name}: ${type}`);
    });
    
    console.log(`\n📊 Total exports: ${exports.length}`);
    console.log(`🔧 Functions: ${exports.filter(e => typeof instance.exports[e] === 'function').length}`);
}

// Run the test
testExports().catch(console.error);