// WebAssembly imports for secure randomness and other browser APIs

export function createWasmImports(wasmMemory: WebAssembly.Memory) {
  return {
    env: {
      // Provide secure randomness from the browser's crypto API
      getRandomValues: (ptr: number, len: number) => {
        const bytes = new Uint8Array(wasmMemory.buffer, ptr, len);
        crypto.getRandomValues(bytes);
      },
      
      // Console logging for debugging
      consoleLog: (ptr: number, len: number) => {
        const bytes = new Uint8Array(wasmMemory.buffer, ptr, len);
        const text = new TextDecoder().decode(bytes);
        console.log('[WASM]:', text);
      },
      
      // High-resolution timestamp
      performanceNow: () => {
        return performance.now();
      },
      
      // Current Unix timestamp in seconds
      getCurrentTimestamp: () => {
        return Math.floor(Date.now() / 1000);
      }
    }
  };
}

// Helper to instantiate WASM with proper imports
export async function instantiateWasm(wasmPath: string): Promise<{
  instance: WebAssembly.Instance;
  memory: WebAssembly.Memory;
}> {
  // Create memory that can be shared
  const memory = new WebAssembly.Memory({
    initial: 1,
    maximum: 10,
    shared: false
  });
  
  const imports = createWasmImports(memory);
  
  // Add memory to imports
  const fullImports = {
    ...imports,
    env: {
      ...imports.env,
      memory
    }
  };
  
  const response = await fetch(wasmPath);
  const { instance } = await WebAssembly.instantiateStreaming(response, fullImports);
  
  return { instance, memory };
}