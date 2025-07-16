import React, { createContext, useContext, useEffect, useState } from 'react';
import { wasm } from '../lib/wasm';

interface WasmContextType {
  isReady: boolean;
  error: Error | null;
  createIdentity: () => { privateKey: Uint8Array; publicKey: Uint8Array };
  generateEphemeralKeys: () => { privateKey: Uint8Array; publicKey: Uint8Array };
  createKeyPackage: (privateKey: Uint8Array) => Uint8Array;
  createGroup: (creatorPrivateKey: Uint8Array, creatorPublicKey: Uint8Array) => Uint8Array;
  sendMessage: (groupState: Uint8Array, senderPrivateKey: Uint8Array, message: string) => Uint8Array;
}

const WasmContext = createContext<WasmContextType | null>(null);

export function WasmProvider({ children }: { children: React.ReactNode }) {
  const [isReady, setIsReady] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    console.log('WasmProvider mounting, initializing WASM...');
    wasm.init()
      .then(() => {
        setIsReady(true);
        console.log('WASM initialized successfully in provider');
        // Test the wasm module
        try {
          const result = wasm.add(2, 3);
          console.log('WASM test: 2 + 3 =', result);
        } catch (testError) {
          console.error('WASM test failed:', testError);
        }
      })
      .catch((err) => {
        setError(err);
        console.error('Failed to initialize WASM in provider:', err);
      });
  }, []);

  const contextValue: WasmContextType = {
    isReady,
    error,
    createIdentity: () => wasm.createIdentity(),
    generateEphemeralKeys: () => wasm.generateEphemeralKeys(),
    createKeyPackage: (privateKey) => wasm.createKeyPackage(privateKey),
    createGroup: (creatorPrivateKey, creatorPublicKey) => wasm.createGroup(creatorPrivateKey, creatorPublicKey),
    sendMessage: (groupState, senderPrivateKey, message) => wasm.sendMessage(groupState, senderPrivateKey, message),
  };

  return (
    <WasmContext.Provider value={contextValue}>
      {children}
    </WasmContext.Provider>
  );
}

export function useWasm() {
  const context = useContext(WasmContext);
  if (!context) {
    throw new Error('useWasm must be used within a WasmProvider');
  }
  return context;
}