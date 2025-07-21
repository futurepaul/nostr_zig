import React, { createContext, useContext, useEffect, useState } from 'react';
import { wasm } from '../lib/wasm';

interface WasmContextType {
  isReady: boolean;
  error: Error | null;
  createIdentity: () => { privateKey: Uint8Array; publicKey: Uint8Array };
  generateEphemeralKeys: () => { privateKey: Uint8Array; publicKey: Uint8Array };
  generateMLSSigningKeys: () => { privateKey: Uint8Array; publicKey: Uint8Array };
  signSchnorr: (messageHash: Uint8Array, privateKey: Uint8Array) => Uint8Array;
  createKeyPackage: (privateKey: Uint8Array) => Uint8Array;
  createGroup: (creatorPrivateKey: Uint8Array, creatorPublicKey: Uint8Array) => Uint8Array;
  generateExporterSecret: (groupState: Uint8Array) => Uint8Array;
  nip44Encrypt: (exporterSecret: Uint8Array, plaintext: string) => Uint8Array;
  nip44Decrypt: (exporterSecret: Uint8Array, ciphertext: Uint8Array) => string;
  nip44DecryptBytes: (exporterSecret: Uint8Array, ciphertext: Uint8Array) => Uint8Array;
  sendMessage: (groupState: Uint8Array, senderPrivateKey: Uint8Array, message: string) => Uint8Array;
  createEncryptedGroupMessage: (
    groupId: Uint8Array,
    epoch: bigint,
    senderIndex: number,
    messageContent: string,
    mlsSignature: Uint8Array,
    exporterSecret: Uint8Array
  ) => Uint8Array;
  deserializeMLSMessage: (serializedData: Uint8Array) => {
    groupId: Uint8Array;
    epoch: bigint;
    senderIndex: number;
    applicationData: string;
    signature: Uint8Array;
  };
  decryptGroupMessage: (exporterSecret: Uint8Array, encryptedData: Uint8Array) => Uint8Array;
  // Event publishing functions
  wasmReady: boolean;
  createTextNote: (privateKey: Uint8Array, content: string) => string;
  getPublicKey: (privateKey: Uint8Array) => Uint8Array;
  pubkeyToHex: (publicKey: Uint8Array) => string;
  verifyEvent: (eventJson: string) => boolean;
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
    generateMLSSigningKeys: () => wasm.generateMLSSigningKeys(),
    signSchnorr: (messageHash, privateKey) => wasm.signSchnorr(messageHash, privateKey),
    createKeyPackage: (privateKey) => wasm.createKeyPackage(privateKey),
    createGroup: (creatorPrivateKey, creatorPublicKey) => wasm.createGroup(creatorPrivateKey, creatorPublicKey),
    generateExporterSecret: (groupState) => wasm.generateExporterSecret(groupState),
    nip44Encrypt: (exporterSecret, plaintext) => wasm.nip44Encrypt(exporterSecret, plaintext),
    nip44Decrypt: (exporterSecret, ciphertext) => wasm.nip44Decrypt(exporterSecret, ciphertext),
    nip44DecryptBytes: (exporterSecret, ciphertext) => wasm.nip44DecryptBytes(exporterSecret, ciphertext),
    sendMessage: (groupState, senderPrivateKey, message) => wasm.sendMessage(groupState, senderPrivateKey, message),
    createEncryptedGroupMessage: (groupId, epoch, senderIndex, messageContent, mlsSignature, exporterSecret) => 
      wasm.createEncryptedGroupMessage(groupId, epoch, senderIndex, messageContent, mlsSignature, exporterSecret),
    deserializeMLSMessage: (serializedData) => wasm.deserializeMLSMessage(serializedData),
    decryptGroupMessage: (exporterSecret, encryptedData) => wasm.decryptGroupMessage(exporterSecret, encryptedData),
    // Event publishing functions
    wasmReady: isReady,
    createTextNote: (privateKey, content) => wasm.createTextNote(privateKey, content),
    getPublicKey: (privateKey) => wasm.getPublicKey(privateKey),
    pubkeyToHex: (publicKey) => wasm.pubkeyToHex(publicKey),
    verifyEvent: (eventJson) => wasm.verifyEvent(eventJson),
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