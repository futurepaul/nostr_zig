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
  // REMOVED: createGroup - use initGroup instead
  // REMOVED: generateExporterSecret - use generateExporterSecretForEpoch instead
  // REMOVED: nip44Encrypt/Decrypt - use createEncryptedGroupMessage/decryptGroupMessage instead
  // REMOVED: sendMessage - use createEncryptedGroupMessage instead
  createEncryptedGroupMessage: (
    groupId: Uint8Array,
    epoch: bigint,
    senderIndex: number,
    messageContent: string,
    mlsSignature: Uint8Array,
    exporterSecret: Uint8Array
  ) => Uint8Array;
  // REMOVED: deserializeMLSMessage - MLS messages are handled internally
  decryptGroupMessage: (exporterSecret: Uint8Array, encryptedData: Uint8Array) => Uint8Array;
  // Event publishing functions
  wasmReady: boolean;
  createTextNote: (privateKey: Uint8Array, content: string) => string;
  getPublicKey: (privateKey: Uint8Array) => Uint8Array;
  pubkeyToHex: (publicKey: Uint8Array) => string;
  verifyEvent: (eventJson: string) => boolean;
  
  // Real MLS State Machine Functions
  initGroup: (groupId: Uint8Array, creatorIdentityPubkey: Uint8Array, creatorSigningKey: Uint8Array) => { 
    state: Uint8Array; 
    epoch: bigint; 
    memberCount: number 
  };
  proposeAddMember: (state: Uint8Array, memberKeyPackage: Uint8Array) => { 
    newState: Uint8Array; 
    epoch: bigint; 
    memberCount: number 
  };
  commitProposals: (state: Uint8Array) => { 
    newState: Uint8Array; 
    epoch: bigint; 
    memberCount: number; 
    secretsRotated: boolean 
  };
  getGroupInfo: (state: Uint8Array) => { 
    groupId: Uint8Array; 
    epoch: bigint; 
    memberCount: number 
  };
  generateExporterSecretForEpoch: (state: Uint8Array) => Uint8Array;
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
        // WASM test removed - add function no longer exists
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
    // Deprecated functions removed - use MLS state machine and NIP-EE functions instead
    createEncryptedGroupMessage: (groupId, epoch, senderIndex, messageContent, mlsSignature, exporterSecret) => 
      wasm.createEncryptedGroupMessage(groupId, epoch, senderIndex, messageContent, mlsSignature, exporterSecret),
    // deserializeMLSMessage removed - handled internally
    decryptGroupMessage: (exporterSecret, encryptedData) => wasm.decryptGroupMessage(exporterSecret, encryptedData),
    // Event publishing functions
    wasmReady: isReady,
    createTextNote: (privateKey, content) => wasm.createTextNote(privateKey, content),
    getPublicKey: (privateKey) => wasm.getPublicKey(privateKey),
    pubkeyToHex: (publicKey) => wasm.pubkeyToHex(publicKey),
    verifyEvent: (eventJson) => wasm.verifyEvent(eventJson),
    
    // Real MLS State Machine Functions
    initGroup: (groupId, creatorIdentityPubkey, creatorSigningKey) => 
      wasm.initGroup(groupId, creatorIdentityPubkey, creatorSigningKey),
    proposeAddMember: (state, memberKeyPackage) => 
      wasm.proposeAddMember(state, memberKeyPackage),
    commitProposals: (state) => 
      wasm.commitProposals(state),
    getGroupInfo: (state) => 
      wasm.getGroupInfo(state),
    generateExporterSecretForEpoch: (state) => 
      wasm.generateExporterSecretForEpoch(state),
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