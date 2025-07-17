import React, { useState } from 'react';
import { WasmProvider, useWasm } from './WasmProvider';
import { ParticipantPanel } from './ParticipantPanel';
import { ProtocolFlow } from './ProtocolFlow';
import { NostrEventViewer } from './NostrEventViewer';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card';
import { Button } from './ui/button';

export interface Identity {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  nickname: string;
}

export interface KeyPackage {
  data: Uint8Array;
  timestamp: number;
}

export interface GroupState {
  id: string;
  state: Uint8Array;
  members: string[];
  exporterSecret?: Uint8Array; // Current decryption key for NIP-44 layer
  groupSecret?: Uint8Array; // Group encryption secret for MLS layer
}

export interface NostrEvent {
  id: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
  sig: string;
}

export interface Message {
  sender: string;
  content: string;
  timestamp: number;
  encrypted: boolean;
  eventId?: string; // Optional event ID to track the source Nostr event
  decrypted?: string; // Optional decrypted content
}

export interface EphemeralKeyInfo {
  publicKey: Uint8Array;
  privateKey?: Uint8Array; // For verification demos
  timestamp: number;
  messageId: string;
  exporterSecret?: Uint8Array; // For decryption demos
}

export interface MLSState {
  identity?: Identity;
  keyPackage?: KeyPackage;
  groups: Map<string, GroupState>;
  events: NostrEvent[];
  messages: Message[];
  pendingInvite?: {
    groupId: string;
    keyPackage: KeyPackage;
  };
  ephemeralKeys?: Map<string, EphemeralKeyInfo>;
}

export type ProtocolStep = 
  | 'setup'
  | 'keyPackages'
  | 'groupCreation'
  | 'welcome'
  | 'groupJoined'
  | 'messaging';

export function MLSVisualizer() {
  const [aliceState, setAliceState] = useState<MLSState>({
    groups: new Map(),
    events: [],
    messages: [],
    ephemeralKeys: new Map(),
  });

  const [bobState, setBobState] = useState<MLSState>({
    groups: new Map(),
    events: [],
    messages: [],
    ephemeralKeys: new Map(),
  });

  const [currentStep, setCurrentStep] = useState<ProtocolStep>('setup');
  const [selectedEvent, setSelectedEvent] = useState<NostrEvent | null>(null);

  const allEvents = [...aliceState.events, ...bobState.events].sort(
    (a, b) => a.created_at - b.created_at
  );
  
  // Build known identities map
  const knownIdentities = new Map<string, any>();
  if (aliceState.identity) {
    const alicePubkey = Array.from(aliceState.identity.publicKey)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
    knownIdentities.set(alicePubkey, { name: 'Alice', identity: aliceState.identity });
  }
  if (bobState.identity) {
    const bobPubkey = Array.from(bobState.identity.publicKey)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
    knownIdentities.set(bobPubkey, { name: 'Bob', identity: bobState.identity });
  }

  return (
    <WasmProvider>
      <div className="min-h-screen bg-gray-50 p-4">
        <div className="max-w-7xl mx-auto">
          <h1 className="text-3xl font-bold text-center mb-8">
            NIP-EE MLS Visual Explainer
          </h1>
          
          <div className="grid grid-cols-12 gap-4">
            {/* Alice Panel */}
            <div className="col-span-3">
              <ParticipantPanel
                name="Alice"
                state={aliceState}
                setState={setAliceState}
                otherState={bobState}
                currentStep={currentStep}
                setCurrentStep={setCurrentStep}
                isCreator={true}
              />
            </div>

            {/* Protocol Flow */}
            <div className="col-span-6">
              <ProtocolFlow
                currentStep={currentStep}
                aliceState={aliceState}
                bobState={bobState}
                events={allEvents}
                onEventClick={setSelectedEvent}
                knownIdentities={knownIdentities}
              />
            </div>

            {/* Bob Panel */}
            <div className="col-span-3">
              <ParticipantPanel
                name="Bob"
                state={bobState}
                setState={setBobState}
                otherState={aliceState}
                currentStep={currentStep}
                setCurrentStep={setCurrentStep}
                isCreator={false}
              />
            </div>
          </div>

          {/* Event Viewer */}
          {selectedEvent && (
            <div className="mt-8">
              <NostrEventViewer
                event={selectedEvent}
                onClose={() => setSelectedEvent(null)}
                knownIdentities={knownIdentities}
              />
            </div>
          )}

          {/* PGP-style Decryptor */}
          <div className="mt-8">
            <DecryptorBox />
          </div>
        </div>
      </div>
    </WasmProvider>
  );
}

// Two-stage decryptor component
function DecryptorBox() {
  const [encryptedData, setEncryptedData] = useState('');
  const [exporterSecret, setExporterSecret] = useState('');
  const [mlsSecret, setMlsSecret] = useState('');
  const [stage1Result, setStage1Result] = useState('');
  const [stage2Result, setStage2Result] = useState('');
  const [error, setError] = useState('');
  const [currentStage, setCurrentStage] = useState<'none' | 'stage1' | 'stage2'>('none');
  const { nip44Decrypt } = useWasm();

  const handleStage1Decrypt = async () => {
    setError('');
    setStage1Result('');
    setStage2Result('');
    
    try {
      // Parse the encrypted data
      console.log('🔍 Parsing encrypted data...');
      const event = JSON.parse(encryptedData);
      console.log('📦 Event parsed:', {
        kind: event.kind,
        contentLength: event.content?.length,
        tags: event.tags
      });
      
      if (!event.content || !event.kind || event.kind !== 445) {
        throw new Error('Invalid encrypted data format. Expected Nostr event with kind 445.');
      }

      if (exporterSecret.length !== 64) {
        throw new Error('Exporter secret should be 64 hex characters (32 bytes)');
      }

      console.log('🔑 Converting exporter secret from hex...');
      // Convert hex exporter secret to bytes
      const secretBytes = new Uint8Array(32);
      for (let i = 0; i < 32; i++) {
        secretBytes[i] = parseInt(exporterSecret.substr(i * 2, 2), 16);
      }
      console.log('🔑 Exporter secret bytes:', Array.from(secretBytes.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join(' ') + '...');

      // The content is already base64 NIP-44 ciphertext
      const nip44CiphertextBase64 = event.content;
      console.log('📝 NIP-44 ciphertext (base64):', nip44CiphertextBase64.substring(0, 50) + '...');
      
      // The wasm_nip44_decrypt expects base64 string as bytes, not raw bytes
      // So we need to encode the base64 string as UTF-8 bytes
      const encoder = new TextEncoder();
      const nip44CiphertextBytes = encoder.encode(nip44CiphertextBase64);
      console.log('📝 NIP-44 ciphertext (as UTF-8 bytes) length:', nip44CiphertextBytes.length, 'bytes');
      console.log('📝 First 16 bytes (UTF-8 of base64):', Array.from(nip44CiphertextBytes.slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join(' '));

      // Stage 1: Decrypt NIP-44 layer
      console.log('🔓 Attempting NIP-44 decryption...');
      const mlsBase64 = nip44Decrypt(secretBytes, nip44CiphertextBytes);
      console.log('✅ NIP-44 decryption successful! MLS payload length:', mlsBase64.length);
      
      setStage1Result(mlsBase64);
      setCurrentStage('stage1');
      
      console.log('✅ Stage 1 complete: NIP-44 decrypted, revealed MLS ciphertext');
      
    } catch (e) {
      setError('Stage 1 failed: ' + (e as Error).message);
      setCurrentStage('none');
    }
  };

  const handleStage2Decrypt = async () => {
    setError('');
    setStage2Result('');
    
    try {
      if (!stage1Result) {
        throw new Error('Must complete Stage 1 first');
      }

      if (mlsSecret.length !== 64) {
        throw new Error('MLS secret should be 64 hex characters (32 bytes)');
      }

      // For now, simulate MLS decryption since we don't have the full MLS implementation
      // In a real implementation, this would use the MLS group secret to decrypt
      setStage2Result(`🔓 Stage 2: MLS Decryption (Simulated)

MLS Ciphertext: ${stage1Result.substring(0, 100)}...

Note: This would use the MLS group secret to decrypt the inner layer.
In a full implementation, this would:
1. Parse the MLS message format
2. Use the current epoch's group secret
3. Decrypt to reveal the original plaintext message

Simulated result: "Hello from Alice!" (original message)`);
      
      setCurrentStage('stage2');
      console.log('✅ Stage 2 complete: MLS decrypted, revealed plaintext');
      
    } catch (e) {
      setError('Stage 2 failed: ' + (e as Error).message);
    }
  };

  const clearAll = () => {
    setEncryptedData('');
    setExporterSecret('');
    setMlsSecret('');
    setStage1Result('');
    setStage2Result('');
    setError('');
    setCurrentStage('none');
  };

  return (
    <Card className="border-2 border-blue-200 bg-blue-50">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-blue-800">
          🔐 Message Decryptor
          <span className="text-sm font-normal text-blue-600">(PGP-style UI)</span>
        </CardTitle>
        <CardDescription className="text-blue-700">
          Paste encrypted message data and decryption key to see how NIP-EE double encryption works
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Encrypted Data Input */}
        <div className="space-y-2">
          <label className="text-sm font-semibold">Encrypted Message Data:</label>
          <textarea
            value={encryptedData}
            onChange={(e) => setEncryptedData(e.target.value)}
            placeholder='Paste complete Nostr event JSON from "Copy Encrypted" button (should include id, pubkey, content, etc.)'
            className="w-full h-24 text-xs font-mono border rounded p-2 resize-none"
          />
        </div>

        {/* Two Stage Decryption */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Stage 1: NIP-44 Decryption */}
          <div className="space-y-3 p-4 border-2 border-orange-200 bg-orange-50 rounded">
            <h3 className="text-sm font-bold text-orange-800">🔓 Stage 1: NIP-44 Decryption (Outer Layer)</h3>
            
            <div className="space-y-2">
              <label className="text-xs font-semibold">Exporter Secret (64 hex chars):</label>
              <textarea
                value={exporterSecret}
                onChange={(e) => setExporterSecret(e.target.value)}
                placeholder="Paste exporter secret from Groups section..."
                className="w-full h-16 text-xs font-mono border rounded p-2 resize-none"
              />
            </div>
            
            <Button 
              onClick={handleStage1Decrypt} 
              disabled={!encryptedData || !exporterSecret || exporterSecret.length !== 64}
              size="sm"
              className="w-full"
            >
              🔓 Decrypt NIP-44 Layer
            </Button>
            
            {stage1Result && (
              <div className="space-y-2">
                <label className="text-xs font-semibold text-green-700">✅ NIP-44 Decrypted (MLS Ciphertext):</label>
                <div className="p-2 bg-green-50 border border-green-200 rounded max-h-32 overflow-y-auto">
                  <pre className="text-xs text-green-800 whitespace-pre-wrap break-all">{stage1Result}</pre>
                </div>
              </div>
            )}
          </div>

          {/* Stage 2: MLS Decryption */}
          <div className="space-y-3 p-4 border-2 border-purple-200 bg-purple-50 rounded">
            <h3 className="text-sm font-bold text-purple-800">🔐 Stage 2: MLS Decryption (Inner Layer)</h3>
            
            <div className="space-y-2">
              <label className="text-xs font-semibold">MLS Group Secret (64 hex chars):</label>
              <textarea
                value={mlsSecret}
                onChange={(e) => setMlsSecret(e.target.value)}
                placeholder="Paste MLS group secret (simulated for now)..."
                className="w-full h-16 text-xs font-mono border rounded p-2 resize-none"
              />
            </div>
            
            <Button 
              onClick={handleStage2Decrypt} 
              disabled={!stage1Result || !mlsSecret || mlsSecret.length !== 64}
              size="sm"
              className="w-full"
              variant={currentStage === 'stage1' ? 'default' : 'outline'}
            >
              🔐 Decrypt MLS Layer
            </Button>
            
            {stage2Result && (
              <div className="space-y-2">
                <label className="text-xs font-semibold text-green-700">✅ Final Result:</label>
                <div className="p-2 bg-green-50 border border-green-200 rounded max-h-32 overflow-y-auto">
                  <pre className="text-xs text-green-800 whitespace-pre-wrap">{stage2Result}</pre>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Progress Indicator */}
        <div className="flex items-center justify-center space-x-4 py-2">
          <div className={`px-3 py-1 rounded text-xs font-semibold ${
            currentStage === 'none' ? 'bg-gray-200 text-gray-600' :
            currentStage === 'stage1' ? 'bg-orange-200 text-orange-800' : 'bg-green-200 text-green-800'
          }`}>
            Stage 1: NIP-44
          </div>
          <div className="text-xl">→</div>
          <div className={`px-3 py-1 rounded text-xs font-semibold ${
            currentStage !== 'stage2' ? 'bg-gray-200 text-gray-600' : 'bg-green-200 text-green-800'
          }`}>
            Stage 2: MLS
          </div>
        </div>

        {/* Clear Button */}
        <div className="flex justify-center">
          <Button variant="outline" onClick={clearAll}>
            🗑️ Clear All
          </Button>
        </div>

        {/* Error Display */}
        {error && (
          <div className="p-3 bg-red-50 border border-red-200 rounded">
            <div className="text-sm font-semibold text-red-700">Error:</div>
            <div className="text-sm text-red-600 font-mono">{error}</div>
          </div>
        )}

        {/* Educational Info */}
        <div className="text-xs text-gray-600 bg-blue-50 p-3 rounded">
          <div className="font-semibold mb-1">💡 How NIP-EE Double Encryption Works:</div>
          <div className="space-y-1">
            <div><strong>Layer 1 (Inner):</strong> MLS encryption using group-derived secrets</div>
            <div><strong>Layer 2 (Outer):</strong> NIP-44 v2 encryption using exporter secret</div>
            <div><strong>Result:</strong> Only group members with current keys can decrypt</div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}