import React, { useState } from 'react';
import { WasmProvider, useWasm } from './WasmProvider';
import { ParticipantPanel } from './ParticipantPanel';
import { ProtocolFlow } from './ProtocolFlow';
import { NostrEventViewer } from './NostrEventViewer';
import { MessageFlow } from './MessageFlow';
import { StateTransitionDiagram } from './StateTransitionDiagram';
import { InfoPanelProvider } from './InfoPanel';
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
      <InfoPanelProvider>
        <div className="min-h-screen bg-gray-50 p-4">
          <div className="w-full">
            <h1 className="text-3xl font-bold text-center mb-8">
              NIP-EE MLS Visual Explainer
            </h1>
          
          <div className="grid grid-cols-3 gap-4">
            {/* Alice Panel */}
            <div>
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
            <div>
              <ProtocolFlow
                currentStep={currentStep}
                aliceState={aliceState}
                bobState={bobState}
                events={allEvents}
                onEventClick={setSelectedEvent}
                knownIdentities={knownIdentities}
                selectedEvent={selectedEvent}
                setSelectedEvent={setSelectedEvent}
              />
            </div>

            {/* Bob Panel */}
            <div>
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

          {/* PGP-style Decryptor */}
          <div className="mt-8">
            <DecryptorBox />
          </div>

          {/* Message Flow and Protocol State */}
          <div className="mt-8 grid grid-cols-2 gap-4">
            <MessageFlowCard
              aliceState={aliceState}
              bobState={bobState}
              currentStep={currentStep}
              events={allEvents}
              knownIdentities={knownIdentities}
            />
            <ProtocolStateCard currentStep={currentStep} />
          </div>
        </div>
      </div>
      </InfoPanelProvider>
    </WasmProvider>
  );
}

// Message Flow Card component
function MessageFlowCard({
  aliceState,
  bobState,
  currentStep,
  events,
  knownIdentities,
}: {
  aliceState: MLSState;
  bobState: MLSState;
  currentStep: ProtocolStep;
  events: NostrEvent[];
  knownIdentities?: Map<string, any>;
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Message Flow</CardTitle>
      </CardHeader>
      <CardContent>
        <MessageFlow
          aliceState={aliceState}
          bobState={bobState}
          currentStep={currentStep}
          events={events}
          knownIdentities={knownIdentities}
        />
      </CardContent>
    </Card>
  );
}

// Protocol State Card component
function ProtocolStateCard({ currentStep }: { currentStep: ProtocolStep }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Protocol State</CardTitle>
      </CardHeader>
      <CardContent>
        <StateTransitionDiagram currentStep={currentStep} />
      </CardContent>
    </Card>
  );
}

// Two-stage decryptor component
function DecryptorBox() {
  const [encryptedData, setEncryptedData] = useState('');
  const [exporterSecret, setExporterSecret] = useState('');
  const [stage2Result, setStage2Result] = useState('');
  const [error, setError] = useState('');
  const [currentStage, setCurrentStage] = useState<'none' | 'stage2'>('none');
  const { decryptGroupMessage } = useWasm();

  const handleStage1Decrypt = async () => {
    setError('');
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

      // Use the NIP-EE decrypt function that handles both layers
      console.log('🔓 Attempting NIP-EE decryption (both layers)...');
      
      // First decode the base64 ciphertext to raw bytes
      const ciphertextBytes = Uint8Array.from(atob(nip44CiphertextBase64), c => c.charCodeAt(0));
      console.log('📦 Ciphertext bytes length:', ciphertextBytes.length);
      
      // Decrypt using the combined function
      const decryptedBytes = decryptGroupMessage(secretBytes, ciphertextBytes);
      console.log('✅ NIP-EE decryption successful! Decrypted length:', decryptedBytes.length);
      
      // The result is the decrypted Nostr event JSON
      const decryptedText = new TextDecoder().decode(decryptedBytes);
      setStage2Result(decryptedText);
      setCurrentStage('stage2');
      
      // Parse and format the result
      try {
        const parsedEvent = JSON.parse(decryptedText);
        const formattedResult = `🔓 NIP-EE Message Decrypted!

📨 Recovered Nostr Event:
${JSON.stringify(parsedEvent, null, 2)}

💬 Final Message Content:
"${parsedEvent.content || decryptedText}"`;
        setStage2Result(formattedResult);
      } catch (e) {
        // Not JSON, just show as text
        setStage2Result(`🔓 Decrypted Message:\n\n${decryptedText}`);
      }
      
    } catch (e) {
      setError('Stage 1 failed: ' + (e as Error).message);
      setCurrentStage('none');
    }
  };


  const clearAll = () => {
    setEncryptedData('');
    setExporterSecret('');
    setStage2Result('');
    setError('');
    setCurrentStage('none');
  };

  return (
    <Card className="border-2 border-blue-200 bg-blue-50">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-blue-800">
          🔐 Message Decryptor
        </CardTitle>
        <CardDescription className="text-blue-700">
          Paste encrypted message data and exporter secret to decrypt NIP-EE group messages. The content contains a serialized MLS MLSMessage encrypted with NIP-44.
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

        {/* NIP-EE Decryption */}
        <div className="space-y-4">
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
            🔓 Decrypt NIP-EE Message
          </Button>
          
          {stage2Result && (
            <div className="space-y-2">
              <label className="text-xs font-semibold text-green-700">✅ Decrypted Result:</label>
              <div className="p-2 bg-green-50 border border-green-200 rounded max-h-48 overflow-y-auto">
                <pre className="text-xs text-green-800 whitespace-pre-wrap">{stage2Result}</pre>
              </div>
            </div>
          )}
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
      </CardContent>
    </Card>
  );
}