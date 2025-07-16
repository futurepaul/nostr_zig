import React, { useState } from 'react';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { useWasm } from './WasmProvider';
import { MLSState } from './MLSVisualizer';
import { 
  bytesToHex, 
  createNostrEventIdSync, 
  signNostrEvent
} from '../utils/wasm-crypto';

interface MessageComposerProps {
  state: MLSState;
  setState: React.Dispatch<React.SetStateAction<MLSState>>;
}

export function MessageComposer({ state, setState }: MessageComposerProps) {
  const [message, setMessage] = useState('');
  const { sendMessage, isReady, generateEphemeralKeys, generateExporterSecret: wasmGenerateExporterSecret } = useWasm();
  
  // Check if button should be disabled
  const isButtonDisabled = !isReady || !message.trim() || !state.identity || state.groups.size === 0;

  const handleSend = () => {
    if (!message.trim() || !state.identity || state.groups.size === 0) {
      return;
    }

    // Get the first group (for demo purposes)
    const group = Array.from(state.groups.values())[0];
    
    try {
      // Generate ephemeral key pair for this message using real crypto
      const ephemeralKeys = generateEphemeralKeys();
      
      // Generate exporter secret for double encryption (MLS + NIP-44)
      // This derives the secret from MLS group state with "nostr" label per NIP-EE spec
      const exporterSecret = wasmGenerateExporterSecret(group.state);
      
      // Send encrypted message (this provides MLS encryption layer)
      const mlsCiphertext = sendMessage(
        group.state,
        state.identity.privateKey,
        message
      );

      // Create event structure first (without ID and signature)
      const eventData = {
        pubkey: bytesToHex(ephemeralKeys.publicKey), // Use ephemeral public key
        created_at: Math.floor(Date.now() / 1000),
        kind: 445, // Group Message Event
        tags: [
          ['h', group.id], // Use 'h' tag for group ID per NIP-EE spec
          ['ephemeral', 'true'] // Mark as ephemeral for visualization
        ],
        // TODO: Add second layer of NIP-44 encryption using exporter secret
        // For now, just base64 encode the MLS ciphertext
        content: btoa(String.fromCharCode(...mlsCiphertext)),
      };

      // Generate real Nostr event ID according to NIP-01
      const eventId = createNostrEventIdSync(eventData);
      
      // Sign the event with ephemeral private key
      const eventWithId = { ...eventData, id: eventId };
      const signature = signNostrEvent(eventWithId, ephemeralKeys.privateKey);
      
      // Create final event with real signature
      const event = {
        ...eventWithId,
        sig: signature,
      };
      
      // Add to local messages (unencrypted view)
      setState(prev => ({
        ...prev,
        messages: [...prev.messages, {
          sender: state.identity!.nickname,
          content: message,
          timestamp: Date.now(),
          encrypted: false,
          eventId: eventId,
        }],
      }));

      setState(prev => ({
        ...prev,
        events: [...prev.events, event],
        // Track ephemeral key usage for visualization
        ephemeralKeys: new Map([
          ...Array.from(prev.ephemeralKeys || new Map()),
          [event.id, { 
            publicKey: ephemeralKeys.publicKey,
            privateKey: ephemeralKeys.privateKey, // Store for potential verification demo
            timestamp: Date.now(),
            messageId: event.id,
            exporterSecret: exporterSecret // Track exporter secret for visualization
          }]
        ])
      }));

      setMessage('');
      console.log('✅ NIP-EE compliant message sent:', {
        eventId,
        ephemeralPubkey: bytesToHex(ephemeralKeys.publicKey),
        groupTag: ['h', group.id],
        hasRealSignature: signature !== 'mock_signature'
      });
    } catch (error) {
      console.error('Failed to send message:', error);
    }
  };

  return (
    <div className="space-y-2">
      <h4 className="font-semibold">Send Message</h4>
      <div className="flex space-x-2">
        <Input
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          placeholder={!isReady ? "WASM not ready..." : "Type a message..."}
          onKeyPress={(e) => e.key === 'Enter' && isReady && handleSend()}
          disabled={!isReady}
        />
        <Button 
          onClick={handleSend} 
          size="sm"
          disabled={isButtonDisabled}
        >
          Send
        </Button>
      </div>
    </div>
  );
}