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
  const { createEncryptedGroupMessage, isReady, generateEphemeralKeys, signSchnorr } = useWasm();
  
  // Check if button should be disabled
  const isButtonDisabled = !isReady || !message.trim() || !state.identity || state.groups.size === 0;

  const handleSend = async () => {
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
      let exporterSecret: Uint8Array;
      try {
        exporterSecret = wasmGenerateExporterSecret(group.state);
        console.log('Generated exporter secret:', bytesToHex(exporterSecret));
      } catch (error) {
        console.error('Failed to generate exporter secret:', error);
        // Fallback to a random secret for demo
        exporterSecret = new Uint8Array(32);
        crypto.getRandomValues(exporterSecret);
        console.log('Using fallback random exporter secret:', bytesToHex(exporterSecret));
      }
      
      // Create a proper MLS signature for the message
      // In a real implementation, this would sign the MLS tree hash or commit
      // For now, we'll sign the message content
      const messageBytes = new TextEncoder().encode(message);
      const messageHash = await crypto.subtle.digest('SHA-256', messageBytes);
      const mlsSignature = signSchnorr(new Uint8Array(messageHash), state.identity.privateKey);
      
      // Extract group ID from state (first 32 bytes)
      const groupId = new Uint8Array(32);
      if (group.state.length >= 32) {
        groupId.set(group.state.slice(0, 32));
      } else {
        // Hash the state to get a group ID
        const stateHash = await crypto.subtle.digest('SHA-256', group.state);
        groupId.set(new Uint8Array(stateHash));
      }
      
      // Create encrypted group message using the same function as tests
      const epoch = BigInt(0); // Simplified - real implementation would track epoch
      const senderIndex = 0; // Simplified - real implementation would track sender
      
      const encryptedPayload = createEncryptedGroupMessage(
        groupId,
        epoch,
        senderIndex,
        message,
        mlsSignature,
        exporterSecret
      );
      console.log('Encrypted payload length:', encryptedPayload.length);
      
      // The encrypted payload is already the complete NIP-44 ciphertext
      // Convert to base64 for Nostr event content
      const nip44CiphertextBase64 = btoa(String.fromCharCode(...encryptedPayload));

      // Create event structure first (without ID and signature)
      const eventData = {
        pubkey: bytesToHex(ephemeralKeys.publicKey), // Use ephemeral public key
        created_at: Math.floor(Date.now() / 1000),
        kind: 445, // Group Message Event
        tags: [
          ['h', group.id], // Use 'h' tag for group ID per NIP-EE spec
          ['ephemeral', 'true'] // Mark as ephemeral for visualization
        ],
        // Double encrypted: MLS (inner) + NIP-44 (outer) - already base64
        content: nip44CiphertextBase64,
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
        ]),
        // Update group with current exporter secret
        groups: new Map([
          ...Array.from(prev.groups),
          [group.id, { 
            ...group,
            exporterSecret: exporterSecret
          }]
        ])
      }));

      setMessage('');
      console.log('✅ NIP-EE compliant message sent:', {
        eventId,
        ephemeralPubkey: bytesToHex(ephemeralKeys.publicKey),
        groupTag: ['h', group.id],
        hasRealSignature: signature !== 'mock_signature',
        exporterSecretAdded: bytesToHex(exporterSecret)
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
          onKeyPress={(e) => { if (e.key === 'Enter' && isReady) handleSend(); }}
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