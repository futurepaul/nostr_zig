import React, { useState } from 'react';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { useWasm } from './WasmProvider';
import { MLSState } from './MLSVisualizer';
import { getRandomBytes, hexToBytes, bytesToHex } from '../utils/crypto';

interface MessageComposerProps {
  state: MLSState;
  setState: React.Dispatch<React.SetStateAction<MLSState>>;
}

export function MessageComposer({ state, setState }: MessageComposerProps) {
  const [message, setMessage] = useState('');
  const { sendMessage } = useWasm();

  const handleSend = () => {
    if (!message.trim() || !state.identity || state.groups.size === 0) return;

    // Get the first group (for demo purposes)
    const group = Array.from(state.groups.values())[0];
    
    try {
      // Generate ephemeral key pair for this message
      const ephemeralPrivateKey = getRandomBytes(32);
      // In a real implementation, we'd derive the public key properly
      // For now, we'll simulate it
      const ephemeralPublicKey = getRandomBytes(32);
      
      // Send encrypted message
      const ciphertext = sendMessage(
        group.state,
        state.identity.privateKey,
        message
      );

      // Add to local messages (unencrypted view)
      setState(prev => ({
        ...prev,
        messages: [...prev.messages, {
          sender: state.identity!.nickname,
          content: message,
          timestamp: Date.now(),
          encrypted: false,
        }],
      }));

      // Create encrypted message event with ephemeral pubkey
      const event = {
        id: Math.random().toString(36).substring(7),
        pubkey: bytesToHex(ephemeralPublicKey), // Use ephemeral public key
        created_at: Math.floor(Date.now() / 1000),
        kind: 445,
        tags: [
          ['g', group.id],
          ['ephemeral', 'true'] // Mark as ephemeral for visualization
        ],
        content: btoa(String.fromCharCode(...ciphertext)),
        sig: 'mock_signature',
      };

      setState(prev => ({
        ...prev,
        events: [...prev.events, event],
        // Track ephemeral key usage for visualization
        ephemeralKeys: new Map([
          ...Array.from(prev.ephemeralKeys || new Map()),
          [event.id, { 
            publicKey: ephemeralPublicKey,
            timestamp: Date.now(),
            messageId: event.id
          }]
        ])
      }));

      setMessage('');
      
      // Log ephemeral key usage for debugging
      console.log('Message sent with ephemeral key:', {
        eventId: event.id,
        ephemeralPubkey: bytesToHex(ephemeralPublicKey),
        realPubkey: bytesToHex(state.identity.publicKey)
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
          placeholder="Type a message..."
          onKeyPress={(e) => e.key === 'Enter' && handleSend()}
        />
        <Button onClick={handleSend} size="sm">
          Send
        </Button>
      </div>
    </div>
  );
}