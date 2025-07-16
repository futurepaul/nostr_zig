import React, { useState } from 'react';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { useWasm } from './WasmProvider';
import { MLSState } from './MLSVisualizer';
import { bytesToHex } from '../utils/wasm-crypto';

interface MessageComposerProps {
  state: MLSState;
  setState: React.Dispatch<React.SetStateAction<MLSState>>;
}

export function MessageComposer({ state, setState }: MessageComposerProps) {
  const [message, setMessage] = useState('');
  const { sendMessage, isReady, generateEphemeralKeys } = useWasm();
  
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
      
      // Send encrypted message
      const ciphertext = sendMessage(
        group.state,
        state.identity.privateKey,
        message
      );

      // Generate event ID first so we can reference it
      const eventId = Math.random().toString(36).substring(7);
      
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

      // Create encrypted message event with ephemeral pubkey
      const event = {
        id: eventId,
        pubkey: bytesToHex(ephemeralKeys.publicKey), // Use ephemeral public key
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
            publicKey: ephemeralKeys.publicKey,
            timestamp: Date.now(),
            messageId: event.id
          }]
        ])
      }));

      setMessage('');
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