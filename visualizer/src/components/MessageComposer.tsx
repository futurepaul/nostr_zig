import React, { useState } from 'react';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { useWasm } from './WasmProvider';
import { MLSState } from './MLSVisualizer';

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

      // Create encrypted message event
      const event = {
        id: Math.random().toString(36).substring(7),
        pubkey: Array.from(state.identity.publicKey).map(b => b.toString(16).padStart(2, '0')).join(''),
        created_at: Math.floor(Date.now() / 1000),
        kind: 445,
        tags: [['g', group.id]],
        content: btoa(String.fromCharCode(...ciphertext)),
        sig: 'mock_signature',
      };

      setState(prev => ({
        ...prev,
        events: [...prev.events, event],
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