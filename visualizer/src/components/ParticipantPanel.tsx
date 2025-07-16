import React, { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card';
import { Button } from './ui/button';
import { IdentityCard } from './IdentityCard';
import { KeyPackageManager } from './KeyPackageManager';
import { MessageComposer } from './MessageComposer';
import { useWasm } from './WasmProvider';
import { MLSState, ProtocolStep, Message } from './MLSVisualizer';

interface ParticipantPanelProps {
  name: string;
  state: MLSState;
  setState: React.Dispatch<React.SetStateAction<MLSState>>;
  otherState: MLSState;
  currentStep: ProtocolStep;
  setCurrentStep: React.Dispatch<React.SetStateAction<ProtocolStep>>;
  isCreator: boolean;
}

export function ParticipantPanel({
  name,
  state,
  setState,
  otherState,
  currentStep,
  setCurrentStep,
  isCreator,
}: ParticipantPanelProps) {
  const { isReady, createIdentity, createKeyPackage, createGroup } = useWasm();
  
  // Watch for encrypted messages from the other participant
  React.useEffect(() => {
    // Look for kind 445 events from the other participant
    const otherEvents = otherState.events.filter(e => e.kind === 445);
    
    otherEvents.forEach(event => {
      // Check if we already have this message
      const hasMessage = state.messages.some(m => m.eventId === event.id);
      if (!hasMessage) {
        // Add as encrypted message
        setState(prev => ({
          ...prev,
          messages: [...prev.messages, {
            sender: otherState.identity?.nickname || 'Unknown',
            content: event.content, // Base64 encrypted content
            timestamp: event.created_at * 1000,
            encrypted: true,
            eventId: event.id,
          }]
        }));
      }
    });
  }, [otherState.events, state.messages, setState, otherState.identity]);

  const handleCreateIdentity = () => {
    if (!isReady) return;
    
    const { privateKey, publicKey } = createIdentity();
    setState(prev => ({
      ...prev,
      identity: {
        privateKey,
        publicKey,
        nickname: name,
      },
    }));

    // Progress to next step if both have identities
    if (otherState.identity && currentStep === 'setup') {
      setCurrentStep('keyPackages');
    }
  };

  const handleCreateKeyPackage = () => {
    if (!isReady || !state.identity) return;

    const keyPackageData = createKeyPackage(state.identity.privateKey);
    const keyPackage = {
      data: keyPackageData,
      timestamp: Date.now(),
    };

    setState(prev => ({
      ...prev,
      keyPackage,
    }));

    // Create a mock Nostr event
    const event = {
      id: Math.random().toString(36).substring(7),
      pubkey: Array.from(state.identity.publicKey).map(b => b.toString(16).padStart(2, '0')).join(''),
      created_at: Math.floor(Date.now() / 1000),
      kind: 443,
      tags: [],
      content: btoa(String.fromCharCode(...keyPackageData)),
      sig: 'mock_signature',
    };

    setState(prev => ({
      ...prev,
      events: [...prev.events, event],
    }));

    // Progress to next step if both have key packages
    if (otherState.keyPackage && currentStep === 'keyPackages') {
      setCurrentStep('groupCreation');
    }
  };

  const handleCreateGroup = () => {
    if (!isReady || !state.identity || !isCreator) return;

    const groupId = `group_${Date.now()}`;
    const groupStateData = createGroup(state.identity.privateKey, state.identity.publicKey);
    
    const groupState = {
      id: groupId,
      state: groupStateData,
      members: [name],
    };

    setState(prev => ({
      ...prev,
      groups: new Map(prev.groups).set(groupId, groupState),
    }));

    // Automatically add Bob's key package if available
    if (otherState.keyPackage) {
      // Store the group ID for Bob to join later
      setState(prev => ({
        ...prev,
        pendingInvite: {
          groupId,
          keyPackage: otherState.keyPackage,
        }
      }));
    }

    setCurrentStep('welcome');
  };

  const handleSendWelcome = () => {
    if (!isReady || !state.identity || !isCreator) return;
    
    // In a real implementation, this would add Bob to the group
    // and generate a welcome message
    // For now, we'll simulate this
    
    // Create a mock welcome event
    const welcomeEvent = {
      id: Math.random().toString(36).substring(7),
      pubkey: Array.from(state.identity.publicKey).map(b => b.toString(16).padStart(2, '0')).join(''),
      created_at: Math.floor(Date.now() / 1000),
      kind: 444,
      tags: [['p', Array.from(otherState.identity!.publicKey).map(b => b.toString(16).padStart(2, '0')).join('')]],
      content: btoa('mock_welcome_message'),
      sig: 'mock_signature',
    };

    setState(prev => ({
      ...prev,
      events: [...prev.events, welcomeEvent],
    }));

    setCurrentStep('groupJoined');
  };

  const handleJoinGroup = () => {
    if (!isReady || !state.identity || isCreator) return;
    
    // Bob joins the group
    const aliceGroup = Array.from(otherState.groups.values())[0];
    if (!aliceGroup) return;

    setState(prev => ({
      ...prev,
      groups: new Map(prev.groups).set(aliceGroup.id, {
        ...aliceGroup,
        members: [...aliceGroup.members, name],
      }),
    }));

    setCurrentStep('messaging');
  };

  return (
    <Card className="h-full">
      <CardHeader>
        <CardTitle>{name}</CardTitle>
        <CardDescription>
          {isCreator ? 'Group Creator' : 'Group Member'}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Identity Section */}
        <div>
          {!state.identity ? (
            <Button 
              onClick={handleCreateIdentity}
              disabled={!isReady || currentStep !== 'setup'}
              className="w-full"
            >
              Create Identity
            </Button>
          ) : (
            <IdentityCard identity={state.identity} />
          )}
        </div>

        {/* Key Package Section */}
        {state.identity && currentStep >= 'keyPackages' && (
          <div>
            {!state.keyPackage ? (
              <Button 
                onClick={handleCreateKeyPackage}
                disabled={!isReady || currentStep !== 'keyPackages'}
                className="w-full"
              >
                Publish Key Package
              </Button>
            ) : (
              <KeyPackageManager keyPackage={state.keyPackage} />
            )}
          </div>
        )}

        {/* Group Creation (Alice only) */}
        {isCreator && state.keyPackage && currentStep === 'groupCreation' && (
          <Button onClick={handleCreateGroup} className="w-full">
            Create Group
          </Button>
        )}

        {/* Send Welcome (Alice only) */}
        {isCreator && state.groups.size > 0 && currentStep === 'welcome' && (
          <Button onClick={handleSendWelcome} className="w-full">
            Send Welcome to Bob
          </Button>
        )}

        {/* Join Group (Bob only) */}
        {!isCreator && otherState.groups.size > 0 && currentStep === 'groupJoined' && (
          <Button onClick={handleJoinGroup} className="w-full">
            Join Group
          </Button>
        )}

        {/* Group Membership */}
        {state.groups.size > 0 && (
          <div className="space-y-2">
            <h4 className="font-semibold">Groups</h4>
            {Array.from(state.groups.values()).map(group => (
              <div key={group.id} className="text-sm bg-gray-100 p-2 rounded">
                <div className="font-mono text-xs">{group.id}</div>
                <div>Members: {group.members.join(', ')}</div>
              </div>
            ))}
          </div>
        )}

        {/* Message Composer */}
        {state.groups.size > 0 && currentStep === 'messaging' && (
          <MessageComposer
            state={state}
            setState={setState}
          />
        )}

        {/* Message History */}
        {state.messages.length > 0 && (
          <div className="space-y-2">
            <h4 className="font-semibold">Messages</h4>
            <div className="max-h-40 overflow-y-auto space-y-1">
              {state.messages.map((msg, idx) => (
                <MessageDisplay
                  key={idx}
                  message={msg}
                  state={state}
                  setState={setState}
                  otherState={otherState}
                />
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// Message display component with decrypt functionality
interface MessageDisplayProps {
  message: Message;
  state: MLSState;
  setState: React.Dispatch<React.SetStateAction<MLSState>>;
  otherState: MLSState;
}

function MessageDisplay({ message, state, setState, otherState }: MessageDisplayProps) {
  const [isDecrypting, setIsDecrypting] = useState(false);
  
  // Check if this is an encrypted message from the other participant
  const isEncryptedFromOther = message.sender !== state.identity?.nickname && message.encrypted;
  const showDecryptButton = isEncryptedFromOther && message.eventId && !message.decrypted;
  
  const handleDecrypt = async () => {
    if (!message.eventId) return;
    
    setIsDecrypting(true);
    
    // Find the corresponding event
    const event = [...state.events, ...otherState.events].find(e => e.id === message.eventId);
    if (!event) {
      setIsDecrypting(false);
      return;
    }
    
    try {
      // In a real implementation, we would decrypt the message using MLS
      // For now, we'll simulate decryption by showing the original content
      const originalMessage = otherState.messages.find(m => m.eventId === message.eventId && !m.encrypted);
      
      if (originalMessage) {
        // Update the message with decrypted content
        setState(prev => ({
          ...prev,
          messages: prev.messages.map(m => 
            m.eventId === message.eventId 
              ? { ...m, decrypted: originalMessage.content }
              : m
          )
        }));
      }
    } catch (error) {
      console.error('Failed to decrypt message:', error);
    } finally {
      setIsDecrypting(false);
    }
  };
  
  return (
    <div className="text-sm bg-gray-100 p-2 rounded">
      <div className="font-semibold">{message.sender}</div>
      {message.decrypted ? (
        <div>
          <div className="text-green-600 text-xs">✓ Decrypted</div>
          <div>{message.decrypted}</div>
        </div>
      ) : (
        <div className={message.encrypted ? 'font-mono text-xs' : ''}>
          {message.content}
        </div>
      )}
      {showDecryptButton && (
        <Button 
          size="sm" 
          variant="outline" 
          className="mt-1"
          onClick={handleDecrypt}
          disabled={isDecrypting}
        >
          {isDecrypting ? 'Decrypting...' : '🔓 Decrypt'}
        </Button>
      )}
    </div>
  );
}