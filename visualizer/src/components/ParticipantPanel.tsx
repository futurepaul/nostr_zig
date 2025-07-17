import React, { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card';
import { Button } from './ui/button';
import { IdentityCard } from './IdentityCard';
import { KeyPackageManager } from './KeyPackageManager';
import { MessageComposer } from './MessageComposer';
import { useWasm } from './WasmProvider';
import { MLSState, ProtocolStep, Message, GroupState } from './MLSVisualizer';
import { bytesToHex, createNostrEventIdSync, signNostrEvent } from '../utils/wasm-crypto';
import { InfoTooltip } from './InfoTooltip';

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

    // Create a real Nostr event
    const pubkey = Array.from(state.identity.publicKey).map(b => b.toString(16).padStart(2, '0')).join('');
    const content = btoa(String.fromCharCode(...keyPackageData));
    const created_at = Math.floor(Date.now() / 1000);
    
    const eventData = {
      pubkey,
      created_at,
      kind: 443,
      tags: [],
      content,
    };

    // Generate real Nostr event ID
    const eventId = createNostrEventIdSync(eventData);
    
    // Sign the event with identity private key
    const eventWithId = { ...eventData, id: eventId };
    const signature = signNostrEvent(eventWithId, state.identity.privateKey);

    const event = {
      ...eventWithId,
      sig: signature,
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
    console.log('Creating group with identity:', {
      privateKeyLength: state.identity.privateKey.length,
      publicKeyLength: state.identity.publicKey.length
    });
    
    const groupStateData = createGroup(state.identity.privateKey, state.identity.publicKey);
    console.log('Group created with state length:', groupStateData?.length || 0);
    
    if (!groupStateData || groupStateData.length === 0) {
      console.error('Failed to create group state');
      return;
    }
    
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
    
    // Create a real welcome event
    const pubkey = Array.from(state.identity.publicKey).map(b => b.toString(16).padStart(2, '0')).join('');
    const recipientPubkey = Array.from(otherState.identity!.publicKey).map(b => b.toString(16).padStart(2, '0')).join('');
    
    // In a real implementation, this would be the serialized MLS Welcome message
    // For now, we'll use a placeholder that indicates it's a welcome message
    const welcomeData = {
      type: 'mls_welcome',
      group_id: Array.from(state.groups.values())[0]?.id || 'unknown',
      timestamp: Date.now()
    };
    const content = btoa(JSON.stringify(welcomeData));
    const created_at = Math.floor(Date.now() / 1000);
    
    const eventData = {
      pubkey,
      created_at,
      kind: 444,
      tags: [['p', recipientPubkey]],
      content,
    };

    // Generate real Nostr event ID
    const eventId = createNostrEventIdSync(eventData);
    
    // Sign the event with identity private key
    const eventWithId = { ...eventData, id: eventId };
    const signature = signNostrEvent(eventWithId, state.identity.privateKey);

    const welcomeEvent = {
      ...eventWithId,
      sig: signature,
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
              <InfoTooltip tooltip="KeyPackages contain a signing key (different from Nostr identity) and credentials. They allow asynchronous group invitations. Each user must publish at least one KeyPackage to be reachable for MLS messaging.">
                <Button 
                  onClick={handleCreateKeyPackage}
                  disabled={!isReady || currentStep !== 'keyPackages'}
                  className="w-full"
                >
                  Publish Key Package
                </Button>
              </InfoTooltip>
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
            <InfoTooltip tooltip="Groups are created with a random 32-byte ID that is private to the group. Each group has its own cryptographic state including signing keys and encryption secrets.">
              <h4 className="font-semibold">Groups</h4>
            </InfoTooltip>
            {Array.from(state.groups.values()).map(group => (
              <GroupDisplay key={group.id} group={group} />
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
            <InfoTooltip tooltip="Messages are encrypted with double-layer encryption: MLS (inner) + NIP-44 (outer). Each message uses a unique ephemeral key for signing. Group events are published with kind 445.">
              <h4 className="font-semibold">Messages</h4>
            </InfoTooltip>
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

// Group display component with decryption keys
interface GroupDisplayProps {
  group: GroupState;
}

function GroupDisplay({ group }: GroupDisplayProps) {
  const [showKeys, setShowKeys] = useState(false);

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    console.log(`Copied ${label} to clipboard`);
  };

  return (
    <div className="text-sm bg-gray-100 p-2 rounded space-y-2">
      <div className="font-mono text-xs">{group.id}</div>
      <div>Members: {group.members.join(', ')}</div>
      
      <Button
        size="sm"
        variant="outline"
        onClick={() => setShowKeys(!showKeys)}
        className="text-xs"
      >
        {showKeys ? 'Hide' : 'Show'} Decryption Keys
      </Button>
      
      {showKeys && (
        <div className="space-y-2 border-t pt-2">
          {group.exporterSecret && (
            <div>
              <InfoTooltip tooltip="The exporter secret is derived from MLS group state with 'nostr' label. It's used as the private key for NIP-44 v2 encryption (outer layer). This secret rotates on each new epoch to provide forward secrecy.">
                <div className="text-xs font-semibold text-blue-600">NIP-44 Exporter Secret:</div>
              </InfoTooltip>
              <div className="font-mono text-xs break-all bg-white p-1 rounded">
                {bytesToHex(group.exporterSecret)}
              </div>
              <Button
                size="sm"
                variant="outline"
                onClick={() => copyToClipboard(bytesToHex(group.exporterSecret!), 'Exporter Secret')}
                className="text-xs mt-1"
              >
                📋 Copy
              </Button>
            </div>
          )}
          
          {group.groupSecret && (
            <div>
              <InfoTooltip tooltip="The MLS group secret is used for the inner encryption layer. It's derived from the MLS ratchet tree and provides the core group encryption. This is separate from the NIP-44 layer.">
                <div className="text-xs font-semibold text-green-600">MLS Group Secret:</div>
              </InfoTooltip>
              <div className="font-mono text-xs break-all bg-white p-1 rounded">
                {bytesToHex(group.groupSecret)}
              </div>
              <Button
                size="sm"
                variant="outline"
                onClick={() => copyToClipboard(bytesToHex(group.groupSecret!), 'Group Secret')}
                className="text-xs mt-1"
              >
                📋 Copy
              </Button>
            </div>
          )}
          
          {!group.exporterSecret && !group.groupSecret && (
            <div className="text-xs text-gray-500 italic">
              Decryption keys will appear after sending messages
            </div>
          )}
        </div>
      )}
    </div>
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
  
  // Check if this is a message from current user (to show copy encrypted button)
  const isOwnMessage = message.sender === state.identity?.nickname;
  
  const copyEncryptedMessage = () => {
    if (!message.eventId) return;
    
    // Find the corresponding event to get the encrypted content
    const event = [...state.events, ...otherState.events].find(e => e.id === message.eventId);
    if (!event) return;
    
    // Copy the raw Nostr event exactly as it is
    navigator.clipboard.writeText(JSON.stringify(event, null, 2));
    console.log('Copied encrypted Nostr event to clipboard:', event);
  };
  
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
      // Use real two-stage decryption: NIP-44 + MLS
      console.log('Starting two-stage decryption for event:', event.id);
      
      // Get the encrypted content from the event
      const encryptedContent = event.content;
      if (!encryptedContent) {
        throw new Error('No encrypted content found in event');
      }
      
      // Perform two-stage decryption using WASM
      const decryptedJson = await wasm.receiveMessage(
        state.groupState,
        state.privateKey,
        encryptedContent
      );
      
      console.log('Decrypted JSON:', decryptedJson);
      
      // Parse the decrypted JSON to get the actual message content
      try {
        const parsedMessage = JSON.parse(decryptedJson);
        const messageContent = parsedMessage.content || decryptedJson;
        
        // Update the message with decrypted content
        setState(prev => ({
          ...prev,
          messages: prev.messages.map(m => 
            m.eventId === message.eventId 
              ? { ...m, decrypted: messageContent }
              : m
          )
        }));
      } catch (parseError) {
        // If parsing fails, use the raw decrypted content
        setState(prev => ({
          ...prev,
          messages: prev.messages.map(m => 
            m.eventId === message.eventId 
              ? { ...m, decrypted: decryptedJson }
              : m
          )
        }));
      }
    } catch (error) {
      console.error('Failed to decrypt message:', error);
      // Show error message instead of fallback
      setState(prev => ({
        ...prev,
        messages: prev.messages.map(m => 
          m.eventId === message.eventId 
            ? { ...m, decrypted: `❌ Decryption failed: ${error.message || 'Unknown error'}` }
            : m
        )
      }));
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
      <div className="flex gap-1 mt-1">
        {showDecryptButton && (
          <Button 
            size="sm" 
            variant="outline" 
            onClick={handleDecrypt}
            disabled={isDecrypting}
          >
            {isDecrypting ? 'Decrypting...' : '🔓 Decrypt'}
          </Button>
        )}
        {isOwnMessage && message.eventId && (
          <InfoTooltip tooltip="Copies the complete encrypted Nostr event (kind 445) including the double-encrypted content, ephemeral pubkey, group ID tag, and signature. Use this with the decryptor below.">
            <Button 
              size="sm" 
              variant="outline" 
              onClick={copyEncryptedMessage}
              title="Copy as encrypted Nostr event"
            >
              📋 Copy Encrypted
            </Button>
          </InfoTooltip>
        )}
      </div>
    </div>
  );
}