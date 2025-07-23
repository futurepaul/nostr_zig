import React, { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card';
import { Button } from './ui/button';
import { IdentityCard } from './IdentityCard';
import { KeyPackageManager } from './KeyPackageManager';
import { MessageComposer } from './MessageComposer';
import { useWasm } from './WasmProvider';
import { MLSState, ProtocolStep, Message, GroupState } from './MLSVisualizer';
import { bytesToHex, createNostrEventIdSync, signNostrEvent } from '../utils/wasm-crypto';
import { InfoWrapper } from './InfoPanel';

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
  const { 
    isReady, 
    createIdentity, 
    generateMLSSigningKeys,
    createKeyPackage,
    // MLS Welcome Message Functions
    createWelcomeMessage,
    // NIP-59 Gift Wrapping
    createGiftWrap,
    // Real MLS State Machine Functions
    initGroup,
    proposeAddMember,
    commitProposals,
    getGroupInfo,
    generateExporterSecretForEpoch
  } = useWasm();
  
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

  // Watch for group membership changes from the other participant
  React.useEffect(() => {
    if (!isCreator) return; // Only Alice needs to sync Bob's membership
    
    // Check if Bob has joined any groups
    otherState.groups.forEach((otherGroup, groupId) => {
      const myGroup = state.groups.get(groupId);
      if (myGroup && otherGroup.members.includes('Bob') && !myGroup.members.includes('Bob')) {
        // Update Alice's view to show Bob has joined
        setState(prev => ({
          ...prev,
          groups: new Map(prev.groups).set(groupId, {
            ...myGroup,
            members: [...myGroup.members, 'Bob']
          })
        }));
      }
    });
  }, [otherState.groups, state.groups, setState, isCreator]);

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
      tags: [
        ['cs', '1'],  // cipher suite: MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
        ['pv', '1'],  // protocol version: MLS 1.0
      ],
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

    // Generate a random 32-byte group ID as per NIP-EE spec
    const groupIdBytes = new Uint8Array(32);
    crypto.getRandomValues(groupIdBytes);
    const groupId = bytesToHex(groupIdBytes);

    try {
      
      // Generate MLS signing keys (separate from Nostr identity)
      const mlsSigningKeys = generateMLSSigningKeys();
      
      console.log('Creating group with real MLS state machine:', {
        groupId,
        identityPubkey: bytesToHex(state.identity.publicKey),
        mlsSigningKeyPublic: bytesToHex(mlsSigningKeys.publicKey),
        mlsSigningKeyPrivate: bytesToHex(mlsSigningKeys.privateKey),
        privateKeyLength: mlsSigningKeys.privateKey.length,
        groupIdLength: groupIdBytes.length
      });
      
      // Use real MLS state machine to initialize group
      const { state: groupStateData, epoch, memberCount } = initGroup(
        groupIdBytes,
        state.identity.publicKey,
        mlsSigningKeys.privateKey
      );
      
      console.log('Real MLS group created:', {
        stateLength: groupStateData.length,
        epoch: epoch.toString(),
        memberCount
      });
      
      // Generate exporter secret for the current epoch
      const exporterSecret = generateExporterSecretForEpoch(groupStateData);
      console.log(`${name} generated exporter secret for epoch ${epoch}:`, bytesToHex(exporterSecret));
      
      const groupState: GroupState = {
        id: groupId,
        state: groupStateData,
        members: [name],
        // Real MLS state tracking
        epoch,
        memberCount,
        currentExporterSecret: exporterSecret,
        previousEpochSecrets: new Map(),
        pendingProposals: 0,
        lastCommitTimestamp: Date.now(),
      };

      setState(prev => ({
        ...prev,
        mlsSigningKeys,  // Store the MLS signing keys
        groups: new Map(prev.groups).set(groupId, groupState),
        currentEpoch: epoch,  // Update global epoch
        epochHistory: [...prev.epochHistory, {
          epoch,
          timestamp: new Date(),
          eventType: 'group_init',
          groupId,
          memberCount,
          secretsRotated: false,
          description: `${name} created group with epoch ${epoch}`
        }]
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

    } catch (error) {
      console.error('Failed to create group with real MLS state machine:', error);
      return;
    }
  };

  const handleCommitProposals = async (groupId: string) => {
    if (!isReady || !state.identity) return;

    const group = state.groups.get(groupId);
    if (!group) return;

    try {
      console.log(`${name} committing proposals for group ${groupId}...`);
      
      // Use real MLS state machine to commit proposals
      const { newState, epoch, memberCount, secretsRotated } = commitProposals(group.state);
      
      console.log(`${name} committed proposals:`, {
        newEpoch: epoch.toString(),
        memberCount,
        secretsRotated,
        stateLength: newState.length
      });

      // Generate new exporter secret for the new epoch
      const newExporterSecret = generateExporterSecretForEpoch(newState);
      
      // Store the previous epoch's secret for forward secrecy demonstration
      const updatedPreviousSecrets = new Map(group.previousEpochSecrets);
      if (group.currentExporterSecret) {
        updatedPreviousSecrets.set(group.epoch, group.currentExporterSecret);
      }

      const updatedGroup: GroupState = {
        ...group,
        state: newState,
        epoch,
        memberCount,
        currentExporterSecret: newExporterSecret,
        previousEpochSecrets: updatedPreviousSecrets,
        pendingProposals: 0,
        lastCommitTimestamp: Date.now(),
      };

      setState(prev => ({
        ...prev,
        groups: new Map(prev.groups).set(groupId, updatedGroup),
        currentEpoch: epoch,
        epochHistory: [...prev.epochHistory, {
          epoch,
          timestamp: new Date(),
          eventType: 'commit',
          groupId,
          memberCount,
          secretsRotated,
          description: `${name} committed proposals and advanced to epoch ${epoch}${secretsRotated ? ' (keys rotated)' : ''}`
        }]
      }));

    } catch (error) {
      console.error('Failed to commit proposals:', error);
    }
  };

  const handleSendWelcome = () => {
    if (!isReady || !state.identity || !isCreator) return;
    
    // Find the KeyPackage Event ID from Bob's (otherState) KeyPackage event
    const bobKeyPackageEvent = otherState.events.find(event => event.kind === 443);
    if (!bobKeyPackageEvent) {
      console.error('No KeyPackage event found for recipient');
      return;
    }
    
    // Create a real welcome event
    const pubkey = Array.from(state.identity.publicKey).map(b => b.toString(16).padStart(2, '0')).join('');
    
    // Create real MLS Welcome message
    // For the demo, we'll create a welcome for member index 1 (Bob would be the second member)
    const group = Array.from(state.groups.values())[0];
    if (!group) {
      console.error('No group found to create welcome for');
      return;
    }
    
    let content: string;
    try {
      // Create real MLS Welcome message using the group state
      const mlsWelcomeBytes = createWelcomeMessage(group.state, 1); // Index 1 for second member (Bob)
      
      // Convert to hex string for content (as per NIP-EE spec)
      content = Array.from(mlsWelcomeBytes).map(b => b.toString(16).padStart(2, '0')).join('');
      
      console.log('Created real MLS Welcome message:', {
        welcomeLength: mlsWelcomeBytes.length,
        hexLength: content.length
      });
    } catch (error) {
      console.error('Failed to create MLS welcome message:', error);
      // Fallback to placeholder for demo
      const welcomeData = {
        type: 'mls_welcome_fallback',
        group_id: group.id,
        timestamp: Date.now(),
        error: error.message
      };
      content = btoa(JSON.stringify(welcomeData));
    }
    const created_at = Math.floor(Date.now() / 1000);
    
    // According to NIP-EE spec, welcome events should have:
    // - 'e' tag with KeyPackage Event ID that was used to add user
    // - 'relays' tag with array of relay URLs
    // - Must be unsigned rumor for NIP-59 gift wrapping
    const rumorEvent = {
      pubkey,
      created_at,
      kind: 444,
      tags: [
        ['e', bobKeyPackageEvent.id],
        ['relays', 'ws://localhost:10547', 'wss://relay.example.com'],
      ],
      content,
      sig: '', // Unsigned rumor as per NIP-59
    };

    // Generate event ID for the rumor
    const eventId = createNostrEventIdSync(rumorEvent);
    const rumorWithId = { ...rumorEvent, id: eventId };
    
    // Get recipient's public key  
    const recipientPubkey = otherState.identity!.publicKey;
    
    // Create NIP-59 gift wrap (this creates a kind 1059 event)
    const giftWrappedJson = createGiftWrap(state.identity.privateKey, recipientPubkey, rumorWithId);
    const welcomeEvent = JSON.parse(giftWrappedJson);

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

    // Generate exporter secret for Bob when joining the group
    let exporterSecret: Uint8Array;
    try {
      exporterSecret = generateExporterSecretForEpoch(aliceGroup.state);
      console.log('Bob generated exporter secret on join:', bytesToHex(exporterSecret));
    } catch (error) {
      console.error('Failed to generate exporter secret:', error);
      throw error; // No fallback - must use proper MLS exporter secret
    }

    setState(prev => ({
      ...prev,
      groups: new Map(prev.groups).set(aliceGroup.id, {
        ...aliceGroup,
        members: [...aliceGroup.members, name],
        currentExporterSecret: exporterSecret,
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
              <InfoWrapper tooltip="KeyPackages contain a signing key (different from Nostr identity) and credentials. They allow asynchronous group invitations. Each user must publish at least one KeyPackage to be reachable for MLS messaging.">
                <Button 
                  onClick={handleCreateKeyPackage}
                  disabled={!isReady || currentStep !== 'keyPackages'}
                  className="w-full"
                >
                  Publish Key Package
                </Button>
              </InfoWrapper>
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
            <InfoWrapper tooltip="Groups are created with a random 32-byte ID that is private to the group. Each group has its own cryptographic state including signing keys and encryption secrets.">
              <h4 className="font-semibold">Groups</h4>
            </InfoWrapper>
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
            <InfoWrapper tooltip="Messages are sent as serialized MLS MLSMessage objects, then encrypted with NIP-44 using the group's exporter secret. The MLS format handles framing, authentication, and ordering. Each message should use a unique ephemeral key for privacy. Group events are published with kind 445.">
              <h4 className="font-semibold">Messages</h4>
            </InfoWrapper>
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
  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    console.log(`Copied ${label} to clipboard`);
  };

  return (
    <div className="text-sm bg-gray-100 p-2 rounded space-y-2">
      <div className="font-mono text-xs break-all">{group.id}</div>
      <div>Members: {group.members.join(', ')}</div>
      
      <div className="space-y-2 border-t pt-2">
        {group.currentExporterSecret && (
          <div>
            <InfoWrapper tooltip="The exporter secret is derived from MLS group state with 'nostr' label. It's used as the private key for NIP-44 v2 encryption (outer layer). This secret rotates on each new epoch to provide forward secrecy.">
              <div className="text-xs font-semibold text-blue-600">NIP-44 Exporter Secret:</div>
            </InfoWrapper>
            <div className="font-mono text-xs break-all bg-white p-1 rounded">
              {bytesToHex(group.currentExporterSecret)}
            </div>
            <Button
              size="sm"
              variant="outline"
              onClick={() => copyToClipboard(bytesToHex(group.currentExporterSecret!), 'Exporter Secret')}
              className="text-xs mt-1"
            >
              📋 Copy
            </Button>
          </div>
          )}
          
          {group.groupSecret && (
            <div>
              <InfoWrapper tooltip="The MLS group secret is used for the inner encryption layer. It's derived from the MLS ratchet tree and provides the core group encryption. This is separate from the NIP-44 layer.">
                <div className="text-xs font-semibold text-green-600">MLS Group Secret:</div>
              </InfoWrapper>
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
          
        {!group.currentExporterSecret && !group.groupSecret && (
          <div className="text-xs text-gray-500 italic">
            Decryption keys will appear after sending messages
          </div>
        )}
      </div>
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
  const { decryptGroupMessage } = useWasm();
  
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
      
      // Find the group to get the exporter secret
      const groupId = event.tags.find(tag => tag[0] === 'h')?.[1];
      if (!groupId) {
        throw new Error('No group ID found in event');
      }
      
      const group = state.groups.get(groupId);
      if (!group || !group.currentExporterSecret) {
        throw new Error('No group or exporter secret found');
      }
      
      console.log('Attempting to decrypt with:', {
        groupId,
        exporterSecret: bytesToHex(group.currentExporterSecret),
        epoch: group.epoch?.toString(),
        encryptedContentLength: encryptedContent.length
      });
      
      // Decode the base64 encrypted content to bytes
      const ciphertextBytes = Uint8Array.from(atob(encryptedContent), c => c.charCodeAt(0));
      console.log('Ciphertext bytes:', {
        length: ciphertextBytes.length,
        preview: Array.from(ciphertextBytes.slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join(' ')
      });
      
      // Perform two-stage decryption using WASM
      const decryptedBytes = decryptGroupMessage(group.currentExporterSecret, ciphertextBytes);
      const decryptedJson = new TextDecoder().decode(decryptedBytes);
      
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
          <InfoWrapper tooltip="Copies the complete encrypted Nostr event (kind 445). The content field contains a serialized MLS MLSMessage object that has been encrypted with NIP-44 using the group's exporter secret. The event includes ephemeral pubkey, group ID tag, and signature.">
            <Button 
              size="sm" 
              variant="outline" 
              onClick={copyEncryptedMessage}
              title="Copy as encrypted Nostr event"
            >
              📋 Copy Encrypted
            </Button>
          </InfoWrapper>
        )}
      </div>
    </div>
  );
}