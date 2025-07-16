import React, { useState } from 'react';
import { WasmProvider } from './WasmProvider';
import { ParticipantPanel } from './ParticipantPanel';
import { ProtocolFlow } from './ProtocolFlow';
import { NostrEventViewer } from './NostrEventViewer';
import { Card } from './ui/card';

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
  });

  const [bobState, setBobState] = useState<MLSState>({
    groups: new Map(),
    events: [],
    messages: [],
  });

  const [currentStep, setCurrentStep] = useState<ProtocolStep>('setup');
  const [selectedEvent, setSelectedEvent] = useState<NostrEvent | null>(null);

  const allEvents = [...aliceState.events, ...bobState.events].sort(
    (a, b) => a.created_at - b.created_at
  );

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
              />
            </div>
          )}
        </div>
      </div>
    </WasmProvider>
  );
}