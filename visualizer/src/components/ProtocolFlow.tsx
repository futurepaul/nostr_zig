import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { StateTransitionDiagram } from './StateTransitionDiagram';
import { EventTimeline } from './EventTimeline';
import { MessageFlow } from './MessageFlow';
import { MLSState, NostrEvent, ProtocolStep } from './MLSVisualizer';

interface ProtocolFlowProps {
  currentStep: ProtocolStep;
  aliceState: MLSState;
  bobState: MLSState;
  events: NostrEvent[];
  onEventClick: (event: NostrEvent) => void;
  knownIdentities?: Map<string, any>;
}

export function ProtocolFlow({
  currentStep,
  aliceState,
  bobState,
  events,
  onEventClick,
  knownIdentities,
}: ProtocolFlowProps) {
  return (
    <div className="space-y-4">
      {/* State Diagram */}
      <Card>
        <CardHeader>
          <CardTitle>Protocol State</CardTitle>
        </CardHeader>
        <CardContent>
          <StateTransitionDiagram currentStep={currentStep} />
        </CardContent>
      </Card>

      {/* Message Flow */}
      <Card>
        <CardHeader>
          <CardTitle>Message Flow</CardTitle>
        </CardHeader>
        <CardContent>
          <MessageFlow
            aliceState={aliceState}
            bobState={bobState}
            currentStep={currentStep}
          />
        </CardContent>
      </Card>

      {/* Event Timeline */}
      <Card>
        <CardHeader>
          <CardTitle>Nostr Events</CardTitle>
        </CardHeader>
        <CardContent>
          <EventTimeline events={events} onEventClick={onEventClick} knownIdentities={knownIdentities} />
        </CardContent>
      </Card>
    </div>
  );
}