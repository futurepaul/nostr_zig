import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { StateTransitionDiagram } from './StateTransitionDiagram';
import { EventTimeline } from './EventTimeline';
import { MessageFlow } from './MessageFlow';
import { NostrEventViewer } from './NostrEventViewer';
import { InfoWrapper } from './InfoPanel';
import { MLSState, NostrEvent, ProtocolStep } from './MLSVisualizer';

interface ProtocolFlowProps {
  currentStep: ProtocolStep;
  aliceState: MLSState;
  bobState: MLSState;
  events: NostrEvent[];
  onEventClick: (event: NostrEvent) => void;
  knownIdentities?: Map<string, any>;
  selectedEvent?: NostrEvent | null;
  setSelectedEvent?: (event: NostrEvent | null) => void;
}

export function ProtocolFlow({
  currentStep,
  aliceState,
  bobState,
  events,
  onEventClick,
  knownIdentities,
  selectedEvent,
  setSelectedEvent,
}: ProtocolFlowProps) {
  // Debug logging
  console.log('ProtocolFlow render:', { 
    hasSelectedEvent: !!selectedEvent, 
    hasSetSelectedEvent: !!setSelectedEvent,
    selectedEventId: selectedEvent?.id 
  });

  return (
    <div className="space-y-4">
      {/* Event Timeline - Now at the top */}
      <Card>
        <CardHeader>
          <InfoWrapper tooltip="Events shown in chronological order by creation time. Note: Gift-wrapped Welcome events (🎁) use randomized timestamps between 2 weeks ago and now as per NIP-59 for metadata protection - the real timestamp is encrypted inside the gift wrap. This privacy feature prevents timing correlation attacks.">
            <CardTitle>Nostr Events</CardTitle>
          </InfoWrapper>
        </CardHeader>
        <CardContent>
          <EventTimeline events={events} onEventClick={onEventClick} knownIdentities={knownIdentities} />
        </CardContent>
      </Card>

      {/* Event Viewer */}
      {selectedEvent && (
        <NostrEventViewer
          event={selectedEvent}
          onClose={() => setSelectedEvent ? setSelectedEvent(null) : () => {}}
          knownIdentities={knownIdentities}
        />
      )}
    </div>
  );
}