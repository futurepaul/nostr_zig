import React from 'react';
import { NostrEvent } from './MLSVisualizer';
import { motion } from 'framer-motion';
import { isEphemeralKey } from '../utils/crypto';

interface EventTimelineProps {
  events: NostrEvent[];
  onEventClick: (event: NostrEvent) => void;
  knownIdentities?: Map<string, any>;
}

const eventKindNames: Record<number, string> = {
  443: 'Key Package',
  444: 'Welcome',
  445: 'Group Message',
};

const eventKindIcons: Record<number, string> = {
  443: '📦',
  444: '✉️',
  445: '💬',
};

const eventKindColors: Record<number, string> = {
  443: 'bg-blue-100 border-blue-300',
  444: 'bg-green-100 border-green-300',
  445: 'bg-purple-100 border-purple-300',
};

export function EventTimeline({ events, onEventClick, knownIdentities }: EventTimelineProps) {
  if (events.length === 0) {
    return (
      <div className="text-center text-gray-500 py-4">
        No events yet. Start by creating identities.
      </div>
    );
  }

  return (
    <div className="space-y-2 max-h-64 overflow-y-auto">
      {events.map((event, index) => (
        <motion.div
          key={event.id}
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: index * 0.1 }}
          className={`
            border rounded-lg p-3 cursor-pointer hover:shadow-md transition-shadow
            ${eventKindColors[event.kind] || 'bg-gray-100 border-gray-300'}
          `}
          onClick={() => onEventClick(event)}
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <span className="text-xl">{eventKindIcons[event.kind] || '📄'}</span>
              <div>
                <div className="font-semibold text-sm">
                  {eventKindNames[event.kind] || `Kind ${event.kind}`}
                </div>
                <div className="text-xs text-gray-600">
                  {new Date(event.created_at * 1000).toLocaleTimeString()}
                </div>
              </div>
            </div>
            <div className="flex items-center space-x-1">
              {event.kind === 445 && knownIdentities && isEphemeralKey(event.pubkey, knownIdentities) && (
                <span className="text-xs bg-green-500 text-white px-2 py-1 rounded-full">
                  EPH
                </span>
              )}
              <div className="text-xs font-mono text-gray-500">
                {event.pubkey.substring(0, 8)}...
              </div>
            </div>
          </div>
        </motion.div>
      ))}
    </div>
  );
}