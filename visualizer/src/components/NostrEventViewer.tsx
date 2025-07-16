import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { Button } from './ui/button';
import { NostrEvent } from './MLSVisualizer';
import { isEphemeralKey } from '../utils/crypto';

interface NostrEventViewerProps {
  event: NostrEvent;
  onClose: () => void;
  knownIdentities?: Map<string, any>;
}

const eventKindNames: Record<number, string> = {
  443: 'MLS Key Package',
  444: 'MLS Welcome',
  445: 'MLS Group Message',
};

export function NostrEventViewer({ event, onClose, knownIdentities }: NostrEventViewerProps) {
  const eventJson = JSON.stringify(event, null, 2);
  const isEphemeral = event.kind === 445 && knownIdentities && isEphemeralKey(event.pubkey, knownIdentities);

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle>
          {eventKindNames[event.kind] || `Nostr Event (Kind ${event.kind})`}
        </CardTitle>
        <Button variant="ghost" size="sm" onClick={onClose}>
          ✕
        </Button>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          {/* Event Summary */}
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <span className="font-semibold">Event ID:</span>
              <div className="font-mono text-xs">{event.id}</div>
            </div>
            <div>
              <span className="font-semibold">Timestamp:</span>
              <div>{new Date(event.created_at * 1000).toLocaleString()}</div>
            </div>
            <div>
              <span className="font-semibold">Public Key:</span>
              <div className="font-mono text-xs">
                {event.pubkey.substring(0, 16)}...{event.pubkey.substring(event.pubkey.length - 16)}
                {isEphemeral && (
                  <span className="ml-2 text-green-600 font-normal">[EPHEMERAL]</span>
                )}
              </div>
            </div>
            <div>
              <span className="font-semibold">Kind:</span>
              <div>{event.kind} ({eventKindNames[event.kind] || 'Unknown'})</div>
            </div>
          </div>

          {/* Ephemeral Key Notice */}
          {isEphemeral && (
            <div className="bg-green-50 border border-green-200 rounded p-3 text-sm">
              <span className="font-semibold text-green-700">✓ Privacy Protected</span>
              <p className="text-green-600 mt-1">
                This message was sent using an ephemeral key pair, ensuring sender privacy.
              </p>
            </div>
          )}

          {/* Tags */}
          {event.tags.length > 0 && (
            <div>
              <span className="font-semibold">Tags:</span>
              <div className="mt-1 space-y-1">
                {event.tags.map((tag, idx) => (
                  <div key={idx} className="font-mono text-xs bg-gray-100 p-1 rounded">
                    [{tag.join(', ')}]
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Content Preview */}
          <div>
            <span className="font-semibold">Content:</span>
            <div className="mt-1 font-mono text-xs bg-gray-100 p-2 rounded max-h-32 overflow-y-auto">
              {event.content.length > 100
                ? `${event.content.substring(0, 100)}...`
                : event.content}
            </div>
          </div>

          {/* Raw JSON */}
          <details className="cursor-pointer">
            <summary className="font-semibold text-sm">Raw Event JSON</summary>
            <pre className="mt-2 text-xs bg-gray-100 p-2 rounded overflow-x-auto">
              {eventJson}
            </pre>
          </details>
        </div>
      </CardContent>
    </Card>
  );
}