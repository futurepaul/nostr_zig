import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { Button } from './ui/button';
import { NostrEvent } from './MLSVisualizer';

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

export function NostrEventViewer({ event, onClose }: NostrEventViewerProps) {
  const eventJson = JSON.stringify(event, null, 2);
  
  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    console.log(`Copied ${label} to clipboard`);
  };

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
          {/* Content */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <h3 className="font-semibold">Content:</h3>
              <Button
                size="sm"
                variant="outline"
                onClick={() => copyToClipboard(event.content, 'Content')}
              >
                📋 Copy
              </Button>
            </div>
            <div className="font-mono text-xs bg-gray-100 p-3 rounded max-h-48 overflow-y-auto break-all">
              {event.content}
            </div>
          </div>

          {/* Raw JSON */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <h3 className="font-semibold">Raw Event JSON:</h3>
              <Button
                size="sm"
                variant="outline"
                onClick={() => copyToClipboard(eventJson, 'Raw JSON')}
              >
                📋 Copy
              </Button>
            </div>
            <pre className="text-xs bg-gray-100 p-3 rounded overflow-x-auto max-h-64 overflow-y-auto">
              {eventJson}
            </pre>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}