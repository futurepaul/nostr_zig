import React, { useState } from 'react';
import { createRoot } from 'react-dom/client';
import { WasmProvider, useWasm } from './components/WasmProvider';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './components/ui/card';
import { Button } from './components/ui/button';
import { Input } from './components/ui/input';
import { Label } from './components/ui/label';
import { NostrEventViewer } from './components/NostrEventViewer';
import './index.css';

interface NostrEvent {
  id: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
  sig: string;
}

function EventPublisher() {
  const [privateKey, setPrivateKey] = useState('');
  const [content, setContent] = useState('');
  const [relays, setRelays] = useState('wss://relay.damus.io\nwss://nos.lol\nwss://relay.primal.net');
  const [publishing, setPublishing] = useState(false);
  const [publishingProgress, setPublishingProgress] = useState<Array<{relay: string, status: 'pending' | 'connecting' | 'publishing' | 'success' | 'error', message: string}>>([]);
  const [results, setResults] = useState<Array<{relay: string, success: boolean, message: string}>>([]);
  const [createdEvent, setCreatedEvent] = useState<NostrEvent | null>(null);
  const { wasmReady, createTextNote, getPublicKey, pubkeyToHex } = useWasm();

  const handlePublish = async () => {
    if (!wasmReady || !privateKey || !content) {
      alert('Please fill in all fields');
      return;
    }

    // Validate private key
    if (privateKey.length !== 64 || !/^[0-9a-fA-F]+$/.test(privateKey)) {
      alert('Invalid private key format (must be 64 hex characters)');
      return;
    }

    setPublishing(true);
    setResults([]);
    setCreatedEvent(null);
    setPublishingProgress([]); // Clear any previous progress

    // Parse relay URLs first to initialize progress
    const relayUrls = relays.split('\n').map(url => url.trim()).filter(url => url);
    const initialProgress = relayUrls.map(relay => ({
      relay,
      status: 'pending' as const,
      message: 'Waiting to start...'
    }));
    setPublishingProgress(initialProgress);

    try {
      // Convert hex private key to bytes
      const privkeyBytes = new Uint8Array(32);
      for (let i = 0; i < 32; i++) {
        privkeyBytes[i] = parseInt(privateKey.substr(i * 2, 2), 16);
      }

      // Get public key
      const pubkeyBytes = getPublicKey(privkeyBytes);
      const pubkeyHex = pubkeyToHex(pubkeyBytes);

      // Create the event
      const eventJson = createTextNote(privkeyBytes, content);
      const event = JSON.parse(eventJson) as NostrEvent;
      setCreatedEvent(event);

      // Connect and publish to each relay
      const publishResults: typeof results = [];
      const publishPromises = relayUrls.map(async (relayUrl, index) => {
        const updateProgress = (status: any, message: string) => {
          setPublishingProgress(prev => prev.map((item, i) => 
            i === index ? { ...item, status, message } : item
          ));
        };

        try {
          updateProgress('connecting', 'Connecting to relay...');
          
          // Create WebSocket connection
          const ws = new WebSocket(relayUrl);
          
          await new Promise((resolve, reject) => {
            const timeout = setTimeout(() => {
              updateProgress('error', 'Connection timeout (5s)');
              ws.close();
              reject(new Error('Connection timeout'));
            }, 5000);

            ws.onopen = () => {
              clearTimeout(timeout);
              updateProgress('publishing', 'Publishing event...');
              // Send the event
              ws.send(JSON.stringify(['EVENT', event]));
            };

            ws.onmessage = (msg) => {
              try {
                const data = JSON.parse(msg.data);
                if (Array.isArray(data) && data[0] === 'OK' && data[1] === event.id) {
                  const success = data[2];
                  const message = data[3] || (success ? 'Event accepted' : 'Event rejected');
                  updateProgress(success ? 'success' : 'error', message);
                  publishResults.push({ relay: relayUrl, success, message });
                  ws.close();
                  resolve(null);
                }
              } catch (e) {
                console.error('Error parsing relay response:', e);
                updateProgress('error', 'Invalid response from relay');
                reject(new Error('Invalid response from relay'));
              }
            };

            ws.onerror = () => {
              clearTimeout(timeout);
              updateProgress('error', 'WebSocket connection error');
              reject(new Error('WebSocket error'));
            };

            ws.onclose = (event) => {
              clearTimeout(timeout);
              if (!publishResults.find(r => r.relay === relayUrl)) {
                updateProgress('error', `Connection closed unexpectedly (code: ${event.code})`);
                reject(new Error('Connection closed'));
              }
            };
          });
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : 'Unknown error';
          updateProgress('error', errorMessage);
          publishResults.push({
            relay: relayUrl,
            success: false,
            message: errorMessage
          });
        }
      });

      // Wait for all publishing attempts to complete
      await Promise.allSettled(publishPromises);

      setResults(publishResults);
    } catch (error) {
      console.error('Error publishing event:', error);
      alert('Error creating event: ' + (error instanceof Error ? error.message : 'Unknown error'));
      // Clear progress on error
      setPublishingProgress([]);
    } finally {
      setPublishing(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 p-4">
      <div className="max-w-4xl mx-auto space-y-6">
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold mb-2">Nostr Event Publisher</h1>
          <p className="text-gray-600">Test the new core event infrastructure</p>
          <div className="mt-4">
            <a href="/" className="text-blue-600 hover:underline">← Back to MLS Demo</a>
          </div>
        </div>

        <Card>
          <CardHeader>
            <CardTitle>Publish Text Note (Kind 1)</CardTitle>
            <CardDescription>
              Create and publish a Nostr text note event using the new core event infrastructure
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <Label htmlFor="privateKey">Private Key (hex)</Label>
              <Input
                id="privateKey"
                type="password"
                value={privateKey}
                onChange={(e) => setPrivateKey(e.target.value)}
                placeholder="Your 64-character hex private key"
                className="font-mono"
              />
              <p className="text-sm text-gray-500 mt-1">Your Nostr private key in hexadecimal format</p>
            </div>

            <div>
              <Label htmlFor="content">Message Content</Label>
              <textarea
                id="content"
                value={content}
                onChange={(e) => setContent(e.target.value)}
                placeholder="What's on your mind?"
                className="w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 min-h-[100px]"
              />
            </div>

            <div>
              <Label htmlFor="relays">Relay URLs (one per line)</Label>
              <textarea
                id="relays"
                value={relays}
                onChange={(e) => setRelays(e.target.value)}
                className="w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 min-h-[100px] font-mono text-sm"
              />
            </div>

            <Button
              onClick={handlePublish}
              disabled={publishing || !wasmReady}
              className="w-full"
            >
              {publishing 
                ? `Publishing to ${publishingProgress.filter(p => p.status !== 'pending').length}/${publishingProgress.length} relays...` 
                : 'Publish Event'}
            </Button>
          </CardContent>
        </Card>

        {createdEvent && (
          <Card>
            <CardHeader>
              <CardTitle>Created Event</CardTitle>
            </CardHeader>
            <CardContent>
              <NostrEventViewer event={createdEvent} />
            </CardContent>
          </Card>
        )}

        {publishingProgress.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle>Publishing Progress</CardTitle>
              <CardDescription>Real-time status of publishing to each relay</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {publishingProgress.map((progress, index) => (
                  <div key={index} className="flex items-center space-x-3">
                    <div className="flex-shrink-0">
                      {progress.status === 'pending' && (
                        <div className="w-4 h-4 bg-gray-300 rounded-full"></div>
                      )}
                      {progress.status === 'connecting' && (
                        <div className="w-4 h-4 bg-yellow-400 rounded-full animate-pulse"></div>
                      )}
                      {progress.status === 'publishing' && (
                        <div className="w-4 h-4 bg-blue-500 rounded-full animate-pulse"></div>
                      )}
                      {progress.status === 'success' && (
                        <div className="w-4 h-4 bg-green-500 rounded-full flex items-center justify-center">
                          <svg className="w-3 h-3 text-white" fill="currentColor" viewBox="0 0 20 20">
                            <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                          </svg>
                        </div>
                      )}
                      {progress.status === 'error' && (
                        <div className="w-4 h-4 bg-red-500 rounded-full flex items-center justify-center">
                          <svg className="w-3 h-3 text-white" fill="currentColor" viewBox="0 0 20 20">
                            <path fillRule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clipRule="evenodd" />
                          </svg>
                        </div>
                      )}
                    </div>
                    <div className="flex-1">
                      <div className="font-medium text-sm">{progress.relay}</div>
                      <div className={`text-xs ${
                        progress.status === 'success' ? 'text-green-600' :
                        progress.status === 'error' ? 'text-red-600' :
                        progress.status === 'connecting' ? 'text-yellow-600' :
                        progress.status === 'publishing' ? 'text-blue-600' :
                        'text-gray-500'
                      }`}>
                        {progress.message}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        {results.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle>Publishing Results</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {results.map((result, index) => (
                  <div
                    key={index}
                    className={`p-3 rounded-md ${
                      result.success
                        ? 'bg-green-50 text-green-800 border border-green-200'
                        : 'bg-red-50 text-red-800 border border-red-200'
                    }`}
                  >
                    <div className="font-medium">{result.relay}</div>
                    <div className="text-sm">{result.message}</div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}

function App() {
  return (
    <WasmProvider>
      <EventPublisher />
    </WasmProvider>
  );
}

const root = createRoot(document.getElementById('root')!);
root.render(<App />);