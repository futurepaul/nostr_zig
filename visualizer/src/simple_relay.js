// Simple WebSocket relay interface for Nostr event publishing

class SimpleNostrRelay {
    constructor() {
        this.ws = null;
        this.connected = false;
        this.eventCallbacks = new Map();
        this.messageQueue = [];
        this.connectionPromise = null;
    }

    async connect(url) {
        if (this.connected && this.ws?.readyState === WebSocket.OPEN) {
            return true;
        }

        // If already connecting, wait for it
        if (this.connectionPromise) {
            return this.connectionPromise;
        }

        this.connectionPromise = new Promise((resolve, reject) => {
            try {
                this.ws = new WebSocket(url);
                
                this.ws.onopen = () => {
                    console.log(`Connected to ${url}`);
                    this.connected = true;
                    this.connectionPromise = null;
                    
                    // Send any queued messages
                    while (this.messageQueue.length > 0) {
                        const msg = this.messageQueue.shift();
                        this.ws.send(msg);
                    }
                    
                    resolve(true);
                };

                this.ws.onmessage = (event) => {
                    this.handleMessage(event.data);
                };

                this.ws.onerror = (error) => {
                    console.error('WebSocket error:', error);
                    this.connected = false;
                    this.connectionPromise = null;
                    reject(error);
                };

                this.ws.onclose = () => {
                    console.log('Disconnected from relay');
                    this.connected = false;
                    this.connectionPromise = null;
                };

                // Set a timeout
                setTimeout(() => {
                    if (!this.connected) {
                        this.ws?.close();
                        this.connectionPromise = null;
                        reject(new Error('Connection timeout'));
                    }
                }, 5000);

            } catch (error) {
                this.connectionPromise = null;
                reject(error);
            }
        });

        return this.connectionPromise;
    }

    disconnect() {
        if (this.ws) {
            this.ws.close();
            this.ws = null;
            this.connected = false;
            this.eventCallbacks.clear();
            this.messageQueue = [];
        }
    }

    async publishEvent(event) {
        if (!this.connected) {
            throw new Error('Not connected to relay');
        }

        const message = JSON.stringify(["EVENT", event]);
        
        return new Promise((resolve, reject) => {
            // Store callback for this event
            this.eventCallbacks.set(event.id, { resolve, reject });

            // Send the event
            if (this.ws.readyState === WebSocket.OPEN) {
                this.ws.send(message);
            } else {
                // Queue the message if not fully connected yet
                this.messageQueue.push(message);
            }

            // Set a timeout for the response
            setTimeout(() => {
                if (this.eventCallbacks.has(event.id)) {
                    this.eventCallbacks.delete(event.id);
                    reject(new Error('Publish timeout'));
                }
            }, 10000);
        });
    }

    handleMessage(data) {
        try {
            const msg = JSON.parse(data);
            
            if (!Array.isArray(msg) || msg.length < 2) {
                return;
            }

            const [type, ...args] = msg;

            switch (type) {
                case 'OK':
                    this.handleOK(args[0], args[1], args[2]);
                    break;
                case 'NOTICE':
                    console.log('Relay notice:', args[0]);
                    break;
                case 'EOSE':
                    // End of stored events - we don't use subscriptions here
                    break;
                default:
                    console.log('Unknown message type:', type);
            }
        } catch (error) {
            console.error('Error handling message:', error);
        }
    }

    handleOK(eventId, accepted, message) {
        const callback = this.eventCallbacks.get(eventId);
        if (callback) {
            this.eventCallbacks.delete(eventId);
            
            if (accepted) {
                callback.resolve({ success: true, message: message || 'Event accepted' });
            } else {
                callback.reject(new Error(message || 'Event rejected'));
            }
        }
    }
}

// Create a simple interface for the visualizer
window.SimpleRelay = {
    relays: new Map(),

    async connect(url) {
        if (!this.relays.has(url)) {
            this.relays.set(url, new SimpleNostrRelay());
        }
        
        const relay = this.relays.get(url);
        return await relay.connect(url);
    },

    disconnect(url) {
        const relay = this.relays.get(url);
        if (relay) {
            relay.disconnect();
            this.relays.delete(url);
        }
    },

    disconnectAll() {
        for (const relay of this.relays.values()) {
            relay.disconnect();
        }
        this.relays.clear();
    },

    async publish(url, event) {
        const relay = this.relays.get(url);
        if (!relay) {
            throw new Error('Not connected to relay: ' + url);
        }
        
        return await relay.publishEvent(event);
    }
};