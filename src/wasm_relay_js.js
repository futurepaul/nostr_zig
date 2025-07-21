// JavaScript implementation of the WASM relay interface
// This file provides the WebSocket functionality that the WASM module calls

class WasmRelayInterface {
    constructor() {
        this.connections = new Map(); // url -> WebSocket
        this.subscriptions = new Map(); // subId -> callback
        this.eventCallbacks = new Map(); // callbackId -> callback
        this.decoder = new TextDecoder();
        this.encoder = new TextEncoder();
    }

    // Called by WASM to connect to a relay
    connect(urlPtr, urlLen) {
        try {
            const url = this.readString(urlPtr, urlLen);
            
            if (this.connections.has(url)) {
                return 0; // Already connected
            }

            const ws = new WebSocket(url);
            
            ws.onopen = () => {
                console.log(`Connected to relay: ${url}`);
            };

            ws.onmessage = (event) => {
                this.handleMessage(url, event.data);
            };

            ws.onerror = (error) => {
                console.error(`Relay error for ${url}:`, error);
            };

            ws.onclose = () => {
                console.log(`Disconnected from relay: ${url}`);
                this.connections.delete(url);
            };

            this.connections.set(url, ws);
            return 0; // Success
        } catch (error) {
            console.error('Connect error:', error);
            return -1; // Error
        }
    }

    // Called by WASM to disconnect from a relay
    disconnect() {
        for (const [url, ws] of this.connections) {
            ws.close();
        }
        this.connections.clear();
    }

    // Called by WASM to publish an event
    publish(eventJsonPtr, eventJsonLen, callbackId) {
        try {
            const eventJson = this.readString(eventJsonPtr, eventJsonLen);
            const event = JSON.parse(eventJson);
            
            // Send to all connected relays
            for (const [url, ws] of this.connections) {
                if (ws.readyState === WebSocket.OPEN) {
                    const message = JSON.stringify(["EVENT", event]);
                    ws.send(message);
                }
            }

            // Store callback if provided
            if (callbackId > 0) {
                this.eventCallbacks.set(event.id, callbackId);
            }

            return 0; // Success
        } catch (error) {
            console.error('Publish error:', error);
            return -1; // Error
        }
    }

    // Called by WASM to subscribe to events
    subscribe(subIdPtr, subIdLen, filtersJsonPtr, filtersJsonLen, callbackId) {
        try {
            const subId = this.readString(subIdPtr, subIdLen);
            const filtersJson = this.readString(filtersJsonPtr, filtersJsonLen);
            const filters = JSON.parse(filtersJson);
            
            // Store subscription callback
            if (callbackId > 0) {
                this.subscriptions.set(subId, callbackId);
            }

            // Send REQ to all connected relays
            for (const [url, ws] of this.connections) {
                if (ws.readyState === WebSocket.OPEN) {
                    const message = JSON.stringify(["REQ", subId, ...filters]);
                    ws.send(message);
                }
            }

            return 0; // Success
        } catch (error) {
            console.error('Subscribe error:', error);
            return -1; // Error
        }
    }

    // Called by WASM to unsubscribe
    unsubscribe(subIdPtr, subIdLen) {
        try {
            const subId = this.readString(subIdPtr, subIdLen);
            
            // Remove subscription
            this.subscriptions.delete(subId);

            // Send CLOSE to all connected relays
            for (const [url, ws] of this.connections) {
                if (ws.readyState === WebSocket.OPEN) {
                    const message = JSON.stringify(["CLOSE", subId]);
                    ws.send(message);
                }
            }

            return 0; // Success
        } catch (error) {
            console.error('Unsubscribe error:', error);
            return -1; // Error
        }
    }

    // Handle incoming WebSocket messages
    handleMessage(url, data) {
        try {
            const message = JSON.parse(data);
            
            if (!Array.isArray(message) || message.length < 2) {
                console.warn('Invalid message format:', data);
                return;
            }

            const [type, ...args] = message;

            switch (type) {
                case 'EVENT':
                    this.handleEventMessage(args[0], args[1]); // subId, event
                    break;
                case 'OK':
                    this.handleOkMessage(args[0], args[1], args[2]); // eventId, accepted, message
                    break;
                case 'EOSE':
                    this.handleEoseMessage(args[0]); // subId
                    break;
                case 'NOTICE':
                    console.log(`NOTICE from ${url}:`, args[0]);
                    break;
                default:
                    console.warn('Unknown message type:', type);
            }
        } catch (error) {
            console.error('Message handling error:', error);
        }
    }

    // Handle EVENT messages
    handleEventMessage(subId, event) {
        const callbackId = this.subscriptions.get(subId);
        if (callbackId && window.wasmExports) {
            const message = {
                type: 'event',
                subscription_id: subId,
                event: event
            };
            const messageJson = JSON.stringify(message);
            const messageBytes = this.encoder.encode(messageJson);
            
            // Allocate memory in WASM for the message
            const ptr = window.wasmExports.allocate(messageBytes.length);
            const wasmMemory = new Uint8Array(window.wasmExports.memory.buffer);
            wasmMemory.set(messageBytes, ptr);
            
            // Call WASM callback
            window.wasmExports.wasm_relay_message_callback(callbackId, ptr, messageBytes.length);
            
            // Free memory
            window.wasmExports.deallocate(ptr, messageBytes.length);
        }
    }

    // Handle OK messages
    handleOkMessage(eventId, accepted, message) {
        const callbackId = this.eventCallbacks.get(eventId);
        if (callbackId && window.wasmExports) {
            const messageBytes = message ? this.encoder.encode(message) : null;
            
            if (messageBytes) {
                const ptr = window.wasmExports.allocate(messageBytes.length);
                const wasmMemory = new Uint8Array(window.wasmExports.memory.buffer);
                wasmMemory.set(messageBytes, ptr);
                
                window.wasmExports.wasm_relay_event_callback(callbackId, accepted, ptr, messageBytes.length);
                window.wasmExports.deallocate(ptr, messageBytes.length);
            } else {
                window.wasmExports.wasm_relay_event_callback(callbackId, accepted, 0, 0);
            }
            
            // Remove callback after use
            this.eventCallbacks.delete(eventId);
        }
    }

    // Handle EOSE messages
    handleEoseMessage(subId) {
        const callbackId = this.subscriptions.get(subId);
        if (callbackId && window.wasmExports) {
            const message = {
                type: 'eose',
                subscription_id: subId
            };
            const messageJson = JSON.stringify(message);
            const messageBytes = this.encoder.encode(messageJson);
            
            const ptr = window.wasmExports.allocate(messageBytes.length);
            const wasmMemory = new Uint8Array(window.wasmExports.memory.buffer);
            wasmMemory.set(messageBytes, ptr);
            
            window.wasmExports.wasm_relay_message_callback(callbackId, ptr, messageBytes.length);
            window.wasmExports.deallocate(ptr, messageBytes.length);
        }
    }

    // Helper to read string from WASM memory
    readString(ptr, len) {
        const wasmMemory = new Uint8Array(window.wasmExports.memory.buffer);
        const bytes = wasmMemory.slice(ptr, ptr + len);
        return this.decoder.decode(bytes);
    }
}

// Create global instance
window.wasmRelay = new WasmRelayInterface();

// Export functions for WASM to call
window.wasm_relay_connect = (urlPtr, urlLen) => window.wasmRelay.connect(urlPtr, urlLen);
window.wasm_relay_disconnect = () => window.wasmRelay.disconnect();
window.wasm_relay_publish = (eventJsonPtr, eventJsonLen, callbackId) => 
    window.wasmRelay.publish(eventJsonPtr, eventJsonLen, callbackId);
window.wasm_relay_subscribe = (subIdPtr, subIdLen, filtersJsonPtr, filtersJsonLen, callbackId) => 
    window.wasmRelay.subscribe(subIdPtr, subIdLen, filtersJsonPtr, filtersJsonLen, callbackId);
window.wasm_relay_unsubscribe = (subIdPtr, subIdLen) => 
    window.wasmRelay.unsubscribe(subIdPtr, subIdLen);