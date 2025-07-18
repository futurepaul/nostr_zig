// WASM-based crypto utilities
// This replaces crypto.ts to ensure all cryptographic operations use the WASM module

import { wasm } from '../lib/wasm';

export function bytesToHex(bytes: Uint8Array): string {
  return wasm.bytesToHex(bytes);
}

export function isEphemeralKey(pubkey: string, knownIdentities: Map<string, any>): boolean {
  // This doesn't need WASM - it's just a simple check
  // Check if the pubkey is NOT in our known identities
  return !knownIdentities.has(pubkey);
}

// Create Nostr event ID according to NIP-01 (synchronous using SubtleCrypto)
export async function createNostrEventId(event: {
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
}): Promise<string> {
  // Serialize event according to NIP-01 spec
  const serialized = JSON.stringify([
    0, // Reserved for future use
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags,
    event.content
  ]);
  
  // Hash with SHA-256
  const encoder = new TextEncoder();
  const data = encoder.encode(serialized);
  
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = new Uint8Array(hashBuffer);
  return bytesToHex(hashArray);
}

// Synchronous hash function using WASM
export function sha256Sync(data: Uint8Array): Uint8Array {
  return wasm.sha256(data);
}

// Create Nostr event ID synchronously using WASM
export function createNostrEventIdSync(event: {
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
}): string {
  // Use WASM function for proper event ID generation
  const eventId = wasm.createNostrEventId(
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags,
    event.content
  );
  return bytesToHex(eventId);
}

// Sign Nostr event with WASM crypto
export function signNostrEvent(event: {
  id: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
}, privateKey: Uint8Array): string {
  // Convert hex event ID to bytes for signing
  const eventIdBytes = hexToBytes(event.id);
  
  // Sign with Schnorr signature
  const signature = wasm.signSchnorr(eventIdBytes, privateKey);
  
  // Convert to hex string
  return bytesToHex(signature);
}

// Convert hex string to bytes
export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

// NOTE: generateExporterSecret is now handled by WASM
// Use wasm.generateExporterSecret(groupState) instead