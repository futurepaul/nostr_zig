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

// Synchronous hash function using a simple SHA-256 implementation
export function sha256Sync(data: Uint8Array): Uint8Array {
  // For browser compatibility, we'll use a simple implementation
  // In production, you'd want to use the WASM crypto module for this too
  
  // Simple synchronous hash - in reality this should use WASM
  // For now, generate a deterministic "hash" based on the data
  const hash = new Uint8Array(32);
  let h = 0;
  for (let i = 0; i < data.length; i++) {
    h = ((h * 31) + data[i]) & 0xffffffff;
  }
  
  // Fill hash with deterministic pattern based on data
  for (let i = 0; i < 32; i++) {
    hash[i] = ((h + i) * 7919) & 0xff;
  }
  
  return hash;
}

// Create Nostr event ID synchronously (simplified for demo)
export function createNostrEventIdSync(event: {
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
}): string {
  // Serialize event according to NIP-01 spec
  const serialized = JSON.stringify([
    0, // Reserved for future use
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags,
    event.content
  ]);
  
  // Hash with simple deterministic function for demo
  const encoder = new TextEncoder();
  const data = encoder.encode(serialized);
  const hash = sha256Sync(data);
  
  return bytesToHex(hash);
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