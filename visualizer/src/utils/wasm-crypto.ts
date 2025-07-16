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