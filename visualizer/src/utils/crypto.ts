// Crypto utility functions for the visualizer

export function getRandomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

export function generateEphemeralKeyPair(): { privateKey: Uint8Array; publicKey: Uint8Array } {
  // This is a placeholder for visualization
  // The actual implementation in WASM uses proper secp256k1 key derivation
  const privateKey = getRandomBytes(32);
  
  // In the real WASM implementation, this would be derived using secp256k1
  // For now, we'll mark it clearly as a demo key
  const publicKey = new Uint8Array(32);
  publicKey.set(privateKey.slice(0, 16));
  publicKey.set(privateKey.slice(16).map(b => b ^ 0xFF), 16);
  
  return { privateKey, publicKey };
}

export function isEphemeralKey(pubkey: string, knownIdentities: Map<string, any>): boolean {
  // Check if the pubkey is NOT in our known identities
  return !knownIdentities.has(pubkey);
}