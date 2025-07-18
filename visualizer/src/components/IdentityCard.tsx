import React from 'react';
import { Identity } from './MLSVisualizer';
import { Card, CardContent } from './ui/card';
import { InfoWrapper } from './InfoPanel';

interface IdentityCardProps {
  identity: Identity;
}

export function IdentityCard({ identity }: IdentityCardProps) {
  const pubkeyHex = Array.from(identity.publicKey)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  
  const shortPubkey = `${pubkeyHex.substring(0, 8)}...${pubkeyHex.substring(pubkeyHex.length - 8)}`;
  
  // Log the full pubkey for debugging
  console.log(`${identity.nickname} full pubkey:`, pubkeyHex);

  return (
    <Card>
      <CardContent className="pt-4">
        <div className="space-y-2">
          <div className="flex items-center space-x-2">
            <div className="w-10 h-10 bg-gradient-to-br from-blue-500 to-purple-500 rounded-full" />
            <div>
              <div className="font-semibold">{identity.nickname}</div>
              <div className="text-xs font-mono text-gray-500">{shortPubkey}</div>
            </div>
          </div>
          <InfoWrapper tooltip="Your Nostr identity consists of a private key (kept secret) and a public key (shared publicly). The public key serves as your unique identifier on the Nostr network. In NIP-EE, your Nostr identity is used to authenticate KeyPackages but NOT for MLS signing operations.">
            <div className="text-xs text-gray-500">
              Identity created ✓
            </div>
          </InfoWrapper>
        </div>
      </CardContent>
    </Card>
  );
}