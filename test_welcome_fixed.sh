#!/bin/bash

set -e

echo "=== Fixed Welcome Test ==="

# Use test keys
BOB_PRIVATE_KEY="02"
ALICE_PRIVATE_KEY="01"

# Get Bob's public key and npub
echo "Getting Bob's public key info..."
BOB_PUB_HEX=$(./zig-out/bin/nostr_zig event --sec "$BOB_PRIVATE_KEY" -c "test" 2>&1 | grep "Public key:" | awk '{print $3}' | cut -d')' -f1)
echo "Bob's public key hex: $BOB_PUB_HEX"

# Convert hex to npub using a different approach
BOB_KP_OUTPUT=$(./zig-out/bin/nostr_zig publish-keypackage --sec "$BOB_PRIVATE_KEY" 2>&1)
BOB_PUBKEY=$(echo "$BOB_KP_OUTPUT" | grep '"pubkey":' | head -1 | cut -d'"' -f4)
echo "Bob's pubkey from event: $BOB_PUBKEY"

# Use python to convert to npub
BOB_NPUB=$(python3 -c "
import sys
pubkey_hex = '$BOB_PUBKEY'
# For now just use the hex directly since bech32 encoding is complex
print(f'npub1{pubkey_hex[:20]}...')  # Fake npub for testing
")
echo "Bob's npub (approx): $BOB_NPUB"

echo ""
echo "Testing with hex pubkey instead..."

# 1. Bob already published KeyPackage above
echo "1. Bob's KeyPackage already published"

sleep 2

# 2. Alice creates welcome using hex pubkey
echo ""
echo "2. Alice creates welcome using hex pubkey..."
./zig-out/bin/nostr_zig create-welcome "$BOB_PUBKEY" --sec "$ALICE_PRIVATE_KEY" --name "Test Group" --description "Fixed test"

sleep 2

# 3. Bob joins
echo ""
echo "3. Bob joins group..."
./zig-out/bin/nostr_zig join-group --sec "$BOB_PRIVATE_KEY"