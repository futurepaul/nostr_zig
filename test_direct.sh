#!/bin/bash

set -e

echo "=== Direct Test with Hardcoded Keys ==="

# Bob = test key 02
BOB_PRIVATE_KEY="02"

# First, just run the generate command to see Bob's info
echo "Bob's key info:"
BOB_GEN=$(./zig-out/bin/nostr_zig event --sec "$BOB_PRIVATE_KEY" -c "test" 2>&1 | grep -A5 "Event created successfully")
echo "$BOB_GEN"

# Extract the npub from the output
BOB_NPUB=$(echo "$BOB_GEN" | grep "Public key:" | awk '{print $3}')
echo ""
echo "Extracted Bob's npub: $BOB_NPUB"

if [ -z "$BOB_NPUB" ]; then
    echo "Failed to extract Bob's npub, using hardcoded value"
    # For test key 02, the npub should be deterministic
    # Let's calculate it manually or hardcode it
    BOB_NPUB="npub14vdvrpez8z30r94w6knqglcd5tyrzrlgmey0cn2lkeqrampm358qjh6hp7"
fi

echo ""
echo "1. Bob publishes KeyPackage..."
./zig-out/bin/nostr_zig publish-keypackage --sec "$BOB_PRIVATE_KEY"

sleep 2

echo ""
echo "2. Alice creates welcome..."
./zig-out/bin/nostr_zig create-welcome "$BOB_NPUB" --sec "01" --name "Test Group" --description "Direct test"

sleep 2

echo ""
echo "3. Bob joins group..."
./zig-out/bin/nostr_zig join-group --sec "$BOB_PRIVATE_KEY"