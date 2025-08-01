#!/bin/bash

set -e

echo "=== Final Welcome Test ==="

# Step 1: Create Bob's KeyPackage and get his npub
echo "1. Creating Bob's account..."
BOB_KEY="02"
BOB_OUTPUT=$(./zig-out/bin/nostr_zig publish-keypackage --sec "$BOB_KEY" 2>&1)

# Extract Bob's pubkey from the event JSON
BOB_PUBKEY=$(echo "$BOB_OUTPUT" | grep -o '"pubkey":"[^"]*"' | cut -d'"' -f4 | head -1)
echo "   Bob's pubkey: $BOB_PUBKEY"

# Now we need to find Bob's npub. Let's check if there's a way to derive it
# For now, let's use a hardcoded mapping for test key "02"
# Based on the output we saw: pubkey ab1ac1872a38a2f196bed5a6047f0da2c8130fe8de49fc4d5dfb201f7611d8e2
# We need to encode this as bech32 npub

# Let's try to extract from an event command that shows the npub
echo ""
echo "Getting Bob's npub..."
# Create a dummy event to see the output format
DUMMY_OUTPUT=$(./zig-out/bin/nostr_zig event --sec "$BOB_KEY" -c "dummy" 2>&1 || true)

# Check if the dummy output contains an npub
if echo "$DUMMY_OUTPUT" | grep -q "npub"; then
    BOB_NPUB=$(echo "$DUMMY_OUTPUT" | grep -o 'npub[0-9a-z]*' | head -1)
    echo "   Found Bob's npub: $BOB_NPUB"
else
    # Hardcode it based on what we know
    # For test key "02" -> pubkey ab1ac1872a38a2f196bed5a6047f0da2c8130fe8de49fc4d5dfb201f7611d8e2
    BOB_NPUB="npub14vdvrpez8z30r94w6knqglcd5tyrzrlgmey0cn2lkeqrampm358qjh4spe"
    echo "   Using hardcoded npub: $BOB_NPUB"
fi

sleep 2

# Step 2: Alice creates a group and sends welcome
echo ""
echo "2. Alice creates group and sends welcome to Bob..."
ALICE_KEY="01"

# Try the create-welcome command
WELCOME_OUTPUT=$(./zig-out/bin/nostr_zig create-welcome "$BOB_NPUB" --sec "$ALICE_KEY" --name "Test Group" --description "Final test" 2>&1)
WELCOME_SUCCESS=$?

if [ $WELCOME_SUCCESS -ne 0 ]; then
    echo "   Failed to create welcome. Error output:"
    echo "$WELCOME_OUTPUT" | head -20
    echo ""
    echo "   Trying alternative approach..."
    
    # Maybe we need to fetch Bob's KeyPackage first?
    echo "   Fetching Bob's KeyPackage..."
    FETCH_OUTPUT=$(./zig-out/bin/nostr_zig fetch-keypackage "$BOB_NPUB" 2>&1 || true)
    echo "$FETCH_OUTPUT" | grep -E "(Found|KeyPackage|Error)" || true
else
    echo "   Welcome created successfully!"
fi

sleep 2

# Step 3: Bob joins the group
echo ""
echo "3. Bob attempts to join the group..."
JOIN_OUTPUT=$(./zig-out/bin/nostr_zig join-group --sec "$BOB_KEY" 2>&1)
echo "$JOIN_OUTPUT" | grep -E "(Successfully joined|Failed|Error|✅|❌)" || echo "$JOIN_OUTPUT"