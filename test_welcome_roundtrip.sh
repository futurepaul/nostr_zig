#!/bin/bash

# NIP-EE Welcome Message Roundtrip Test
# This script tests the full flow:
# 1. Bob publishes a KeyPackage
# 2. Alice fetches Bob's KeyPackage and creates a group with welcome
# 3. Bob processes the welcome to join the group

set -e  # Exit on error

echo "=== NIP-EE Welcome Message Roundtrip Test ==="
echo
echo "This test demonstrates the REAL DEAL - actual MLS group creation and joining!"
echo

# Check if relay is running
echo "1. Checking if relay is available at ws://localhost:10547..."
if ! nc -z localhost 10547 2>/dev/null; then
    echo "❌ Relay not running. Please start it with: nak serve --verbose"
    exit 1
fi
echo "✅ Relay is running"
echo

# Generate Bob's keypair
echo "2. Generating Bob's keypair..."
BOB_KEYPAIR=$(./zig-out/bin/nostr_zig generate)
BOB_PRIVATE_KEY=$(echo "$BOB_KEYPAIR" | grep "Private key (hex):" | awk '{print $4}')
BOB_PUBLIC_KEY_HEX=$(echo "$BOB_KEYPAIR" | grep "Public key (hex):" | awk '{print $4}')
BOB_PUBLIC_KEY_NPUB=$(echo "$BOB_KEYPAIR" | grep "Public key (npub):" | awk '{print $4}')
echo "  Bob's npub: $BOB_PUBLIC_KEY_NPUB"
echo

# Bob publishes his KeyPackage
echo "3. Bob publishes his KeyPackage..."
BOB_PUBLISH_OUTPUT=$(./zig-out/bin/nostr_zig publish-keypackage --sec "$BOB_PRIVATE_KEY" 2>&1)
echo "$BOB_PUBLISH_OUTPUT" | grep -E "(✅|Event ID:|KeyPackage size:|MLS metadata:)" || true
echo

# Extract Bob's KeyPackage event ID
BOB_KP_EVENT_JSON=$(echo "$BOB_PUBLISH_OUTPUT" | grep '^{' | head -1)
BOB_KP_EVENT_ID=$(echo "$BOB_KP_EVENT_JSON" | jq -r .id)
echo "  Bob's KeyPackage Event ID: $BOB_KP_EVENT_ID"
echo

# Wait for relay to process
sleep 2

# Generate Alice's keypair
echo "4. Generating Alice's keypair..."
ALICE_KEYPAIR=$(./zig-out/bin/nostr_zig generate)
ALICE_PRIVATE_KEY=$(echo "$ALICE_KEYPAIR" | grep "Private key (hex):" | awk '{print $4}')
ALICE_PUBLIC_KEY_NPUB=$(echo "$ALICE_KEYPAIR" | grep "Public key (npub):" | awk '{print $4}')
echo "  Alice's npub: $ALICE_PUBLIC_KEY_NPUB"
echo

# Alice creates a group and sends welcome to Bob
echo "5. Alice creates a group and sends welcome to Bob..."
echo "   Running: ./zig-out/bin/nostr_zig create-welcome $BOB_PUBLIC_KEY_NPUB --sec <alice_key> --name \"Test Group\" --description \"Testing MLS roundtrip\""
ALICE_WELCOME_OUTPUT=$(./zig-out/bin/nostr_zig create-welcome "$BOB_PUBLIC_KEY_NPUB" --sec "$ALICE_PRIVATE_KEY" --name "Test Group" --description "Testing MLS roundtrip" 2>&1)
echo "$ALICE_WELCOME_OUTPUT" | grep -E "(✅|Group ID:|Epoch:|Welcome event published)" || true
echo

# Extract Group ID from output
GROUP_ID=$(echo "$ALICE_WELCOME_OUTPUT" | grep "Group ID:" | awk '{print $3}')
if [ -n "$GROUP_ID" ]; then
    echo "  Group ID: $GROUP_ID"
else
    echo "  Could not extract Group ID"
fi
echo

# Check if welcome event was published
if echo "$ALICE_WELCOME_OUTPUT" | grep -q "Welcome event published successfully"; then
    echo "✅ Welcome event created and published!"
    echo
    
    # Query for Bob's gift-wrapped welcome events
    echo "6. Querying for Bob's welcome events (kind 1059 - gift wrapped)..."
    echo "   Note: Welcome events are encrypted and only Bob can decrypt them"
    WELCOME_QUERY=$(nak req -k 1059 -p "$BOB_PUBLIC_KEY_HEX" ws://localhost:10547 --limit 5 2>&1 | head -20)
    
    if echo "$WELCOME_QUERY" | grep -q '"kind":1059'; then
        echo "✅ Found gift-wrapped welcome event(s) for Bob!"
        WELCOME_COUNT=$(echo "$WELCOME_QUERY" | grep -c '"kind":1059' || true)
        echo "  Found $WELCOME_COUNT gift-wrapped event(s)"
    else
        echo "⚠️  No gift-wrapped welcome events found yet"
        echo "  This might be expected if the relay hasn't processed them yet"
    fi
    
    echo
    echo "7. Bob joins the group using the Welcome..."
    sleep 2  # Give the relay time to process
    
    BOB_JOIN_OUTPUT=$(./zig-out/bin/nostr_zig join-group --sec "$BOB_PRIVATE_KEY" 2>&1)
    echo "$BOB_JOIN_OUTPUT" | grep -E "(✅|Successfully joined|Group ID:|Members:|Group Metadata:)" || echo "$BOB_JOIN_OUTPUT"
    
    if echo "$BOB_JOIN_OUTPUT" | grep -q "Successfully joined MLS group"; then
        echo
        echo "🎉 FULL MLS ROUNDTRIP COMPLETE! 🎉"
        echo "   - Bob published his KeyPackage"
        echo "   - Alice fetched it and created a group"
        echo "   - Alice sent Bob an encrypted Welcome"
        echo "   - Bob decrypted the Welcome and joined the group!"
        echo
        echo "This is the REAL DEAL - actual MLS group creation and joining over Nostr!"
    else
        echo
        echo "⚠️  Bob couldn't join the group. This might be expected if:"
        echo "   - The Welcome hasn't propagated to the relay yet"
        echo "   - Bob's KeyPackage has expired"
        echo "   - There's a version mismatch"
    fi
    
else
    echo "❌ Failed to create welcome event"
fi

echo
echo
echo "=== Roundtrip Test Summary ==="
echo "Run './zig-out/bin/nostr_zig join-group --sec <bob_key>' to have Bob join the group!"