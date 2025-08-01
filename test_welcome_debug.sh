#!/bin/bash

set -e

echo "=== Debug Welcome Test ==="

# Generate fixed keys for testing (use 01 and 02 as shortcuts)
BOB_PRIVATE_KEY="02"

# Get Bob's npub by using the generate command with the test key
BOB_EVENT_OUTPUT=$(./zig-out/bin/nostr_zig event --sec "$BOB_PRIVATE_KEY" -c "test" 2>&1)
BOB_NPUB=$(echo "$BOB_EVENT_OUTPUT" | grep "Public key:" | awk '{print $3}')
echo "Bob's npub: $BOB_NPUB"

echo ""
echo "1. Bob publishes KeyPackage..."
./zig-out/bin/nostr_zig publish-keypackage --sec "$BOB_PRIVATE_KEY"

sleep 2

echo ""
echo "2. Alice creates welcome..."
ALICE_PRIVATE_KEY="01"
./zig-out/bin/nostr_zig create-welcome "$BOB_NPUB" --sec "$ALICE_PRIVATE_KEY" --name "Debug Group" --description "Testing welcome"

sleep 2

echo ""
echo "3. Bob joins group..."
./zig-out/bin/nostr_zig join-group --sec "$BOB_PRIVATE_KEY"