#!/bin/bash

set -e

echo "=== Simple Welcome Test ==="

# 1. Generate Bob's keys
echo "1. Generating Bob's keypair..."
BOB_KEYPAIR=$(./zig-out/bin/nostr_zig generate)
BOB_PRIVATE_KEY=$(echo "$BOB_KEYPAIR" | grep "Private key (hex):" | awk '{print $4}')
BOB_PUBLIC_KEY_HEX=$(echo "$BOB_KEYPAIR" | grep "Public key (hex):" | awk '{print $4}')
BOB_PUBLIC_KEY_NPUB=$(echo "$BOB_KEYPAIR" | grep "Public key (npub):" | awk '{print $4}')
echo "  Bob's npub: $BOB_PUBLIC_KEY_NPUB"
echo "  Bob's hex: $BOB_PUBLIC_KEY_HEX"

# 2. Bob publishes his KeyPackage
echo "2. Bob publishes his KeyPackage..."
./zig-out/bin/nostr_zig publish-keypackage --sec "$BOB_PRIVATE_KEY" > /dev/null 2>&1
echo "  ✅ KeyPackage published"

# Wait for relay
sleep 2

# 3. Generate Alice's keys
echo "3. Generating Alice's keypair..."
ALICE_KEYPAIR=$(./zig-out/bin/nostr_zig generate)
ALICE_PRIVATE_KEY=$(echo "$ALICE_KEYPAIR" | grep "Private key (hex):" | awk '{print $4}')
echo "  ✅ Alice keypair generated"

# 4. Alice creates welcome
echo "4. Alice creates group and sends welcome to Bob..."
./zig-out/bin/nostr_zig create-welcome "$BOB_PUBLIC_KEY_NPUB" --sec "$ALICE_PRIVATE_KEY" --name "Test Group" --description "Simple test" > /dev/null 2>&1
echo "  ✅ Welcome sent"

# Wait for relay
sleep 2

# 5. Bob tries to join
echo "5. Bob attempts to join the group..."
echo "Running: ./zig-out/bin/nostr_zig join-group --sec <bob_key>"
./zig-out/bin/nostr_zig join-group --sec "$BOB_PRIVATE_KEY"