#!/bin/bash

set -e

echo "=== Working Welcome Test ==="

# Test keys
BOB_KEY="02"
ALICE_KEY="01"
BOB_NPUB="npub14vdvrpe28z30r9476knqglcd5typxrlgmeylcn2alvsp7as3mr3qyewvhj"

echo "Bob's npub: $BOB_NPUB"

# 1. Bob publishes KeyPackage
echo ""
echo "1. Bob publishes KeyPackage..."
./zig-out/bin/nostr_zig publish-keypackage --sec "$BOB_KEY"

sleep 2

# 2. Alice creates welcome
echo ""
echo "2. Alice creates group and sends welcome..."
./zig-out/bin/nostr_zig create-welcome "$BOB_NPUB" --sec "$ALICE_KEY" --name "Test Group" --description "Working test"

sleep 2

# 3. Bob joins
echo ""
echo "3. Bob joins group..."
./zig-out/bin/nostr_zig join-group --sec "$BOB_KEY"