#!/bin/bash

# NIP-EE KeyPackage Roundtrip Test
# This script tests the full flow of generating, publishing, and fetching a KeyPackage

set -e  # Exit on error

echo "=== NIP-EE KeyPackage Roundtrip Test ==="
echo

# Check if relay is running
echo "1. Checking if relay is available at ws://localhost:10547..."
if ! nc -z localhost 10547 2>/dev/null; then
    echo "❌ Relay not running. Please start it with: nak serve --verbose"
    exit 1
fi
echo "✅ Relay is running"
echo

# Generate a new keypair
echo "2. Generating new keypair..."
KEYPAIR_OUTPUT=$(./zig-out/bin/nostr_zig generate)
echo "$KEYPAIR_OUTPUT"
echo

# Extract the private key (hex) and public key (npub) from output
PRIVATE_KEY=$(echo "$KEYPAIR_OUTPUT" | grep "Private key (hex):" | awk '{print $4}')
PUBLIC_KEY_HEX=$(echo "$KEYPAIR_OUTPUT" | grep "Public key (hex):" | awk '{print $4}')
PUBLIC_KEY_NPUB=$(echo "$KEYPAIR_OUTPUT" | grep "Public key (npub):" | awk '{print $4}')

echo "Extracted keys:"
echo "  Private key: $PRIVATE_KEY"
echo "  Public key (hex): $PUBLIC_KEY_HEX"
echo "  Public key (npub): $PUBLIC_KEY_NPUB"
echo

# Publish KeyPackage
echo "3. Publishing KeyPackage..."
PUBLISH_OUTPUT=$(./zig-out/bin/nostr_zig publish-keypackage --sec "$PRIVATE_KEY" 2>&1)
echo "$PUBLISH_OUTPUT"
echo

# Extract event details
EVENT_JSON=$(echo "$PUBLISH_OUTPUT" | grep '^{' | head -1)
if [ -z "$EVENT_JSON" ]; then
    echo "❌ Failed to extract event JSON"
    exit 1
fi

EVENT_ID=$(echo "$EVENT_JSON" | jq -r .id)
CONTENT=$(echo "$EVENT_JSON" | jq -r .content)

echo "Published event details:"
echo "  Event ID: $EVENT_ID"
echo "  Content length: ${#CONTENT} chars"
echo

# Wait a bit for relay to process
echo "4. Waiting for relay to process..."
sleep 2

# Query the relay directly using nak
echo "5. Querying relay for KeyPackage events..."
echo "Running: nak req -k 443 -a $PUBLIC_KEY_HEX ws://localhost:10547"
QUERY_OUTPUT=$(nak req -k 443 -a "$PUBLIC_KEY_HEX" ws://localhost:10547 2>&1 | head -10)
echo "$QUERY_OUTPUT"
echo

# Check if we got the event back
if echo "$QUERY_OUTPUT" | grep -q "$EVENT_ID"; then
    echo "✅ Successfully retrieved KeyPackage event from relay!"
    
    # Extract and verify content
    FETCHED_CONTENT=$(echo "$QUERY_OUTPUT" | grep '^{' | jq -r .content | head -1)
    if [ "$CONTENT" = "$FETCHED_CONTENT" ]; then
        echo "✅ Content matches!"
    else
        echo "❌ Content mismatch!"
        echo "  Original: ${CONTENT:0:50}..."
        echo "  Fetched:  ${FETCHED_CONTENT:0:50}..."
    fi
    
    # Parse the KeyPackage content
    echo
    echo "6. Parsing KeyPackage content..."
    echo "  Content is hex-encoded TLS-serialized KeyPackage"
    echo "  Length: $((${#CONTENT} / 2)) bytes"
    
    # Show first few bytes to verify it's a valid KeyPackage
    echo "  First 8 bytes: ${CONTENT:0:16}"
    echo "  Protocol version: ${CONTENT:0:4} (0001 = MLS 1.0)"
    echo "  Cipher suite: ${CONTENT:4:4} (0001 = MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)"
    
    # Verify MLS tags
    echo
    echo "7. Verifying MLS tags..."
    MLS_VERSION=$(echo "$QUERY_OUTPUT" | grep '^{' | jq -r '.tags[] | select(.[0] == "mls_protocol_version") | .[1]' | head -1)
    MLS_SUITE=$(echo "$QUERY_OUTPUT" | grep '^{' | jq -r '.tags[] | select(.[0] == "mls_ciphersuite") | .[1]' | head -1)
    MLS_EXTENSIONS=$(echo "$QUERY_OUTPUT" | grep '^{' | jq -r '.tags[] | select(.[0] == "mls_extensions") | .[1]' | head -1)
    
    echo "  MLS Protocol Version: $MLS_VERSION"
    echo "  MLS Ciphersuite: $MLS_SUITE"
    echo "  MLS Extensions: $MLS_EXTENSIONS"
    
    if [ "$MLS_VERSION" = "1.0" ] && [ "$MLS_SUITE" = "1" ]; then
        echo "✅ MLS metadata is correct!"
    else
        echo "❌ MLS metadata mismatch!"
    fi
    
else
    echo "❌ Failed to retrieve KeyPackage event from relay"
    echo "Debug: Looking for event ID $EVENT_ID"
fi

echo
echo "=== Test Complete ==="

# Test the fetch command (even though it's not fully implemented)
echo
echo "8. Testing fetch-keypackage command..."
./zig-out/bin/nostr_zig fetch-keypackage "$PUBLIC_KEY_NPUB"