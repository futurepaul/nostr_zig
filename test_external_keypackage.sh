#!/bin/bash

# Test parsing external KeyPackages from other NIP-EE implementations
# Usage: ./test_external_keypackage.sh <npub_or_pubkey_hex>

set -e

if [ $# -ne 1 ]; then
    echo "Usage: $0 <npub_or_pubkey_hex>"
    echo "Example: $0 npub1..."
    echo "Example: $0 8c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa"
    exit 1
fi

INPUT=$1

echo "=== External KeyPackage Integration Test ==="
echo

# Check if input is npub or hex
if [[ $INPUT == npub1* ]]; then
    echo "Input is npub format"
    NPUB=$INPUT
    # Convert npub to hex using our tool
    echo "Converting npub to hex..."
    # For now, we'll use the hex directly since fetch-keypackage isn't fully implemented
    echo "Note: Full npub conversion not yet implemented"
    echo "Please provide hex pubkey for now"
    exit 1
else
    echo "Input is hex pubkey format"
    PUBKEY_HEX=$INPUT
fi

# Check relay
echo "1. Checking relay availability..."
if ! nc -z localhost 10547 2>/dev/null; then
    echo "❌ Relay not running. Please start it with: nak serve --verbose"
    exit 1
fi
echo "✅ Relay is available"
echo

# Query for KeyPackages from this author
echo "2. Querying relay for KeyPackages from $PUBKEY_HEX..."
echo "Command: nak req -k 443 -a $PUBKEY_HEX ws://localhost:10547"
echo

EVENTS=$(nak req -k 443 -a "$PUBKEY_HEX" ws://localhost:10547 2>&1 | grep '^{' || true)

if [ -z "$EVENTS" ]; then
    echo "❌ No KeyPackage events found for this pubkey"
    echo
    echo "Debugging: Check all KeyPackages on relay:"
    nak req -k 443 ws://localhost:10547 | head -5
    exit 1
fi

echo "✅ Found KeyPackage event(s)!"
echo

# Parse the first event
EVENT=$(echo "$EVENTS" | head -1)
echo "3. Parsing KeyPackage event..."
echo "$EVENT" | jq . || echo "$EVENT"
echo

# Extract details
EVENT_ID=$(echo "$EVENT" | jq -r .id)
CREATED_AT=$(echo "$EVENT" | jq -r .created_at)
CONTENT=$(echo "$EVENT" | jq -r .content)

echo "Event details:"
echo "  ID: $EVENT_ID"
echo "  Created: $CREATED_AT ($(date -r $CREATED_AT 2>/dev/null || date -d @$CREATED_AT 2>/dev/null || echo 'timestamp'))"
echo "  Content length: ${#CONTENT} chars ($(( ${#CONTENT} / 2 )) bytes)"
echo

# Check MLS tags
echo "4. Verifying NIP-EE tags..."
MLS_VERSION=$(echo "$EVENT" | jq -r '.tags[] | select(.[0] == "mls_protocol_version") | .[1]' | head -1)
MLS_SUITE=$(echo "$EVENT" | jq -r '.tags[] | select(.[0] == "mls_ciphersuite") | .[1]' | head -1)
MLS_EXTENSIONS=$(echo "$EVENT" | jq -r '.tags[] | select(.[0] == "mls_extensions") | .[1]' | head -1)
RELAYS=$(echo "$EVENT" | jq -r '.tags[] | select(.[0] == "relays") | .[1]' | head -1)

echo "  Protocol Version: $MLS_VERSION"
echo "  Cipher Suite: $MLS_SUITE"
echo "  Extensions: $MLS_EXTENSIONS"
echo "  Relays: $RELAYS"

if [ "$MLS_VERSION" != "1.0" ]; then
    echo "⚠️  Warning: Unexpected MLS version (expected 1.0)"
fi

if [ "$MLS_SUITE" != "1" ] && [ "$MLS_SUITE" != "0x0001" ]; then
    echo "⚠️  Warning: Unexpected cipher suite (expected 1)"
fi
echo

# Parse the KeyPackage content
echo "5. Analyzing KeyPackage structure..."
if [ -f "./parse_keypackage.sh" ]; then
    ./parse_keypackage.sh "$CONTENT"
else
    echo "Basic structure analysis:"
    echo "  First 8 bytes: ${CONTENT:0:16}"
    echo "  Protocol: ${CONTENT:0:4}"
    echo "  Cipher Suite: ${CONTENT:4:4}"
    
    # Try to identify if it's our format or external
    if [ "${CONTENT:0:8}" = "00010001" ]; then
        echo "  ✅ Standard MLS 1.0 with X25519/Ed25519 cipher suite"
    else
        echo "  ⚠️  Different protocol version or cipher suite"
    fi
fi
echo

# Compare with our KeyPackages
echo "6. Compatibility check..."
echo "Comparing with our KeyPackage format:"
echo "  Our format: 242 bytes, flat structure"
echo "  External: $(( ${#CONTENT} / 2 )) bytes"

if [ $(( ${#CONTENT} / 2 )) -gt 300 ]; then
    echo "  Note: External KeyPackage is larger - may include extensions or different encoding"
fi

echo
echo "=== Summary ==="
if [ "$MLS_VERSION" = "1.0" ]; then
    echo "✅ External client is using MLS 1.0"
    echo "✅ KeyPackage found and retrieved"
    echo "🔄 Next step: Parse the KeyPackage in Zig to extract keys"
else
    echo "⚠️  External client may be using different MLS version"
fi

echo
echo "To continue integration testing:"
echo "1. Update fetch-keypackage command to parse this content"
echo "2. Extract init_key, encryption_key, and signature_key"
echo "3. Use the KeyPackage to create a group with this external member"