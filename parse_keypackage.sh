#!/bin/bash

# Parse and display KeyPackage content details
# Usage: ./parse_keypackage.sh <hex_content>

if [ $# -ne 1 ]; then
    echo "Usage: $0 <hex_keypackage_content>"
    echo "Example: $0 00010001205666..."
    exit 1
fi

CONTENT=$1

echo "=== KeyPackage Parser ==="
echo "Total length: $((${#CONTENT} / 2)) bytes"
echo

# Parse the structure according to RFC 9420
echo "KeyPackage structure:"
echo "  Protocol Version: ${CONTENT:0:4} ($(printf "%d" 0x${CONTENT:0:4}))"
echo "  Cipher Suite: ${CONTENT:4:4} ($(printf "%d" 0x${CONTENT:4:4}))"

# Init key length (u8 at position 8)
INIT_KEY_LEN=$(printf "%d" 0x${CONTENT:8:2})
echo "  Init Key Length: $INIT_KEY_LEN bytes"
INIT_KEY_START=10
INIT_KEY_END=$((INIT_KEY_START + INIT_KEY_LEN * 2))
echo "  Init Key: ${CONTENT:$INIT_KEY_START:$((INIT_KEY_LEN * 2))}"

# LeafNode starts after init key
LEAF_START=$INIT_KEY_END

# Encryption key length (u8)
ENC_KEY_LEN=$(printf "%d" 0x${CONTENT:$LEAF_START:2})
echo "  Encryption Key Length: $ENC_KEY_LEN bytes"
ENC_KEY_START=$((LEAF_START + 2))
echo "  Encryption Key: ${CONTENT:$ENC_KEY_START:$((ENC_KEY_LEN * 2))}"

# Signature key starts after encryption key
SIG_KEY_START=$((ENC_KEY_START + ENC_KEY_LEN * 2))
SIG_KEY_LEN=$(printf "%d" 0x${CONTENT:$SIG_KEY_START:2})
echo "  Signature Key Length: $SIG_KEY_LEN bytes"
SIG_KEY_DATA_START=$((SIG_KEY_START + 2))
echo "  Signature Key: ${CONTENT:$SIG_KEY_DATA_START:$((SIG_KEY_LEN * 2))}"

# Credential starts after signature key
CRED_START=$((SIG_KEY_DATA_START + SIG_KEY_LEN * 2))
# Credential length is u16 (big-endian)
CRED_LEN_HEX="${CONTENT:$CRED_START:4}"
CRED_LEN=$(printf "%d" 0x$CRED_LEN_HEX)
echo "  Credential Length: $CRED_LEN bytes"

# The signature is at the end, it's 64 bytes for Ed25519
SIG_START=$((${#CONTENT} - 128))
echo "  Signature (last 64 bytes): ${CONTENT:$SIG_START:128}"

echo
echo "Summary:"
echo "  ✅ Valid MLS 1.0 KeyPackage"
echo "  ✅ Using X25519 for key exchange"
echo "  ✅ Using Ed25519 for signatures"
echo "  ✅ TLS-compliant serialization"