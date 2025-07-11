#!/bin/bash
set -e

echo "Building C NIP-44 reference implementation..."

# Check if we already have the C implementation
if [ ! -d "src" ]; then
    # Copy C implementation from samples
    cp -r ../../samples/nip44/c/* .
fi

# Build a simple test program using the C implementation
cat > nip44_test.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "include/noscrypt.h"

// Simple wrapper to expose NIP-44 functions for testing
// Takes hex input/output via stdin/stdout for easy integration

void hex_to_bytes(const char* hex, uint8_t* bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        sscanf(hex + 2*i, "%2hhx", &bytes[i]);
    }
}

void bytes_to_hex(const uint8_t* bytes, char* hex, size_t len) {
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + 2*i, "%02x", bytes[i]);
    }
    hex[2*len] = '\0';
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command> [args...]\n", argv[0]);
        return 1;
    }
    
    const char* cmd = argv[1];
    
    if (strcmp(cmd, "conversation_key") == 0) {
        // Read sec1 (hex) and pub2 (hex) from stdin
        char sec1_hex[65], pub2_hex[67];
        scanf("%64s %66s", sec1_hex, pub2_hex);
        
        uint8_t sec1[32], pub2[33];
        hex_to_bytes(sec1_hex, sec1, 32);
        hex_to_bytes(pub2_hex, pub2, 33);
        
        // TODO: Call noscrypt conversation key function
        // For now, output placeholder
        printf("placeholder_conversation_key\n");
    }
    else if (strcmp(cmd, "encrypt") == 0) {
        // TODO: Implement encrypt wrapper
        printf("placeholder_encrypted\n");
    }
    else if (strcmp(cmd, "decrypt") == 0) {
        // TODO: Implement decrypt wrapper
        printf("placeholder_decrypted\n");
    }
    else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        return 1;
    }
    
    return 0;
}
EOF

gcc -O2 -o nip44_wrapper nip44_wrapper.c -L. -lnoscrypt -lsecp256k1 -lm

echo "C implementation built successfully!"