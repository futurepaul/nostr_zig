#!/bin/bash
set -e

echo "🚀 NIP-44 Simple Integration Test"
echo "================================"
echo

# First, let's just test that our implementation works
echo "Testing Zig NIP-44 implementation..."

# Create a simple test program
cat > test_nip44.zig << 'EOF'
const std = @import("std");
const nip44 = @import("nip44");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // Test keys from test vectors
    const sec1: [32]u8 = .{
        0x31, 0x5e, 0x59, 0xff, 0x51, 0xcb, 0x92, 0x09,
        0x76, 0x8c, 0xf7, 0xda, 0x80, 0x79, 0x1d, 0xdc,
        0xaa, 0xe5, 0x6a, 0xc9, 0x77, 0x5e, 0xb2, 0x5b,
        0x6d, 0xee, 0x12, 0x34, 0xbc, 0x5d, 0x22, 0x68,
    };
    
    const pub2: [32]u8 = .{
        0xc2, 0xf9, 0xd9, 0x94, 0x8d, 0xc8, 0xc7, 0xc3,
        0x83, 0x21, 0xe4, 0xb8, 0x5c, 0x85, 0x58, 0x87,
        0x2e, 0xaf, 0xa0, 0x64, 0x1c, 0xd2, 0x69, 0xdb,
        0x76, 0x84, 0x8a, 0x60, 0x73, 0xe6, 0x91, 0x33,
    };
    
    const message = "Hello, NIP-44!";
    
    // Encrypt
    const ciphertext = try nip44.encrypt(allocator, sec1, pub2, message);
    defer allocator.free(ciphertext);
    
    std.debug.print("✅ Encryption successful\n", .{});
    std.debug.print("   Ciphertext (first 50 chars): {s}...\n", .{ciphertext[0..@min(50, ciphertext.len)]});
    
    // Decrypt (would need sec2 and pub1 for proper roundtrip)
    // For now, just verify encryption works
    
    // Test conversation key
    const conv_key = try nip44.getConversationKey(sec1, pub2);
    std.debug.print("\n✅ Conversation key generation successful\n", .{});
    std.debug.print("   Key: ", .{});
    for (conv_key.key) |byte| {
        std.debug.print("{x:0>2}", .{byte});
    }
    std.debug.print("\n", .{});
}
EOF

# Build and run the test
echo
echo "Building test program..."
cd ..
zig build-exe integration_testing/test_nip44.zig \
    --mod nip44:secp256k1,v2.zig:src/nip44/mod.zig \
    --mod v2.zig::src/nip44/v2.zig \
    --mod secp256k1::src/secp256k1/secp256k1.zig \
    --deps nip44,secp256k1 \
    -lc \
    -Ldeps/secp256k1/.libs -lsecp256k1 \
    --verbose

if [ -f test_nip44 ]; then
    echo
    echo "Running test..."
    ./test_nip44
    rm test_nip44
else
    echo "❌ Build failed"
    exit 1
fi

echo
echo "✅ Basic test passed!"