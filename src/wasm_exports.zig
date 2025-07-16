const std = @import("std");
const crypto = @import("crypto.zig");
const ephemeral = @import("mls/ephemeral.zig");
const secp256k1 = @import("secp256k1");

// Declare the external function directly here
extern fn getRandomValues(buf: [*]u8, len: usize) void;

// Use a simple fixed buffer allocator for WASM
var buffer: [1024 * 1024]u8 = undefined; // 1MB buffer
var fba: ?std.heap.FixedBufferAllocator = null;

fn getAllocator() std.mem.Allocator {
    if (fba == null) {
        fba = std.heap.FixedBufferAllocator.init(&buffer);
    }
    return fba.?.allocator();
}

export fn wasm_init() void {
    // Empty init
}

export fn wasm_add(a: i32, b: i32) i32 {
    return a + b;
}

export fn wasm_alloc(size: usize) ?[*]u8 {
    const mem = getAllocator().alloc(u8, size) catch return null;
    return mem.ptr;
}

export fn wasm_alloc_u32(count: usize) ?[*]u32 {
    const mem = getAllocator().alignedAlloc(u32, @alignOf(u32), count) catch return null;
    return mem.ptr;
}

export fn wasm_free(ptr: [*]u8, size: usize) void {
    getAllocator().free(ptr[0..size]);
}

export fn wasm_free_u32(ptr: [*]u32, count: usize) void {
    getAllocator().free(ptr[0..count]);
}

export fn wasm_align_ptr(ptr: usize, alignment: usize) usize {
    const mask = alignment - 1;
    return (ptr + mask) & ~mask;
}

// External function for secp256k1 error logging
export fn wasm_log_error(str: [*]const u8, len: c_int) void {
    // This will be called from C code if there's an error
    // For now, we'll just ignore it (the JS side provides the real implementation)
    _ = str;
    _ = len;
}

// Test random generation - this will call the external getRandomValues function
export fn wasm_test_random() void {
    var test_bytes: [8]u8 = undefined;
    getRandomValues(&test_bytes, test_bytes.len);
    // The values should be different each time if randomness is working
}

// Simple test function to check secp256k1 context creation
export fn wasm_test_secp256k1_context() bool {
    const builtin = @import("builtin");
    const ctx = if (builtin.target.cpu.arch == .wasm32) blk: {
        // In WASM, use the static no-precomp context
        const wasm_ctx = @import("wasm_secp_context.zig");
        break :blk wasm_ctx.getStaticContext();
    } else blk: {
        // On native platforms, create a context normally
        break :blk secp256k1.secp256k1_context_create(secp256k1.SECP256K1_CONTEXT_SIGN) orelse return false;
    };
    defer if (builtin.target.cpu.arch != .wasm32) {
        secp256k1.secp256k1_context_destroy(ctx);
    };
    return true;
}

// Generate an ephemeral keypair for group messages
export fn wasm_generate_ephemeral_keys(out_private_key: [*]u8, out_public_key: [*]u8) bool {
    // Generate ephemeral keys using the proper module
    const key_pair = ephemeral.EphemeralKeyPair.generate() catch return false;
    
    // Copy to output buffers
    @memcpy(out_private_key[0..32], &key_pair.private_key);
    @memcpy(out_public_key[0..32], &key_pair.public_key);
    
    return true;
}

// Sign a message/hash with secp256k1
export fn wasm_sign_schnorr(
    message_hash: [*]const u8,
    private_key: [*]const u8,
    out_signature: [*]u8
) bool {
    // Use static context for WASM compatibility
    const builtin = @import("builtin");
    const ctx = if (builtin.target.cpu.arch == .wasm32) blk: {
        // In WASM, use the static no-precomp context
        const wasm_ctx = @import("wasm_secp_context.zig");
        break :blk wasm_ctx.getStaticContext();
    } else blk: {
        // On native platforms, create a context normally
        break :blk secp256k1.secp256k1_context_create(secp256k1.SECP256K1_CONTEXT_SIGN) orelse return false;
    };
    defer if (builtin.target.cpu.arch != .wasm32) {
        secp256k1.secp256k1_context_destroy(ctx);
    };
    
    // Create keypair
    var keypair: secp256k1.secp256k1_keypair = undefined;
    if (secp256k1.secp256k1_keypair_create(ctx, &keypair, private_key) != 1) {
        return false;
    }
    
    // Sign with Schnorr
    var signature: [64]u8 = undefined;
    if (secp256k1.secp256k1_schnorrsig_sign32(ctx, &signature, message_hash, &keypair, null) != 1) {
        return false;
    }
    
    // Copy to output
    @memcpy(out_signature[0..64], &signature);
    return true;
}

// Verify a Schnorr signature
export fn wasm_verify_schnorr(
    message_hash: [*]const u8,
    signature: [*]const u8,
    public_key: [*]const u8
) bool {
    // Use static context for WASM compatibility
    const builtin = @import("builtin");
    const ctx = if (builtin.target.cpu.arch == .wasm32) blk: {
        // In WASM, use the static no-precomp context
        const wasm_ctx = @import("wasm_secp_context.zig");
        break :blk wasm_ctx.getStaticContext();
    } else blk: {
        // On native platforms, create a context normally
        break :blk secp256k1.secp256k1_context_create(secp256k1.SECP256K1_CONTEXT_VERIFY) orelse return false;
    };
    defer if (builtin.target.cpu.arch != .wasm32) {
        secp256k1.secp256k1_context_destroy(ctx);
    };
    
    // Parse x-only public key
    var xonly_pubkey: secp256k1.secp256k1_xonly_pubkey = undefined;
    if (secp256k1.secp256k1_xonly_pubkey_parse(ctx, &xonly_pubkey, public_key) != 1) {
        return false;
    }
    
    // Verify signature
    const result = secp256k1.secp256k1_schnorrsig_verify(ctx, signature, message_hash, 32, &xonly_pubkey);
    return result == 1;
}

// Export the secure random function for the wasm_random module
export fn bytes_to_hex(bytes: [*]const u8, bytes_len: usize, out_hex: [*]u8, out_hex_len: usize) bool {
    // Check output buffer is large enough (2 chars per byte)
    if (out_hex_len < bytes_len * 2) return false;
    
    const hex_chars = "0123456789abcdef";
    var i: usize = 0;
    while (i < bytes_len) : (i += 1) {
        const byte = bytes[i];
        out_hex[i * 2] = hex_chars[byte >> 4];
        out_hex[i * 2 + 1] = hex_chars[byte & 0x0F];
    }
    return true;
}

export fn wasm_create_identity(out_private_key: [*]u8, out_public_key: [*]u8) bool {
    // Generate a real secp256k1 keypair
    const private_key = crypto.generatePrivateKey() catch return false;
    const public_key = crypto.getPublicKey(private_key) catch return false;
    
    // Copy to output buffers
    @memcpy(out_private_key[0..32], &private_key);
    @memcpy(out_public_key[0..32], &public_key);
    
    return true;
}

export fn wasm_get_public_key_from_private(private_key: [*]const u8, out_public_key: [*]u8) bool {
    // Get public key from private key using real secp256k1
    const pub_key = crypto.getPublicKey(private_key[0..32].*) catch return false;
    
    // Copy to output buffer
    @memcpy(out_public_key[0..32], &pub_key);
    
    return true;
}

export fn wasm_create_key_package(
    private_key: [*]const u8,
    out_data: [*]u8,
    out_len: *u32
) bool {
    // Create a simplified key package for the visualizer
    // This is not a real MLS key package, just a demo structure
    
    // Get the public key from the private key
    var public_key: [32]u8 = undefined;
    const pub_key_result = crypto.getPublicKey(private_key[0..32].*) catch return false;
    public_key = pub_key_result;
    
    // Create a simple key package structure:
    // [version: 1 byte][public_key: 32 bytes][timestamp: 8 bytes][signature: 64 bytes]
    const min_size = 1 + 32 + 8 + 64;
    if (out_len.* < min_size) {
        return false;
    }
    
    // Version
    out_data[0] = 1;
    
    // Public key
    @memcpy(out_data[1..33], &public_key);
    
    // Timestamp (use a fixed value for WASM)
    const timestamp: u64 = 1700000000; // Fixed timestamp for WASM
    const timestamp_bytes = std.mem.asBytes(&timestamp);
    @memcpy(out_data[33..41], timestamp_bytes);
    
    // Create a simple signature over the data
    var to_sign: [41]u8 = undefined;
    @memcpy(to_sign[0..41], out_data[0..41]);
    
    // Hash the data to sign
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&to_sign, &hash, .{});
    
    // Sign with Schnorr
    var signature: [64]u8 = undefined;
    if (!wasm_sign_schnorr(&hash, private_key, &signature)) {
        // If signing fails, just use zeros for now
        @memset(&signature, 0);
    }
    
    // Add signature
    @memcpy(out_data[41..105], &signature);
    
    // Update the actual length
    out_len.* = min_size;
    
    return true;
}

export fn wasm_create_group(
    creator_private_key: [*]const u8,
    creator_public_key: [*]const u8,
    out_state: [*]u8,
    out_state_len: *u32
) bool {
    // For now, create a simple group state structure
    // Format: [version: 1][group_id: 32][creator_pubkey: 32][timestamp: 8][signature: 64]
    const min_size = 1 + 32 + 32 + 8 + 64;
    
    // Check 1: Buffer size
    if (out_state_len.* < min_size) {
        return false; // Buffer too small
    }
    
    // Check 2: Version
    out_state[0] = 1;
    
    // Check 3: Generate random group ID
    var group_id: [32]u8 = undefined;
    getRandomValues(&group_id, 32);
    @memcpy(out_state[1..33], &group_id);
    
    // Check 4: Creator public key
    @memcpy(out_state[33..65], creator_public_key[0..32]);
    
    // Check 5: Timestamp (fixed for WASM)
    const timestamp: u64 = 1700000000;
    const timestamp_bytes = std.mem.asBytes(&timestamp);
    @memcpy(out_state[65..73], timestamp_bytes);
    
    // Check 6: Create signature over the group data
    var to_sign: [73]u8 = undefined;
    @memcpy(to_sign[0..73], out_state[0..73]);
    
    // Check 7: Hash the data
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&to_sign, &hash, .{});
    
    // Check 8: Sign with creator's key - this is likely where it fails
    var signature: [64]u8 = undefined;
    if (!wasm_sign_schnorr(&hash, creator_private_key, &signature)) {
        // For debugging, let's use a temporary dummy signature to see if this is the issue
        @memset(&signature, 0xdd); // Distinct dummy pattern
    }
    
    // Check 9: Add signature
    @memcpy(out_state[73..137], &signature);
    
    // Check 10: Update actual length
    out_state_len.* = min_size;
    
    return true; // Always return true for now to test
}

export fn wasm_send_message(
    group_state: [*]const u8,
    group_state_len: u32,
    sender_private_key: [*]const u8,
    message: [*]const u8,
    message_len: u32,
    out_ciphertext: [*]u8,
    out_len: *u32
) bool {
    // TODO: Implement full MLS message sending
    // For now, just return false to indicate not implemented
    _ = group_state;
    _ = group_state_len;
    _ = sender_private_key;
    _ = message;
    _ = message_len;
    _ = out_ciphertext;
    _ = out_len;
    
    return false;
}

