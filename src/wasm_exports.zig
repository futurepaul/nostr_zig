const std = @import("std");
// const wasm_random = @import("wasm_random.zig");

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

export fn wasm_free(ptr: [*]u8, size: usize) void {
    getAllocator().free(ptr[0..size]);
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
    // Generate secure random keys using browser crypto
    getRandomValues(out_private_key, 32);
    getRandomValues(out_public_key, 32);
    
    return true;
}

export fn wasm_create_key_package(
    private_key: [*]const u8,
    out_data: [*]u8,
    out_len: *u32
) bool {
    // For now, MLS functionality is not implemented in WASM
    // Just return false to indicate not implemented
    _ = private_key;
    _ = out_data;
    _ = out_len;
    
    return false;
}

export fn wasm_create_group(
    creator_private_key: [*]const u8,
    group_id: [*]const u8,
    group_id_len: u32,
    out_state: [*]u8,
    out_state_len: *u32
) bool {
    _ = group_id;
    _ = group_id_len;
    // TODO: Implement full MLS group creation
    // For now, just return false to indicate not implemented
    _ = creator_private_key;
    _ = out_state;
    _ = out_state_len;
    
    return false;
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

