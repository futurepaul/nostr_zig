const std = @import("std");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();

export fn wasm_init() void {
    _ = gpa;
}

export fn wasm_add(a: i32, b: i32) i32 {
    return a + b;
}

export fn wasm_alloc(size: usize) ?[*]u8 {
    const mem = allocator.alloc(u8, size) catch return null;
    return mem.ptr;
}

export fn wasm_free(ptr: [*]u8, size: usize) void {
    allocator.free(ptr[0..size]);
}

export fn wasm_create_identity(out_private_key: [*]u8, out_public_key: [*]u8) bool {
    // For now, just use fixed test keys as placeholders
    // We'll integrate the actual crypto later
    
    // Test private key (all 0x01)
    @memset(out_private_key[0..32], 0x01);
    
    // Test public key (all 0x02)
    @memset(out_public_key[0..32], 0x02);
    
    return true;
}

export fn wasm_create_key_package(
    private_key: [*]const u8,
    out_data: [*]u8,
    out_len: *u32
) bool {
    _ = private_key;
    // Placeholder implementation
    const test_data = "test_key_package";
    if (test_data.len > out_len.*) {
        out_len.* = @intCast(test_data.len);
        return false;
    }
    @memcpy(out_data[0..test_data.len], test_data);
    out_len.* = @intCast(test_data.len);
    return true;
}

export fn wasm_create_group(
    creator_private_key: [*]const u8,
    group_id: [*]const u8,
    group_id_len: u32,
    out_state: [*]u8,
    out_state_len: *u32
) bool {
    _ = creator_private_key;
    _ = group_id;
    _ = group_id_len;
    // Placeholder implementation
    const test_state = "test_group_state";
    if (test_state.len > out_state_len.*) {
        out_state_len.* = @intCast(test_state.len);
        return false;
    }
    @memcpy(out_state[0..test_state.len], test_state);
    out_state_len.* = @intCast(test_state.len);
    return true;
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
    _ = group_state;
    _ = group_state_len;
    _ = sender_private_key;
    _ = message;
    _ = message_len;
    // Placeholder implementation
    const test_ciphertext = "encrypted_message";
    if (test_ciphertext.len > out_len.*) {
        out_len.* = @intCast(test_ciphertext.len);
        return false;
    }
    @memcpy(out_ciphertext[0..test_ciphertext.len], test_ciphertext);
    out_len.* = @intCast(test_ciphertext.len);
    return true;
}