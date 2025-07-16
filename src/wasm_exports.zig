const std = @import("std");
const crypto = @import("crypto.zig");
const wasm_random = @import("wasm_random.zig");
const mls = @import("mls/mls.zig");

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

// Export the secure random function for the wasm_random module
export fn random_bytes(buf: [*]u8, len: usize) void {
    wasm_random.random_bytes(buf, len);
}

export fn wasm_create_identity(out_private_key: [*]u8, out_public_key: [*]u8) bool {
    // Generate real cryptographically secure key pair
    const private_key = crypto.generatePrivateKey() catch return false;
    const public_key = crypto.getPublicKey(private_key) catch return false;
    
    // Copy to output buffers
    @memcpy(out_private_key[0..32], &private_key);
    @memcpy(out_public_key[0..32], &public_key);
    
    return true;
}

export fn wasm_create_key_package(
    private_key: [*]const u8,
    out_data: [*]u8,
    out_len: *u32
) bool {
    // Create real key package
    const params = mls.key_packages.KeyPackageParams{
        .cipher_suite = .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        .credential_type = .basic,
        .extensions = &.{},
    };
    
    const mls_provider = mls.provider.MlsProvider.init(allocator);
    const key_package = mls.key_packages.generateKeyPackage(
        allocator,
        private_key[0..32].*,
        params,
        &mls_provider,
    ) catch return false;
    defer allocator.free(key_package.signature);
    defer allocator.free(key_package.leaf_node.signature);
    
    // Serialize to wire format
    const serialized = mls.key_packages.serializeKeyPackage(allocator, key_package) catch return false;
    defer allocator.free(serialized);
    
    if (serialized.len > out_len.*) {
        out_len.* = @intCast(serialized.len);
        return false;
    }
    
    @memcpy(out_data[0..serialized.len], serialized);
    out_len.* = @intCast(serialized.len);
    return true;
}

export fn wasm_create_group(
    creator_private_key: [*]const u8,
    group_id: [*]const u8,
    group_id_len: u32,
    out_state: [*]u8,
    out_state_len: *u32
) bool {
    // Create real group with ephemeral messaging support
    const group_params = mls.groups.GroupCreationParams{
        .cipher_suite = .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        .creator_private_key = creator_private_key[0..32].*,
        .nostr_group_data = .{
            .nostr_group_id = group_id[0..group_id_len].*,
            .name = "WASM Group",
            .description = "Created from WASM",
            .admin_pubkeys = &.{},
            .relays = &.{},
        },
    };
    
    const mls_provider = mls.provider.MlsProvider.init(allocator);
    const group_state = mls.groups.createGroup(
        allocator,
        group_params,
        &mls_provider,
    ) catch return false;
    defer mls.groups.freeGroupState(allocator, group_state);
    
    // Serialize group state
    const serialized = mls.groups.serializeGroupState(allocator, group_state) catch return false;
    defer allocator.free(serialized);
    
    if (serialized.len > out_state_len.*) {
        out_state_len.* = @intCast(serialized.len);
        return false;
    }
    
    @memcpy(out_state[0..serialized.len], serialized);
    out_state_len.* = @intCast(serialized.len);
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
    // Parse group state
    const state = mls.groups.deserializeGroupState(
        allocator,
        group_state[0..group_state_len],
    ) catch return false;
    defer mls.groups.freeGroupState(allocator, state);
    
    // Create group messenger with ephemeral keys
    const mls_provider = mls.provider.MlsProvider.init(allocator);
    var messenger = mls.group_messaging.GroupMessenger.init(allocator, &mls_provider);
    defer messenger.deinit();
    
    // Send message with automatic ephemeral key generation
    const group_msg = messenger.sendMessage(
        &state,
        message[0..message_len],
        sender_private_key[0..32].*,
    ) catch return false;
    defer allocator.free(group_msg.event.content);
    
    // Return the encrypted content
    if (group_msg.event.content.len > out_len.*) {
        out_len.* = @intCast(group_msg.event.content.len);
        return false;
    }
    
    @memcpy(out_ciphertext[0..group_msg.event.content.len], group_msg.event.content);
    out_len.* = @intCast(group_msg.event.content.len);
    return true;
}