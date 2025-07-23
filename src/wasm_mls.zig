const std = @import("std");
const mls_zig = @import("mls_zig");
const crypto = @import("crypto.zig");
const wasm_exports = @import("wasm_exports.zig");
// Import wasm_random from our own copy since mls_zig doesn't export it
const wasm_random = @import("wasm_random.zig");

/// Real WASM MLS integration using actual mls_zig with serialization
/// This replaces the simplified demo with actual MLS protocol operations

/// Initialize a new MLS group using mls_zig
export fn wasm_mls_init_group(
    group_id: [*]const u8, // 32 bytes (currently unused - mls_zig generates its own)
    creator_identity_pubkey: [*]const u8, // 32 bytes
    creator_signing_key: [*]const u8, // 32 bytes
    out_state: [*]u8, // Serialized MlsGroup state
    out_state_len: *u32,
) bool {
    _ = group_id; // mls_zig generates its own group ID
    
    const allocator = wasm_exports.getAllocator();
    
    // Test basic allocator functionality first
    wasm_exports.logError("Testing basic allocator...", .{});
    const test_alloc = allocator.alloc(u8, 32) catch {
        wasm_exports.logError("FAILED: Basic allocator test failed", .{});
        return false;
    };
    defer allocator.free(test_alloc);
    test_alloc[0] = 0x42; // Test write
    if (test_alloc[0] != 0x42) {
        wasm_exports.logError("FAILED: Allocator memory corruption", .{});
        return false;
    }
    wasm_exports.logError("✅ Basic allocator test passed", .{});
    
    // Create MLS state machine with real mls_zig
    _ = creator_signing_key; // TODO: Use for MLS operations when needed
    
    // Create a proper KeyPackage for the creator
    const cipher_suite = mls_zig.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    
    // Create credential from creator's identity
    const creator_pubkey_hex = std.fmt.allocPrint(allocator, "{s}", .{
        std.fmt.fmtSliceHexLower(creator_identity_pubkey[0..32])
    }) catch {
        wasm_exports.logError("Failed to format creator pubkey", .{});
        return false;
    };
    defer allocator.free(creator_pubkey_hex);
    
    wasm_exports.logError("Step 1: Creating basic credential", .{});
    var basic_credential = mls_zig.BasicCredential.init(allocator, creator_pubkey_hex) catch {
        wasm_exports.logError("FAILED at Step 1: create basic credential", .{});
        return false;
    };
    defer basic_credential.deinit();
    
    wasm_exports.logError("Step 2: Creating credential from basic", .{});
    var credential = mls_zig.Credential.fromBasic(allocator, &basic_credential) catch {
        wasm_exports.logError("FAILED at Step 2: create credential from basic", .{});
        return false;
    };
    defer credential.deinit();
    
    wasm_exports.logError("Step 3: Creating KeyPackageBundle", .{});
    
    // Create KeyPackageBundle with the main allocator
    // DO NOT use arena here as it would be destroyed before we use the data
    var key_package_bundle = mls_zig.KeyPackageBundle.init(
        allocator,
        cipher_suite,
        credential,
        wasm_random.secure_random.bytes, // Use WASM-compatible random
    ) catch |err| {
        wasm_exports.logError("FAILED at Step 3: create KeyPackageBundle, error: {any}", .{err});
        return false;
    };
    // Debug immediately after creation
    {
        const immediate_kp = key_package_bundle.key_package;
        const immediate_init_len = immediate_kp.initKey().asSlice().len;
        const immediate_enc_len = immediate_kp.leafNode().encryption_key.asSlice().len;
        const immediate_sig_len = immediate_kp.leafNode().signature_key.asSlice().len;
        wasm_exports.logError("IMMEDIATELY after creation - Key lengths: init={}, enc={}, sig={}", .{immediate_init_len, immediate_enc_len, immediate_sig_len});
    }
    
    defer key_package_bundle.deinit(allocator);
    
    // Debug key lengths before creating group
    const kp = key_package_bundle.key_package;
    wasm_exports.logError("About to access init key", .{});
    const init_key_ptr = kp.initKey();
    wasm_exports.logError("Got init key ptr, checking slice", .{});
    const init_key_slice = init_key_ptr.asSlice();
    wasm_exports.logError("Got init key slice, checking length", .{});
    const init_key_len = init_key_slice.len;
    wasm_exports.logError("Init key length: {}", .{init_key_len});
    
    const enc_key_len = kp.leafNode().encryption_key.asSlice().len;
    const sig_key_len = kp.leafNode().signature_key.asSlice().len;
    wasm_exports.logError("Key lengths: init={}, enc={}, sig={}", .{init_key_len, enc_key_len, sig_key_len});
    
    wasm_exports.logError("Step 4: Creating MLS group", .{});
    // Create MLS group
    var mls_group = mls_zig.MlsGroup.createGroup(
        allocator,
        cipher_suite,
        key_package_bundle,
        wasm_random.secure_random.bytes, // Use WASM-compatible random
    ) catch |err| {
        wasm_exports.logError("FAILED at Step 4: create MLS group, error: {any}", .{err});
        return false;
    };
    defer mls_group.deinit();
    
    // Serialize the MLS group state using our new serialization
    const serialized = mls_group.serialize(allocator) catch {
        wasm_exports.logError("Failed to serialize MLS group", .{});
        return false;
    };
    defer allocator.free(serialized);
    
    // Check output buffer size
    if (out_state_len.* < serialized.len) {
        out_state_len.* = @intCast(serialized.len);
        wasm_exports.logError("Output buffer too small: need {} bytes", .{serialized.len});
        return false;
    }
    
    // Copy serialized state to output
    @memcpy(out_state[0..serialized.len], serialized);
    out_state_len.* = @intCast(serialized.len);
    
    wasm_exports.logError("Real MLS group created successfully, {} bytes", .{serialized.len});
    return true;
}

/// Get current group information from MLS group
export fn wasm_mls_get_info(
    state_data: [*]const u8,
    state_data_len: u32,
    out_epoch: *u64,
    out_member_count: *u32,
    out_pending_proposals: *u32,
    out_exporter_secret: [*]u8, // 32 bytes
    out_tree_hash: [*]u8, // 32 bytes
) bool {
    const allocator = wasm_exports.getAllocator();
    
    // Deserialize MLS group state using our new deserialization
    var mls_group = mls_zig.MlsGroup.deserialize(
        allocator,
        state_data[0..state_data_len],
    ) catch {
        wasm_exports.logError("Failed to deserialize MLS group", .{});
        return false;
    };
    defer mls_group.deinit();
    
    // Extract information from real MLS group
    out_epoch.* = mls_group.epoch();
    out_member_count.* = @intCast(mls_group.tree.tree.leafCount());
    out_pending_proposals.* = @intCast(mls_group.pending_proposals.items.len);
    
    // Extract exporter secret if available
    if (mls_group.epoch_secrets) |secrets| {
        const secret_slice = secrets.exporter_secret.asSlice();
        const copy_len = @min(32, secret_slice.len);
        @memcpy(out_exporter_secret[0..copy_len], secret_slice[0..copy_len]);
        // Zero-fill any remaining bytes
        if (copy_len < 32) {
            @memset(out_exporter_secret[copy_len..32], 0);
        }
    } else {
        // No secrets available yet
        @memset(out_exporter_secret[0..32], 0);
    }
    
    // Extract tree hash from group context
    const tree_hash_slice = mls_group.group_context.tree_hash.asSlice();
    const tree_copy_len = @min(32, tree_hash_slice.len);
    @memcpy(out_tree_hash[0..tree_copy_len], tree_hash_slice[0..tree_copy_len]);
    if (tree_copy_len < 32) {
        @memset(out_tree_hash[tree_copy_len..32], 0);
    }
    
    wasm_exports.logError("MLS group info extracted: epoch={}, members={}, proposals={}", .{
        out_epoch.*, out_member_count.*, out_pending_proposals.*
    });
    return true;
}

/// Test function to verify MLS integration is working
export fn wasm_mls_test() bool {
    wasm_exports.logError("Testing real MLS integration...", .{});
    
    // Test data
    var creator_identity: [32]u8 = undefined;
    var creator_signing_key: [32]u8 = undefined;
    wasm_random.secure_random.bytes(&creator_identity);
    wasm_random.secure_random.bytes(&creator_signing_key);
    
    // Test group creation
    var state_buffer: [4096]u8 = undefined;
    var state_len: u32 = state_buffer.len;
    
    const success = wasm_mls_init_group(
        &creator_identity, // group_id (unused)
        &creator_identity,
        &creator_signing_key,
        &state_buffer,
        &state_len,
    );
    
    if (!success) {
        wasm_exports.logError("Failed to create test MLS group", .{});
        return false;
    }
    
    // Test getting info
    var epoch: u64 = 0;
    var member_count: u32 = 0;
    var pending_proposals: u32 = 0;
    var exporter_secret: [32]u8 = undefined;
    var tree_hash: [32]u8 = undefined;
    
    const info_success = wasm_mls_get_info(
        &state_buffer,
        state_len,
        &epoch,
        &member_count,
        &pending_proposals,
        &exporter_secret,
        &tree_hash,
    );
    
    if (!info_success) {
        wasm_exports.logError("Failed to get MLS group info", .{});
        return false;
    }
    
    wasm_exports.logError("MLS test successful: epoch={}, members={}", .{epoch, member_count});
    return true;
}