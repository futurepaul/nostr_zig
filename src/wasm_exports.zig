const std = @import("std");
const crypto = @import("crypto.zig");
const nip_ee = @import("nip_ee.zig");
const nostr = @import("nostr.zig");
const welcome_events = @import("mls/welcome_events.zig");
const nip59 = @import("mls/nip59.zig");

// Import MLS integration functions (REAL MLS only)
const wasm_mls = @import("wasm_mls.zig");

// Re-export to make functions available (REAL MLS only)
pub usingnamespace wasm_mls;

// External functions provided by JavaScript
extern fn getRandomValues(buf: [*]u8, len: usize) void;
extern fn getCurrentTimestamp() u64;
extern fn wasm_log_error(str: [*]const u8, len: usize) void;

// Memory management - back to FixedBufferAllocator to eliminate arena-related corruption
var buffer: [64 * 1024 * 1024]u8 = undefined; // 64MB buffer (finding minimum viable size)
var fba: ?std.heap.FixedBufferAllocator = null;

pub fn getAllocator() std.mem.Allocator {
    if (fba == null) {
        fba = std.heap.FixedBufferAllocator.init(&buffer);
        logError("WASM allocator initialized with {} MB buffer (FixedBufferAllocator)", .{buffer.len / (1024 * 1024)});
    }
    return fba.?.allocator();
}

/// Get current memory usage statistics
pub fn getMemoryStats() struct { used: usize, total: usize, free: usize } {
    if (fba) |*f| {
        const used = f.end_index;
        const total = buffer.len;
        const free = total - used;
        return .{ .used = used, .total = total, .free = free };
    }
    return .{ .used = 0, .total = buffer.len, .free = buffer.len };
}

/// Export memory stats for debugging
export fn wasm_get_memory_stats(out_used: *u32, out_total: *u32, out_free: *u32) void {
    const stats = getMemoryStats();
    out_used.* = @intCast(stats.used);
    out_total.* = @intCast(stats.total);
    out_free.* = @intCast(stats.free);
}

// Debug helper
pub fn logError(comptime fmt: []const u8, args: anytype) void {
    var buf: [256]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, fmt, args) catch return;
    wasm_log_error(msg.ptr, msg.len);
}

// =============================================================================
// ESSENTIAL MEMORY MANAGEMENT
// =============================================================================

export fn wasm_init() void {
    // Initialize allocator on first use
    _ = getAllocator();
}

export fn wasm_get_version() i32 {
    return 3; // Version 3: cleaned up, thin wrappers only
}

/// Minimal reproduction test for VarBytes memory corruption
export fn wasm_test_varbytes_minimal() bool {
    const allocator = getAllocator();
    const mls_zig = @import("mls_zig");
    
    logError("=== VarBytes Minimal Reproduction Test ===", .{});
    
    // Test 1: Basic VarBytes creation
    logError("Test 1: Creating basic VarBytes with known data", .{});
    const test_data = "hello world"; // 11 bytes
    var basic_varbytes = mls_zig.tls_codec.VarBytes.init(allocator, test_data) catch {
        logError("FAIL: Could not create basic VarBytes", .{});
        return false;
    };
    defer basic_varbytes.deinit();
    
    const basic_slice = basic_varbytes.asSlice();
    logError("Basic VarBytes length: {} (expected: 11)", .{basic_slice.len});
    if (basic_slice.len != 11) {
        logError("FAIL: Basic VarBytes has wrong length", .{});
        return false;
    }
    
    // Test 2: Create a BasicCredential (this is where the issue starts)
    logError("Test 2: Creating BasicCredential", .{});
    const test_identity = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    var basic_credential = mls_zig.BasicCredential.init(allocator, test_identity) catch {
        logError("FAIL: Could not create BasicCredential", .{});
        return false;
    };
    defer basic_credential.deinit();
    logError("✅ BasicCredential created successfully", .{});
    
    // Test 3: Create Credential from BasicCredential
    logError("Test 3: Creating Credential from BasicCredential", .{});
    var credential = mls_zig.Credential.fromBasic(allocator, &basic_credential) catch {
        logError("FAIL: Could not create Credential from BasicCredential", .{});
        return false;
    };
    defer credential.deinit();
    logError("✅ Credential created successfully", .{});
    
    // Test 4: Create KeyPackageBundle (this is where VarBytes corruption happens)
    logError("Test 4: Creating KeyPackageBundle - this should expose the VarBytes corruption", .{});
    const cipher_suite = mls_zig.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    const wasm_random = @import("wasm_random.zig");
    
    logError("Test 4a: About to call KeyPackageBundle.init", .{});
    
    // Check memory usage before KeyPackageBundle creation
    const stats_before = getMemoryStats();
    logError("Memory before KeyPackageBundle: used={} KB, free={} KB", .{stats_before.used / 1024, stats_before.free / 1024});
    
    // First test the key generation functions directly
    logError("Test 4a.1: Testing HPKE key generation directly", .{});
    var test_hpke_keypair = mls_zig.key_package.generateHpkeKeyPair(
        allocator,
        cipher_suite,
        wasm_random.secure_random.bytes,
    ) catch |err| {
        logError("FAIL: HPKE key generation failed: {any}", .{err});
        return false;
    };
    defer test_hpke_keypair.deinit();
    logError("HPKE keys: public={} bytes, private={} bytes", .{test_hpke_keypair.public_key.len, test_hpke_keypair.private_key.len});
    logError("HPKE public key data (first 8 bytes): {any}", .{test_hpke_keypair.public_key[0..@min(8, test_hpke_keypair.public_key.len)]});
    
    // Test creating an HpkePublicKey wrapper from the raw key
    logError("Test 4a.1b: Testing HpkePublicKey wrapper creation", .{});
    var test_hpke_wrapper = mls_zig.key_package.HpkePublicKey.initOwned(allocator, test_hpke_keypair.public_key) catch |err| {
        logError("FAIL: HpkePublicKey wrapper creation failed: {any}", .{err});
        return false;
    };
    defer test_hpke_wrapper.deinit(allocator);
    logError("HpkePublicKey wrapper: {} bytes", .{test_hpke_wrapper.len()});
    logError("HpkePublicKey wrapper data (first 8 bytes): {any}", .{test_hpke_wrapper.asSlice()[0..@min(8, test_hpke_wrapper.len())]});
    
    logError("Test 4a.2: Testing signature key generation directly", .{});
    var test_sig_keypair = mls_zig.key_package.generateSignatureKeyPair(
        allocator,
        cipher_suite,
    ) catch |err| {
        logError("FAIL: Signature key generation failed: {any}", .{err});
        return false;
    };
    defer test_sig_keypair.deinit();
    logError("Signature keys: public={} bytes, private={} bytes", .{test_sig_keypair.public_key.len, test_sig_keypair.private_key.len});
    
    var key_package_bundle = mls_zig.KeyPackageBundle.init(
        allocator,
        cipher_suite,
        credential,
        wasm_random.secure_random.bytes,
    ) catch |err| {
        logError("FAIL: Could not create KeyPackageBundle: {any}", .{err});
        return false; 
    };
    defer key_package_bundle.deinit(allocator);
    logError("Test 4b: KeyPackageBundle.init completed successfully", .{});
    
    // Detailed corruption analysis immediately after KeyPackageBundle creation
    logError("Test 4c: Detailed corruption analysis immediately after KeyPackageBundle creation", .{});
    const kp_immediate = key_package_bundle.key_package;
    
    // Step by step analysis to find exact corruption point
    logError("4c.1: Getting initKey pointer", .{});
    const init_key_ptr = kp_immediate.initKey();
    logError("4c.2: initKey pointer = {*}", .{init_key_ptr});
    
    logError("4c.3: Getting data slice from initKey", .{});
    const init_key_slice = init_key_ptr.asSlice();
    logError("4c.4: initKey slice ptr={*}, len={}", .{init_key_slice.ptr, init_key_slice.len});
    
    // Check if it's specifically the .len access that's corrupted
    const init_len_immediate = init_key_slice.len;
    logError("4c.5: initKey length extracted = {}", .{init_len_immediate});
    
    // Also check the other keys for comparison
    const enc_key_ptr = kp_immediate.leafNode().encryption_key;
    const enc_len_immediate = enc_key_ptr.asSlice().len;
    const sig_key_ptr = kp_immediate.leafNode().signature_key;
    const sig_len_immediate = sig_key_ptr.asSlice().len;
    
    logError("Immediate key lengths: init={}, enc={}, sig={}", .{init_len_immediate, enc_len_immediate, sig_len_immediate});
    
    // Check memory usage after KeyPackageBundle creation
    const stats_after = getMemoryStats();
    logError("Memory after KeyPackageBundle: used={} KB, free={} KB", .{stats_after.used / 1024, stats_after.free / 1024});
    
    // Test 5: Check VarBytes lengths in the KeyPackage
    logError("Test 5: Checking VarBytes lengths in KeyPackage", .{});
    const kp = key_package_bundle.key_package;
    const init_key = kp.initKey();
    const init_key_data = init_key.asSlice();
    const init_key_len = init_key_data.len;
    const enc_key_len = kp.leafNode().encryption_key.asSlice().len;
    const sig_key_len = kp.leafNode().signature_key.asSlice().len;
    
    logError("Key lengths: init={}, enc={}, sig={}", .{init_key_len, enc_key_len, sig_key_len});
    
    // Debug the actual init key data if it's 33 bytes
    if (init_key_len == 33) {
        logError("DEBUG: Init key is 33 bytes! First byte: 0x{x:0>2}, last 32 bytes likely the actual key", .{init_key_data[0]});
        // Check if it's a TLS length prefix or type byte
        if (init_key_data[0] == 0x20) { // 0x20 = 32 in decimal
            logError("DEBUG: First byte is 0x20 (32) - looks like a length prefix!", .{});
        }
    }
    
    // Check if any keys have suspicious lengths
    if (init_key_len > 1000 or enc_key_len > 1000 or sig_key_len > 1000) {
        logError("FAIL: VarBytes corruption detected! Keys have suspiciously large sizes", .{});
        return false;
    }
    
    if (init_key_len != 32 or enc_key_len != 32 or sig_key_len != 32) {
        logError("FAIL: Keys have unexpected lengths (should be 32 bytes each)", .{});
        logError("init_key_len = {}, enc_key_len = {}, sig_key_len = {}", .{init_key_len, enc_key_len, sig_key_len});
        
        // This might be the corruption we're looking for
        if (init_key_len == 33 and enc_key_len == 0 and sig_key_len == 0) {
            logError("INFO: Found the 1-byte difference! init_key is 33 bytes instead of 32", .{});
            logError("INFO: This matches the WASM corruption pattern described in NIP_EE_PLAN.md", .{});
            // Don't return false here, let's see more details
        }
    } else {
        logError("✅ All tests passed! VarBytes are working correctly", .{});
    }
    return false; // Always return false for now to see all debug output
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

// =============================================================================
// CORE CRYPTOGRAPHIC FUNCTIONS
// Thin wrappers around src/crypto.zig - no business logic here
// =============================================================================

export fn wasm_create_identity(out_private_key: [*]u8, out_public_key: [*]u8) bool {
    const private_key = crypto.generatePrivateKey() catch return false;
    const public_key = crypto.getPublicKey(private_key) catch return false;
    
    @memcpy(out_private_key[0..32], &private_key);
    @memcpy(out_public_key[0..32], &public_key);
    
    return true;
}

export fn wasm_get_public_key_from_private(private_key: [*]const u8, out_public_key: [*]u8) bool {
    const pub_key = crypto.getPublicKey(private_key[0..32].*) catch return false;
    @memcpy(out_public_key[0..32], &pub_key);
    return true;
}

export fn wasm_get_public_key_hex(private_key: [*]const u8, out_pubkey_hex: [*]u8) bool {
    const priv_key = private_key[0..32].*;
    const pubkey = crypto.getPublicKey(priv_key) catch return false;
    
    var hex_buffer: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&hex_buffer, "{s}", .{std.fmt.fmtSliceHexLower(&pubkey)}) catch return false;
    
    @memcpy(out_pubkey_hex[0..64], &hex_buffer);
    return true;
}

export fn wasm_sign_schnorr(message_hash: [*]const u8, private_key: [*]const u8, out_signature: [*]u8) bool {
    const signature = crypto.sign(message_hash[0..32], private_key[0..32].*) catch return false;
    @memcpy(out_signature[0..64], &signature);
    return true;
}

export fn wasm_verify_schnorr(message_hash: [*]const u8, signature: [*]const u8, public_key: [*]const u8) bool {
    return crypto.verifyMessageSignature(message_hash[0..32], signature[0..64].*, public_key[0..32].*) catch false;
}

export fn wasm_sha256(data: [*]const u8, data_len: u32, out_hash: [*]u8) bool {
    if (data_len == 0) return false;
    
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data[0..data_len], &hash, .{});
    @memcpy(out_hash[0..32], &hash);
    
    return true;
}

// =============================================================================
// CORE EVENT FUNCTIONS
// Thin wrappers around src/nostr/ - leverages existing infrastructure
// =============================================================================

export fn wasm_create_event(
    private_key: [*]const u8,      // 32 bytes
    kind: u32,
    content: [*]const u8,
    content_len: u32,
    tags_json: [*]const u8,        // JSON array of tag arrays
    tags_json_len: u32,
    out_event_json: [*]u8,
    out_len: *u32,
) bool {
    const allocator = getAllocator();
    
    // Parse private key
    const priv_key = private_key[0..32].*;
    const content_str = content[0..content_len];
    const tags_json_str = if (tags_json_len > 0) tags_json[0..tags_json_len] else "[]";
    
    // Use arena allocator for temporary tag parsing
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_alloc = arena.allocator();
    
    var tags: [][]const []const u8 = &[_][]const []const u8{};
    if (tags_json_len > 0) {
        const parsed = std.json.parseFromSlice(
            [][]const []const u8,
            arena_alloc,
            tags_json_str,
            .{ .allocate = .alloc_always },
        ) catch return false;
        tags = parsed.value;
    }
    
    // Use existing EventBuilder infrastructure
    const builder = nostr.EventBuilder.initWithKey(arena_alloc, priv_key);
    const event = builder.build(.{
        .kind = @intCast(kind),
        .content = content_str,
        .tags = tags,
    }) catch return false;
    defer event.deinit(arena_alloc);
    
    // Serialize to JSON
    const event_json = event.toJson(allocator) catch return false;
    defer allocator.free(event_json);
    
    // Check buffer size and copy result
    if (out_len.* < event_json.len) {
        out_len.* = @intCast(event_json.len);
        return false;
    }
    
    @memcpy(out_event_json[0..event_json.len], event_json);
    out_len.* = @intCast(event_json.len);
    
    return true;
}

export fn wasm_create_nostr_event_id(
    pubkey: [*]const u8, // 64 bytes hex string
    created_at: u64,
    kind: u32,
    tags_json: [*]const u8,
    tags_json_len: u32,
    content: [*]const u8,
    content_len: u32,
    out_event_id: [*]u8 // 32 bytes output
) bool {
    const allocator = getAllocator();
    
    // Build canonical form: [0, pubkey, created_at, kind, tags, content]
    var event_data = std.ArrayList(u8).init(allocator);
    defer event_data.deinit();
    
    event_data.appendSlice("[0,\"") catch return false;
    event_data.appendSlice(pubkey[0..64]) catch return false;
    event_data.appendSlice("\",") catch return false;
    
    var created_at_buf: [32]u8 = undefined;
    const created_at_str = std.fmt.bufPrint(&created_at_buf, "{d}", .{created_at}) catch return false;
    event_data.appendSlice(created_at_str) catch return false;
    event_data.append(',') catch return false;
    
    var kind_buf: [16]u8 = undefined;
    const kind_str = std.fmt.bufPrint(&kind_buf, "{d}", .{kind}) catch return false;
    event_data.appendSlice(kind_str) catch return false;
    event_data.append(',') catch return false;
    
    if (tags_json_len > 0) {
        event_data.appendSlice(tags_json[0..tags_json_len]) catch return false;
    } else {
        event_data.appendSlice("[]") catch return false;
    }
    event_data.append(',') catch return false;
    
    event_data.append('"') catch return false;
    if (content_len > 0) {
        event_data.appendSlice(content[0..content_len]) catch return false;
    }
    event_data.appendSlice("\"]") catch return false;
    
    // Calculate SHA256
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(event_data.items, &hash, .{});
    @memcpy(out_event_id[0..32], &hash);
    
    return true;
}

// =============================================================================
// NIP-EE CORE FUNCTIONS  
// Thin wrappers around src/nip_ee.zig - follows DEVELOPMENT.md best practices
// =============================================================================

export fn wasm_nip_ee_create_encrypted_group_message(
    group_id: [*]const u8,         // 32 bytes
    epoch: u64,
    sender_index: u32,
    message_content: [*]const u8,
    message_content_len: u32,
    mls_signature: [*]const u8,
    mls_signature_len: u32,
    exporter_secret: [*]const u8,   // 32 bytes
    out_encrypted: [*]u8,
    out_len: *u32
) bool {
    const allocator = getAllocator();
    
    // Type conversions for Zig
    const group_id_array = group_id[0..32].*;
    const message_slice = message_content[0..message_content_len];
    const signature_slice = mls_signature[0..mls_signature_len];
    const exporter_secret_array = exporter_secret[0..32].*;
    
    // Call the pure Zig function
    const encrypted_payload = nip_ee.createEncryptedGroupMessage(
        allocator,
        allocator, // Use same allocator for both
        group_id_array,
        epoch,
        sender_index,
        message_slice,
        signature_slice,
        exporter_secret_array,
    ) catch return false;
    defer allocator.free(encrypted_payload);
    
    // Buffer size check and copy result
    if (out_len.* < encrypted_payload.len) {
        out_len.* = @intCast(encrypted_payload.len);
        return false;
    }
    
    @memcpy(out_encrypted[0..encrypted_payload.len], encrypted_payload);
    out_len.* = @intCast(encrypted_payload.len);
    
    return true;
}

export fn wasm_nip_ee_decrypt_group_message(
    encrypted_content: [*]const u8,
    encrypted_content_len: u32,
    exporter_secret: [*]const u8,   // 32 bytes
    out_decrypted: [*]u8,
    out_len: *u32
) bool {
    const allocator = getAllocator();
    
    // Type conversions for Zig
    const encrypted_slice = encrypted_content[0..encrypted_content_len];
    const exporter_secret_array = exporter_secret[0..32].*;
    
    // Log input parameters
    logError("wasm_nip_ee_decrypt_group_message: encrypted_len={}, exporter_secret[0..4]={x:0>2} {x:0>2} {x:0>2} {x:0>2}", .{
        encrypted_content_len,
        exporter_secret_array[0],
        exporter_secret_array[1],
        exporter_secret_array[2],
        exporter_secret_array[3],
    });
    
    // Call the pure Zig function
    const decrypted_content = nip_ee.decryptGroupMessage(
        allocator,
        allocator, // Use same allocator for both
        encrypted_slice,
        exporter_secret_array,
    ) catch |err| {
        logError("decryptGroupMessage failed: {}", .{err});
        return false;
    };
    defer allocator.free(decrypted_content);
    
    // Buffer size check and copy result
    if (out_len.* < decrypted_content.len) {
        out_len.* = @intCast(decrypted_content.len);
        return false;
    }
    
    @memcpy(out_decrypted[0..decrypted_content.len], decrypted_content);
    out_len.* = @intCast(decrypted_content.len);
    
    return true;
}

export fn wasm_nip_ee_generate_exporter_secret(
    group_state: [*]const u8,
    group_state_len: u32,
    out_secret: [*]u8  // 32 bytes
) bool {
    const allocator = getAllocator();
    
    const group_state_slice = group_state[0..group_state_len];
    const exporter_secret = nip_ee.generateExporterSecret(allocator, group_state_slice) catch return false;
    
    @memcpy(out_secret[0..32], &exporter_secret);
    return true;
}

// =============================================================================
// NIP-59 GIFT WRAPPING FUNCTIONS
// Thin wrappers around src/mls/nip59.zig and welcome_events.zig  
// =============================================================================

export fn wasm_create_gift_wrap(
    sender_privkey: [*]const u8,    // 32 bytes
    recipient_pubkey: [*]const u8,  // 32 bytes
    rumor_json: [*]const u8,        // Unsigned event JSON
    rumor_json_len: u32,
    out_wrapped_json: [*]u8,
    out_len: *u32,
) bool {
    const allocator = getAllocator();
    
    const sender_key = sender_privkey[0..32].*;
    const recipient_key = recipient_pubkey[0..32].*;
    const rumor_str = rumor_json[0..rumor_json_len];
    
    // Parse rumor from JSON using existing infrastructure
    const rumor = nostr.Event.fromJson(allocator, rumor_str) catch return false;
    defer rumor.deinit(allocator);
    
    // Ensure it's unsigned
    if (rumor.sig.len > 0) {
        return false; // Must be unsigned rumor
    }
    
    // Create gift wrap using existing NIP-59 infrastructure
    const wrapped = nip59.createGiftWrappedEvent(
        allocator,
        sender_key,
        recipient_key,
        rumor,
    ) catch return false;
    defer wrapped.deinit(allocator);
    
    // Serialize to JSON
    const wrapped_json = wrapped.toJson(allocator) catch return false;
    defer allocator.free(wrapped_json);
    
    // Buffer size check and copy result
    if (out_len.* < wrapped_json.len) {
        out_len.* = @intCast(wrapped_json.len);
        return false;
    }
    
    @memcpy(out_wrapped_json[0..wrapped_json.len], wrapped_json);
    out_len.* = @intCast(wrapped_json.len);
    
    return true;
}

export fn wasm_unwrap_gift_wrap(
    wrapped_json: [*]const u8,
    wrapped_json_len: u32,
    recipient_privkey: [*]const u8,  // 32 bytes
    out_rumor_json: [*]u8,
    out_len: *u32,
) bool {
    const allocator = getAllocator();
    
    const recipient_key = recipient_privkey[0..32].*;
    const wrapped_str = wrapped_json[0..wrapped_json_len];
    
    // Parse wrapped event using existing infrastructure
    const wrapped_event = nostr.Event.fromJson(allocator, wrapped_str) catch return false;
    defer wrapped_event.deinit(allocator);
    
    // Unwrap using existing NIP-59 infrastructure
    const rumor = nip59.GiftWrap.unwrapAndDecrypt(
        allocator,
        wrapped_event,
        recipient_key,
    ) catch return false;
    defer rumor.deinit(allocator);
    
    // Serialize rumor to JSON
    const rumor_json = rumor.toJson(allocator) catch return false;
    defer allocator.free(rumor_json);
    
    // Buffer size check and copy result
    if (out_len.* < rumor_json.len) {
        out_len.* = @intCast(rumor_json.len);
        return false;
    }
    
    @memcpy(out_rumor_json[0..rumor_json.len], rumor_json);
    out_len.* = @intCast(rumor_json.len);
    
    return true;
}

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

export fn bytes_to_hex(bytes: [*]const u8, bytes_len: usize, out_hex: [*]u8, out_hex_len: usize) bool {
    if (out_hex_len < bytes_len * 2) return false;
    
    const hex_chars = "0123456789abcdef";
    for (0..bytes_len) |i| {
        const byte = bytes[i];
        out_hex[i * 2] = hex_chars[byte >> 4];
        out_hex[i * 2 + 1] = hex_chars[byte & 0x0F];
    }
    return true;
}

export fn hex_to_bytes(hex: [*]const u8, hex_len: usize, out_bytes: [*]u8, out_bytes_len: usize) bool {
    if (hex_len % 2 != 0 or out_bytes_len < hex_len / 2) return false;
    
    for (0..hex_len / 2) |i| {
        const high_char = hex[i * 2];
        const low_char = hex[i * 2 + 1];
        
        const high_nibble = switch (high_char) {
            '0'...'9' => high_char - '0',
            'a'...'f' => high_char - 'a' + 10,
            'A'...'F' => high_char - 'A' + 10,
            else => return false,
        };
        
        const low_nibble = switch (low_char) {
            '0'...'9' => low_char - '0',
            'a'...'f' => low_char - 'a' + 10,
            'A'...'F' => low_char - 'A' + 10,
            else => return false,
        };
        
        out_bytes[i] = (high_nibble << 4) | low_nibble;
    }
    return true;
}

export fn base64_encode(bytes: [*]const u8, bytes_len: usize, out_base64: [*]u8, out_base64_len: usize) bool {
    const encoder = std.base64.standard.Encoder;
    const encoded_len = encoder.calcSize(bytes_len);
    
    if (out_base64_len < encoded_len) return false;
    
    const encoded = encoder.encode(out_base64[0..encoded_len], bytes[0..bytes_len]);
    return encoded.len == encoded_len;
}

export fn base64_decode(base64: [*]const u8, base64_len: usize, out_bytes: [*]u8, out_bytes_len: *usize) bool {
    const decoder = std.base64.standard.Decoder;
    const decoded_len = decoder.calcSizeForSlice(base64[0..base64_len]) catch return false;
    
    if (out_bytes_len.* < decoded_len) {
        out_bytes_len.* = decoded_len;
        return false;
    }
    
    decoder.decode(out_bytes[0..decoded_len], base64[0..base64_len]) catch return false;
    out_bytes_len.* = decoded_len;
    return true;
}

// Note: Functions are already re-exported above via usingnamespace