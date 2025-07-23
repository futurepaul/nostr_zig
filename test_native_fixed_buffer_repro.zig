const std = @import("std");
const testing = std.testing;

// Use the root module to get access to the proper imports
const nostr = @import("root.zig");

// Try to reproduce WASM memory corruption using FixedBufferAllocator in native tests
test "FixedBufferAllocator native reproduction test" {
    std.debug.print("\n=== Native FixedBufferAllocator Memory Corruption Reproduction ===\n", .{});
    
    // Use the same buffer size as WASM initially, then we'll scale it down
    var buffer: [128 * 1024 * 1024]u8 = undefined; // 128MB buffer (same as WASM)
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const allocator = fba.allocator();
    
    std.debug.print("Using FixedBufferAllocator with {} MB buffer (same as WASM)\n", .{buffer.len / (1024 * 1024)});
    
    // Test 1: Basic VarBytes creation
    std.debug.print("\nTest 1: Creating basic VarBytes with known data\n", .{});
    const test_data = "hello world"; // 11 bytes
    var basic_varbytes = mls_zig.tls_codec.VarBytes.init(allocator, test_data) catch {
        std.debug.print("FAIL: Could not create basic VarBytes\n", .{});
        return error.TestFailed;
    };
    defer basic_varbytes.deinit();
    
    const basic_slice = basic_varbytes.asSlice();
    std.debug.print("Basic VarBytes length: {} (expected: 11)\n", .{basic_slice.len});
    try testing.expect(basic_slice.len == 11);
    
    // Test 2: Create a BasicCredential (this is where the issue starts)
    std.debug.print("\nTest 2: Creating BasicCredential\n", .{});
    const test_identity = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    var basic_credential = mls_zig.BasicCredential.init(allocator, test_identity) catch {
        std.debug.print("FAIL: Could not create BasicCredential\n", .{});
        return error.TestFailed;
    };
    defer basic_credential.deinit();
    std.debug.print("✅ BasicCredential created successfully\n", .{});
    
    // Test 3: Create Credential from BasicCredential
    std.debug.print("\nTest 3: Creating Credential from BasicCredential\n", .{});
    var credential = mls_zig.Credential.fromBasic(allocator, &basic_credential) catch {
        std.debug.print("FAIL: Could not create Credential from BasicCredential\n", .{});
        return error.TestFailed;
    };
    defer credential.deinit();
    std.debug.print("✅ Credential created successfully\n", .{});
    
    // Test 4: Create KeyPackageBundle (this is where VarBytes corruption happens)
    std.debug.print("\nTest 4: Creating KeyPackageBundle - this should expose the VarBytes corruption\n", .{});
    const cipher_suite = mls_zig.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    
    std.debug.print("Test 4a: About to call KeyPackageBundle.init\n", .{});
    
    // Check memory usage before KeyPackageBundle creation
    const used_before = fba.end_index;
    const free_before = buffer.len - used_before;
    std.debug.print("Memory before KeyPackageBundle: used={} KB, free={} KB\n", .{used_before / 1024, free_before / 1024});
    
    var key_package_bundle = mls_zig.KeyPackageBundle.init(
        allocator,
        cipher_suite,
        credential,
        wasm_random.secure_random.bytes,
    ) catch |err| {
        std.debug.print("FAIL: Could not create KeyPackageBundle: {any}\n", .{err});
        return error.TestFailed; 
    };
    defer key_package_bundle.deinit();
    std.debug.print("Test 4b: KeyPackageBundle.init completed successfully\n", .{});
    
    // Detailed corruption analysis immediately after KeyPackageBundle creation
    std.debug.print("\nTest 4c: Detailed corruption analysis immediately after KeyPackageBundle creation\n", .{});
    const kp_immediate = key_package_bundle.key_package;
    
    // Step by step analysis to find exact corruption point
    std.debug.print("4c.1: Getting initKey pointer\n", .{});
    const init_key_ptr = kp_immediate.initKey();
    std.debug.print("4c.2: initKey pointer = {*}\n", .{init_key_ptr});
    
    std.debug.print("4c.3: Getting data slice from initKey\n", .{});
    const init_key_slice = init_key_ptr.asSlice();
    std.debug.print("4c.4: initKey slice ptr={*}, len={}\n", .{init_key_slice.ptr, init_key_slice.len});
    
    // Check if it's specifically the .len access that's corrupted
    const init_len_immediate = init_key_slice.len;
    std.debug.print("4c.5: initKey length extracted = {}\n", .{init_len_immediate});
    
    // Also check the other keys for comparison
    const enc_key_ptr = kp_immediate.leafNode().encryption_key;
    const enc_len_immediate = enc_key_ptr.asSlice().len;
    const sig_key_ptr = kp_immediate.leafNode().signature_key;
    const sig_len_immediate = sig_key_ptr.asSlice().len;
    
    std.debug.print("Immediate key lengths: init={}, enc={}, sig={}\n", .{init_len_immediate, enc_len_immediate, sig_len_immediate});
    
    // Check memory usage after KeyPackageBundle creation
    const used_after = fba.end_index;
    const free_after = buffer.len - used_after;
    std.debug.print("Memory after KeyPackageBundle: used={} KB, free={} KB\n", .{used_after / 1024, free_after / 1024});
    
    // Test 5: Check VarBytes lengths in the KeyPackage
    std.debug.print("\nTest 5: Checking VarBytes lengths in KeyPackage\n", .{});
    const kp = key_package_bundle.key_package;
    const init_key_len = kp.initKey().asSlice().len;
    const enc_key_len = kp.leafNode().encryption_key.asSlice().len;
    const sig_key_len = kp.leafNode().signature_key.asSlice().len;
    
    std.debug.print("Key lengths: init={}, enc={}, sig={}\n", .{init_key_len, enc_key_len, sig_key_len});
    
    // Check if any keys have suspicious lengths
    if (init_key_len > 1000 or enc_key_len > 1000 or sig_key_len > 1000) {
        std.debug.print("DETECTED: VarBytes corruption! Keys have suspiciously large sizes\n", .{});
        std.debug.print("This reproduces the WASM corruption bug in native code!\n", .{});
        
        // This is expected - we're reproducing the bug, so don't fail the test
        std.debug.print("SUCCESS: Native reproduction confirmed the memory corruption issue\n", .{});
        return;
    }
    
    if (init_key_len != 32 or enc_key_len != 32 or sig_key_len != 32) {
        std.debug.print("Keys have unexpected lengths (should be 32 bytes each)\n", .{});
        std.debug.print("init_key_len = {}, enc_key_len = {}, sig_key_len = {}\n", .{init_key_len, enc_key_len, sig_key_len});
        
        // This might be the corruption we're looking for
        if (init_key_len == 33 and enc_key_len == 32 and sig_key_len == 32) {
            std.debug.print("SUCCESS: Found the 1-byte difference! init_key is 33 bytes instead of 32\n", .{});
            std.debug.print("This matches the WASM corruption pattern described in NIP_EE_PLAN.md\n", .{});
            return;
        }
    }
    
    std.debug.print("UNEXPECTED: All tests passed! VarBytes are working correctly in native FixedBufferAllocator\n", .{});
    std.debug.print("This suggests the corruption might be WASM-specific, not allocator-specific\n", .{});
}

test "FixedBufferAllocator smaller buffer reproduction test" {
    std.debug.print("\n=== Native FixedBufferAllocator Small Buffer Reproduction ===\n", .{});
    
    // Try with a much smaller buffer to see if we can trigger different behavior
    var buffer: [1024 * 1024]u8 = undefined; // 1MB buffer
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const allocator = fba.allocator();
    
    const mls_zig = @import("mls_zig");
    const crypto = @import("src/crypto.zig");
    const wasm_random = @import("src/wasm_random.zig");
    
    std.debug.print("Using FixedBufferAllocator with {} MB buffer (much smaller)\n", .{buffer.len / (1024 * 1024)});
    
    // Simplified test - just create KeyPackageBundle and check for corruption
    const test_identity = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    var basic_credential = mls_zig.BasicCredential.init(allocator, test_identity) catch {
        std.debug.print("FAIL: Could not create BasicCredential\n", .{});
        return error.TestFailed;
    };
    defer basic_credential.deinit();
    
    var credential = mls_zig.Credential.fromBasic(allocator, &basic_credential) catch {
        std.debug.print("FAIL: Could not create Credential from BasicCredential\n", .{});
        return error.TestFailed;
    };
    defer credential.deinit();
    
    const cipher_suite = mls_zig.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    
    var key_package_bundle = mls_zig.KeyPackageBundle.init(
        allocator,
        cipher_suite,
        credential,
        wasm_random.secure_random.bytes,
    ) catch |err| {
        std.debug.print("FAIL: Could not create KeyPackageBundle: {any}\n", .{err});
        return error.TestFailed; 
    };
    defer key_package_bundle.deinit();
    
    // Check key lengths
    const kp = key_package_bundle.key_package;
    const init_key_len = kp.initKey().asSlice().len;
    const enc_key_len = kp.leafNode().encryption_key.asSlice().len;
    const sig_key_len = kp.leafNode().signature_key.asSlice().len;
    
    std.debug.print("Key lengths with small buffer: init={}, enc={}, sig={}\n", .{init_key_len, enc_key_len, sig_key_len});
    
    if (init_key_len > 1000 or enc_key_len > 1000 or sig_key_len > 1000) {
        std.debug.print("SUCCESS: Reproduced corruption with smaller buffer!\n", .{});
        return;
    }
    
    if (init_key_len == 33) {
        std.debug.print("SUCCESS: Found 1-byte corruption with smaller buffer!\n", .{});
        return;
    }
    
    std.debug.print("No corruption detected with smaller buffer. Keys appear normal.\n", .{});
}