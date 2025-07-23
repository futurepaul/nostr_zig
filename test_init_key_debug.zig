const std = @import("std");
const mls_zig = @import("mls_zig");
const wasm_random = @import("src/wasm_random.zig");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    
    // Create test identity
    const test_identity = "test_identity_1234567890abcdef";
    
    // Create basic credential
    var basic_credential = try mls_zig.BasicCredential.init(allocator, test_identity);
    defer basic_credential.deinit();
    
    var credential = try mls_zig.Credential.fromBasic(allocator, &basic_credential);
    defer credential.deinit();
    
    const cipher_suite = mls_zig.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    
    // Create key package bundle
    var key_package_bundle = try mls_zig.KeyPackageBundle.init(
        allocator,
        cipher_suite,
        credential,
        mls_zig.Extensions{},
        wasm_random.secure_random.bytes
    );
    defer key_package_bundle.deinit();
    
    // Get the init key
    const init_key = key_package_bundle.key_package.initKey();
    const init_key_slice = init_key.asSlice();
    
    std.debug.print("Init key length: {}\n", .{init_key_slice.len});
    std.debug.print("Init key data (first 10 bytes): ", .{});
    for (init_key_slice[0..@min(10, init_key_slice.len)]) |byte| {
        std.debug.print("{x:0>2} ", .{byte});
    }
    std.debug.print("\n", .{});
    
    // Check if first byte is 0x20
    if (init_key_slice.len > 0 and init_key_slice[0] == 0x20) {
        std.debug.print("WARNING: First byte is 0x20 (32 decimal) - looks like a length prefix!\n", .{});
    }
    
    // Also check the raw HpkePublicKey struct
    std.debug.print("HpkePublicKey.data ptr: {*}\n", .{init_key.data.ptr});
    std.debug.print("HpkePublicKey.data len: {}\n", .{init_key.data.len});
}