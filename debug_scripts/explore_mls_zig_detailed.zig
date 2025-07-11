const std = @import("std");
const mls_zig = @import("mls_zig");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    
    std.debug.print("=== Detailed mls_zig API Exploration ===\n\n", .{});
    
    // Check cipher_suite module
    if (@hasDecl(mls_zig, "cipher_suite")) {
        std.debug.print("1. cipher_suite module:\n", .{});
        const cs = mls_zig.cipher_suite;
        
        // Check for specific cipher suite types
        if (@hasDecl(cs, "CipherSuiteTag")) {
            std.debug.print("   - Has CipherSuiteTag\n", .{});
        }
        if (@hasDecl(cs, "getCipherSuite")) {
            std.debug.print("   - Has getCipherSuite function\n", .{});
        }
        if (@hasDecl(cs, "hkdf_extract")) {
            std.debug.print("   - Has hkdf_extract\n", .{});
        }
        if (@hasDecl(cs, "hkdf_expand")) {
            std.debug.print("   - Has hkdf_expand\n", .{});
        }
        if (@hasDecl(cs, "hpke")) {
            std.debug.print("   - Has hpke support\n", .{});
        }
        
        // Try to use HKDF functions
        std.debug.print("\n   Testing HKDF functions:\n", .{});
        const suite_tag = cs.CipherSuiteTag.mls_128_dhkemx25519_aes128gcm_sha256_ed25519;
        const suite = cs.getCipherSuite(suite_tag);
        
        // Test HKDF extract
        const salt = "test-salt";
        const ikm = "test-input-key-material";
        var extract_out: [32]u8 = undefined;
        
        try suite.kdf.extract(&extract_out, salt, ikm);
        std.debug.print("   - HKDF extract works! Output: {x}\n", .{std.fmt.fmtSliceHexLower(&extract_out)});
        
        // Test HKDF expand
        const info = "test-info";
        var expand_out: [32]u8 = undefined;
        try suite.kdf.expand(&expand_out, &extract_out, info);
        std.debug.print("   - HKDF expand works! Output: {x}\n", .{std.fmt.fmtSliceHexLower(&expand_out)});
    }
    
    std.debug.print("\n", .{});
    
    // Check key_package module
    if (@hasDecl(mls_zig, "key_package")) {
        std.debug.print("2. key_package module:\n", .{});
        const kp = mls_zig.key_package;
        
        if (@hasDecl(kp, "KeyPackage")) {
            std.debug.print("   - Has KeyPackage type\n", .{});
        }
        if (@hasDecl(kp, "KeyPackageTBS")) {
            std.debug.print("   - Has KeyPackageTBS type\n", .{});
        }
        if (@hasDecl(kp, "create")) {
            std.debug.print("   - Has create function\n", .{});
        }
        if (@hasDecl(kp, "verify")) {
            std.debug.print("   - Has verify function\n", .{});
        }
    }
    
    std.debug.print("\n", .{});
    
    // Check for other potential modules
    std.debug.print("3. Other modules:\n", .{});
    if (@hasDecl(mls_zig, "credential")) {
        std.debug.print("   ✓ credential\n", .{});
    }
    if (@hasDecl(mls_zig, "extension")) {
        std.debug.print("   ✓ extension\n", .{});
    }
    if (@hasDecl(mls_zig, "proposal")) {
        std.debug.print("   ✓ proposal\n", .{});
    }
    if (@hasDecl(mls_zig, "tree")) {
        std.debug.print("   ✓ tree\n", .{});
    }
    if (@hasDecl(mls_zig, "welcome")) {
        std.debug.print("   ✓ welcome\n", .{});
    }
    if (@hasDecl(mls_zig, "group")) {
        std.debug.print("   ✓ group\n", .{});
    }
    if (@hasDecl(mls_zig, "framing")) {
        std.debug.print("   ✓ framing\n", .{});
    }
    if (@hasDecl(mls_zig, "serialization")) {
        std.debug.print("   ✓ serialization\n", .{});
    }
    
    std.debug.print("\n", .{});
    
    // Check for crypto primitives
    std.debug.print("4. Crypto primitives:\n", .{});
    if (@hasDecl(mls_zig, "hpke")) {
        std.debug.print("   ✓ hpke module\n", .{});
    }
    if (@hasDecl(mls_zig, "signature")) {
        std.debug.print("   ✓ signature module\n", .{});
    }
    
    // Check if we can access specific cipher suite implementations
    std.debug.print("\n5. Available cipher suites:\n", .{});
    const cs_tag = mls_zig.cipher_suite.CipherSuiteTag;
    std.debug.print("   - MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519: {}\n", .{@intFromEnum(cs_tag.mls_128_dhkemx25519_aes128gcm_sha256_ed25519)});
    std.debug.print("   - MLS_128_DHKEMP256_AES128GCM_SHA256_P256: {}\n", .{@intFromEnum(cs_tag.mls_128_dhkemp256_aes128gcm_sha256_p256)});
    std.debug.print("   - MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448: {}\n", .{@intFromEnum(cs_tag.mls_256_dhkemx448_aes256gcm_sha512_ed448)});
}