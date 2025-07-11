const std = @import("std");
const mls_zig = @import("mls_zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    std.debug.print("=== Detailed MLS API Analysis ===\n\n", .{});
    
    // 1. Analyze the CipherSuite type structure
    std.debug.print("1. CipherSuite Analysis:\n", .{});
    const cs = mls_zig.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    std.debug.print("   - CipherSuite value: {}\n", .{cs});
    
    // Check what methods exist on cipher suite
    const cs_type = @TypeOf(cs);
    const cs_info = @typeInfo(cs_type);
    std.debug.print("   - CipherSuite type info: {}\n", .{cs_info});
    
    // 2. Check key_package module in detail
    std.debug.print("\n2. Key Package Module:\n", .{});
    const kp = mls_zig.key_package;
    
    // Test generating signature key pair
    std.debug.print("   - Testing generateSignatureKeyPair()...\n", .{});
    if (@hasDecl(kp, "generateSignatureKeyPair")) {
        const keypair = kp.generateSignatureKeyPair(allocator) catch |err| {
            std.debug.print("   - Failed to generate signature key pair: {}\n", .{err});
            return;
        };
        defer keypair.deinit();
        
        std.debug.print("   - ✅ Generated signature key pair!\n", .{});
        std.debug.print("   - Public key length: {}\n", .{keypair.public_key.len});
        std.debug.print("   - Private key length: {}\n", .{keypair.private_key.len});
        
        // Now test if we can sign with this key pair
        std.debug.print("   - Testing signing with key pair...\n", .{});
        const test_data = "Test message for signing";
        
        // Try different approaches to sign
        if (@hasDecl(keypair, "sign")) {
            std.debug.print("   - keypair.sign() method exists\n", .{});
            const signature = keypair.sign(allocator, test_data) catch |err| {
                std.debug.print("   - keypair.sign() failed: {}\n", .{err});
                return;
            };
            defer signature.deinit();
            std.debug.print("   - ✅ Signed with keypair! Signature length: {}\n", .{signature.len});
        } else {
            std.debug.print("   - keypair.sign() method not found\n", .{});
        }
        
        // Check if there's a separate signing function
        if (@hasDecl(kp, "sign")) {
            std.debug.print("   - key_package.sign() method exists\n", .{});
            const signature = kp.sign(allocator, keypair.private_key, test_data) catch |err| {
                std.debug.print("   - key_package.sign() failed: {}\n", .{err});
                return;
            };
            defer signature.deinit();
            std.debug.print("   - ✅ Signed with key_package.sign()! Signature length: {}\n", .{signature.len});
        } else {
            std.debug.print("   - key_package.sign() method not found\n", .{});
        }
        
        // Test verification
        std.debug.print("   - Testing verification...\n", .{});
        if (@hasDecl(kp, "verify")) {
            std.debug.print("   - key_package.verify() method exists\n", .{});
        } else {
            std.debug.print("   - key_package.verify() method not found\n", .{});
        }
    }
    
    // 3. Check cipher_suite module methods
    std.debug.print("\n3. Cipher Suite Module Methods:\n", .{});
    const cs_mod = mls_zig.cipher_suite;
    const cs_actual = cs_mod.getCipherSuite(cs_mod.CipherSuiteTag.mls_128_dhkemx25519_aes128gcm_sha256_ed25519);
    
    std.debug.print("   - Got cipher suite instance\n", .{});
    
    // Check if cipher suite has signature methods
    if (@hasDecl(@TypeOf(cs_actual), "signature")) {
        std.debug.print("   - Cipher suite has signature field\n", .{});
        const sig_field = cs_actual.signature;
        
        // Check what methods are available on signature
        if (@hasDecl(@TypeOf(sig_field), "sign")) {
            std.debug.print("   - signature.sign() method exists\n", .{});
            
            // Test signing with signature field
            std.debug.print("   - Testing signature.sign()...\n", .{});
            var private_key: [32]u8 = undefined;
            std.crypto.random.bytes(&private_key);
            
            const test_data = "Test message for signature field";
            const signature = sig_field.sign(allocator, &private_key, test_data) catch |err| {
                std.debug.print("   - signature.sign() failed: {}\n", .{err});
                return;
            };
            defer signature.deinit();
            
            std.debug.print("   - ✅ Signed with signature field! Length: {}\n", .{signature.data.len});
            
            // Test verification
            if (@hasDecl(@TypeOf(sig_field), "verify")) {
                std.debug.print("   - signature.verify() method exists\n", .{});
                
                // Generate public key from private key
                var public_key: [32]u8 = undefined;
                const seed = std.crypto.sign.Ed25519.KeyPair.fromBytes(private_key);
                public_key = seed.public_key.bytes;
                
                const is_valid = sig_field.verify(&public_key, test_data, signature.data) catch |err| {
                    std.debug.print("   - signature.verify() failed: {}\n", .{err});
                    return;
                };
                
                std.debug.print("   - ✅ Verification result: {}\n", .{is_valid});
            } else {
                std.debug.print("   - signature.verify() method not found\n", .{});
            }
        } else {
            std.debug.print("   - signature.sign() method not found\n", .{});
        }
    } else {
        std.debug.print("   - Cipher suite does not have signature field\n", .{});
    }
    
    // 4. Check for TLS codec signing
    std.debug.print("\n4. TLS Codec Signing:\n", .{});
    if (@hasDecl(mls_zig, "tls_codec")) {
        const tls = mls_zig.tls_codec;
        std.debug.print("   - tls_codec module available\n", .{});
        
        if (@hasDecl(tls, "sign")) {
            std.debug.print("   - tls_codec.sign() method exists\n", .{});
        } else {
            std.debug.print("   - tls_codec.sign() method not found\n", .{});
        }
    }
    
    // 5. Check for low-level crypto functions
    std.debug.print("\n5. Low-level Crypto Functions:\n", .{});
    if (@hasDecl(mls_zig, "crypto")) {
        const crypto = mls_zig.crypto;
        std.debug.print("   - crypto module available\n", .{});
        
        if (@hasDecl(crypto, "sign")) {
            std.debug.print("   - crypto.sign() method exists\n", .{});
        } else {
            std.debug.print("   - crypto.sign() method not found\n", .{});
        }
    }
    
    // 6. Check for Ed25519 specific functions
    std.debug.print("\n6. Ed25519 Functions:\n", .{});
    if (@hasDecl(mls_zig, "ed25519")) {
        const ed25519 = mls_zig.ed25519;
        std.debug.print("   - ed25519 module available\n", .{});
        
        if (@hasDecl(ed25519, "sign")) {
            std.debug.print("   - ed25519.sign() method exists\n", .{});
        } else {
            std.debug.print("   - ed25519.sign() method not found\n", .{});
        }
    }
    
    std.debug.print("\n=== Analysis Complete ===\n", .{});
}