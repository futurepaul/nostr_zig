const std = @import("std");
const mls_zig = @import("mls_zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    std.debug.print("=== MLS Signing API Exploration ===\n\n", .{});
    
    // 1. Test cipher suite signing methods
    std.debug.print("1. Testing CipherSuite signing methods:\n", .{});
    const cs = mls_zig.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    
    // Generate a test Ed25519 key pair
    var private_key: [32]u8 = undefined;
    std.crypto.random.bytes(&private_key);
    
    // Test data to sign
    const test_data = "Hello, MLS signing!";
    
    // Try to sign using the cipher suite
    std.debug.print("   - Testing cs.sign()...\n", .{});
    if (@hasDecl(@TypeOf(cs), "sign")) {
        var signature = cs.sign(allocator, &private_key, test_data) catch |err| {
            std.debug.print("   - cs.sign() failed: {}\n", .{err});
            return;
        };
        defer signature.deinit();
        
        std.debug.print("   - ✅ cs.sign() works! Signature length: {}\n", .{signature.data.len});
        
        // Try to verify the signature
        std.debug.print("   - Testing cs.verify()...\n", .{});
        
        // First we need to derive the public key from private key
        var public_key: [32]u8 = undefined;
        const seed = std.crypto.sign.Ed25519.KeyPair.fromBytes(private_key);
        public_key = seed.public_key.bytes;
        
        const is_valid = cs.verify(&public_key, test_data, signature.data) catch |err| {
            std.debug.print("   - cs.verify() failed: {}\n", .{err});
            return;
        };
        
        std.debug.print("   - ✅ cs.verify() works! Valid: {}\n", .{is_valid});
    } else {
        std.debug.print("   - cs.sign() method not found\n", .{});
    }
    
    // 2. Test credential signing
    std.debug.print("\n2. Testing credential signing:\n", .{});
    if (@hasDecl(mls_zig, "credential")) {
        const cred = mls_zig.credential;
        std.debug.print("   - credential module available\n", .{});
        
        // Check for BasicCredential
        if (@hasDecl(cred, "BasicCredential")) {
            std.debug.print("   - BasicCredential type available\n", .{});
            
            // Try to create a basic credential
            const identity = "alice@nostr.com";
            var identity_bytes = try mls_zig.tls_codec.VarBytes.init(allocator, identity);
            defer identity_bytes.deinit();
            
            const basic_cred = cred.BasicCredential{
                .identity = identity_bytes,
            };
            
            std.debug.print("   - Created BasicCredential for: {s}\n", .{basic_cred.identity.data});
            
            // Check if credentials have signing methods
            if (@hasDecl(cred, "sign")) {
                std.debug.print("   - credential.sign() method available\n", .{});
            } else {
                std.debug.print("   - credential.sign() method not found\n", .{});
            }
        }
    }
    
    // 3. Test signature module if available
    std.debug.print("\n3. Testing signature module:\n", .{});
    if (@hasDecl(mls_zig, "signature")) {
        const sig = mls_zig.signature;
        std.debug.print("   - signature module available\n", .{});
        
        // Check for various signature types
        if (@hasDecl(sig, "Ed25519")) {
            std.debug.print("   - Ed25519 signature type available\n", .{});
        }
        if (@hasDecl(sig, "sign")) {
            std.debug.print("   - signature.sign() method available\n", .{});
        }
        if (@hasDecl(sig, "verify")) {
            std.debug.print("   - signature.verify() method available\n", .{});
        }
    } else {
        std.debug.print("   - signature module not found\n", .{});
    }
    
    // 4. Test key generation
    std.debug.print("\n4. Testing key generation:\n", .{});
    if (@hasDecl(mls_zig, "key_package")) {
        const kp = mls_zig.key_package;
        std.debug.print("   - key_package module available\n", .{});
        
        // Check for key generation methods
        if (@hasDecl(kp, "generateSignatureKeyPair")) {
            std.debug.print("   - generateSignatureKeyPair() method available\n", .{});
        }
        if (@hasDecl(kp, "generateKeyPair")) {
            std.debug.print("   - generateKeyPair() method available\n", .{});
        }
        if (@hasDecl(kp, "SignatureKeyPair")) {
            std.debug.print("   - SignatureKeyPair type available\n", .{});
        }
    }
    
    // 5. Test HPKE signing (if available)
    std.debug.print("\n5. Testing HPKE signing:\n", .{});
    if (@hasDecl(mls_zig, "hpke")) {
        const hpke = mls_zig.hpke;
        std.debug.print("   - hpke module available\n", .{});
        
        if (@hasDecl(hpke, "sign")) {
            std.debug.print("   - hpke.sign() method available\n", .{});
        }
        if (@hasDecl(hpke, "verify")) {
            std.debug.print("   - hpke.verify() method available\n", .{});
        }
    }
    
    // 6. Test framing signing
    std.debug.print("\n6. Testing framing signing:\n", .{});
    if (@hasDecl(mls_zig, "framing")) {
        const framing = mls_zig.framing;
        std.debug.print("   - framing module available\n", .{});
        
        if (@hasDecl(framing, "sign")) {
            std.debug.print("   - framing.sign() method available\n", .{});
        }
        if (@hasDecl(framing, "verify")) {
            std.debug.print("   - framing.verify() method available\n", .{});
        }
    }
    
    // 7. Test leaf node signing
    std.debug.print("\n7. Testing leaf node signing:\n", .{});
    if (@hasDecl(mls_zig, "tree")) {
        const tree = mls_zig.tree;
        std.debug.print("   - tree module available\n", .{});
        
        if (@hasDecl(tree, "LeafNode")) {
            std.debug.print("   - LeafNode type available\n", .{});
            
            // Check if LeafNode has signing methods
            if (@hasDecl(tree.LeafNode, "sign")) {
                std.debug.print("   - LeafNode.sign() method available\n", .{});
            }
        }
    }
    
    // 8. Test authentication methods
    std.debug.print("\n8. Testing authentication methods:\n", .{});
    if (@hasDecl(mls_zig, "auth")) {
        const auth = mls_zig.auth;
        std.debug.print("   - auth module available\n", .{});
        
        if (@hasDecl(auth, "sign")) {
            std.debug.print("   - auth.sign() method available\n", .{});
        }
        if (@hasDecl(auth, "verify")) {
            std.debug.print("   - auth.verify() method available\n", .{});
        }
    }
    
    // 9. Test group signing
    std.debug.print("\n9. Testing group signing:\n", .{});
    if (@hasDecl(mls_zig, "group")) {
        const group = mls_zig.group;
        std.debug.print("   - group module available\n", .{});
        
        if (@hasDecl(group, "MlsGroup")) {
            std.debug.print("   - MlsGroup type available\n", .{});
            
            // Check if MlsGroup has signing methods
            if (@hasDecl(group.MlsGroup, "sign")) {
                std.debug.print("   - MlsGroup.sign() method available\n", .{});
            }
        }
    }
    
    // 10. Test low-level cipher suite access
    std.debug.print("\n10. Testing cipher suite internals:\n", .{});
    if (@hasDecl(mls_zig, "cipher_suite")) {
        const cs_mod = mls_zig.cipher_suite;
        std.debug.print("   - cipher_suite module available\n", .{});
        
        if (@hasDecl(cs_mod, "CipherSuite")) {
            std.debug.print("   - CipherSuite type available\n", .{});
            
            const cs_type = cs_mod.CipherSuite;
            std.debug.print("   - CipherSuite type: {}\n", .{@TypeOf(cs_type)});
            
            // Check what methods are available on the cipher suite
            const cs_info = @typeInfo(cs_type);
            if (cs_info == .@"struct") {
                std.debug.print("   - CipherSuite is a struct\n", .{});
                
                // Check for signature-related fields
                if (@hasDecl(cs_type, "signature")) {
                    std.debug.print("   - CipherSuite has signature field\n", .{});
                }
                if (@hasDecl(cs_type, "sign")) {
                    std.debug.print("   - CipherSuite has sign method\n", .{});
                }
                if (@hasDecl(cs_type, "verify")) {
                    std.debug.print("   - CipherSuite has verify method\n", .{});
                }
            }
        }
    }
    
    std.debug.print("\n=== API Exploration Complete ===\n", .{});
}