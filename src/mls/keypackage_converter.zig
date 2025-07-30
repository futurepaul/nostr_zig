const std = @import("std");
const types = @import("types.zig");
const mls_zig = @import("mls_zig");

/// Convert a flat KeyPackage to the legacy types.KeyPackage format
/// This is a temporary bridge while we migrate to flat KeyPackages everywhere
/// Note: The converted KeyPackage will have empty signatures in the LeafNode
/// because the flat format doesn't separate leaf node and package signatures
pub fn flatToLegacy(
    allocator: std.mem.Allocator,
    flat: mls_zig.key_package_flat.KeyPackage,
) !types.KeyPackage {
    // Create HPKEPublicKey for init key
    const init_key_data = try allocator.dupe(u8, &flat.init_key);
    const init_key = types.HPKEPublicKey.init(init_key_data);
    
    // Create HPKEPublicKey for encryption key
    const enc_key_data = try allocator.dupe(u8, &flat.encryption_key);
    const enc_key = types.HPKEPublicKey.init(enc_key_data);
    
    // Create SignaturePublicKey for signature key
    const sig_key_data = try allocator.dupe(u8, &flat.signature_key);
    const sig_key = types.SignaturePublicKey.init(sig_key_data);
    
    // Create a basic credential with the public key as hex
    // The flat KeyPackage stores credential_len but we need to reconstruct the credential
    // For NIP-EE, the credential is the Nostr public key in hex format
    const pubkey_hex = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(&flat.signature_key)});
    const credential = types.Credential{
        .basic = types.BasicCredential{
            .identity = pubkey_hex,
        },
    };
    
    // Create empty capabilities
    const capabilities = types.Capabilities{
        .versions = try allocator.alloc(types.ProtocolVersion, 0),
        .ciphersuites = try allocator.alloc(types.Ciphersuite, 0),
        .extensions = try allocator.alloc(types.ExtensionType, 0),
        .proposals = try allocator.alloc(types.ProposalType, 0),
        .credentials = try allocator.alloc(types.CredentialType, 0),
    };
    
    // Create LeafNode
    const leaf_node = types.LeafNode{
        .encryption_key = enc_key,
        .signature_key = sig_key,
        .credential = credential,
        .capabilities = capabilities,
        .leaf_node_source = .key_package,
        .extensions = try allocator.alloc(types.Extension, 0),
        .signature = try allocator.alloc(u8, 0), // Empty, as it's in the KeyPackage
    };
    
    // Map cipher suite - both enums use the same values, so we can convert directly
    const cipher_suite: types.Ciphersuite = types.Ciphersuite.fromInt(@intFromEnum(flat.cipher_suite));
    
    // Create the signature copy
    const signature = try allocator.dupe(u8, &flat.signature);
    
    return types.KeyPackage{
        .version = .mls10,
        .cipher_suite = cipher_suite,
        .init_key = init_key,
        .leaf_node = leaf_node,
        .extensions = try allocator.alloc(types.Extension, 0),
        .signature = signature,
    };
}

/// Free memory allocated by flatToLegacy
pub fn freeLegacyKeyPackage(allocator: std.mem.Allocator, kp: types.KeyPackage) void {
    allocator.free(kp.init_key.data);
    allocator.free(kp.leaf_node.encryption_key.data);
    allocator.free(kp.leaf_node.signature_key.data);
    
    // Free credential - this was allocated by allocPrint
    switch (kp.leaf_node.credential) {
        .basic => |basic| allocator.free(basic.identity),
        .x509 => |cert| allocator.free(cert),
        .reserved => {},
    }
    
    // Free capabilities
    allocator.free(kp.leaf_node.capabilities.versions);
    allocator.free(kp.leaf_node.capabilities.ciphersuites);
    allocator.free(kp.leaf_node.capabilities.extensions);
    allocator.free(kp.leaf_node.capabilities.proposals);
    allocator.free(kp.leaf_node.capabilities.credentials);
    
    // Free extensions
    for (kp.leaf_node.extensions) |ext| {
        allocator.free(ext.extension_data);
    }
    allocator.free(kp.leaf_node.extensions);
    
    allocator.free(kp.leaf_node.signature);
    
    for (kp.extensions) |ext| {
        allocator.free(ext.extension_data);
    }
    allocator.free(kp.extensions);
    
    allocator.free(kp.signature);
}