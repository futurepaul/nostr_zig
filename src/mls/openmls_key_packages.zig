const std = @import("std");
const mls_zig = @import("mls_zig");
const types = @import("types.zig");

/// Parse a KeyPackage in OpenMLS wire format
/// This format uses u8 length prefixes for some fields instead of u16
pub fn parseOpenMlsKeyPackage(
    allocator: std.mem.Allocator,
    data: []const u8,
) types.KeyPackageError!types.KeyPackage {
    var stream = std.io.fixedBufferStream(data);
    var reader = stream.reader();
    
    // Version (u16)
    const version_raw = reader.readInt(u16, .big) catch return error.UnexpectedEndOfStream;
    const version = types.ProtocolVersion.fromInt(version_raw);
    
    // Cipher suite (u16)  
    const cipher_suite_raw = reader.readInt(u16, .big) catch return error.UnexpectedEndOfStream;
    const cipher_suite = types.Ciphersuite.fromInt(cipher_suite_raw);
    
    // Init key with u8 length prefix
    const init_key_len = reader.readByte() catch return error.UnexpectedEndOfStream;
    std.log.debug("OpenMLS format - Init key length: {}", .{init_key_len});
    if (init_key_len > 128) return error.InvalidKeyLength; // Sanity check
    const init_key = allocator.alloc(u8, init_key_len) catch return error.UnexpectedEndOfStream;
    reader.readNoEof(init_key) catch return error.UnexpectedEndOfStream;
    
    // Read remaining data for leaf node
    _ = data.len - stream.pos;
    _ = data[stream.pos..];
    
    // Try to parse the leaf node - for now, create a minimal one
    // TODO: Implement proper OpenMLS leaf node parsing
    const leaf_node = types.LeafNode{
        .encryption_key = types.HPKEPublicKey{ .data = init_key }, // Placeholder
        .signature_key = types.SignaturePublicKey{ .data = &.{} },
        .credential = types.Credential{ .basic = .{ .identity = &.{} } },
        .capabilities = .{
            .versions = &.{},
            .ciphersuites = &.{},
            .extensions = &.{},
            .proposals = &.{},
            .credentials = &.{},
        },
        .leaf_node_source = .key_package,
        .extensions = &.{},
        .signature = &.{},
    };
    
    return types.KeyPackage{
        .version = version,
        .cipher_suite = cipher_suite,
        .init_key = types.HPKEPublicKey{ .data = init_key },
        .leaf_node = leaf_node,
        .extensions = &.{},
        .signature = &.{},
    };
}