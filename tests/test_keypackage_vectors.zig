const std = @import("std");
const testing = std.testing;
const mls_zig = @import("mls_zig");

test "parse external keypackage with TLS variable-length encoding" {
    const allocator = testing.allocator;
    
    // Test with known keypackage hex from external implementation
    const hex_content = "0001000120f669f741e0b716880d5566675b19ff8988094e95f4901be58f75f2408762826d20bdf2cfb3f23ae3ba4131deccba3eb98b715e5df2e972375f7b086e707e00585520e24199b416369d1df58b54e301b66710ceb03b3871d8a1321744430a325df08f0001404064353264646533653030303933653839326363353133666632663061386530626337336333306331306231633233643331626238373637343032366436393238020001020001080003000a0002f2ee000200010100000000688151550000000068f01d65004040faf6b36587b1a1d80e34aa51a8a4d775c6726ff5430bc03a4fc5451c21dfc64d07646e05355ad457c333b589bcb2b3c42e478b75dfe564bccd330282de3eae0c03000a004040247f66ad55ded58ccba144b7a8af5a7b9fb5fd856c54976e8fae70717aa3f7d78ae35c24a381888d676b84d4878459da878e6ced20f3fdcdaf87df4601c27604";
    
    const decoded = try allocator.alloc(u8, hex_content.len / 2);
    defer allocator.free(decoded);
    _ = try std.fmt.hexToBytes(decoded, hex_content);
    
    // Try to parse with our updated implementation
    const key_package = try mls_zig.KeyPackage.tlsDeserialize(allocator, decoded);
    
    std.log.info("✅ Successfully parsed external keypackage!", .{});
    std.log.info("  Protocol version: {x:0>4}", .{key_package.protocol_version});
    std.log.info("  Cipher suite: {}", .{key_package.cipher_suite});
    std.log.info("  Init key length: {}", .{key_package.init_key.len});
    std.log.info("  Encryption key length: {}", .{key_package.encryption_key.len});
    std.log.info("  Signature key length: {}", .{key_package.signature_key.len});
    
    // Verify the keys are correct length
    try testing.expectEqual(@as(u16, 0x0001), key_package.protocol_version);
    try testing.expectEqual(@as(usize, 32), key_package.init_key.len);
    try testing.expectEqual(@as(usize, 32), key_package.encryption_key.len);
    try testing.expectEqual(@as(usize, 32), key_package.signature_key.len);
    try testing.expectEqual(@as(usize, 64), key_package.signature.len);
}

test "analyze external keypackage structure" {
    const allocator = testing.allocator;
    
    // Test with known keypackage hex from our vector
    const hex_content = "0001000120f669f741e0b716880d5566675b19ff8988094e95f4901be58f75f2408762826d20bdf2cfb3f23ae3ba4131deccba3eb98b715e5df2e972375f7b086e707e00585520e24199b416369d1df58b54e301b66710ceb03b3871d8a1321744430a325df08f0001404064353264646533653030303933653839326363353133666632663061386530626337336333306331306231633233643331626238373637343032366436393238020001020001080003000a0002f2ee000200010100000000688151550000000068f01d65004040faf6b36587b1a1d80e34aa51a8a4d775c6726ff5430bc03a4fc5451c21dfc64d07646e05355ad457c333b589bcb2b3c42e478b75dfe564bccd330282de3eae0c03000a004040247f66ad55ded58ccba144b7a8af5a7b9fb5fd856c54976e8fae70717aa3f7d78ae35c24a381888d676b84d4878459da878e6ced20f3fdcdaf87df4601c27604";
    
    const decoded = try allocator.alloc(u8, hex_content.len / 2);
    defer allocator.free(decoded);
    _ = try std.fmt.hexToBytes(decoded, hex_content);
    
    std.log.info("Analyzing KeyPackage structure:", .{});
    std.log.info("Total size: {} bytes", .{decoded.len});
    
    var offset: usize = 0;
    
    // Version
    const version = std.mem.readInt(u16, decoded[offset..][0..2], .big);
    std.log.info("Version: 0x{x:0>4} (offset {})", .{version, offset});
    try testing.expectEqual(@as(u16, 0x0001), version);
    offset += 2;
    
    // Cipher suite
    const cipher_suite = std.mem.readInt(u16, decoded[offset..][0..2], .big);
    std.log.info("Cipher suite: 0x{x:0>4} (offset {})", .{cipher_suite, offset});
    try testing.expectEqual(@as(u16, 0x0001), cipher_suite);
    offset += 2;
    
    // Init key - check if it's using u8 or u16 length prefix
    const init_key_len_byte = decoded[offset];
    std.log.info("Init key length byte: 0x{x:0>2} (decimal: {}) at offset {}", .{init_key_len_byte, init_key_len_byte, offset});
    
    // This appears to be using TLS variable-length encoding
    // For lengths < 256, it uses a single byte
    if (init_key_len_byte == 0x20) { // 32 bytes
        std.log.info("Init key uses single-byte length prefix (TLS encoding)", .{});
        offset += 1;
        const init_key = decoded[offset..][0..32];
        std.log.info("Init key: {}", .{std.fmt.fmtSliceHexLower(init_key)});
        offset += 32;
        
        // Next should be the leaf node with another length prefix
        const next_byte = decoded[offset];
        std.log.info("Next byte after init key: 0x{x:0>2} at offset {}", .{next_byte, offset});
        
        // Continue analyzing to understand the full structure
        std.log.info("Remaining bytes: {} at offset {}", .{decoded.len - offset, offset});
    }
    
    std.log.info("✅ Successfully analyzed external keypackage structure", .{});
}

const KeyPackageVector = struct {
    event_id: []const u8,
    pubkey: []const u8,
    created_at: i64,
    content: []const u8,
    tags: [][]const []const u8,
};

test "verify keypackage vectors match NIP-EE format" {
    const allocator = testing.allocator;
    
    // Read the JSONL file
    const file = try std.fs.cwd().openFile("tests/keypackage_vectors.jsonl", .{});
    defer file.close();
    
    const file_contents = try file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(file_contents);
    
    var lines = std.mem.tokenizeScalar(u8, file_contents, '\n');
    var verified_count: usize = 0;
    
    while (lines.next()) |line| {
        const parsed = try std.json.parseFromSlice(KeyPackageVector, allocator, line, .{});
        defer parsed.deinit();
        
        const vector = parsed.value;
        
        std.log.info("Verifying keypackage event: {s}", .{vector.event_id});
        
        // Verify it has the required NIP-EE tags
        var has_protocol_version = false;
        var has_ciphersuite = false;
        var has_extensions = false;
        var has_relays = false;
        
        for (vector.tags) |tag| {
            if (tag.len >= 2) {
                if (std.mem.eql(u8, tag[0], "mls_protocol_version")) {
                    has_protocol_version = true;
                    try testing.expectEqualStrings("1.0", tag[1]);
                } else if (std.mem.eql(u8, tag[0], "mls_ciphersuite")) {
                    has_ciphersuite = true;
                    try testing.expectEqualStrings("1", tag[1]);
                } else if (std.mem.eql(u8, tag[0], "mls_extensions")) {
                    has_extensions = true;
                } else if (std.mem.eql(u8, tag[0], "relays")) {
                    has_relays = true;
                }
            }
        }
        
        try testing.expect(has_protocol_version);
        try testing.expect(has_ciphersuite);
        try testing.expect(has_extensions);
        try testing.expect(has_relays);
        
        // Verify content is hex and can be decoded
        try testing.expect(vector.content.len % 2 == 0);
        const decoded = try allocator.alloc(u8, vector.content.len / 2);
        defer allocator.free(decoded);
        _ = try std.fmt.hexToBytes(decoded, vector.content);
        
        // Basic structure checks
        try testing.expect(decoded.len >= 6); // At minimum: version(2) + suite(2) + some data
        const version = std.mem.readInt(u16, decoded[0..2], .big);
        const suite = std.mem.readInt(u16, decoded[2..4], .big);
        try testing.expectEqual(@as(u16, 0x0001), version); // MLS 1.0
        try testing.expectEqual(@as(u16, 0x0001), suite);   // MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
        
        verified_count += 1;
    }
    
    try testing.expect(verified_count > 0);
    std.log.info("✅ Successfully verified {} keypackage vectors", .{verified_count});
}