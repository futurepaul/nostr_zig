const std = @import("std");
const mls_zig = @import("mls_zig");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    
    // Test with known keypackage hex from external implementation
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
    offset += 2;
    
    // Cipher suite
    const cipher_suite = std.mem.readInt(u16, decoded[offset..][0..2], .big);
    std.log.info("Cipher suite: 0x{x:0>4} (offset {})", .{cipher_suite, offset});
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
        
        // Parse encryption key 
        const enc_key_len = decoded[offset];
        std.log.info("Encryption key length: 0x{x:0>2} (decimal: {}) at offset {}", .{enc_key_len, enc_key_len, offset});
        offset += 1;
        if (enc_key_len == 32) {
            const enc_key = decoded[offset..][0..32];
            std.log.info("Encryption key: {}", .{std.fmt.fmtSliceHexLower(enc_key)});
            offset += 32;
        }
        
        // Parse signature key
        const sig_key_len = decoded[offset];
        std.log.info("Signature key length: 0x{x:0>2} (decimal: {}) at offset {}", .{sig_key_len, sig_key_len, offset});
        offset += 1;
        if (sig_key_len == 32) {
            const sig_key = decoded[offset..][0..32];
            std.log.info("Signature key: {}", .{std.fmt.fmtSliceHexLower(sig_key)});
            offset += 32;
        }
        
        // Parse credential - this is u16 length prefix since it can be > 255
        const cred_len = std.mem.readInt(u16, decoded[offset..][0..2], .big);
        std.log.info("Credential length: 0x{x:0>4} (decimal: {}) at offset {}", .{cred_len, cred_len, offset});
        offset += 2;
        if (cred_len > 0 and cred_len < 200) {
            const cred_data = decoded[offset..][0..cred_len];
            std.log.info("Credential data: {}", .{std.fmt.fmtSliceHexLower(cred_data)});
            offset += cred_len;
        }
        
        // Continue with the rest - parse capabilities, leaf_node_source, extensions
        std.log.info("Remaining bytes after credential: {} at offset {}", .{decoded.len - offset, offset});
        
        // Let me check what these bytes are - they might be ASCII hex
        const next_bytes = decoded[offset..][0..@min(20, decoded.len - offset)];
        std.log.info("Next bytes as hex: {}", .{std.fmt.fmtSliceHexLower(next_bytes)});
        
        // Check if they're ASCII characters
        for (next_bytes, 0..) |byte, i| {
            if (std.ascii.isPrint(byte)) {
                std.log.info("Byte {} at offset {}: '{c}' (0x{x:0>2})", .{i, offset + i, byte, byte});
            } else {
                std.log.info("Byte {} at offset {}: non-printable 0x{x:0>2}", .{i, offset + i, byte});
            }
            if (i >= 10) break;
        }
        
        // Let me try a different approach - skip trying to parse and just find the signature at the end
        // The signature should be the last 66 bytes (u16 length + 64 bytes signature)
        if (decoded.len >= 66) {
            const sig_start = decoded.len - 66;
            const sig_len = std.mem.readInt(u16, decoded[sig_start..][0..2], .big);
            std.log.info("Potential signature length at end-66: 0x{x:0>4} (decimal: {})", .{sig_len, sig_len});
            if (sig_len == 64) {
                const sig_data = decoded[sig_start + 2..][0..64];
                std.log.info("Potential signature: {}", .{std.fmt.fmtSliceHexLower(sig_data[0..16])});
                std.log.info("Signature continues...", .{}); 
            }
        }
        
        // Parse leaf_node_source (u8)
        const leaf_node_source = decoded[offset];
        std.log.info("Leaf node source: 0x{x:0>2} at offset {}", .{leaf_node_source, offset});
        offset += 1;
        
        // Parse leaf node extensions (u16 length prefix)
        const leaf_ext_len = std.mem.readInt(u16, decoded[offset..][0..2], .big);
        std.log.info("Leaf extensions length: 0x{x:0>4} (decimal: {}) at offset {}", .{leaf_ext_len, leaf_ext_len, offset});
        offset += 2;
        if (leaf_ext_len > 0) {
            const ext_data = decoded[offset..][0..leaf_ext_len];
            std.log.info("Leaf extensions data: {}", .{std.fmt.fmtSliceHexLower(ext_data)});
            offset += leaf_ext_len;
        }
        
        // Parse keypackage extensions (u16 length prefix)
        const kp_ext_len = std.mem.readInt(u16, decoded[offset..][0..2], .big);
        std.log.info("KeyPackage extensions length: 0x{x:0>4} (decimal: {}) at offset {}", .{kp_ext_len, kp_ext_len, offset});
        offset += 2;
        if (kp_ext_len > 0) {
            const ext_data = decoded[offset..][0..kp_ext_len];
            std.log.info("KeyPackage extensions data: {}", .{std.fmt.fmtSliceHexLower(ext_data)});
            offset += kp_ext_len;
        }
        
        // Finally, the signature should be here (u16 length prefix)
        if (offset + 2 <= decoded.len) {
            const sig_len = std.mem.readInt(u16, decoded[offset..][0..2], .big);
            std.log.info("Signature length: 0x{x:0>4} (decimal: {}) at offset {}", .{sig_len, sig_len, offset});
            offset += 2;
            if (sig_len > 0 and offset + sig_len <= decoded.len) {
                const sig_data = decoded[offset..][0..sig_len];
                std.log.info("Signature data: {}", .{std.fmt.fmtSliceHexLower(sig_data)});
                offset += sig_len;
            }
        }
        
        std.log.info("Total bytes parsed: {} out of {}", .{offset, decoded.len});
    }
    
    std.log.info("✅ Successfully analyzed external keypackage structure", .{});
}