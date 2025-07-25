const std = @import("std");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    
    // Test with known keypackage hex from external implementation
    const hex_content = "0001000120f669f741e0b716880d5566675b19ff8988094e95f4901be58f75f2408762826d20bdf2cfb3f23ae3ba4131deccba3eb98b715e5df2e972375f7b086e707e00585520e24199b416369d1df58b54e301b66710ceb03b3871d8a1321744430a325df08f0001404064353264646533653030303933653839326363353133666632663061386530626337336333306331306231633233643331626238373637343032366436393238020001020001080003000a0002f2ee000200010100000000688151550000000068f01d65004040faf6b36587b1a1d80e34aa51a8a4d775c6726ff5430bc03a4fc5451c21dfc64d07646e05355ad457c333b589bcb2b3c42e478b75dfe564bccd330282de3eae0c03000a004040247f66ad55ded58ccba144b7a8af5a7b9fb5fd856c54976e8fae70717aa3f7d78ae35c24a381888d676b84d4878459da878e6ced20f3fdcdaf87df4601c27604";
    
    const decoded = try allocator.alloc(u8, hex_content.len / 2);
    defer allocator.free(decoded);
    _ = try std.fmt.hexToBytes(decoded, hex_content);
    
    std.log.info("Total keypackage size: {} bytes", .{decoded.len});
    
    // Work backwards to find the signature - look for 0x0040 (64 in big endian) followed by 64 bytes
    var offset = decoded.len;
    while (offset >= 66) {
        offset -= 1;
        if (offset >= 2) {
            const potential_len = std.mem.readInt(u16, decoded[offset-2..][0..2], .big);
            if (potential_len == 64 and offset + 64 <= decoded.len) {
                std.log.info("Found potential signature at offset {}: length = {}", .{offset-2, potential_len});
                const sig_data = decoded[offset..][0..64];
                std.log.info("Signature: {}", .{std.fmt.fmtSliceHexLower(sig_data[0..16])});
                
                // Now let's see what's right before the signature length
                if (offset >= 4) {
                    const before_sig = decoded[offset-4..offset-2];
                    std.log.info("2 bytes before sig: {}", .{std.fmt.fmtSliceHexLower(before_sig)});
                }
                break;
            }
        }
    }
    
    // Also try finding 0x4040 which could be the length
    for (decoded, 0..) |_, i| {
        if (i + 1 < decoded.len) {
            const bytes = decoded[i..i+2];
            if (std.mem.eql(u8, bytes, &[_]u8{0x40, 0x40})) {
                std.log.info("Found 0x4040 at offset {}", .{i});
                if (i + 2 + 64 <= decoded.len) {
                    const sig_data = decoded[i+2..][0..64];
                    std.log.info("Data after 0x4040: {}", .{std.fmt.fmtSliceHexLower(sig_data[0..16])});
                }
            }
        }
    }
}