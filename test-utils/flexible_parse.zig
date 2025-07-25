const std = @import("std");
const mls_zig = @import("mls_zig");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    
    // Test with known keypackage hex from external implementation
    const hex_content = "0001000120f669f741e0b716880d5566675b19ff8988094e95f4901be58f75f2408762826d20bdf2cfb3f23ae3ba4131deccba3eb98b715e5df2e972375f7b086e707e00585520e24199b416369d1df58b54e301b66710ceb03b3871d8a1321744430a325df08f0001404064353264646533653030303933653839326363353133666632663061386530626337336333306331306231633233643331626238373637343032366436393238020001020001080003000a0002f2ee000200010100000000688151550000000068f01d65004040faf6b36587b1a1d80e34aa51a8a4d775c6726ff5430bc03a4fc5451c21dfc64d07646e05355ad457c333b589bcb2b3c42e478b75dfe564bccd330282de3eae0c03000a004040247f66ad55ded58ccba144b7a8af5a7b9fb5fd856c54976e8fae70717aa3f7d78ae35c24a381888d676b84d4878459da878e6ced20f3fdcdaf87df4601c27604";
    
    const decoded = try allocator.alloc(u8, hex_content.len / 2);
    defer allocator.free(decoded);
    _ = try std.fmt.hexToBytes(decoded, hex_content);
    
    std.log.info("Trying flexible parsing approach", .{});
    
    // Try to create a modified version of the external keypackage that has the right credential length
    var modified = try allocator.dupe(u8, decoded);
    defer allocator.free(modified);
    
    // The credential starts at offset 103, but let's try changing its length from 0x0001 to a larger value
    // Looking at the ASCII hex data starting at 106, if that's the actual credential data
    // Then the credential might be 64 bytes long (hex-encoded 32-byte identity)
    
    // Let's try setting credential length to 64 bytes
    std.mem.writeInt(u16, modified[103..105], 64, .big);
    
    std.log.info("Modified credential length from {} to 64", .{std.mem.readInt(u16, decoded[103..105], .big)});
    
    // Now try to parse it
    const key_package = mls_zig.KeyPackage.tlsDeserialize(allocator, modified) catch |err| {
        std.log.err("Failed to parse modified keypackage: {}", .{err});
        return;
    };
    
    std.log.info("✅ Successfully parsed modified keypackage!", .{});
    std.log.info("  Protocol version: {x:0>4}", .{key_package.protocol_version});
    std.log.info("  Cipher suite: {}", .{key_package.cipher_suite});
}