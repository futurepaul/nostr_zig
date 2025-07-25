const std = @import("std");
const mls_zig = @import("mls_zig");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    
    std.log.info("Creating our own KeyPackage to compare with external", .{});
    
    // Create a simple test KeyPackage
    var init_key: [32]u8 = undefined;
    var enc_key: [32]u8 = undefined;
    var sig_key: [32]u8 = undefined;
    var signature: [64]u8 = undefined;
    
    // Fill with test data
    @memset(&init_key, 0x01);
    @memset(&enc_key, 0x02);
    @memset(&sig_key, 0x03);
    @memset(&signature, 0x04);
    
    const cs = mls_zig.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    const key_package = mls_zig.KeyPackage.init(
        cs,
        init_key,
        enc_key,
        sig_key,
        1, // small credential for now
        signature,
    );
    
    // Serialize our KeyPackage
    const our_serialized = try key_package.tlsSerialize(allocator);
    defer allocator.free(our_serialized);
    
    std.log.info("Our serialized KeyPackage ({} bytes):", .{our_serialized.len});
    std.log.info("{}", .{std.fmt.fmtSliceHexLower(our_serialized)});
    
    // External KeyPackage for comparison
    const external_hex = "0001000120f669f741e0b716880d5566675b19ff8988094e95f4901be58f75f2408762826d20bdf2cfb3f23ae3ba4131deccba3eb98b715e5df2e972375f7b086e707e00585520e24199b416369d1df58b54e301b66710ceb03b3871d8a1321744430a325df08f0001404064353264646533653030303933653839326363353133666632663061386530626337336333306331306231633233643331626238373637343032366436393238020001020001080003000a0002f2ee000200010100000000688151550000000068f01d65004040faf6b36587b1a1d80e34aa51a8a4d775c6726ff5430bc03a4fc5451c21dfc64d07646e05355ad457c333b589bcb2b3c42e478b75dfe564bccd330282de3eae0c03000a004040247f66ad55ded58ccba144b7a8af5a7b9fb5fd856c54976e8fae70717aa3f7d78ae35c24a381888d676b84d4878459da878e6ced20f3fdcdaf87df4601c27604";
    
    const external_decoded = try allocator.alloc(u8, external_hex.len / 2);
    defer allocator.free(external_decoded);
    _ = try std.fmt.hexToBytes(external_decoded, external_hex);
    
    std.log.info("External KeyPackage ({} bytes):", .{external_decoded.len});
    std.log.info("{}", .{std.fmt.fmtSliceHexLower(external_decoded[0..@min(100, external_decoded.len)])});
    
    // Try to round-trip our own KeyPackage
    const parsed_back = try mls_zig.KeyPackage.tlsDeserialize(allocator, our_serialized);
    std.log.info("✅ Successfully round-tripped our own KeyPackage", .{});
    std.log.info("  Protocol version: {x:0>4}", .{parsed_back.protocol_version});
    std.log.info("  Cipher suite: {}", .{parsed_back.cipher_suite});
}