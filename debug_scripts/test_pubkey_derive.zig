const std = @import("std");
const secp = @import("src/secp256k1/secp256k1.zig");

pub fn main() \!void {
    const ctx = secp.secp256k1_context_create(secp.SECP256K1_CONTEXT_SIGN) orelse return error.CryptoError;
    defer secp.secp256k1_context_destroy(ctx);
    
    // sec2 from test vector
    var sec2: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&sec2, "0000000000000000000000000000000000000000000000000000000000000002");
    
    // Generate public key
    var pubkey: secp.secp256k1_pubkey = undefined;
    if (secp.secp256k1_ec_pubkey_create(ctx, &pubkey, &sec2) \!= 1) {
        return error.CryptoError;
    }
    
    // Serialize public key in compressed format
    var public_key_bytes: [33]u8 = undefined;
    var output_len: usize = 33;
    if (secp.secp256k1_ec_pubkey_serialize(ctx, &public_key_bytes, &output_len, &pubkey, secp.SECP256K1_EC_COMPRESSED) \!= 1) {
        return error.CryptoError;
    }
    
    std.debug.print("sec2: {s}\n", .{std.fmt.fmtSliceHexLower(&sec2)});
    std.debug.print("pub2 (compressed): {s}\n", .{std.fmt.fmtSliceHexLower(&public_key_bytes)});
    std.debug.print("pub2 (x-only): {s}\n", .{std.fmt.fmtSliceHexLower(public_key_bytes[1..33])});
    
    // Compare with expected from test vector
    const expected_pub2 = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    std.debug.print("Expected pub2 (x-only): {s}\n", .{expected_pub2});
}
