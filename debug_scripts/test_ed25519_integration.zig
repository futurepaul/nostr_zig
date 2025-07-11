const std = @import("std");
const mls = @import("nostr").mls;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    std.debug.print("=== Testing Ed25519 Integration with mls_zig ===\n\n", .{});
    
    // Create MLS provider
    const provider = mls.provider.MlsProvider.init(allocator);
    
    // Generate a test key pair using Ed25519
    const Ed25519 = std.crypto.sign.Ed25519;
    var seed: [32]u8 = undefined;
    std.crypto.random.bytes(&seed);
    const kp = try Ed25519.KeyPair.create(seed);
    
    std.debug.print("1. Generated Ed25519 key pair:\n", .{});
    std.debug.print("   - Public key: {x}\n", .{std.fmt.fmtSliceHexLower(&kp.public_key.bytes)});
    std.debug.print("   - Private key: {x}\n", .{std.fmt.fmtSliceHexLower(&kp.secret_key.bytes)});
    
    // Test signing
    const message = "Hello, MLS world!";
    std.debug.print("\n2. Testing signing with message: \"{s}\"\n", .{message});
    
    const signature = try provider.crypto.signFn(allocator, &kp.secret_key.bytes[0..32], message);
    defer allocator.free(signature);
    
    std.debug.print("   - Signature: {x}\n", .{std.fmt.fmtSliceHexLower(signature)});
    std.debug.print("   - Signature length: {} bytes\n", .{signature.len});
    
    // Test verification
    std.debug.print("\n3. Testing verification:\n", .{});
    const is_valid = try provider.crypto.verifyFn(&kp.public_key.bytes, message, signature);
    std.debug.print("   - Verification result: {}\n", .{is_valid});
    
    // Test with wrong signature
    std.debug.print("\n4. Testing with wrong signature:\n", .{});
    var wrong_signature = try allocator.alloc(u8, signature.len);
    defer allocator.free(wrong_signature);
    @memcpy(wrong_signature, signature);
    wrong_signature[0] ^= 0x01; // Flip a bit
    
    const is_invalid = try provider.crypto.verifyFn(&kp.public_key.bytes, message, wrong_signature);
    std.debug.print("   - Wrong signature result: {}\n", .{is_invalid});
    
    // Test with wrong message
    std.debug.print("\n5. Testing with wrong message:\n", .{});
    const wrong_message = "Hello, wrong world!";
    const wrong_msg_result = try provider.crypto.verifyFn(&kp.public_key.bytes, wrong_message, signature);
    std.debug.print("   - Wrong message result: {}\n", .{wrong_msg_result});
    
    std.debug.print("\n✅ Ed25519 integration with mls_zig successful!\n", .{});
    
    if (is_valid and !is_invalid and !wrong_msg_result) {
        std.debug.print("✅ All tests passed!\n", .{});
    } else {
        std.debug.print("❌ Some tests failed!\n", .{});
    }
}