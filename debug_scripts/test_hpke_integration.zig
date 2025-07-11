const std = @import("std");
const mls = @import("nostr").mls;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    std.debug.print("=== Testing HPKE Integration ===\n\n", .{});
    
    // Create MLS provider
    const provider = mls.provider.MlsProvider.init(allocator);
    
    // Test key pair generation
    std.debug.print("1. Testing HPKE key pair generation:\n", .{});
    const keypair = try provider.crypto.hpkeGenerateKeyPairFn(allocator);
    defer allocator.free(keypair.private_key);
    defer allocator.free(keypair.public_key);
    
    std.debug.print("   - Private key: {x}\n", .{std.fmt.fmtSliceHexLower(keypair.private_key)});
    std.debug.print("   - Public key: {x}\n", .{std.fmt.fmtSliceHexLower(keypair.public_key)});
    std.debug.print("   - Private key length: {} bytes\n", .{keypair.private_key.len});
    std.debug.print("   - Public key length: {} bytes\n", .{keypair.public_key.len});
    
    // Test encryption
    std.debug.print("\n2. Testing HPKE encryption:\n", .{});
    const plaintext = "Hello, HPKE world!";
    const info = "test-info";
    const aad = "test-aad";
    
    const ciphertext = try provider.crypto.hpkeSealFn(allocator, keypair.public_key, info, aad, plaintext);
    defer allocator.free(ciphertext.kem_output);
    defer allocator.free(ciphertext.ciphertext);
    
    std.debug.print("   - Plaintext: \"{s}\"\n", .{plaintext});
    std.debug.print("   - KEM output: {x}\n", .{std.fmt.fmtSliceHexLower(ciphertext.kem_output)});
    std.debug.print("   - Ciphertext: {x}\n", .{std.fmt.fmtSliceHexLower(ciphertext.ciphertext)});
    std.debug.print("   - KEM output length: {} bytes\n", .{ciphertext.kem_output.len});
    std.debug.print("   - Ciphertext length: {} bytes\n", .{ciphertext.ciphertext.len});
    
    // Test decryption
    std.debug.print("\n3. Testing HPKE decryption:\n", .{});
    const decrypted = try provider.crypto.hpkeOpenFn(allocator, keypair.private_key, info, aad, ciphertext);
    defer allocator.free(decrypted);
    
    std.debug.print("   - Decrypted: \"{s}\"\n", .{decrypted});
    std.debug.print("   - Match original: {}\n", .{std.mem.eql(u8, plaintext, decrypted)});
    
    // Test with wrong key
    std.debug.print("\n4. Testing with wrong private key:\n", .{});
    const wrong_keypair = try provider.crypto.hpkeGenerateKeyPairFn(allocator);
    defer allocator.free(wrong_keypair.private_key);
    defer allocator.free(wrong_keypair.public_key);
    
    const wrong_decrypt = provider.crypto.hpkeOpenFn(allocator, wrong_keypair.private_key, info, aad, ciphertext);
    if (wrong_decrypt) |_| {
        std.debug.print("   - ERROR: Decryption with wrong key should have failed!\n", .{});
    } else |err| {
        std.debug.print("   - Correctly failed with error: {}\n", .{err});
    }
    
    std.debug.print("\n✅ HPKE integration successful!\n", .{});
    
    if (std.mem.eql(u8, plaintext, decrypted)) {
        std.debug.print("✅ All tests passed!\n", .{});
    } else {
        std.debug.print("❌ Some tests failed!\n", .{});
    }
}