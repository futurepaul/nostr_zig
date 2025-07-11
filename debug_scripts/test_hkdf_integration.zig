const std = @import("std");
const mls = @import("nostr").mls;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    std.debug.print("=== Testing HKDF Integration with mls_zig ===\n\n", .{});
    
    // Create MLS provider
    const provider = mls.provider.MlsProvider.init(allocator);
    
    // Test HKDF Extract
    std.debug.print("1. Testing HKDF Extract:\n", .{});
    const salt = "test-salt";
    const ikm = "test-input-key-material";
    const prk = try provider.crypto.hkdfExtractFn(allocator, salt, ikm);
    defer allocator.free(prk);
    std.debug.print("   - Extract result: {x}\n", .{std.fmt.fmtSliceHexLower(prk)});
    std.debug.print("   - Length: {} bytes\n", .{prk.len});
    
    // Test HKDF Expand
    std.debug.print("\n2. Testing HKDF Expand:\n", .{});
    const info = "test-info";
    const expanded = try provider.crypto.hkdfExpandFn(allocator, prk, info, 64);
    defer allocator.free(expanded);
    std.debug.print("   - Expand result: {x}\n", .{std.fmt.fmtSliceHexLower(expanded)});
    std.debug.print("   - Length: {} bytes\n", .{expanded.len});
    
    // Compare with known test vectors if available
    std.debug.print("\n3. Testing with NIP-44 parameters:\n", .{});
    const nip44_salt = "nip44-v2";
    const nip44_ikm = "test-key-material";
    const nip44_prk = try provider.crypto.hkdfExtractFn(allocator, nip44_salt, nip44_ikm);
    defer allocator.free(nip44_prk);
    std.debug.print("   - NIP-44 extract: {x}\n", .{std.fmt.fmtSliceHexLower(nip44_prk)});
    
    std.debug.print("\n✅ HKDF integration with mls_zig successful!\n", .{});
}