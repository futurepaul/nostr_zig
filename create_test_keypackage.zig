const std = @import("std");
const nostr = @import("nostr");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Generate a test private key
    var prng = std.Random.DefaultPrng.init(@intCast(std.time.milliTimestamp()));
    const random = prng.random();
    
    var nostr_private_key: [32]u8 = undefined;
    random.bytes(&nostr_private_key);
    
    // Initialize MLS provider
    var provider = nostr.mls.provider.MlsProvider.init(allocator);
    
    // Generate KeyPackage
    const keypackage = try nostr.mls.key_packages.generateKeyPackage(
        allocator,
        &provider,
        nostr_private_key,
        .{},
    );
    
    // Serialize as hex
    const binary = try nostr.mls.key_packages.serializeKeyPackage(allocator, keypackage);
    defer allocator.free(binary);
    
    const hex = try allocator.alloc(u8, binary.len * 2);
    _ = try std.fmt.bufPrint(hex, "{s}", .{std.fmt.fmtSliceHexLower(binary)});
    
    std.debug.print("{s}\n", .{hex});
}