const std = @import("std");
const nostr = @import("nostr");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const hex = "000100010020aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00ce0020bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0020cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc0100403031323334353637383961626364656630313233343536373839616263646566303132333435363738396162636465663031323334353637383961626364656600000100000040dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd00000040eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    
    const decoded = try allocator.alloc(u8, hex.len / 2);
    defer allocator.free(decoded);
    _ = try std.fmt.hexToBytes(decoded, hex);
    
    std.debug.print("Parsing {} bytes...\n", .{decoded.len});
    
    const keypackage = nostr.mls.key_packages.parseKeyPackage(allocator, decoded) catch |err| {
        std.debug.print("Parse error: {}\n", .{err});
        return;
    };
    
    std.debug.print("✅ Successfully parsed KeyPackage!\n", .{});
    std.debug.print("  Version: {}\n", .{keypackage.version});
    std.debug.print("  Cipher suite: {}\n", .{keypackage.cipher_suite});
    std.debug.print("  Init key length: {}\n", .{keypackage.init_key.data.len});
}