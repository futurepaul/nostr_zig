const std = @import("std");
const mls_zig = @import("mls_zig");

pub fn main() !void {
    std.debug.print("Available mls_zig modules:\n", .{});
    
    // Check what's available in mls_zig
    if (@hasDecl(mls_zig, "cipher_suite")) {
        std.debug.print("✓ cipher_suite\n", .{});
    }
    if (@hasDecl(mls_zig, "hpke")) {
        std.debug.print("✓ hpke\n", .{});
    }
    if (@hasDecl(mls_zig, "credential")) {
        std.debug.print("✓ credential\n", .{});
    }
    if (@hasDecl(mls_zig, "key_package")) {
        std.debug.print("✓ key_package\n", .{});
    }
    if (@hasDecl(mls_zig, "welcome")) {
        std.debug.print("✓ welcome\n", .{});
    }
    if (@hasDecl(mls_zig, "group")) {
        std.debug.print("✓ group\n", .{});
    }
    if (@hasDecl(mls_zig, "messages")) {
        std.debug.print("✓ messages\n", .{});
    }
    if (@hasDecl(mls_zig, "wire_format")) {
        std.debug.print("✓ wire_format\n", .{});
    }
    if (@hasDecl(mls_zig, "serialization")) {
        std.debug.print("✓ serialization\n", .{});
    }
}