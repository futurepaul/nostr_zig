const std = @import("std");

pub fn main() !void {
    std.debug.print("Checking NIP-44 test implementation...\n\n", .{});
    
    // Run the test and capture output
    const result = try std.process.Child.run(.{
        .allocator = std.heap.page_allocator,
        .argv = &.{ "zig", "test", "src/nip44/test_vectors.zig", "--test-filter", "run nip44 test vectors" },
    });
    defer std.heap.page_allocator.free(result.stdout);
    defer std.heap.page_allocator.free(result.stderr);
    
    std.debug.print("STDOUT:\n{s}\n", .{result.stdout});
    std.debug.print("STDERR:\n{s}\n", .{result.stderr});
    
    // Count how many tests are actually run
    var test_count: u32 = 0;
    var skip_count: u32 = 0;
    
    var lines = std.mem.tokenizeAny(u8, result.stdout, "\n");
    while (lines.next()) |line| {
        if (std.mem.indexOf(u8, line, "✅") != null) {
            test_count += 1;
        } else if (std.mem.indexOf(u8, line, "Skipping") != null or 
                   std.mem.indexOf(u8, line, "⏭️") != null) {
            skip_count += 1;
        }
    }
    
    std.debug.print("\n📊 Test Summary:\n", .{});
    std.debug.print("  Tests passed: {}\n", .{test_count});
    std.debug.print("  Tests skipped: {}\n", .{skip_count});
}