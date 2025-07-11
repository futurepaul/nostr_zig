const std = @import("std");

pub fn main() !void {
    std.debug.print("🧪 Running NIP-44 Test Vectors\n", .{});
    std.debug.print("==============================\n\n", .{});
    
    // Create a child process to run the test
    var child = std.process.Child.init(
        &.{ "zig", "test", "src/nip44/test_vectors.zig", "--test-filter", "run nip44 test vectors" },
        std.heap.page_allocator,
    );
    
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    
    try child.spawn();
    
    // Read output
    const stdout = try child.stdout.?.reader().readAllAlloc(std.heap.page_allocator, 1024 * 1024);
    defer std.heap.page_allocator.free(stdout);
    
    const stderr = try child.stderr.?.reader().readAllAlloc(std.heap.page_allocator, 1024 * 1024);
    defer std.heap.page_allocator.free(stderr);
    
    const result = try child.wait();
    
    // Print output
    std.debug.print("{s}", .{stdout});
    if (stderr.len > 0) {
        std.debug.print("\nErrors:\n{s}", .{stderr});
    }
    
    // Analyze results
    var passed: u32 = 0;
    var failed: u32 = 0;
    var skipped: u32 = 0;
    
    var lines = std.mem.tokenizeAny(u8, stdout, "\n");
    while (lines.next()) |line| {
        if (std.mem.indexOf(u8, line, "✅") != null and std.mem.indexOf(u8, line, "passed") != null) {
            // Count individual test passes
            if (std.mem.indexOf(u8, line, "test") != null) {
                passed += 1;
            }
        } else if (std.mem.indexOf(u8, line, "❌") != null and std.mem.indexOf(u8, line, "FAILED") != null) {
            failed += 1;
        } else if (std.mem.indexOf(u8, line, "Skipping") != null or std.mem.indexOf(u8, line, "⏭️") != null) {
            // Count skipped tests more carefully
            if (std.mem.indexOf(u8, line, "long message tests") != null) {
                skipped += 3; // From our analysis
            } else if (std.mem.indexOf(u8, line, "invalid decrypt test") != null) {
                skipped += 1;
            }
        }
    }
    
    std.debug.print("\n\n📊 Summary:\n", .{});
    std.debug.print("  Exit code: {}\n", .{result.Exited});
    std.debug.print("  Tests passed: {} (estimated)\n", .{passed});
    std.debug.print("  Tests failed: {}\n", .{failed});
    std.debug.print("  Tests skipped: {} (estimated)\n", .{skipped});
    
    if (result.Exited == 0) {
        std.debug.print("\n✅ NIP-44 test suite passed!\n", .{});
    } else {
        std.debug.print("\n❌ NIP-44 test suite failed!\n", .{});
        std.process.exit(1);
    }
}