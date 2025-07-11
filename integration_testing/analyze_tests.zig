const std = @import("std");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    std.debug.print("📊 NIP-44 Test Coverage Analysis\n", .{});
    std.debug.print("================================\n\n", .{});
    
    // Read test vectors
    const file = try std.fs.cwd().openFile("src/nip44/nip44.vectors.json", .{});
    defer file.close();
    
    const content = try file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(content);
    
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, content, .{});
    defer parsed.deinit();
    
    const v2 = parsed.value.object.get("v2").?;
    
    // Count test cases
    var total_tests: u32 = 0;
    var categories = std.StringHashMap(u32).init(allocator);
    defer categories.deinit();
    
    // Valid tests
    if (v2.object.get("valid")) |valid| {
        std.debug.print("Valid Tests:\n", .{});
        
        var iter = valid.object.iterator();
        while (iter.next()) |entry| {
            const count = switch (entry.value_ptr.*) {
                .array => |arr| arr.items.len,
                .object => |obj| blk: {
                    // Special handling for tests with nested structure
                    if (obj.get("keys")) |keys| {
                        break :blk keys.array.items.len;
                    }
                    break :blk 1;
                },
                else => 1,
            };
            
            std.debug.print("  - {s}: {} tests\n", .{ entry.key_ptr.*, count });
            try categories.put(entry.key_ptr.*, @intCast(count));
            total_tests += @intCast(count);
        }
    }
    
    std.debug.print("\n", .{});
    
    // Invalid tests
    if (v2.object.get("invalid")) |invalid| {
        std.debug.print("Invalid Tests:\n", .{});
        
        var iter = invalid.object.iterator();
        while (iter.next()) |entry| {
            const count = switch (entry.value_ptr.*) {
                .array => |arr| arr.items.len,
                else => 1,
            };
            
            std.debug.print("  - {s}: {} tests\n", .{ entry.key_ptr.*, count });
            try categories.put(entry.key_ptr.*, @intCast(count));
            total_tests += @intCast(count);
        }
    }
    
    std.debug.print("\n📈 Total test cases in vectors: {}\n", .{total_tests});
    
    // Now check what our implementation actually tests
    std.debug.print("\n🔍 Checking implementation coverage...\n", .{});
    
    // Look for skip patterns in test file
    const test_file = try std.fs.cwd().openFile("src/nip44/test_vectors.zig", .{});
    defer test_file.close();
    
    const test_content = try test_file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(test_content);
    
    var skipped = std.ArrayList([]const u8).init(allocator);
    defer skipped.deinit();
    
    // Find skipped tests
    if (std.mem.indexOf(u8, test_content, "Skipping long message tests") != null) {
        try skipped.append("encrypt_decrypt_long_msg");
    }
    
    if (std.mem.indexOf(u8, test_content, "Skipping invalid decrypt test") != null) {
        try skipped.append("invalid decrypt tests");
    }
    
    std.debug.print("\n⚠️  Currently skipped:\n", .{});
    for (skipped.items) |skip| {
        std.debug.print("  - {s}\n", .{skip});
    }
    
    // Calculate coverage
    const long_msg_count = categories.get("encrypt_decrypt_long_msg") orelse 0;
    const invalid_decrypt_count = categories.get("decrypt") orelse 0;
    const skipped_count = long_msg_count + invalid_decrypt_count;
    const tested_count = total_tests - skipped_count;
    
    const coverage = @as(f32, @floatFromInt(tested_count)) / @as(f32, @floatFromInt(total_tests)) * 100.0;
    
    std.debug.print("\n📊 Coverage Summary:\n", .{});
    std.debug.print("  Total tests: {}\n", .{total_tests});
    std.debug.print("  Tests run: {}\n", .{tested_count});
    std.debug.print("  Tests skipped: {}\n", .{skipped_count});
    std.debug.print("  Coverage: {d:.1}%\n", .{coverage});
}