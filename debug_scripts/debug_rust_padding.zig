const std = @import("std");

/// Exact Rust implementation from the reference
pub fn calcPaddingRust(len: usize) usize {
    if (len < 32) {
        return 32;
    }
    
    // let nextpower = 1 << ((len - 1).ilog2() + 1);
    const nextpower = @as(usize, 1) << (@as(u6, @intCast(log2RoundDown(len - 1) + 1)));
    
    // let chunk = if nextpower <= 256 { 32 } else { nextpower / 8 };
    const chunk = if (nextpower <= 256) 32 else nextpower / 8;
    
    // if len <= 32 { 32 } else { chunk * (((len - 1) / chunk) + 1) }
    if (len <= 32) {
        return 32;
    } else {
        return chunk * (((len - 1) / chunk) + 1);
    }
}

/// Returns the base 2 logarithm of the number, rounded down.
fn log2RoundDown(x: usize) u32 {
    if (x == 0) {
        return 0;
    }
    return (@bitSizeOf(usize) - 1) - @clz(x);
}

pub fn main() !void {
    std.debug.print("🔍 Testing Rust reference padding algorithm\n", .{});
    
    // Test cases from old internal test to check what Rust produces
    const test_cases = [_]struct { len: usize, expected: usize }{
        .{ .len = 0, .expected = 32 },  // For debugging
        .{ .len = 1, .expected = 32 },
        .{ .len = 16, .expected = 32 },
        .{ .len = 32, .expected = 32 },
        .{ .len = 33, .expected = 64 },
        .{ .len = 64, .expected = 64 },
        .{ .len = 65, .expected = 0 },  // Let's see what it produces
        .{ .len = 100, .expected = 0 },
        .{ .len = 128, .expected = 0 },
        .{ .len = 129, .expected = 0 },
        .{ .len = 192, .expected = 0 },
        .{ .len = 193, .expected = 0 },
        .{ .len = 320, .expected = 0 },
        .{ .len = 384, .expected = 0 },
        .{ .len = 400, .expected = 0 },
        .{ .len = 500, .expected = 0 },
        .{ .len = 512, .expected = 0 },
        .{ .len = 1000, .expected = 0 },
        .{ .len = 1024, .expected = 0 },
        .{ .len = 65515, .expected = 0 },
    };
    
    for (test_cases) |case| {
        const result = calcPaddingRust(case.len);
        
        std.debug.print("  {} -> {}\n", .{case.len, result});
        
        if (case.expected != 0 and result != case.expected) {
            // Debug the case
            std.debug.print("    Debug for len={}:\n", .{case.len});
            
            const nextpower = @as(usize, 1) << (@as(u6, @intCast(log2RoundDown(case.len - 1) + 1)));
            std.debug.print("      nextpower = {}\n", .{nextpower});
            
            const chunk = if (nextpower <= 256) 32 else nextpower / 8;
            std.debug.print("      chunk = {} (nextpower {} <= 256? {})\n", .{chunk, nextpower, nextpower <= 256});
            
            if (case.len <= 32) {
                std.debug.print("      return 32 (len <= 32)\n", .{});
            } else {
                const calc = chunk * (((case.len - 1) / chunk) + 1);
                std.debug.print("      calc = {} * (({} - 1) / {} + 1) = {} * ({} + 1) = {} * {} = {}\n", .{
                    chunk, case.len, chunk, chunk, (case.len - 1) / chunk, chunk, ((case.len - 1) / chunk) + 1, calc
                });
            }
        }
    }
}