const std = @import("std");

pub fn main() void {
    var list = std.ArrayList(u8).init(std.heap.page_allocator);
    defer list.deinit();
    
    const Writer = std.ArrayList(u8).Writer;
    std.debug.print("Writer type: {s}\n", .{@typeName(Writer)});
}
