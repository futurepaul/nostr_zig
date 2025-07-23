const std = @import("std");

pub fn main() \!void {
    var list = std.ArrayList(u8).init(std.heap.page_allocator);
    defer list.deinit();
    
    // Test writing to ArrayList
    const writer = list.writer();
    
    // ArrayList writer only has write(), not writeAll()
    const bytes_to_write = "Hello";
    const n = try writer.write(bytes_to_write);
    std.debug.print("Wrote {} bytes\n", .{n});
    std.debug.print("List contents: {s}\n", .{list.items});
}
