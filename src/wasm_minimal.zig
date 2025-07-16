const std = @import("std");

// Use a simple fixed buffer allocator for WASM
var buffer: [1024 * 1024]u8 = undefined; // 1MB buffer
var fba: ?std.heap.FixedBufferAllocator = null;

fn getAllocator() std.mem.Allocator {
    if (fba == null) {
        fba = std.heap.FixedBufferAllocator.init(&buffer);
    }
    return fba.?.allocator();
}

export fn wasm_init() void {
    // Empty init
}

export fn wasm_add(a: i32, b: i32) i32 {
    return a + b;
}

export fn wasm_alloc(size: usize) ?[*]u8 {
    const mem = getAllocator().alloc(u8, size) catch return null;
    return mem.ptr;
}

export fn wasm_free(ptr: [*]u8, size: usize) void {
    getAllocator().free(ptr[0..size]);
}