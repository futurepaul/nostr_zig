const std = @import("std");
const builtin = @import("builtin");

// External timestamp function for WASM
extern fn getCurrentTimestamp() u64;

/// Get current timestamp in seconds, works for both native and WASM builds
pub fn timestamp() i64 {
    if (builtin.target.cpu.arch == .wasm32) {
        return @intCast(getCurrentTimestamp());
    } else {
        return std.time.timestamp();
    }
}