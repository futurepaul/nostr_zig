const std = @import("std");

pub fn main() !void {
    // Create a buffer with 0x20 (32) followed by 32 bytes of data
    var data: [33]u8 = undefined;
    data[0] = 0x20; // Length prefix
    @memset(data[1..], 0xAA); // Fill with test data
    
    std.debug.print("Data array: len={}, first byte=0x{x:0>2}\n", .{data.len, data[0]});
    
    // If we accidentally include the length prefix in our key data
    const init_key_with_prefix = data[0..]; // This would be 33 bytes
    std.debug.print("Init key with prefix: len={}\n", .{init_key_with_prefix.len});
    
    // The correct way would be to skip the length prefix
    const init_key_correct = data[1..]; // This would be 32 bytes
    std.debug.print("Init key correct: len={}\n", .{init_key_correct.len});
    
    // Simulate TLS reading
    var stream = std.io.fixedBufferStream(&data);
    var reader = stream.reader();
    
    // Read length prefix
    const len = try reader.readInt(u8, .big);
    std.debug.print("Read length prefix: {}\n", .{len});
    
    // Read the actual key data
    var key_data: [32]u8 = undefined;
    _ = try reader.read(&key_data);
    std.debug.print("Read key data: len={}\n", .{key_data.len});
}