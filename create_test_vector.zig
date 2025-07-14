const std = @import("std");

// This creates a minimal but valid MLS KeyPackage test vector
pub fn main() !void {
    var buffer: [1024]u8 = undefined;
    var pos: usize = 0;
    
    // Version: 0x0001 (draft)
    std.mem.writeInt(u16, buffer[pos..][0..2], 0x0001, .big);
    pos += 2;
    
    // Cipher suite: 0x0001
    std.mem.writeInt(u16, buffer[pos..][0..2], 0x0001, .big);
    pos += 2;
    
    // Init key length: 32 bytes
    std.mem.writeInt(u16, buffer[pos..][0..2], 32, .big);
    pos += 2;
    
    // Init key data (32 bytes of 0xAA)
    @memset(buffer[pos..pos+32], 0xAA);
    pos += 32;
    
    // Leaf node length: minimal leaf node
    // We'll create a minimal leaf node
    var leaf_node_buf: [512]u8 = undefined;
    var leaf_pos: usize = 0;
    
    // Encryption key length: 32
    std.mem.writeInt(u16, leaf_node_buf[leaf_pos..][0..2], 32, .big);
    leaf_pos += 2;
    @memset(leaf_node_buf[leaf_pos..leaf_pos+32], 0xBB);
    leaf_pos += 32;
    
    // Signature key length: 32
    std.mem.writeInt(u16, leaf_node_buf[leaf_pos..][0..2], 32, .big);
    leaf_pos += 2;
    @memset(leaf_node_buf[leaf_pos..leaf_pos+32], 0xCC);
    leaf_pos += 32;
    
    // Credential type: 1 (basic)
    leaf_node_buf[leaf_pos] = 1;
    leaf_pos += 1;
    
    // Identity length: 64 (hex pubkey)
    std.mem.writeInt(u16, leaf_node_buf[leaf_pos..][0..2], 64, .big);
    leaf_pos += 2;
    
    // Identity: hex string
    const identity = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    @memcpy(leaf_node_buf[leaf_pos..leaf_pos+64], identity);
    leaf_pos += 64;
    
    // Capabilities length: 0
    std.mem.writeInt(u16, leaf_node_buf[leaf_pos..][0..2], 0, .big);
    leaf_pos += 2;
    
    // Leaf node source: 1 (key_package)
    leaf_node_buf[leaf_pos] = 1;
    leaf_pos += 1;
    
    // Extensions count: 0
    std.mem.writeInt(u16, leaf_node_buf[leaf_pos..][0..2], 0, .big);
    leaf_pos += 2;
    
    // Signature length: 64
    std.mem.writeInt(u16, leaf_node_buf[leaf_pos..][0..2], 64, .big);
    leaf_pos += 2;
    @memset(leaf_node_buf[leaf_pos..leaf_pos+64], 0xDD);
    leaf_pos += 64;
    
    // Now write leaf node to main buffer
    std.mem.writeInt(u16, buffer[pos..][0..2], @intCast(leaf_pos), .big);
    pos += 2;
    @memcpy(buffer[pos..pos+leaf_pos], leaf_node_buf[0..leaf_pos]);
    pos += leaf_pos;
    
    // Extensions length: 0
    std.mem.writeInt(u16, buffer[pos..][0..2], 0, .big);
    pos += 2;
    
    // Signature length: 64
    std.mem.writeInt(u16, buffer[pos..][0..2], 64, .big);
    pos += 2;
    @memset(buffer[pos..pos+64], 0xEE);
    pos += 64;
    
    // Print as hex
    std.debug.print("{s}\n", .{std.fmt.fmtSliceHexLower(buffer[0..pos])});
    std.debug.print("Total length: {} bytes\n", .{pos});
}