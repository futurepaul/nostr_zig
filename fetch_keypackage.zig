const std = @import("std");
const websocket = @import("websocket");
const nostr = @import("nostr");

const KeyPackageVector = struct {
    event_id: []const u8,
    pubkey: []const u8,
    created_at: i64,
    content: []const u8,
    tags: [][]const []const u8,
    
    pub fn deinit(self: @This(), allocator: std.mem.Allocator) void {
        allocator.free(self.event_id);
        allocator.free(self.pubkey);
        allocator.free(self.content);
        for (self.tags) |tag| {
            for (tag) |elem| {
                allocator.free(elem);
            }
            allocator.free(tag);
        }
        allocator.free(self.tags);
    }
};

fn dupeTags(allocator: std.mem.Allocator, tags: [][]const []const u8) ![][]const []const u8 {
    var new_tags = try allocator.alloc([]const []const u8, tags.len);
    errdefer {
        for (new_tags[0..]) |tag| {
            for (tag) |elem| {
                allocator.free(elem);
            }
            allocator.free(tag);
        }
        allocator.free(new_tags);
    }
    
    for (tags, 0..) |tag, i| {
        var new_tag = try allocator.alloc([]const u8, tag.len);
        errdefer {
            for (new_tag[0..]) |elem| {
                allocator.free(elem);
            }
            allocator.free(new_tag);
        }
        
        for (tag, 0..) |elem, j| {
            new_tag[j] = try allocator.dupe(u8, elem);
        }
        new_tags[i] = new_tag;
    }
    
    return new_tags;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const relay_url = "ws://localhost:10547";
    
    // Array of approved keypackage event IDs to fetch
    const approved_keypackages = [_][]const u8{
        "14618eb63a3cc986e67d81ec8e99c89650bec1ddd5749d6e055e86708b4ceb7e",
        "23944657405b2c9218a901ffc19018abc6061d393f249f16523c29fb14c99246",
    };

    std.log.info("Connecting to relay: {s}", .{relay_url});

    // Parse URL
    const uri = try std.Uri.parse(relay_url);
    const host = switch (uri.host.?) {
        .raw => |h| h,
        .percent_encoded => |h| h,
    };
    const port: u16 = uri.port orelse 80;
    const path = switch (uri.path) {
        .raw => |p| if (p.len == 0) "/" else p,
        .percent_encoded => |p| if (p.len == 0) "/" else p,
    };

    // Create websocket client
    var ws_client = try websocket.Client.init(allocator, .{
        .host = host,
        .port = port,
        .tls = false,
    });
    defer ws_client.deinit();

    // Perform websocket handshake
    var headers_buf: [256]u8 = undefined;
    const headers = try std.fmt.bufPrint(&headers_buf, "Host: {s}:{}\r\n", .{ host, port });
    try ws_client.handshake(path, .{ .headers = headers });

    std.log.info("Connected to relay successfully", .{});

    // Create subscription ID
    const sub_id = "fetch_keypackage";
    
    // Create REQ message to fetch the specific events
    var req_buf = std.ArrayList(u8).init(allocator);
    defer req_buf.deinit();
    
    var writer = req_buf.writer();
    try writer.writeAll("[\"REQ\",\"");
    try writer.writeAll(sub_id);
    try writer.writeAll("\",{\"ids\":[");
    
    // Add all approved keypackage IDs
    for (approved_keypackages, 0..) |kp_id, i| {
        if (i > 0) try writer.writeAll(",");
        try writer.print("\"{s}\"", .{kp_id});
    }
    
    try writer.writeAll("]},{\"kinds\":[443]}]");
    
    std.log.info("Sending REQ: {s}", .{req_buf.items});
    try ws_client.writeText(req_buf.items);

    // Storage for collected keypackages
    var keypackages = std.ArrayList(KeyPackageVector).init(allocator);
    defer {
        for (keypackages.items) |kp| {
            kp.deinit(allocator);
        }
        keypackages.deinit();
    }

    // Read responses
    var msg_count: usize = 0;
    while (true) {
        const msg = try ws_client.read() orelse {
            // No message available, wait a bit
            std.time.sleep(10 * std.time.ns_per_ms);
            continue;
        };
        defer ws_client.done(msg);

        msg_count += 1;
        std.log.info("Received message #{}: {s}", .{ msg_count, msg.data });

        // Parse the message
        const parsed = std.json.parseFromSlice(std.json.Value, allocator, msg.data, .{}) catch |err| {
            std.log.err("Failed to parse JSON: {}", .{err});
            continue;
        };
        defer parsed.deinit();

        const root = parsed.value;
        if (root != .array) {
            std.log.warn("Message is not an array", .{});
            continue;
        }

        const arr = root.array;
        if (arr.items.len < 2) {
            std.log.warn("Message array too short", .{});
            continue;
        }

        const msg_type = arr.items[0];
        if (msg_type != .string) {
            std.log.warn("Message type is not a string", .{});
            continue;
        }

        const type_str = msg_type.string;
        
        if (std.mem.eql(u8, type_str, "EVENT")) {
            std.log.info("Got EVENT message!", .{});
            
            if (arr.items.len < 3) {
                std.log.warn("EVENT message missing event data", .{});
                continue;
            }

            const event_data = arr.items[2];
            if (event_data != .object) {
                std.log.warn("Event data is not an object", .{});
                continue;
            }

            // Parse the event
            const event = try parseEvent(allocator, event_data);
            
            // Store the keypackage
            const kp_vector = KeyPackageVector{
                .event_id = try allocator.dupe(u8, event.id),
                .pubkey = try allocator.dupe(u8, event.pubkey),
                .created_at = event.created_at,
                .content = try allocator.dupe(u8, event.content),
                .tags = try dupeTags(allocator, event.tags),
            };
            try keypackages.append(kp_vector);
            
            event.deinit(allocator);

            std.log.info("Event details:", .{});
            std.log.info("  ID: {s}", .{kp_vector.event_id});
            std.log.info("  Public Key: {s}", .{kp_vector.pubkey});
            std.log.info("  Created At: {}", .{kp_vector.created_at});
            std.log.info("  Kind: {}", .{event.kind});
            std.log.info("  Content length: {} bytes", .{kp_vector.content.len});
            std.log.info("  Tags: {} tags", .{kp_vector.tags.len});
            
            for (kp_vector.tags, 0..) |tag, i| {
                std.log.info("  Tag[{}]: {} elements", .{ i, tag.len });
                for (tag, 0..) |elem, j| {
                    std.log.info("    [{}][{}]: {s}", .{ i, j, elem });
                }
            }

            // Log raw content (first 200 chars)
            const preview_len = @min(kp_vector.content.len, 200);
            std.log.info("  Content preview: {s}...", .{kp_vector.content[0..preview_len]});

            // Try to decode the content as hex
            const decoded = try allocator.alloc(u8, kp_vector.content.len / 2);
            defer allocator.free(decoded);
            
            _ = try std.fmt.hexToBytes(decoded, kp_vector.content);
            std.log.info("  Decoded content size: {} bytes", .{decoded.len});
            
            // Log hex dump of first 64 bytes
            const hex_preview_len = @min(decoded.len, 64);
            std.log.info("  Decoded content hex preview ({} bytes):", .{hex_preview_len});
            for (0..hex_preview_len) |i| {
                if (i % 16 == 0) {
                    std.debug.print("\n    {x:0>4}: ", .{i});
                }
                std.debug.print("{x:0>2} ", .{decoded[i]});
            }
            std.debug.print("\n", .{});

            // Parse MLS keypackage structure
            if (decoded.len > 4) {
                const version = std.mem.readInt(u16, decoded[0..2], .big);
                const cipher_suite = std.mem.readInt(u16, decoded[2..4], .big);
                std.log.info("  MLS version: 0x{x:0>4}", .{version});
                std.log.info("  Cipher suite: 0x{x:0>4}", .{cipher_suite});
                
                // Parse HPKE init key (starts at offset 4)
                // The first byte is the length prefix (TLS-style variable length encoding)
                if (decoded.len > 5) {
                    const init_key_len = decoded[4];
                    std.log.info("  HPKE init key length: {} bytes", .{init_key_len});
                    
                    if (decoded.len >= 5 + init_key_len) {
                        const init_key = decoded[5..5 + init_key_len];
                        std.log.info("  HPKE init key (first 32 bytes):", .{});
                        const key_preview = @min(init_key.len, 32);
                        for (0..key_preview) |i| {
                            if (i % 16 == 0) {
                                std.debug.print("\n      ", .{});
                            }
                            std.debug.print("{x:0>2} ", .{init_key[i]});
                        }
                        std.debug.print("\n", .{});
                        
                        // Parse credential after init key
                        var offset = 5 + init_key_len;
                        if (decoded.len > offset + 2) {
                            const cred_type = decoded[offset];
                            std.log.info("  Credential type: 0x{x:0>2}", .{cred_type});
                            
                            if (cred_type == 1) { // Basic credential
                                offset += 1;
                                if (decoded.len > offset + 2) {
                                    const identity_len = std.mem.readInt(u16, decoded[offset..][0..2], .big);
                                    std.log.info("  Identity length: {} bytes", .{identity_len});
                                    offset += 2;
                                    
                                    if (decoded.len >= offset + identity_len) {
                                        const identity = decoded[offset..offset + identity_len];
                                        if (identity_len == 64) {
                                            // Try to parse as ASCII hex
                                            std.log.info("  Identity (hex): {s}", .{identity});
                                        } else {
                                            std.log.info("  Identity (raw bytes):", .{});
                                            for (0..@min(identity.len, 32)) |i| {
                                                if (i % 16 == 0) {
                                                    std.debug.print("\n      ", .{});
                                                }
                                                std.debug.print("{x:0>2} ", .{identity[i]});
                                            }
                                            std.debug.print("\n", .{});
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

        } else if (std.mem.eql(u8, type_str, "EOSE")) {
            std.log.info("End of stored events", .{});
            break;
        } else if (std.mem.eql(u8, type_str, "OK")) {
            std.log.info("Got OK response", .{});
        } else if (std.mem.eql(u8, type_str, "NOTICE")) {
            if (arr.items.len >= 2 and arr.items[1] == .string) {
                std.log.info("NOTICE: {s}", .{arr.items[1].string});
            }
        }
    }

    // Close subscription
    const close_msg = try std.fmt.allocPrint(allocator, "[\"CLOSE\",\"{s}\"]", .{sub_id});
    defer allocator.free(close_msg);
    try ws_client.writeText(close_msg);

    // Save keypackages to JSONL file
    if (keypackages.items.len > 0) {
        const file = try std.fs.cwd().createFile("keypackage_vectors.jsonl", .{});
        defer file.close();
        
        var buffered_writer = std.io.bufferedWriter(file.writer());
        const file_writer = buffered_writer.writer();
        
        for (keypackages.items) |kp| {
            // Write as JSON object on a single line
            try file_writer.writeAll("{");
            try file_writer.print("\"event_id\":\"{s}\",", .{kp.event_id});
            try file_writer.print("\"pubkey\":\"{s}\",", .{kp.pubkey});
            try file_writer.print("\"created_at\":{},", .{kp.created_at});
            try file_writer.print("\"content\":\"{s}\",", .{kp.content});
            try file_writer.writeAll("\"tags\":[");
            
            for (kp.tags, 0..) |tag, i| {
                if (i > 0) try file_writer.writeAll(",");
                try file_writer.writeAll("[");
                for (tag, 0..) |elem, j| {
                    if (j > 0) try file_writer.writeAll(",");
                    try file_writer.print("\"{s}\"", .{elem});
                }
                try file_writer.writeAll("]");
            }
            
            try file_writer.writeAll("]}\n");
        }
        
        try buffered_writer.flush();
        std.log.info("Saved {} keypackages to keypackage_vectors.jsonl", .{keypackages.items.len});
    }

    std.log.info("Fetch complete", .{});
}

const Event = struct {
    id: []const u8,
    pubkey: []const u8,
    created_at: i64,
    kind: u16,
    tags: [][]const []const u8,
    content: []const u8,
    sig: []const u8,

    pub fn deinit(self: @This(), allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.pubkey);
        for (self.tags) |tag| {
            for (tag) |elem| {
                allocator.free(elem);
            }
            allocator.free(tag);
        }
        allocator.free(self.tags);
        allocator.free(self.content);
        allocator.free(self.sig);
    }
};

fn parseEvent(allocator: std.mem.Allocator, obj: std.json.Value) !Event {
    const id = try allocator.dupe(u8, obj.object.get("id").?.string);
    errdefer allocator.free(id);
    
    const pubkey = try allocator.dupe(u8, obj.object.get("pubkey").?.string);
    errdefer allocator.free(pubkey);
    
    const created_at = obj.object.get("created_at").?.integer;
    const kind = @as(u16, @intCast(obj.object.get("kind").?.integer));
    
    const content = try allocator.dupe(u8, obj.object.get("content").?.string);
    errdefer allocator.free(content);
    
    const sig = try allocator.dupe(u8, obj.object.get("sig").?.string);
    errdefer allocator.free(sig);

    // Parse tags
    const tags_val = obj.object.get("tags").?.array;
    var tags = try allocator.alloc([]const []const u8, tags_val.items.len);
    errdefer {
        for (tags[0..]) |tag| {
            for (tag) |elem| {
                allocator.free(elem);
            }
            allocator.free(tag);
        }
        allocator.free(tags);
    }

    for (tags_val.items, 0..) |tag_val, i| {
        const tag_arr = tag_val.array;
        var tag = try allocator.alloc([]const u8, tag_arr.items.len);
        errdefer {
            for (tag[0..]) |elem| {
                allocator.free(elem);
            }
            allocator.free(tag);
        }

        for (tag_arr.items, 0..) |elem_val, j| {
            tag[j] = try allocator.dupe(u8, elem_val.string);
        }
        tags[i] = tag;
    }

    return Event{
        .id = id,
        .pubkey = pubkey,
        .created_at = created_at,
        .kind = kind,
        .tags = tags,
        .content = content,
        .sig = sig,
    };
}