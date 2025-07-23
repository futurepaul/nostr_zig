const std = @import("std");

/// This imports the separate module containing `root.zig`. Take a look in `build.zig` for details.
const lib = @import("nostr_zig_lib");

const Command = enum {
    event,
    help,
    parse,
};

const CliArgs = struct {
    command: Command = .help,
    secret_key: ?[]const u8 = null,
    content: ?[]const u8 = null,
    tags: std.ArrayList([][]const u8),
    relays: std.ArrayList([]const u8),
    kind: u32 = 1,
    
    pub fn init(allocator: std.mem.Allocator) CliArgs {
        return CliArgs{
            .tags = std.ArrayList([][]const u8).init(allocator),
            .relays = std.ArrayList([]const u8).init(allocator),
        };
    }
    
    pub fn deinit(self: *CliArgs) void {
        self.tags.deinit();
        self.relays.deinit();
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();

    // Parse command line arguments
    var args = CliArgs.init(allocator);
    defer args.deinit();
    
    try parseArgs(allocator, &args);
    
    switch (args.command) {
        .event => try handleEventCommand(allocator, &args, stdout),
        .parse => try handleParseCommand(allocator, stdout),
        .help => try printHelp(stdout),
    }

    try bw.flush();
}

fn parseArgs(allocator: std.mem.Allocator, args: *CliArgs) !void {
    var arg_iter = try std.process.argsWithAllocator(allocator);
    defer arg_iter.deinit();
    
    // Skip program name
    _ = arg_iter.skip();
    
    var expecting_value: ?[]const u8 = null;
    
    while (arg_iter.next()) |arg| {
        if (expecting_value) |flag| {
            if (std.mem.eql(u8, flag, "sec")) {
                args.secret_key = arg;
            } else if (std.mem.eql(u8, flag, "c")) {
                args.content = arg;
            } else if (std.mem.eql(u8, flag, "tag")) {
                // Parse tag in format "key=value" or just "key"
                const tag_parts = try parseTag(allocator, arg);
                try args.tags.append(tag_parts);
            } else if (std.mem.eql(u8, flag, "k")) {
                args.kind = try std.fmt.parseInt(u32, arg, 10);
            }
            expecting_value = null;
        } else if (std.mem.startsWith(u8, arg, "--")) {
            const flag = arg[2..];
            if (std.mem.eql(u8, flag, "sec")) {
                expecting_value = "sec";
            } else if (std.mem.eql(u8, flag, "tag")) {
                expecting_value = "tag";
            }
        } else if (std.mem.startsWith(u8, arg, "-")) {
            const flag = arg[1..];
            if (std.mem.eql(u8, flag, "c")) {
                expecting_value = "c";
            } else if (std.mem.eql(u8, flag, "k")) {
                expecting_value = "k";
            }
        } else {
            // Commands or relay URLs
            if (args.command == .help) {
                if (std.mem.eql(u8, arg, "event")) {
                    args.command = .event;
                } else if (std.mem.eql(u8, arg, "parse")) {
                    args.command = .parse;
                }
            } else {
                // Assume it's a relay URL
                try args.relays.append(arg);
            }
        }
    }
}

fn parseTag(allocator: std.mem.Allocator, tag_str: []const u8) ![][]const u8 {
    var parts = std.ArrayList([]const u8).init(allocator);
    defer parts.deinit();
    
    if (std.mem.indexOf(u8, tag_str, "=")) |eq_pos| {
        try parts.append(tag_str[0..eq_pos]);
        try parts.append(tag_str[eq_pos + 1..]);
    } else {
        try parts.append(tag_str);
    }
    
    return try parts.toOwnedSlice();
}

fn handleEventCommand(allocator: std.mem.Allocator, args: *CliArgs, writer: anytype) !void {
    // Set default values
    const content = args.content orelse "hello from nostr-zig";
    
    // Generate or parse secret key
    var secret_key: [32]u8 = undefined;
    
    // Check for secret key in this priority order:
    // 1. Command line --sec flag
    // 2. NOSTR_SECRET_KEY environment variable
    // 3. Generate random key
    var env_key: ?[]u8 = null;
    const key_str = args.secret_key orelse blk: {
        env_key = std.process.getEnvVarOwned(allocator, "NOSTR_SECRET_KEY") catch null;
        break :blk env_key;
    };
    defer if (env_key) |k| allocator.free(k);
    
    if (key_str) |key| {
        if (key.len == 2 and std.mem.eql(u8, key, "01")) {
            // Default test key like nak
            secret_key = [_]u8{1} ++ [_]u8{0} ** 31;
        } else if (std.mem.startsWith(u8, key, "nsec1")) {
            // NIP-19 bech32 encoded secret key
            secret_key = try lib.bech32.decodeNsec1(allocator, key);
        } else {
            // Parse hex key
            if (key.len != 64) return error.InvalidKeyLength;
            _ = try std.fmt.hexToBytes(&secret_key, key);
        }
    } else {
        // Generate random key
        std.crypto.random.bytes(&secret_key);
    }
    
    // Get public key from secret key
    const public_key = try lib.crypto.getPublicKey(secret_key);
    const pubkey_hex = try std.fmt.allocPrint(allocator, "{}", .{std.fmt.fmtSliceHexLower(&public_key)});
    defer allocator.free(pubkey_hex);
    
    // Create tags
    const tags = try allocator.alloc([][]const u8, args.tags.items.len);
    for (args.tags.items, 0..) |tag, i| {
        tags[i] = tag;
    }
    
    // Calculate event ID
    const created_at = std.time.timestamp();
    const event_id = try lib.crypto.calculateEventId(allocator, pubkey_hex, created_at, args.kind, tags, content);
    defer allocator.free(event_id);
    
    // Sign the event  
    const signature = try lib.crypto.signEvent(event_id, secret_key);
    const signature_hex = try std.fmt.allocPrint(allocator, "{}", .{std.fmt.fmtSliceHexLower(&signature)});
    defer allocator.free(signature_hex);
    
    // Create the event struct
    const event = lib.Event{
        .id = event_id,
        .pubkey = pubkey_hex,
        .created_at = created_at,
        .kind = args.kind,
        .tags = tags,
        .content = content,
        .sig = signature_hex,
    };
    
    // Output JSON
    const json = try event.toJson(allocator);
    defer allocator.free(json);
    
    try writer.print("{s}\n", .{json});
    
    // Publish to relays if specified
    if (args.relays.items.len > 0) {
        for (args.relays.items) |relay_url| {
            try writer.print("publishing to {s}... ", .{relay_url});
            
            // TODO: Implement actual relay publishing
            const success = try publishToRelay(allocator, relay_url, &event);
            if (success) {
                try writer.print("success.\n", .{});
            } else {
                try writer.print("failed.\n", .{});
            }
        }
    }
}

fn handleParseCommand(allocator: std.mem.Allocator, writer: anytype) !void {
    const stdin = std.io.getStdIn().reader();
    
    // Read all input from stdin
    const input = try stdin.readAllAlloc(allocator, 1024 * 1024); // 1MB limit
    defer allocator.free(input);

    // Trim whitespace
    const trimmed_input = std.mem.trim(u8, input, " \t\n\r");
    
    if (trimmed_input.len == 0) {
        try writer.print("No input provided\n", .{});
        return;
    }

    // Try to parse as Nostr event
    parseAndDisplay(allocator, trimmed_input, writer) catch |err| {
        try writer.print("Error parsing Nostr event: {}\n", .{err});
        try writer.print("Input was: {s}\n", .{trimmed_input});
    };
}

fn printHelp(writer: anytype) !void {
    try writer.print("nostr-zig - Nostr CLI tool\n\n", .{});
    try writer.print("USAGE:\n", .{});
    try writer.print("  nostr-zig event [OPTIONS] [RELAYS...]\n", .{});
    try writer.print("  nostr-zig parse\n", .{});
    try writer.print("  nostr-zig help\n\n", .{});
    try writer.print("COMMANDS:\n", .{});
    try writer.print("  event    Create and optionally publish a Nostr event\n", .{});
    try writer.print("  parse    Parse a Nostr event from stdin\n", .{});
    try writer.print("  help     Show this help message\n\n", .{});
    try writer.print("OPTIONS:\n", .{});
    try writer.print("  --sec <key>    Secret key (hex) or '01' for default test key\n", .{});
    try writer.print("  -c <content>   Event content text\n", .{});
    try writer.print("  --tag <tag>    Add tag in format 'key=value' or 'key'\n", .{});
    try writer.print("  -k <kind>      Event kind (default: 1)\n\n", .{});
    try writer.print("EXAMPLES:\n", .{});
    try writer.print("  nostr-zig event\n", .{});
    try writer.print("  nostr-zig event --sec 01 -c 'hello world'\n", .{});
    try writer.print("  nostr-zig event --sec 01 -c 'gm' --tag t=gm relay.example.com\n", .{});
    try writer.print("  echo '{{...}}' | nostr-zig parse\n", .{});
}

fn publishToRelay(allocator: std.mem.Allocator, relay_url: []const u8, event: *const lib.Event) !bool {
    // Normalize the relay URL (add ws:// if no scheme provided)
    const normalized_url = try normalizeRelayUrl(allocator, relay_url);
    defer allocator.free(normalized_url);
    
    // Create WebSocket client 
    var client = lib.Client.init(allocator, normalized_url);
    defer client.deinit();
    
    // Connect to relay
    client.connect() catch {
        return false;
    };
    defer client.disconnect();
    
    // Publish event
    client.publish_event(event.*, CallbackContext.callback) catch {
        return false;
    };
    
    // Wait briefly for response (simplified for now)
    std.time.sleep(1000 * 1000 * 1000); // 1 second
    
    return true;
}

fn normalizeRelayUrl(allocator: std.mem.Allocator, url: []const u8) ![]u8 {
    // If URL already has a scheme, return as-is
    if (std.mem.indexOf(u8, url, "://")) |_| {
        return try allocator.dupe(u8, url);
    }
    
    // Choose protocol based on hostname
    // localhost and 127.x.x.x get ws://, everything else gets wss://
    const protocol = if (std.mem.startsWith(u8, url, "localhost") or 
                         std.mem.startsWith(u8, url, "127.")) "ws" else "wss";
    
    return try std.fmt.allocPrint(allocator, "{s}://{s}", .{ protocol, url });
}


const CallbackContext = struct {
    fn callback(ok: bool, message: ?[]const u8) void {
        _ = ok;
        _ = message;
        // Simple callback that does nothing for now
    }
};

fn parseAndDisplay(allocator: std.mem.Allocator, json_str: []const u8, writer: anytype) !void {
    // Parse the JSON as a Nostr event
    const event = try lib.Event.fromJson(allocator, json_str);
    defer event.deinit(allocator);

    // Display parsed event information
    try writer.print("=== Parsed Nostr Event ===\n", .{});
    try writer.print("ID: {s}\n", .{event.id});
    try writer.print("Public Key: {s}\n", .{event.pubkey});
    try writer.print("Created At: {} ({s})\n", .{ event.created_at, timestampToDate(event.created_at) });
    try writer.print("Kind: {} ({s})\n", .{ event.kind, kindToString(lib.Kind.fromInt(event.kind)) });
    try writer.print("Content: {s}\n", .{event.content});
    try writer.print("Tags: {} tags\n", .{event.tags.len});
    
    for (event.tags, 0..) |tag, i| {
        try writer.print("  Tag {}: [", .{i});
        for (tag, 0..) |tag_part, j| {
            if (j > 0) try writer.print(", ", .{});
            try writer.print("\"{s}\"", .{tag_part});
        }
        try writer.print("]\n", .{});
    }
    
    try writer.print("Signature: {s}\n", .{event.sig});
    
    // Basic validation
    try writer.print("\n=== Validation ===\n", .{});
    try writer.print("ID format: {s}\n", .{if (event.validateId(allocator) catch false) "✓ Valid" else "✗ Invalid"});
    try writer.print("Signature format: {s}\n", .{if (event.validateSignature() catch false) "✓ Valid" else "✗ Invalid"});
    
    // Serialize back to JSON
    try writer.print("\n=== Serialized JSON ===\n", .{});
    const serialized = try event.toJson(allocator);
    defer allocator.free(serialized);
    try writer.print("{s}\n", .{serialized});
}

fn kindToString(kind: lib.Kind) []const u8 {
    return switch (kind) {
        .metadata => "Metadata/Profile",
        .text_note => "Text Note",
        .recommend_relay => "Recommend Relay",
        .contacts => "Contact List",
        .encrypted_dm => "Encrypted DM",
        .event_deletion => "Event Deletion",
        .repost => "Repost",
        .reaction => "Reaction",
        .badge_award => "Badge Award",
        _ => "Unknown",
    };
}

fn timestampToDate(timestamp: i64) []const u8 {
    // Simple timestamp to date conversion (just show the timestamp for now)
    _ = timestamp;
    return "UTC";
}

test "can import nostr lib" {
    const Kind = lib.Kind;
    
    try std.testing.expectEqual(Kind.text_note, Kind.fromInt(1));
    try std.testing.expectEqual(Kind.metadata, Kind.fromInt(0));
}
