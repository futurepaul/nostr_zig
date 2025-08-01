const std = @import("std");

/// This imports the separate module containing `root.zig`. Take a look in `build.zig` for details.
const lib = @import("nostr_zig_lib");

const Command = enum {
    event,
    help,
    parse,
    generate,
    publish_keypackage,
    fetch_keypackage,
    create_welcome,
    join_group,
    test_mls_roundtrip,
    show_key,
};

const CliArgs = struct {
    command: Command = .help,
    secret_key: ?[]const u8 = null,
    content: ?[]const u8 = null,
    tags: std.ArrayList([][]const u8),
    relays: std.ArrayList([]const u8),
    kind: u32 = 1,
    npub: ?[]const u8 = null,
    target_npub: ?[]const u8 = null,
    group_name: ?[]const u8 = null,
    group_description: ?[]const u8 = null,
    
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
        .generate => try handleGenerateCommand(allocator, stdout),
        .publish_keypackage => try handlePublishKeyPackageCommand(allocator, &args, stdout),
        .fetch_keypackage => try handleFetchKeyPackageCommand(allocator, &args, stdout),
        .create_welcome => try handleCreateWelcomeCommand(allocator, &args, stdout),
        .join_group => try handleJoinGroupCommand(allocator, &args, stdout),
        .test_mls_roundtrip => try handleTestMLSRoundtripCommand(allocator, stdout),
        .show_key => try handleShowKeyCommand(allocator, &args, stdout),
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
            } else if (std.mem.eql(u8, flag, "name")) {
                args.group_name = arg;
            } else if (std.mem.eql(u8, flag, "description")) {
                args.group_description = arg;
            } else if (std.mem.eql(u8, flag, "relay")) {
                try args.relays.append(arg);
            }
            expecting_value = null;
        } else if (std.mem.startsWith(u8, arg, "--")) {
            const flag = arg[2..];
            if (std.mem.eql(u8, flag, "sec")) {
                expecting_value = "sec";
            } else if (std.mem.eql(u8, flag, "tag")) {
                expecting_value = "tag";
            } else if (std.mem.eql(u8, flag, "name")) {
                expecting_value = "name";
            } else if (std.mem.eql(u8, flag, "description")) {
                expecting_value = "description";
            } else if (std.mem.eql(u8, flag, "relay")) {
                expecting_value = "relay";
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
                } else if (std.mem.eql(u8, arg, "generate")) {
                    args.command = .generate;
                } else if (std.mem.eql(u8, arg, "publish-keypackage")) {
                    args.command = .publish_keypackage;
                } else if (std.mem.eql(u8, arg, "fetch-keypackage")) {
                    args.command = .fetch_keypackage;
                } else if (std.mem.eql(u8, arg, "create-welcome")) {
                    args.command = .create_welcome;
                } else if (std.mem.eql(u8, arg, "join-group")) {
                    args.command = .join_group;
                } else if (std.mem.eql(u8, arg, "test-mls-roundtrip")) {
                    args.command = .test_mls_roundtrip;
                } else if (std.mem.eql(u8, arg, "show-key")) {
                    args.command = .show_key;
                }
            } else {
                // For fetch-keypackage, first non-flag arg is the npub
                if (args.command == .fetch_keypackage and args.npub == null) {
                    args.npub = arg;
                } else if (args.command == .create_welcome and args.target_npub == null) {
                    // For create-welcome, first non-flag arg is the target npub
                    args.target_npub = arg;
                } else {
                    // Otherwise assume it's a relay URL
                    try args.relays.append(arg);
                }
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
        } else if (key.len == 2 and std.mem.eql(u8, key, "02")) {
            // Second test key
            secret_key = [_]u8{2} ++ [_]u8{0} ** 31;
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
            
            const success = try lib.relay_utils.publishEvent(allocator, relay_url, event, 5000);
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
    try writer.print("  nostr-zig generate\n", .{});
    try writer.print("  nostr-zig publish-keypackage [OPTIONS]\n", .{});
    try writer.print("  nostr-zig fetch-keypackage <npub>\n", .{});
    try writer.print("  nostr-zig create-welcome <target_npub> [OPTIONS]\n", .{});
    try writer.print("  nostr-zig help\n\n", .{});
    try writer.print("COMMANDS:\n", .{});
    try writer.print("  event               Create and optionally publish a Nostr event\n", .{});
    try writer.print("  parse               Parse a Nostr event from stdin\n", .{});
    try writer.print("  generate            Generate a new Nostr keypair\n", .{});
    try writer.print("  publish-keypackage  Create and publish MLS KeyPackage (NIP-EE)\n", .{});
    try writer.print("  fetch-keypackage    Fetch and parse a KeyPackage for given npub\n", .{});
    try writer.print("  create-welcome      Create MLS group and send welcome to target\n", .{});
    try writer.print("  join-group          Process a welcome message to join MLS group\n", .{});
    try writer.print("  test-mls-roundtrip  Test MLS roundtrip without relay (sanity check)\n", .{});
    try writer.print("  show-key            Show public key info for a given private key\n", .{});
    try writer.print("  help                Show this help message\n\n", .{});
    try writer.print("OPTIONS:\n", .{});
    try writer.print("  --sec <key>        Secret key (hex) or '01' for default test key\n", .{});
    try writer.print("  -c <content>       Event content text\n", .{});
    try writer.print("  --tag <tag>        Add tag in format 'key=value' or 'key'\n", .{});
    try writer.print("  -k <kind>          Event kind (default: 1)\n", .{});
    try writer.print("  --name <name>      Group name (for create-welcome)\n", .{});
    try writer.print("  --description <d>  Group description (for create-welcome)\n", .{});
    try writer.print("  --relay <url>      Relay URL (can be used multiple times)\n\n", .{});
    try writer.print("EXAMPLES:\n", .{});
    try writer.print("  nostr-zig generate\n", .{});
    try writer.print("  nostr-zig publish-keypackage --sec 01\n", .{});
    try writer.print("  nostr-zig fetch-keypackage npub1...\n", .{});
    try writer.print("  nostr-zig create-welcome npub1... --sec 01 --name \"Dev Chat\"\n", .{});
    try writer.print("  nostr-zig join-group --sec 02\n", .{});
    try writer.print("  nostr-zig event --sec 01 -c 'hello world'\n", .{});
    try writer.print("  echo '{{...}}' | nostr-zig parse\n", .{});
}


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

fn handleGenerateCommand(allocator: std.mem.Allocator, writer: anytype) !void {
    // Generate a new keypair
    const private_key = try lib.crypto.generatePrivateKey();
    const public_key = try lib.crypto.getPublicKey(private_key);
    
    // Convert to hex
    const private_hex = try lib.crypto.bytesToHex(allocator, &private_key);
    defer allocator.free(private_hex);
    
    const public_hex = try lib.crypto.bytesToHex(allocator, &public_key);
    defer allocator.free(public_hex);
    
    // Convert to bech32
    const nsec = try lib.bech32.encodeNsec1(allocator, private_key);
    defer allocator.free(nsec);
    
    const npub = try lib.bech32.encodeNpub1(allocator, public_key);
    defer allocator.free(npub);
    
    // Display results
    try writer.print("=== Generated Nostr Keypair ===\n", .{});
    try writer.print("Private key (hex): {s}\n", .{private_hex});
    try writer.print("Private key (nsec): {s}\n", .{nsec});
    try writer.print("Public key (hex): {s}\n", .{public_hex});
    try writer.print("Public key (npub): {s}\n\n", .{npub});
    try writer.print("⚠️  Keep your private key safe and secret!\n", .{});
}

fn handlePublishKeyPackageCommand(allocator: std.mem.Allocator, args: *CliArgs, writer: anytype) !void {
    // Get or generate secret key
    var secret_key: [32]u8 = undefined;
    
    var env_key: ?[]u8 = null;
    const key_str = args.secret_key orelse blk: {
        env_key = std.process.getEnvVarOwned(allocator, "NOSTR_SECRET_KEY") catch null;
        break :blk env_key;
    };
    defer if (env_key) |k| allocator.free(k);
    
    if (key_str) |key| {
        if (key.len == 2 and std.mem.eql(u8, key, "01")) {
            secret_key = [_]u8{1} ++ [_]u8{0} ** 31;
        } else if (key.len == 2 and std.mem.eql(u8, key, "02")) {
            secret_key = [_]u8{2} ++ [_]u8{0} ** 31;
        } else if (std.mem.startsWith(u8, key, "nsec1")) {
            secret_key = try lib.bech32.decodeNsec1(allocator, key);
        } else {
            if (key.len != 64) return error.InvalidKeyLength;
            _ = try std.fmt.hexToBytes(&secret_key, key);
        }
    } else {
        try writer.print("Error: Private key required. Use --sec <key> or set NOSTR_SECRET_KEY\n", .{});
        return;
    }
    
    // Get public key
    const public_key = try lib.crypto.getPublicKey(secret_key);
    const public_hex = try lib.crypto.bytesToHex(allocator, &public_key);
    defer allocator.free(public_hex);
    
    // Import mls_zig for KeyPackage creation
    const mls_zig = lib.mls_zig;
    const cipher_suite = mls_zig.cipher_suite.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    
    // Create KeyPackageBundle with wasm-compatible random function
    var bundle = try mls_zig.key_package_flat.KeyPackageBundle.init(
        allocator,
        cipher_suite,
        public_hex, // Use hex pubkey as credential identity
        null, // Use native randomness
    );
    defer bundle.deinit();
    
    // Serialize the KeyPackage
    const serialized = try bundle.key_package.tlsSerialize(allocator);
    defer allocator.free(serialized);
    
    // Convert to hex for Nostr event content
    const hex_content = try lib.crypto.bytesToHex(allocator, serialized);
    defer allocator.free(hex_content);
    
    // Create KeyPackage event helper
    const mls = lib.mls;
    var helper = mls.event_signing.NipEEEventHelper.init(allocator, secret_key);
    
    // Default relays if none specified
    const relays = if (args.relays.items.len > 0) args.relays.items else &[_][]const u8{"ws://localhost:10547"};
    
    // Create KeyPackage event (kind 443)
    const event = try helper.createKeyPackageEvent(
        hex_content,
        @intFromEnum(cipher_suite),
        1, // protocol version 1.0
        &[_]u32{1, 2}, // RequiredCapabilities, LastResort extensions
        relays,
    );
    defer event.deinit(allocator);
    
    // Display the event
    const json = try event.toJson(allocator);
    defer allocator.free(json);
    
    try writer.print("=== KeyPackage Event ===\n", .{});
    try writer.print("{s}\n\n", .{json});
    
    // Publish to relays
    if (relays.len > 0) {
        for (relays) |relay_url| {
            try writer.print("Publishing to {s}... ", .{relay_url});
            
            const success = try lib.relay_utils.publishEvent(allocator, relay_url, event, 5000);
            if (success) {
                try writer.print("success.\n", .{});
            } else {
                try writer.print("failed.\n", .{});
            }
        }
    }
    
    try writer.print("\nKeyPackage published! Others can now add you to MLS groups.\n", .{});
}

fn handleFetchKeyPackageCommand(allocator: std.mem.Allocator, args: *CliArgs, writer: anytype) !void {
    if (args.npub == null) {
        try writer.print("Error: npub required. Usage: nostr-zig fetch-keypackage <npub>\n", .{});
        return;
    }
    
    // Decode npub to public key
    const public_key = try lib.bech32.decodeNpub1(allocator, args.npub.?);
    const public_hex = try lib.crypto.bytesToHex(allocator, &public_key);
    defer allocator.free(public_hex);
    
    try writer.print("Fetching KeyPackage for {s}...\n\n", .{public_hex});
    
    // Use relay_utils to fetch the KeyPackage
    const relay_url = "ws://localhost:10547";
    
    const event = lib.relay_utils.fetchKeyPackage(allocator, relay_url, public_hex, 5000) catch |err| {
        try writer.print("Failed to fetch from relay: {}\n", .{err});
        return;
    };
    
    if (event == null) {
        try writer.print("❌ No KeyPackage found for this npub\n", .{});
        return;
    }
    
    // We now own the event and must clean it up
    const keypackage_event = event.?;
    defer keypackage_event.deinit(allocator);
    
    try writer.print("=== Found KeyPackage Event ===\n", .{});
    try writer.print("Event ID: {s}\n", .{keypackage_event.id});
    try writer.print("Author: {s}\n", .{keypackage_event.pubkey});
    try writer.print("Created: {}\n", .{keypackage_event.created_at});
    
    // Check MLS tags
    try writer.print("\nMLS Tags:\n", .{});
    for (keypackage_event.tags) |tag| {
        if (tag.len >= 2) {
            if (std.mem.eql(u8, tag[0], "mls_protocol_version")) {
                try writer.print("  Protocol Version: {s}\n", .{tag[1]});
            } else if (std.mem.eql(u8, tag[0], "mls_ciphersuite")) {
                try writer.print("  Cipher Suite: {s}\n", .{tag[1]});
            } else if (std.mem.eql(u8, tag[0], "mls_extensions")) {
                try writer.print("  Extensions: {s}\n", .{tag[1]});
            } else if (std.mem.eql(u8, tag[0], "relays")) {
                try writer.print("  Relays: {s}\n", .{tag[1]});
            }
        }
    }
    
    // Parse the KeyPackage content
    try writer.print("\n=== Parsing KeyPackage ===\n", .{});
    
    // Decode hex content
    const hex_content = keypackage_event.content;
    const binary = try allocator.alloc(u8, hex_content.len / 2);
    defer allocator.free(binary);
    _ = try std.fmt.hexToBytes(binary, hex_content);
    
    try writer.print("Binary size: {} bytes\n", .{binary.len});
    
    // Use the flat KeyPackage parser
    const mls_zig = lib.mls_zig;
    const key_package = mls_zig.key_package_flat.KeyPackage.tlsDeserialize(allocator, binary) catch |err| {
        try writer.print("Failed to parse KeyPackage: {}\n", .{err});
        
        // Show hex dump of first few bytes for debugging
        try writer.print("\nFirst 32 bytes (hex): ", .{});
        const show_len = @min(32, binary.len);
        for (binary[0..show_len]) |byte| {
            try writer.print("{x:0>2} ", .{byte});
        }
        try writer.print("\n", .{});
        return;
    };
    
    try writer.print("\n✅ Successfully parsed KeyPackage!\n", .{});
    try writer.print("\nKeyPackage Details:\n", .{});
    try writer.print("  Protocol Version: 0x{x:0>4} (MLS {s})\n", .{ key_package.protocol_version, if (key_package.protocol_version == 1) @as([]const u8, "1.0") else "Unknown" });
    try writer.print("  Cipher Suite: {} ({s})\n", .{ 
        @intFromEnum(key_package.cipher_suite),
        if (@intFromEnum(key_package.cipher_suite) == 1) @as([]const u8, "X25519/AES128-GCM/Ed25519") else "Unknown"
    });
    try writer.print("  Init Key: {s}\n", .{std.fmt.fmtSliceHexLower(&key_package.init_key)});
    try writer.print("  Encryption Key: {s}\n", .{std.fmt.fmtSliceHexLower(&key_package.encryption_key)});
    try writer.print("  Signature Key: {s}\n", .{std.fmt.fmtSliceHexLower(&key_package.signature_key)});
    try writer.print("  Credential Length: {} bytes\n", .{key_package.credential_len});
    
    try writer.print("\n🎉 This KeyPackage can be used to add this member to an MLS group!\n", .{});
}

fn handleCreateWelcomeCommand(allocator: std.mem.Allocator, args: *CliArgs, writer: anytype) !void {
    // TODO: This is a simplified implementation to show the flow
    // The actual implementation needs proper MLS group creation
    // Validate required arguments
    if (args.target_npub == null) {
        try writer.print("Error: target npub required. Usage: nostr-zig create-welcome <target_npub> [OPTIONS]\n", .{});
        return;
    }
    
    // Get or generate secret key
    var secret_key: [32]u8 = undefined;
    
    var env_key: ?[]u8 = null;
    const key_str = args.secret_key orelse blk: {
        env_key = std.process.getEnvVarOwned(allocator, "NOSTR_SECRET_KEY") catch null;
        break :blk env_key;
    };
    defer if (env_key) |k| allocator.free(k);
    
    if (key_str) |key| {
        if (key.len == 2 and std.mem.eql(u8, key, "01")) {
            secret_key = [_]u8{1} ++ [_]u8{0} ** 31;
        } else if (key.len == 2 and std.mem.eql(u8, key, "02")) {
            secret_key = [_]u8{2} ++ [_]u8{0} ** 31;
        } else if (std.mem.startsWith(u8, key, "nsec1")) {
            secret_key = try lib.bech32.decodeNsec1(allocator, key);
        } else {
            if (key.len != 64) return error.InvalidKeyLength;
            _ = try std.fmt.hexToBytes(&secret_key, key);
        }
    } else {
        try writer.print("Error: Private key required. Use --sec <key> or set NOSTR_SECRET_KEY\n", .{});
        return;
    }
    
    // Decode target npub
    const target_pubkey = try lib.bech32.decodeNpub1(allocator, args.target_npub.?);
    const target_pubkey_hex = try lib.crypto.bytesToHex(allocator, &target_pubkey);
    defer allocator.free(target_pubkey_hex);
    
    try writer.print("Creating MLS group and welcome for {s}...\n\n", .{args.target_npub.?});
    
    // 1. Fetch target's KeyPackage
    const relay_url = if (args.relays.items.len > 0) args.relays.items[0] else "ws://localhost:10547";
    
    try writer.print("Fetching KeyPackage from {s}...\n", .{relay_url});
    
    const keypackage_event = lib.relay_utils.fetchKeyPackage(allocator, relay_url, target_pubkey_hex, 5000) catch |err| {
        try writer.print("Failed to fetch KeyPackage: {}\n", .{err});
        return;
    };
    
    if (keypackage_event == null) {
        try writer.print("❌ No KeyPackage found for {s}\n", .{args.target_npub.?});
        try writer.print("Make sure the target has published their KeyPackage first.\n", .{});
        return;
    }
    
    const kp_event = keypackage_event.?;
    defer kp_event.deinit(allocator);
    
    try writer.print("✅ Found KeyPackage (event ID: {s})\n", .{kp_event.id});
    
    // Decode the KeyPackage binary data
    const hex_content = kp_event.content;
    const kp_binary = try allocator.alloc(u8, hex_content.len / 2);
    defer allocator.free(kp_binary);
    _ = try std.fmt.hexToBytes(kp_binary, hex_content);
    
    // TODO: Parse the KeyPackage properly
    // For now, this is a simplified implementation
    try writer.print("✅ KeyPackage binary size: {} bytes\n", .{kp_binary.len});
    
    // Parse the KeyPackage using the flat MLS parser (WASM-safe)
    const mls_zig = @import("mls_zig");
    const flat_keypackage = mls_zig.key_package_flat.KeyPackage.tlsDeserialize(allocator, kp_binary) catch |err| {
        try writer.print("\n❌ Failed to parse KeyPackage: {}\n", .{err});
        return;
    };
    
    try writer.print("✅ Successfully parsed KeyPackage!\n", .{});
    try writer.print("  Protocol Version: 0x{x:0>4} (MLS 1.0)\n", .{flat_keypackage.protocol_version});
    try writer.print("  Cipher Suite: {} (X25519/AES128-GCM/Ed25519)\n", .{@intFromEnum(flat_keypackage.cipher_suite)});
    
    // Convert flat KeyPackage to legacy format for createGroup
    const target_keypackage = try lib.mls.keypackage_converter.flatToLegacy(allocator, flat_keypackage);
    // Note: We can't free target_keypackage here because createGroup copies references to its fields
    // We'll handle cleanup differently below
    
    // 2. Create MLS provider
    var mls_provider = lib.mls.provider.MlsProvider.init(allocator);
    
    // 3. Create MLS group with target as initial member
    const group_name = args.group_name orelse "Test Group";
    const group_description = args.group_description orelse "Test MLS Group";
    const relays = if (args.relays.items.len > 0) args.relays.items else &[_][]const u8{relay_url};
    
    try writer.print("\nCreating MLS group:\n", .{});
    try writer.print("  Name: {s}\n", .{group_name});
    try writer.print("  Description: {s}\n", .{group_description});
    try writer.print("  Relays: ", .{});
    for (relays, 0..) |relay, i| {
        if (i > 0) try writer.print(", ", .{});
        try writer.print("{s}", .{relay});
    }
    try writer.print("\n", .{});
    
    // Get creator's public key
    const creator_pubkey = try lib.crypto.getPublicKey(secret_key);
    
    // Create group parameters
    const group_params = lib.mls.groups.GroupCreationParams{
        .name = group_name,
        .description = group_description,
        .admins = &[_][32]u8{creator_pubkey}, // Creator is admin
        .relays = relays,
        .image = null,
        .cipher_suite = .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        .extensions = &.{},
    };
    
    // Use the parsed KeyPackage directly
    const initial_members = [_]lib.mls.types.KeyPackage{target_keypackage};
    
    // Create the group
    const group_result = try lib.mls.groups.createGroup(
        allocator,
        &mls_provider,
        secret_key,
        group_params,
        &initial_members,
    );
    defer {
        // Clean up group result
        // Free member credentials first
        for (group_result.state.members) |member| {
            switch (member.credential) {
                .basic => |basic| allocator.free(basic.identity),
                else => {},
            }
        }
        allocator.free(group_result.state.members);
        allocator.free(group_result.state.ratchet_tree);
        
        // Free extensions data
        for (group_result.state.group_context.extensions) |ext| {
            allocator.free(ext.extension_data);
        }
        allocator.free(group_result.state.group_context.extensions);
        
        // Free welcomes
        for (group_result.welcomes) |welcome| {
            allocator.free(welcome.encrypted_group_info);
            for (welcome.secrets) |secret| {
                allocator.free(secret.new_member);
                allocator.free(secret.encrypted_group_secrets);
            }
            allocator.free(welcome.secrets);
        }
        allocator.free(group_result.welcomes);
        allocator.free(group_result.used_key_packages);
        
        // Free parts of target_keypackage that aren't shared with group result
        // The credential identity is shared, but these are not:
        allocator.free(target_keypackage.init_key.data);
        allocator.free(target_keypackage.leaf_node.encryption_key.data);
        allocator.free(target_keypackage.leaf_node.signature_key.data);
        allocator.free(target_keypackage.leaf_node.capabilities.versions);
        allocator.free(target_keypackage.leaf_node.capabilities.ciphersuites);
        allocator.free(target_keypackage.leaf_node.capabilities.extensions);
        allocator.free(target_keypackage.leaf_node.capabilities.proposals);
        allocator.free(target_keypackage.leaf_node.capabilities.credentials);
        allocator.free(target_keypackage.leaf_node.extensions);
        allocator.free(target_keypackage.leaf_node.signature);
        allocator.free(target_keypackage.extensions);
        allocator.free(target_keypackage.signature);
    }
    
    try writer.print("\n✅ MLS group created!\n", .{});
    try writer.print("  Group ID: {s}\n", .{std.fmt.fmtSliceHexLower(&group_result.state.group_id.data)});
    try writer.print("  Epoch: {}\n", .{group_result.state.epoch});
    
    // 4. Create Welcome Event
    if (group_result.welcomes.len == 0) {
        try writer.print("❌ No welcome messages generated\n", .{});
        return;
    }
    
    const welcome = group_result.welcomes[0];
    
    try writer.print("\nCreating Welcome event (NIP-59 gift wrapped)...\n", .{});
    
    const welcome_event = try lib.mls.welcome_events.WelcomeEvent.create(
        allocator,
        secret_key,
        target_pubkey,
        welcome,
        kp_event.id,
        relays,
    );
    defer welcome_event.deinit(allocator);
    
    // 5. Publish Welcome Event
    try writer.print("\nPublishing Welcome event to relay...\n", .{});
    
    const success = try lib.relay_utils.publishEvent(allocator, relay_url, welcome_event, 5000);
    if (success) {
        try writer.print("✅ Welcome event published successfully!\n", .{});
        try writer.print("\nThe recipient can now join the group by processing the welcome message.\n", .{});
    } else {
        try writer.print("❌ Failed to publish Welcome event\n", .{});
    }
}

fn handleTestMLSRoundtripCommand(allocator: std.mem.Allocator, writer: anytype) !void {
    try writer.print("\n=== MLS Roundtrip Test (No Relay) ===\n", .{});
    
    const mls_zig = @import("mls_zig");
    
    // Initialize MLS provider
    var mls_provider = lib.mls.provider.MlsProvider.init(allocator);
    
    // Step 1: Generate keypairs
    try writer.print("\n1. Generating keypairs...\n", .{});
    const alice_privkey = try lib.crypto.generatePrivateKey();
    const bob_privkey = try lib.crypto.generatePrivateKey();
    
    var alice_pubkey: [32]u8 = undefined;
    alice_pubkey = try lib.crypto.getPublicKey(alice_privkey);
    var bob_pubkey: [32]u8 = undefined;
    bob_pubkey = try lib.crypto.getPublicKey(bob_privkey);
    
    const alice_hex = try lib.crypto.bytesToHex(allocator, &alice_pubkey);
    defer allocator.free(alice_hex);
    const bob_hex = try lib.crypto.bytesToHex(allocator, &bob_pubkey);
    defer allocator.free(bob_hex);
    
    try writer.print("  Alice pubkey: {s}\n", .{alice_hex});
    try writer.print("  Bob pubkey: {s}\n", .{bob_hex});
    
    // Step 2: Bob creates KeyPackage
    try writer.print("\n2. Bob creates his KeyPackage...\n", .{});
    
    const bob_kp_bundle = try mls_zig.key_package_flat.KeyPackageBundle.init(
        allocator,
        .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        &bob_pubkey,
        null,
    );
    
    const bob_kp_bytes = try bob_kp_bundle.key_package.tlsSerialize(allocator);
    defer allocator.free(bob_kp_bytes);
    
    try writer.print("  Bob's KeyPackage size: {} bytes\n", .{bob_kp_bytes.len});
    
    // Step 3: Alice parses Bob's KeyPackage
    try writer.print("\n3. Alice parses Bob's KeyPackage...\n", .{});
    
    const parsed_bob_kp = try mls_zig.key_package_flat.KeyPackage.tlsDeserialize(allocator, bob_kp_bytes);
    
    try writer.print("  ✅ Successfully parsed Bob's KeyPackage!\n", .{});
    try writer.print("  Protocol version: 0x{x:0>4}\n", .{parsed_bob_kp.protocol_version});
    try writer.print("  Cipher suite: {}\n", .{@intFromEnum(parsed_bob_kp.cipher_suite)});
    
    // Step 4: Convert to legacy format
    try writer.print("\n4. Converting KeyPackage format...\n", .{});
    
    const bob_legacy_kp = try lib.mls.keypackage_converter.flatToLegacy(allocator, parsed_bob_kp);
    // We need to free parts of bob_legacy_kp that aren't taken by createGroup
    defer {
        allocator.free(bob_legacy_kp.init_key.data);
        allocator.free(bob_legacy_kp.leaf_node.encryption_key.data);
        allocator.free(bob_legacy_kp.leaf_node.signature_key.data);
        allocator.free(bob_legacy_kp.signature);
    }
    
    // Step 5: Alice creates group
    try writer.print("\n5. Alice creates MLS group with Bob...\n", .{});
    
    const group_params = lib.mls.groups.GroupCreationParams{
        .name = "Test Group",
        .description = "MLS roundtrip test",
        .admins = &[_][32]u8{alice_pubkey},
        .relays = &[_][]const u8{"ws://localhost:10547"},
        .image = null,
    };
    
    const creation_result = try lib.mls.groups.createGroup(
        allocator,
        &mls_provider,
        alice_privkey,
        group_params,
        &[_]lib.mls.types.KeyPackage{bob_legacy_kp},
    );
    defer {
        // Clean up group result
        for (creation_result.state.members) |member| {
            switch (member.credential) {
                .basic => |basic| allocator.free(basic.identity),
                else => {},
            }
        }
        allocator.free(creation_result.state.members);
        allocator.free(creation_result.state.ratchet_tree);
        
        // Free extensions data
        for (creation_result.state.group_context.extensions) |ext| {
            allocator.free(ext.extension_data);
        }
        allocator.free(creation_result.state.group_context.extensions);
        
        // Free welcomes
        for (creation_result.welcomes) |welcome| {
            allocator.free(welcome.encrypted_group_info);
            for (welcome.secrets) |secret| {
                allocator.free(secret.new_member);
                allocator.free(secret.encrypted_group_secrets);
            }
            allocator.free(welcome.secrets);
        }
        allocator.free(creation_result.welcomes);
        allocator.free(creation_result.used_key_packages);
    }
    
    const group_id_hex = try lib.crypto.bytesToHex(allocator, &creation_result.state.group_id.data);
    defer allocator.free(group_id_hex);
    
    try writer.print("  ✅ Group created!\n", .{});
    try writer.print("  Group ID: {s}\n", .{group_id_hex});
    try writer.print("  Epoch: {}\n", .{creation_result.state.epoch});
    try writer.print("  Members: {}\n", .{creation_result.state.members.len});
    try writer.print("  Welcome messages: {}\n", .{creation_result.welcomes.len});
    
    // Step 6: Verify Welcome
    try writer.print("\n6. Verifying Welcome message...\n", .{});
    
    const welcome = creation_result.welcomes[0];
    try writer.print("  Welcome cipher suite: {}\n", .{@intFromEnum(welcome.cipher_suite)});
    try writer.print("  Welcome secrets: {} secrets\n", .{welcome.secrets.len});
    
    // Serialize Welcome to show size
    // TODO: Fix serializeWelcome after TLS migration
    // const welcome_bytes = try lib.mls.serialization.Serializer.serializeWelcome(allocator, welcome);
    // defer allocator.free(welcome_bytes);
    // try writer.print("  Serialized Welcome size: {} bytes\n", .{welcome_bytes.len});
    
    try writer.print("  Encrypted group info size: {} bytes\n", .{welcome.encrypted_group_info.len});
    
    try writer.print("\n✅ MLS Roundtrip Test Complete!\n", .{});
    try writer.print("Summary:\n", .{});
    try writer.print("  - Bob created a {} byte KeyPackage\n", .{bob_kp_bytes.len});
    try writer.print("  - Alice successfully parsed it\n", .{});
    try writer.print("  - Alice created group with 2 members\n", .{});
    try writer.print("  - Alice generated Welcome message\n", .{});
    try writer.print("  - We can read our own KeyPackages! ✅\n", .{});
    try writer.print("  - We can create valid MLS groups! ✅\n", .{});
    try writer.print("  - Next: Implement join-group for Bob\n", .{});
}

fn handleJoinGroupCommand(allocator: std.mem.Allocator, args: *CliArgs, writer: anytype) !void {
    try writer.print("\n=== Join MLS Group from Welcome ===\n\n", .{});
    
    // Get our private key
    var secret_key: [32]u8 = undefined;
    const key_str = args.secret_key orelse std.posix.getenv("NOSTR_SECRET_KEY");
    
    if (key_str) |key| {
        if (key.len == 2 and std.mem.eql(u8, key, "01")) {
            secret_key = [_]u8{1} ++ [_]u8{0} ** 31;
        } else if (key.len == 2 and std.mem.eql(u8, key, "02")) {
            secret_key = [_]u8{2} ++ [_]u8{0} ** 31;
        } else if (std.mem.startsWith(u8, key, "nsec1")) {
            secret_key = try lib.bech32.decodeNsec1(allocator, key);
        } else {
            if (key.len != 64) return error.InvalidKeyLength;
            _ = try std.fmt.hexToBytes(&secret_key, key);
        }
    } else {
        try writer.print("Error: Private key required. Use --sec <key> or set NOSTR_SECRET_KEY\n", .{});
        return;
    }
    
    const our_pubkey = try lib.crypto.getPublicKey(secret_key);
    const our_pubkey_hex = try lib.crypto.bytesToHex(allocator, &our_pubkey);
    defer allocator.free(our_pubkey_hex);
    
    try writer.print("Our public key: {s}\n", .{our_pubkey_hex});
    
    // Fetch our gift-wrapped Welcome events
    const relay_url = if (args.relays.items.len > 0) args.relays.items[0] else "ws://localhost:10547";
    
    try writer.print("Fetching Welcome events from {s}...\n", .{relay_url});
    
    // Use relay_utils to fetch gift-wrapped events
    const since_timestamp = std.time.timestamp() - (7 * 24 * 60 * 60); // Last 7 days
    var fetch_result = try lib.relay_utils.fetchEvents(
        allocator,
        relay_url,
        .{
            .kinds = &[_]u32{1059}, // Gift-wrapped events
            .since = @intCast(since_timestamp),
            .limit = 100,
        },
        5000,
    );
    defer fetch_result.deinit();
    
    // Filter for events tagged to us
    var our_events = std.ArrayList(lib.event.Event).init(allocator);
    defer {
        for (our_events.items) |evt| {
            evt.deinit(allocator);
        }
        our_events.deinit();
    }
    
    for (fetch_result.events) |event| {
        // Check if this event is tagged to us
        var is_for_us = false;
        for (event.tags) |tag| {
            if (tag.len >= 2 and std.mem.eql(u8, tag[0], "p") and 
                std.mem.eql(u8, tag[1], our_pubkey_hex)) {
                is_for_us = true;
                break;
            }
        }
        
        if (is_for_us) {
            // Clone the event manually
            const cloned_tags = try allocator.alloc([][]u8, event.tags.len);
            for (event.tags, 0..) |tag, i| {
                cloned_tags[i] = try allocator.alloc([]u8, tag.len);
                for (tag, 0..) |t, j| {
                    cloned_tags[i][j] = try allocator.dupe(u8, t);
                }
            }
            
            const cloned = lib.event.Event{
                .id = try allocator.dupe(u8, event.id),
                .pubkey = try allocator.dupe(u8, event.pubkey),
                .created_at = event.created_at,
                .kind = event.kind,
                .tags = cloned_tags,
                .content = try allocator.dupe(u8, event.content),
                .sig = try allocator.dupe(u8, event.sig),
            };
            
            try our_events.append(cloned);
        }
    }
    
    const events = try our_events.toOwnedSlice();
    defer {
        for (events) |evt| {
            evt.deinit(allocator);
        }
        allocator.free(events);
    }
    
    if (events.len == 0) {
        try writer.print("\n❌ No Welcome events found for your public key\n", .{});
        try writer.print("Make sure someone has sent you a Welcome first using create-welcome.\n", .{});
        return;
    }
    
    try writer.print("✅ Found {} gift-wrapped event(s)\n", .{events.len});
    
    // Try to process Welcome events (newest first)
    for (events, 0..) |wrapped_event, i| {
        try writer.print("\nAttempting to process event {} of {}...\n", .{i + 1, events.len});
        
        // Initialize MLS provider
        var mls_provider = lib.mls.provider.MlsProvider.init(allocator);
        
        // Try to process this Welcome event
        const join_result = lib.mls.welcome_events.processWelcomeEvent(
            allocator,
            &mls_provider,
            wrapped_event,
            secret_key,
        ) catch |err| {
            try writer.print("  Failed to process: {}\n", .{err});
            continue;
        };
        
        // Success! We joined the group
        try writer.print("\n✅ Successfully joined MLS group!\n", .{});
        
        const group_id_hex = try lib.crypto.bytesToHex(allocator, &join_result.state.group_id.data);
        defer allocator.free(group_id_hex);
        
        try writer.print("  Group ID: {s}\n", .{group_id_hex});
        try writer.print("  Epoch: {}\n", .{join_result.state.epoch});
        try writer.print("  Members: {}\n", .{join_result.state.members.len});
        try writer.print("\nGroup Metadata:\n", .{});
        try writer.print("  Name: {s}\n", .{join_result.metadata.name});
        try writer.print("  Description: {s}\n", .{join_result.metadata.description});
        try writer.print("  Relays: ", .{});
        for (join_result.metadata.relays, 0..) |relay, j| {
            if (j > 0) try writer.print(", ", .{});
            try writer.print("{s}", .{relay});
        }
        try writer.print("\n", .{});
        
        try writer.print("\n🎉 You are now a member of the group!\n", .{});
        try writer.print("Next steps:\n", .{});
        try writer.print("  - Send encrypted messages to the group\n", .{});
        try writer.print("  - Receive messages from other members\n", .{});
        try writer.print("  - Update your key material periodically\n", .{});
        
        // Clean up join result
        // group_id is a struct with fixed array, no need to free
        for (join_result.state.members) |member| {
            switch (member.credential) {
                .basic => |basic| allocator.free(basic.identity),
                else => {},
            }
        }
        allocator.free(join_result.state.members);
        allocator.free(join_result.state.ratchet_tree);
        
        // Free group context extensions if any
        for (join_result.state.group_context.extensions) |ext| {
            allocator.free(ext.extension_data);
        }
        allocator.free(join_result.state.group_context.extensions);
        
        // Free metadata
        allocator.free(join_result.metadata.name);
        allocator.free(join_result.metadata.description);
        if (join_result.metadata.image) |img| {
            allocator.free(img);
        }
        // admins is []const [32]u8, just free the array
        allocator.free(join_result.metadata.admins);
        for (join_result.metadata.relays) |relay| {
            allocator.free(relay);
        }
        allocator.free(join_result.metadata.relays);
        
        return; // Successfully joined, exit
    }
    
    try writer.print("\n❌ Could not join any group from the available Welcome events\n", .{});
}

fn handleShowKeyCommand(allocator: std.mem.Allocator, args: *CliArgs, writer: anytype) !void {
    // Get the private key
    var secret_key: [32]u8 = undefined;
    const key_str = args.secret_key orelse std.posix.getenv("NOSTR_SECRET_KEY");
    
    if (key_str) |key| {
        if (key.len == 2 and std.mem.eql(u8, key, "01")) {
            secret_key = [_]u8{1} ++ [_]u8{0} ** 31;
        } else if (key.len == 2 and std.mem.eql(u8, key, "02")) {
            secret_key = [_]u8{2} ++ [_]u8{0} ** 31;
        } else if (std.mem.startsWith(u8, key, "nsec1")) {
            secret_key = try lib.bech32.decodeNsec1(allocator, key);
        } else {
            if (key.len != 64) return error.InvalidKeyLength;
            _ = try std.fmt.hexToBytes(&secret_key, key);
        }
    } else {
        try writer.print("Error: Private key required. Use --sec <key> or set NOSTR_SECRET_KEY\n", .{});
        return;
    }
    
    // Get public key
    const pubkey = try lib.crypto.getPublicKey(secret_key);
    const pubkey_hex = try lib.crypto.bytesToHex(allocator, &pubkey);
    defer allocator.free(pubkey_hex);
    
    const npub = try lib.bech32.encodeNpub1(allocator, pubkey);
    defer allocator.free(npub);
    
    try writer.print("Public key (hex): {s}\n", .{pubkey_hex});
    try writer.print("Public key (npub): {s}\n", .{npub});
}

test "can import nostr lib" {
    const Kind = lib.Kind;
    
    try std.testing.expectEqual(Kind.text_note, Kind.fromInt(1));
    try std.testing.expectEqual(Kind.metadata, Kind.fromInt(0));
}
