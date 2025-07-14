const std = @import("std");
const websocket = @import("websocket");
const nostr = @import("nostr");
const crypto = @import("../src/crypto.zig");

const log = std.log.scoped(.publish_keypackages);

const NAK_SERVER_URL = "ws://localhost:10547";

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    log.info("🚀 Starting KeyPackage Publisher", .{});
    log.info("Target server: {s}", .{NAK_SERVER_URL});

    // Initialize MLS provider
    var provider = nostr.mls.provider.MlsProvider.init(allocator);

    // Connect to NAK server
    const url = try std.Uri.parse(NAK_SERVER_URL);
    const host = switch (url.host.?) {
        .raw => |h| h,
        .percent_encoded => |h| h,
    };
    const default_port: u16 = if (std.mem.eql(u8, url.scheme, "wss")) 443 else 80;
    const port = url.port orelse default_port;
    const path = switch (url.path) {
        .raw => |p| if (p.len == 0) "/" else p,
        .percent_encoded => |p| if (p.len == 0) "/" else p,
    };
    
    var ws_client = try websocket.Client.init(allocator, .{
        .host = host,
        .port = port,
        .tls = std.mem.eql(u8, url.scheme, "wss"),
    });
    defer ws_client.deinit();
    
    // Perform websocket handshake
    var headers_buf: [256]u8 = undefined;
    const headers = try std.fmt.bufPrint(&headers_buf, "Host: {s}:{}\r\n", .{ host, port });
    try ws_client.handshake(path, .{ .headers = headers });

    log.info("✅ Connected to NAK server", .{});

    // Generate test key packages
    const num_keypackages = 3;
    var published_count: u32 = 0;

    log.info("📦 Generating and publishing {} test KeyPackages...", .{num_keypackages});

    var i: u32 = 0;
    while (i < num_keypackages) : (i += 1) {
        // Generate a test Nostr private key (just for testing)
        var prng = std.Random.DefaultPrng.init(@intCast(std.time.milliTimestamp() + i));
        const random = prng.random();
        
        var nostr_private_key: [32]u8 = undefined;
        random.bytes(&nostr_private_key);
        
        // Get the public key
        const nostr_public_key = try crypto.getPublicKey(nostr_private_key);
        const pubkey_hex = std.fmt.bytesToHex(nostr_public_key, .lower);
        
        log.info("🔑 Generating KeyPackage #{} for pubkey: {s}", .{ i + 1, pubkey_hex });

        // Generate the MLS KeyPackage
        const params = nostr.mls.key_packages.KeyPackageParams{
            .cipher_suite = .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            .lifetime_seconds = 7 * 24 * 60 * 60, // 7 days
        };
        
        const keypackage = try nostr.mls.key_packages.generateKeyPackage(
            allocator,
            &provider,
            nostr_private_key,
            params,
        );
        defer deallocateKeyPackage(allocator, keypackage);

        // Serialize KeyPackage for Nostr event
        const keypackage_hex = try nostr.mls.key_packages.serializeForNostrEvent(allocator, keypackage);
        defer allocator.free(keypackage_hex);

        // Create Nostr event
        const created_at = @divFloor(std.time.milliTimestamp(), 1000);
        
        // Create the event content
        var content_obj = std.json.ObjectMap.init(allocator);
        defer content_obj.deinit();
        
        try content_obj.put("id", .{ .string = &pubkey_hex });
        try content_obj.put("pubkey", .{ .string = &pubkey_hex });
        try content_obj.put("created_at", .{ .integer = created_at });
        try content_obj.put("kind", .{ .integer = 443 });
        try content_obj.put("tags", .{ .array = std.json.Array.init(allocator) });
        try content_obj.put("content", .{ .string = keypackage_hex });

        // For now, we'll use a dummy signature (in real usage, this would be properly signed)
        var dummy_sig: [64]u8 = undefined;
        random.bytes(&dummy_sig);
        const sig_hex = std.fmt.bytesToHex(dummy_sig, .lower);
        try content_obj.put("sig", .{ .string = &sig_hex });

        // Also compute a dummy event ID
        var dummy_id: [32]u8 = undefined;
        random.bytes(&dummy_id);
        const id_hex = std.fmt.bytesToHex(dummy_id, .lower);
        try content_obj.put("id", .{ .string = &id_hex });

        // Create the JSON value
        const event_json = std.json.Value{ .object = content_obj };
        
        // Serialize to JSON string
        var json_buf = std.ArrayList(u8).init(allocator);
        defer json_buf.deinit();
        try std.json.stringify(event_json, .{}, json_buf.writer());

        // Create EVENT message for relay
        const event_msg = try std.fmt.allocPrint(allocator, 
            \\["EVENT",{s}]
        , .{json_buf.items});
        defer allocator.free(event_msg);

        log.info("📡 Publishing event: {s}...", .{event_msg[0..@min(100, event_msg.len)]});
        
        // Send to relay
        try ws_client.writeText(event_msg);
        published_count += 1;

        // Read response to check if accepted
        if (ws_client.read()) |message| {
            defer ws_client.done(message);
            
            if (message.type == .text) {
                log.info("📥 Relay response: {s}", .{message.data});
                
                // Check if it's an OK message
                if (std.mem.indexOf(u8, message.data, "\"OK\"") != null) {
                    log.info("✅ KeyPackage #{} published successfully!", .{i + 1});
                } else if (std.mem.indexOf(u8, message.data, "\"NOTICE\"") != null) {
                    log.warn("⚠️  Relay notice: {s}", .{message.data});
                }
            }
        } else |_| {}

        // Small delay between publishes
        std.time.sleep(100 * std.time.ns_per_ms);
    }

    log.info("🏁 Finished! Published {} KeyPackages to NAK server", .{published_count});

    // Close the connection properly
    try ws_client.close();
}

fn deallocateKeyPackage(allocator: std.mem.Allocator, keypackage: nostr.mls.types.KeyPackage) void {
    // Clean up allocated memory in the KeyPackage
    allocator.free(keypackage.init_key.data);
    allocator.free(keypackage.signature);
    
    // Clean up leaf node
    allocator.free(keypackage.leaf_node.encryption_key.data);
    allocator.free(keypackage.leaf_node.signature_key.data);
    allocator.free(keypackage.leaf_node.signature);
    
    // Clean up credential
    switch (keypackage.leaf_node.credential) {
        .basic => |basic| {
            allocator.free(basic.identity);
        },
        else => {},
    }
    
    // Clean up capabilities
    allocator.free(keypackage.leaf_node.capabilities.versions);
    allocator.free(keypackage.leaf_node.capabilities.ciphersuites);
    allocator.free(keypackage.leaf_node.capabilities.extensions);
    allocator.free(keypackage.leaf_node.capabilities.proposals);
    allocator.free(keypackage.leaf_node.capabilities.credentials);
    
    // Clean up extensions
    for (keypackage.leaf_node.extensions) |ext| {
        allocator.free(ext.extension_data);
    }
    allocator.free(keypackage.leaf_node.extensions);
}