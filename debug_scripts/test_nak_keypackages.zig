const std = @import("std");
const websocket = @import("websocket");
const nostr = @import("nostr");

const log = std.log.scoped(.nak_test);

const NAK_SERVER_URL = "ws://localhost:10547";

const TestStats = struct {
    total_events: u32 = 0,
    keypackage_events: u32 = 0,
    successful_parses: u32 = 0,
    failed_parses: u32 = 0,
    roundtrip_successes: u32 = 0,
    roundtrip_failures: u32 = 0,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    log.info("🚀 Starting NAK KeyPackage Test", .{});
    log.info("Connecting to NAK server: {s}", .{NAK_SERVER_URL});

    var stats = TestStats{};

    // Initialize MLS provider for parsing
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

    // Subscribe to KeyPackage events (kind 443)
    const subscription_id = "keypackage_test";

    // Create subscription request
    const sub_request = try std.fmt.allocPrint(allocator, 
        \\["REQ","{s}",{{"kinds":[443],"limit":50}}]
    , .{subscription_id});
    defer allocator.free(sub_request);

    log.info("📡 Sending subscription: {s}", .{sub_request});
    try ws_client.writeText(sub_request);

    // Process messages
    var message_count: u32 = 0;
    const max_messages = 100; // Prevent infinite loop

    while (message_count < max_messages) {
        const message = ws_client.read() catch |err| {
            log.warn("Error reading message: {}", .{err});
            break;
        } orelse {
            log.info("No more messages, ending", .{});
            break;
        };
        defer ws_client.done(message);

        message_count += 1;
        
        switch (message.type) {
            .text => {
                const text = message.data;
                log.debug("📥 Received: {s}", .{text});
                
                // Parse relay message
                if (parseRelayMessage(allocator, text)) |relay_msg| {
                    defer deallocateRelayMessage(allocator, relay_msg);
                    
                    try processRelayMessage(allocator, &provider, relay_msg, &stats);
                } else |err| {
                    log.warn("Failed to parse relay message: {}", .{err});
                }
            },
            .binary => {
                log.warn("Received unexpected binary message", .{});
            },
            .close => {
                log.info("Connection closed by server", .{});
                break;
            },
            else => {},
        }
    }

    // Print final statistics
    log.info("🏁 Test Complete! Final Statistics:", .{});
    log.info("  Total events received: {}", .{stats.total_events});
    log.info("  KeyPackage events (kind 443): {}", .{stats.keypackage_events});
    log.info("  Successful KeyPackage parses: {}", .{stats.successful_parses});
    log.info("  Failed KeyPackage parses: {}", .{stats.failed_parses});
    log.info("  Successful roundtrips: {}", .{stats.roundtrip_successes});
    log.info("  Failed roundtrips: {}", .{stats.roundtrip_failures});
    
    const success_rate = if (stats.keypackage_events > 0) 
        (@as(f32, @floatFromInt(stats.successful_parses)) / @as(f32, @floatFromInt(stats.keypackage_events))) * 100.0
    else 0.0;
    
    log.info("  Parse success rate: {d:.1}%", .{success_rate});
    
    if (stats.successful_parses > 0) {
        log.info("🎉 SUCCESS: Our MLS KeyPackage parsing works with real NAK data!", .{});
    } else if (stats.keypackage_events > 0) {
        log.warn("⚠️  No successful parses - may need debugging", .{});
    } else {
        log.warn("⚠️  No KeyPackage events found on server", .{});
    }
}

fn parseRelayMessage(allocator: std.mem.Allocator, json_text: []const u8) !nostr.RelayMessage {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_text, .{});
    defer parsed.deinit();
    
    const root = parsed.value;
    
    if (root != .array) return error.InvalidMessage;
    const array = root.array;
    if (array.items.len < 2) return error.InvalidMessage;
    
    const msg_type = array.items[0].string;
    
    if (std.mem.eql(u8, msg_type, "EVENT")) {
        if (array.items.len < 3) return error.InvalidMessage;
        
        const subscription_id = try allocator.dupe(u8, array.items[1].string);
        const event_json = array.items[2];
        
        // Parse the event
        const event = try parseNostrEvent(allocator, event_json);
        
        return nostr.RelayMessage{
            .event = .{
                .subscription_id = subscription_id,
                .event = event,
            },
        };
    } else if (std.mem.eql(u8, msg_type, "EOSE")) {
        const subscription_id = try allocator.dupe(u8, array.items[1].string);
        return nostr.RelayMessage{
            .eose = .{
                .subscription_id = subscription_id,
            },
        };
    }
    
    return error.UnsupportedMessage;
}

fn parseNostrEvent(allocator: std.mem.Allocator, event_json: std.json.Value) !nostr.Event {
    if (event_json != .object) return error.InvalidEvent;
    const obj = event_json.object;
    
    const id = if (obj.get("id")) |v| try allocator.dupe(u8, v.string) else return error.MissingId;
    const pubkey = if (obj.get("pubkey")) |v| try allocator.dupe(u8, v.string) else return error.MissingPubkey;
    const created_at = if (obj.get("created_at")) |v| @as(i64, @intCast(v.integer)) else return error.MissingCreatedAt;
    const kind = if (obj.get("kind")) |v| @as(u32, @intCast(v.integer)) else return error.MissingKind;
    const content = if (obj.get("content")) |v| try allocator.dupe(u8, v.string) else return error.MissingContent;
    const sig = if (obj.get("sig")) |v| try allocator.dupe(u8, v.string) else return error.MissingSig;
    
    // Parse tags array
    var tags = std.ArrayList([][]const u8).init(allocator);
    if (obj.get("tags")) |tags_json| {
        if (tags_json == .array) {
            for (tags_json.array.items) |tag_json| {
                if (tag_json == .array) {
                    var tag = std.ArrayList([]const u8).init(allocator);
                    for (tag_json.array.items) |item| {
                        if (item == .string) {
                            try tag.append(try allocator.dupe(u8, item.string));
                        }
                    }
                    try tags.append(try tag.toOwnedSlice());
                }
            }
        }
    }
    
    return nostr.Event{
        .id = id,
        .pubkey = pubkey,
        .created_at = created_at,
        .kind = kind,
        .tags = try tags.toOwnedSlice(),
        .content = content,
        .sig = sig,
    };
}

fn processRelayMessage(
    allocator: std.mem.Allocator, 
    provider: *nostr.mls.MlsProvider,
    message: nostr.RelayMessage, 
    stats: *TestStats
) !void {
    switch (message) {
        .event => |event_msg| {
            stats.total_events += 1;
            
            if (event_msg.event.kind == 443) {
                stats.keypackage_events += 1;
                log.info("🔑 Found KeyPackage event (kind 443):", .{});
                log.info("  ID: {s}", .{event_msg.event.id});
                log.info("  Author: {s}", .{event_msg.event.pubkey});
                log.info("  Content length: {}", .{event_msg.event.content.len});
                
                // Attempt to parse the KeyPackage
                if (parseKeyPackageFromEvent(allocator, provider, event_msg.event)) |keypackage| {
                    stats.successful_parses += 1;
                    log.info("  ✅ Successfully parsed KeyPackage!", .{});
                    log.info("    Version: {} (0x{x:0>4})", .{keypackage.version, @intFromEnum(keypackage.version)});
                    log.info("    Cipher Suite: {} (0x{x:0>4})", .{keypackage.cipher_suite, @intFromEnum(keypackage.cipher_suite)});
                    log.info("    Init Key Length: {} bytes", .{keypackage.init_key.data.len});
                    log.info("    Has extensions: {}", .{keypackage.extensions.len > 0});
                    
                    // Extract and show Nostr pubkey
                    if (nostr.mls.key_packages.extractNostrPubkey(keypackage)) |nostr_pubkey| {
                        log.info("    Nostr PubKey: {s}", .{std.fmt.bytesToHex(nostr_pubkey, .lower)});
                    } else |_| {
                        log.debug("    Could not extract Nostr pubkey", .{});
                    }
                    
                    // Test roundtrip serialization
                    if (testRoundtripSerialization(allocator, keypackage)) {
                        stats.roundtrip_successes += 1;
                        log.info("    ✅ Roundtrip serialization successful!", .{});
                    } else |err| {
                        stats.roundtrip_failures += 1;
                        log.warn("    ❌ Roundtrip serialization failed: {}", .{err});
                    }
                    
                    // Clean up KeyPackage
                    deallocateKeyPackage(allocator, keypackage);
                } else |err| {
                    stats.failed_parses += 1;
                    log.warn("  ❌ Failed to parse KeyPackage: {}", .{err});
                    
                    // Debug: show hex dump of first few bytes
                    if (decodeHex(allocator, event_msg.event.content)) |decoded| {
                        defer allocator.free(decoded);
                        log.debug("  First 32 bytes (hex): {x}", .{std.fmt.fmtSliceHexLower(decoded[0..@min(32, decoded.len)])});
                        log.debug("  Total decoded length: {} bytes", .{decoded.len});
                    } else |_| {}
                }
            }
        },
        .eose => |eose_msg| {
            log.info("📄 End of stored events for subscription: {s}", .{eose_msg.subscription_id});
        },
        else => {
            log.debug("🔄 Other message type received", .{});
        },
    }
}

fn parseKeyPackageFromEvent(
    allocator: std.mem.Allocator, 
    provider: *nostr.mls.MlsProvider,
    event: nostr.Event
) !nostr.mls.types.KeyPackage {
    _ = provider; // Not needed for current parsing implementation
    
    // Use the new parseFromNostrEvent helper which handles encoding detection
    return nostr.mls.key_packages.parseFromNostrEvent(allocator, event.content) catch |err| {
        // If it fails, let's debug why
        log.debug("Parse error: {}", .{err});
        
        // Show more details about the data
        if (decodeHex(allocator, event.content)) |decoded_data| {
            defer allocator.free(decoded_data);
            log.debug("  Decoded length: {} bytes", .{decoded_data.len});
            if (decoded_data.len >= 4) {
                const version = std.mem.readInt(u16, decoded_data[0..2], .big);
                const cipher_suite = std.mem.readInt(u16, decoded_data[2..4], .big);
                log.debug("  Version: 0x{x:0>4}", .{version});
                log.debug("  Cipher suite: 0x{x:0>4}", .{cipher_suite});
            }
            log.debug("  First 64 bytes: {x}", .{std.fmt.fmtSliceHexLower(decoded_data[0..@min(64, decoded_data.len)])});
        } else |_| {}
        
        return err;
    };
}

fn decodeBase64(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const decoder = std.base64.standard.Decoder;
    const decoded_len = try decoder.calcSizeForSlice(input);
    const decoded = try allocator.alloc(u8, decoded_len);
    try decoder.decode(decoded, input);
    return decoded;
}

fn decodeHex(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    if (input.len % 2 != 0) return error.InvalidHexLength;
    
    var decoded = try allocator.alloc(u8, input.len / 2);
    _ = std.fmt.hexToBytes(decoded, input) catch return error.InvalidHex;
    return decoded;
}

fn testRoundtripSerialization(allocator: std.mem.Allocator, keypackage: nostr.mls.types.KeyPackage) !void {
    // Serialize the KeyPackage back to bytes
    const serialized = try nostr.mls.key_packages.serializeKeyPackage(allocator, keypackage);
    defer allocator.free(serialized);
    
    // Parse it again
    const reparsed = try nostr.mls.key_packages.parseKeyPackage(allocator, serialized);
    defer deallocateKeyPackage(allocator, reparsed);
    
    // Basic validation that key fields match
    if (keypackage.version != reparsed.version) return error.VersionMismatch;
    if (keypackage.cipher_suite != reparsed.cipher_suite) return error.CipherSuiteMismatch;
    
    // Use the new eql method for comprehensive comparison
    if (!keypackage.init_key.eql(reparsed.init_key)) return error.InitKeyMismatch;
    
    log.debug("Roundtrip validation passed", .{});
}

fn deallocateRelayMessage(allocator: std.mem.Allocator, message: nostr.RelayMessage) void {
    switch (message) {
        .event => |event_msg| {
            allocator.free(event_msg.subscription_id);
            deallocateNostrEvent(allocator, event_msg.event);
        },
        .eose => |eose_msg| {
            allocator.free(eose_msg.subscription_id);
        },
        else => {},
    }
}

fn deallocateNostrEvent(allocator: std.mem.Allocator, event: nostr.Event) void {
    allocator.free(event.id);
    allocator.free(event.pubkey);
    allocator.free(event.content);
    allocator.free(event.sig);
    
    for (event.tags) |tag| {
        for (tag) |item| {
            allocator.free(item);
        }
        allocator.free(tag);
    }
    allocator.free(event.tags);
}

fn deallocateKeyPackage(allocator: std.mem.Allocator, keypackage: nostr.mls.types.KeyPackage) void {
    // Clean up any allocated memory in the KeyPackage
    // This depends on the actual KeyPackage structure
    _ = allocator;
    _ = keypackage;
    // TODO: Implement proper cleanup based on KeyPackage structure
}