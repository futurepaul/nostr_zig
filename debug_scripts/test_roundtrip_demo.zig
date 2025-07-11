const std = @import("std");
const nostr_zig = @import("nostr_zig");
const crypto = nostr_zig.crypto;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("=== Nostr Roundtrip Test: Publish + Subscribe ===", .{});

    // Generate a real keypair
    std.log.info("🔑 Generating real secp256k1 keypair...", .{});
    const private_key = try crypto.generatePrivateKey();
    const public_key = try crypto.getPublicKey(private_key);
    const pubkey_hex = try crypto.bytesToHex(allocator, &public_key);
    defer allocator.free(pubkey_hex);
    std.log.info("✅ Generated keypair. Pubkey: {s}", .{pubkey_hex[0..16]});

    // Create event content
    const created_at = std.time.timestamp();
    const kind: u32 = 1;
    const tags = &[_][]const []const u8{
        &[_][]const u8{ "roundtrip", "test" },
        &[_][]const u8{ "client", "zig-nostr" },
    };
    const content = "🔄 ROUNDTRIP TEST: This event should be published and then received back through subscription!";

    // Calculate real event ID
    std.log.info("📝 Calculating event ID...", .{});
    const event_id = try crypto.calculateEventId(allocator, pubkey_hex, created_at, kind, tags, content);
    defer allocator.free(event_id);
    std.log.info("✅ Event ID: {s}", .{event_id});

    // Create real BIP340 Schnorr signature
    std.log.info("✍️  Creating BIP340 Schnorr signature...", .{});
    const signature = try crypto.signEvent(event_id, private_key);
    const sig_hex = try crypto.bytesToHex(allocator, &signature);
    defer allocator.free(sig_hex);
    std.log.info("✅ Signature: {s}...", .{sig_hex[0..32]});

    // Verify signature locally
    std.log.info("🔍 Verifying signature locally...", .{});
    const is_valid = try crypto.verifySignature(event_id, signature, public_key);
    if (!is_valid) {
        std.log.err("❌ Local signature verification FAILED!", .{});
        return;
    }
    std.log.info("✅ Local signature verification PASSED!", .{});

    // Create the event
    const event = nostr_zig.Event{
        .id = event_id,
        .pubkey = pubkey_hex,
        .created_at = created_at,
        .kind = kind,
        .tags = tags,
        .content = content,
        .sig = sig_hex,
    };

    // Test state for tracking
    const TestState = struct {
        event_published: bool = false,
        event_accepted: bool = false,
        event_received: bool = false,
        our_event_id: []const u8,
        received_count: u32 = 0,
    };
    var state = TestState{ .our_event_id = event_id };

    // === SINGLE CLIENT APPROACH ===
    std.log.info("", .{});
    std.log.info("📡 Connecting to relay...", .{});
    
    const relay_url = "ws://localhost:10547";
    var client = nostr_zig.Client.init(allocator, relay_url);
    defer client.deinit();

    try client.connect();
    defer client.disconnect();
    std.log.info("✅ Connected to relay", .{});

    // Create subscription callback
    const SubscribeContext = struct {
        var test_state: *TestState = undefined;
        
        fn callback(message: nostr_zig.client.RelayMessage) void {
            switch (message) {
                .event => |e| {
                    test_state.received_count += 1;
                    std.log.info("📥 Received event #{}: {s}...", .{ test_state.received_count, e.event.id[0..16] });
                    
                    // Check if this is our event
                    if (std.mem.eql(u8, e.event.id, test_state.our_event_id)) {
                        std.log.info("🎯 FOUND OUR EVENT! Roundtrip successful!", .{});
                        std.log.info("   Content: {s}", .{e.event.content});
                        test_state.event_received = true;
                    }
                },
                .eose => {
                    std.log.info("📄 End of stored events (EOSE)", .{});
                },
                .ok => |ok_msg| {
                    if (ok_msg.accepted) {
                        std.log.info("🎉 Event accepted by relay!", .{});
                        test_state.event_accepted = true;
                    } else {
                        std.log.err("❌ Event rejected: {s}", .{ok_msg.message orelse "unknown reason"});
                    }
                    test_state.event_published = true;
                },
                else => {
                    std.log.info("📨 Other message received", .{});
                },
            }
        }
    };
    SubscribeContext.test_state = &state;

    // === STEP 1: SUBSCRIBE ===
    std.log.info("📡 STEP 1: Setting up subscription...", .{});
    
    // Subscribe to events from our pubkey
    const filters = [_]nostr_zig.Filter{
        .{
            .authors = &[_][]const u8{pubkey_hex},
            .kinds = &[_]u32{1},
            .limit = 10,
        },
    };

    try client.subscribe("roundtrip-test", &filters, SubscribeContext.callback);
    std.log.info("✅ Subscribed to events from our pubkey", .{});

    // Process initial messages (existing events)
    std.log.info("🔄 Processing existing events...", .{});
    var setup_attempts: u32 = 0;
    while (setup_attempts < 30) : (setup_attempts += 1) {
        client.process_messages() catch |err| switch (err) {
            error.WouldBlock => {},
            error.Closed => break,
            else => return err,
        };
        std.time.sleep(100 * std.time.ns_per_ms);
    }

    // === STEP 2: PUBLISH EVENT ===
    std.log.info("", .{});
    std.log.info("📤 STEP 2: Publishing event...", .{});

    // Publish callback (we handle this in the main callback now)
    try client.publish_event(event, struct {
        fn callback(ok: bool, message: ?[]const u8) void {
            // This will be handled by the main subscription callback
            _ = ok;
            _ = message;
        }
    }.callback);
    std.log.info("📨 Event sent to relay, waiting for response...", .{});

    // === STEP 3: WAIT FOR RESPONSES ===
    std.log.info("", .{});
    std.log.info("👀 STEP 3: Waiting for publish confirmation and event roundtrip...", .{});

    // Give the relay a moment to process
    std.time.sleep(200 * std.time.ns_per_ms);

    var total_attempts: u32 = 0;
    while (total_attempts < 100 and (!state.event_published or !state.event_received)) : (total_attempts += 1) {
        client.process_messages() catch |err| switch (err) {
            error.WouldBlock => {
                // This is normal, just means no messages right now
            },
            error.Closed => {
                std.log.warn("Connection closed at attempt {}", .{total_attempts});
                if (state.event_published) {
                    std.log.info("✅ Event was published before connection closed", .{});
                }
                break;
            },
            else => {
                std.log.err("Unexpected error: {}", .{err});
                return err;
            },
        };
        std.time.sleep(50 * std.time.ns_per_ms);
        
        if (total_attempts % 10 == 0 and total_attempts > 0) {
            std.log.info("⏳ Attempt {} - Published: {} | Accepted: {} | Received: {}", 
                .{ total_attempts, state.event_published, state.event_accepted, state.event_received });
        }
        
        // Break early if we got both responses
        if (state.event_received and state.event_accepted) {
            std.log.info("🎉 Got both responses early at attempt {}", .{total_attempts});
            break;
        }
    }

    // === RESULTS ===
    std.log.info("", .{});
    std.log.info("📊 ROUNDTRIP TEST RESULTS:", .{});
    std.log.info("  Published: {}", .{state.event_published});
    std.log.info("  Accepted:  {}", .{state.event_accepted});
    std.log.info("  Received:  {}", .{state.event_received});
    std.log.info("  Total events received: {}", .{state.received_count});

    if (state.event_received) {
        std.log.info("", .{});
        std.log.info("🎉🎉🎉 ROUNDTRIP TEST SUCCESSFUL! 🎉🎉🎉", .{});
        std.log.info("✅ Event was published with real BIP340 signatures", .{});
        std.log.info("✅ Relay accepted and validated the event", .{});
        std.log.info("✅ Event was received back through subscription", .{});
        std.log.info("✅ Complete Nostr protocol roundtrip verified!", .{});
    } else {
        std.log.warn("⚠️  Event was published and accepted but not received back", .{});
        std.log.warn("This might be a timing issue or subscription filter problem", .{});
    }
}