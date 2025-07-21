const std = @import("std");
const crypto = @import("../crypto.zig");
const event = @import("../nostr/event.zig");
const nip44 = @import("../nip44/mod.zig");
const wasm_random = @import("../wasm_random.zig");
const wasm_time = @import("../wasm_time.zig");

/// NIP-59 Gift Wrap Implementation  
/// Gift wrapping provides metadata protection by creating a layered event structure:
/// 1. Rumor - The actual unsigned event content
/// 2. Seal (kind 13) - Encrypts the rumor, signed by sender
/// 3. Gift Wrap (kind 1059) - Wraps the seal with ephemeral keys

pub const Rumor = struct {
    /// Create a rumor (unsigned event) from a signed event
    pub fn fromEvent(allocator: std.mem.Allocator, signed_event: event.Event) !event.Event {
        // Create unsigned version by copying all fields except sig
        var rumor_tags = try allocator.alloc([]const []const u8, signed_event.tags.len);
        for (signed_event.tags, 0..) |tag, i| {
            rumor_tags[i] = try allocator.alloc([]const u8, tag.len);
            for (tag, 0..) |tag_str, j| {
                rumor_tags[i][j] = try allocator.dupe(u8, tag_str);
            }
        }
        
        return event.Event{
            .id = try allocator.dupe(u8, signed_event.id),
            .pubkey = try allocator.dupe(u8, signed_event.pubkey),
            .created_at = signed_event.created_at,
            .kind = signed_event.kind,
            .tags = rumor_tags,
            .content = try allocator.dupe(u8, signed_event.content),
            .sig = "", // Unsigned!
        };
    }
};

pub const SealedEvent = struct {
    /// Create a sealed event (kind: 13) from a rumor
    pub fn create(
        allocator: std.mem.Allocator,
        sender_privkey: [32]u8,
        recipient_pubkey: [32]u8,
        rumor: event.Event,
    ) !event.Event {
        // Ensure rumor is unsigned
        if (rumor.sig.len > 0) {
            return error.RumorMustBeUnsigned;
        }
        
        // Serialize the rumor to JSON
        const rumor_json = try rumor.toJson(allocator);
        defer allocator.free(rumor_json);
        
        // Encrypt using NIP-44
        const encrypted = try nip44.encrypt(
            allocator,
            sender_privkey,
            recipient_pubkey,
            rumor_json,
        );
        // Note: Event now owns the encrypted memory - don't free here
        
        // Create seal event (kind: 13) with random timestamp tweak
        const now = wasm_time.timestamp();
        var random_bytes: [8]u8 = undefined;
        wasm_random.secure_random.bytes(&random_bytes);
        const random_val = std.mem.readInt(u64, &random_bytes, .little);
        const tweak_seconds = @as(i64, @intCast(random_val % 172800)); // 0-2 days
        const tweaked_timestamp = now - tweak_seconds;
        
        const tags = try allocator.alloc([]const []const u8, 0);
        
        const sender_pubkey_hex = try crypto.pubkeyToHex(allocator, try crypto.getPublicKey(sender_privkey));
        
        const seal_event = event.Event{
            .id = try generateEventId(allocator),
            .pubkey = sender_pubkey_hex,
            .created_at = tweaked_timestamp,
            .kind = 13,
            .tags = tags,
            .content = encrypted,
            .sig = try generateDummySig(allocator), // Would be properly signed
        };
        
        return seal_event;
    }
};

pub const GiftWrap = struct {
    /// Create a gift-wrapped event (kind: 1059)
    pub fn wrap(
        allocator: std.mem.Allocator,
        recipient_pubkey: [32]u8,
        sealed_event: event.Event,
    ) !event.Event {
        // Generate ephemeral keypair
        const ephemeral_privkey = try crypto.generatePrivateKey();
        const ephemeral_pubkey = try crypto.getPublicKey(ephemeral_privkey);
        
        // Serialize sealed event
        const sealed_json = try sealed_event.toJson(allocator);
        defer allocator.free(sealed_json);
        
        // Encrypt sealed event with ephemeral keys  
        const encrypted = try nip44.encrypt(
            allocator,
            ephemeral_privkey,
            recipient_pubkey,
            sealed_json,
        );
        // Note: Event now owns the encrypted memory - don't free here
        
        // Create p tag for recipient
        const p_tag = try allocator.alloc([]const u8, 2);
        p_tag[0] = try allocator.dupe(u8, "p");
        p_tag[1] = try crypto.pubkeyToHex(allocator, recipient_pubkey);
        
        const tags = try allocator.alloc([]const []const u8, 1);
        tags[0] = p_tag;
        
        // Random timestamp between 2 weeks ago and now (as per NIP-59)
        const now = wasm_time.timestamp();
        const two_weeks_ago = now - (14 * 24 * 60 * 60);
        var random_bytes: [8]u8 = undefined;
        wasm_random.secure_random.bytes(&random_bytes);
        const random_val = std.mem.readInt(u64, &random_bytes, .little);
        const time_range = @as(u64, @intCast(now - two_weeks_ago));
        const random_offset = @as(i64, @intCast(random_val % time_range));
        const random_timestamp = two_weeks_ago + random_offset;
        
        const ephemeral_pubkey_hex = try crypto.pubkeyToHex(allocator, ephemeral_pubkey);
        
        const wrap_event = event.Event{
            .id = try generateEventId(allocator),
            .pubkey = ephemeral_pubkey_hex,
            .created_at = random_timestamp,
            .kind = 1059,
            .tags = tags,
            .content = encrypted,
            .sig = try generateDummySig(allocator), // Would be properly signed with ephemeral key
        };
        
        return wrap_event;
    }
    
    /// Unwrap a gift-wrapped event
    pub fn unwrap(
        allocator: std.mem.Allocator,
        wrapped_event: event.Event,
        recipient_privkey: [32]u8,
    ) !event.Event {
        // Check it's a gift wrap event
        if (wrapped_event.kind != 1059) {
            return error.NotGiftWrap;
        }
        
        // Get sender's ephemeral public key
        const sender_pubkey = try crypto.hexToPubkey(wrapped_event.pubkey);
        
        // Decrypt the content
        const decrypted = try nip44.decrypt(
            allocator,
            recipient_privkey,
            sender_pubkey,
            wrapped_event.content,
        );
        defer allocator.free(decrypted);
        
        // Parse the sealed event
        const sealed_event = try event.Event.fromJson(allocator, decrypted);
        
        return sealed_event;
    }
    
    /// Unwrap and decrypt the inner event
    pub fn unwrapAndDecrypt(
        allocator: std.mem.Allocator,
        wrapped_event: event.Event,
        recipient_privkey: [32]u8,
    ) !event.Event {
        // First unwrap to get sealed event
        const sealed_event = try unwrap(allocator, wrapped_event, recipient_privkey);
        defer sealed_event.deinit(allocator);
        
        // Check it's a sealed event
        if (sealed_event.kind != 13) {
            return error.NotSealedEvent;
        }
        
        // Get sender's public key
        const sender_pubkey = try crypto.hexToPubkey(sealed_event.pubkey);
        
        // Decrypt the inner content
        const decrypted = try nip44.decrypt(
            allocator,
            recipient_privkey,
            sender_pubkey,
            sealed_event.content,
        );
        defer allocator.free(decrypted);
        
        // Parse and return the inner event
        return try event.Event.fromJson(allocator, decrypted);
    }
};

/// Helper to create a fully gift-wrapped event in one step  
/// Takes a rumor (unsigned event) and creates the full NIP-59 gift wrap
pub fn createGiftWrappedEvent(
    allocator: std.mem.Allocator,
    sender_privkey: [32]u8,
    recipient_pubkey: [32]u8,
    rumor: event.Event,
) !event.Event {
    // Ensure it's an unsigned rumor
    if (rumor.sig.len > 0) {
        return error.RumorMustBeUnsigned;
    }
    
    // Create sealed event
    const sealed = try SealedEvent.create(
        allocator,
        sender_privkey,
        recipient_pubkey,
        rumor,
    );
    defer sealed.deinit(allocator);
    
    // Wrap it
    return try GiftWrap.wrap(allocator, recipient_pubkey, sealed);
}

// Helper functions

fn generateEventId(allocator: std.mem.Allocator) ![]const u8 {
    // Generate a temporary event ID
    var random_bytes: [32]u8 = undefined;
    wasm_random.secure_random.bytes(&random_bytes);
    
    const hex_id = try allocator.alloc(u8, 64);
    _ = std.fmt.bufPrint(hex_id, "{}", .{std.fmt.fmtSliceHexLower(&random_bytes)}) catch unreachable;
    
    return hex_id;
}

fn generateDummySig(allocator: std.mem.Allocator) ![]const u8 {
    // Generate a dummy signature for testing
    var random_bytes: [64]u8 = undefined;
    wasm_random.secure_random.bytes(&random_bytes);
    
    const hex_sig = try allocator.alloc(u8, 128);
    _ = std.fmt.bufPrint(hex_sig, "{}", .{std.fmt.fmtSliceHexLower(&random_bytes)}) catch unreachable;
    
    return hex_sig;
}

test "gift wrap and unwrap" {
    const allocator = std.testing.allocator;
    
    // Generate test keys
    const alice_privkey = try crypto.generatePrivateKey();
    const alice_pubkey = try crypto.getPublicKey(alice_privkey);
    const bob_privkey = try crypto.generatePrivateKey();
    const bob_pubkey = try crypto.getPublicKey(bob_privkey);
    
    // Create rumor (unsigned event)
    const tags = try allocator.alloc([]const []const u8, 0);
    defer allocator.free(tags);
    
    const rumor = event.Event{
        .id = "test_id",
        .pubkey = try crypto.pubkeyToHex(allocator, alice_pubkey),
        .created_at = std.time.timestamp(),
        .kind = 444, // Welcome event
        .tags = tags,
        .content = "Welcome message content",
        .sig = "", // Unsigned rumor!
    };
    defer allocator.free(rumor.pubkey);
    
    // Create gift-wrapped event
    const wrapped = try createGiftWrappedEvent(
        allocator,
        alice_privkey,
        bob_pubkey,
        rumor,
    );
    defer wrapped.deinit(allocator);
    
    // Verify it's a gift wrap
    try std.testing.expectEqual(@as(u32, 1059), wrapped.kind);
    
    // Unwrap and decrypt
    const unwrapped = try GiftWrap.unwrapAndDecrypt(
        allocator,
        wrapped,
        bob_privkey,
    );
    defer unwrapped.deinit(allocator);
    
    // Verify we got the original content back
    try std.testing.expectEqual(rumor.kind, unwrapped.kind);
    try std.testing.expectEqualStrings(rumor.content, unwrapped.content);
}