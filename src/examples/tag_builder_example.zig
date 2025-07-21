const std = @import("std");
const nostr = @import("nostr");

// Example: Creating tags the OLD way (error-prone)
fn createTagsOldWay(allocator: std.mem.Allocator) ![]const []const []const u8 {
    var tags_list = std.ArrayList([]const []const u8).init(allocator);
    defer tags_list.deinit();
    
    // Create an "e" tag - lots of manual allocation
    const e_tag = try allocator.alloc([]const u8, 2);
    e_tag[0] = try allocator.dupe(u8, "e");
    e_tag[1] = try allocator.dupe(u8, "event_id_here");
    try tags_list.append(e_tag);
    
    // Create a "p" tag - more manual allocation
    const p_tag = try allocator.alloc([]const u8, 2);
    p_tag[0] = try allocator.dupe(u8, "p");
    p_tag[1] = try allocator.dupe(u8, "pubkey_here");
    try tags_list.append(p_tag);
    
    // Create relay tags
    const relays = [_][]const u8{ "wss://relay1.com", "wss://relay2.com" };
    for (relays) |relay| {
        const r_tag = try allocator.alloc([]const u8, 2);
        r_tag[0] = try allocator.dupe(u8, "r");
        r_tag[1] = try allocator.dupe(u8, relay);
        try tags_list.append(r_tag);
    }
    
    return try tags_list.toOwnedSlice();
}

// Example: Creating tags the NEW way (safe and simple)
fn createTagsNewWay(allocator: std.mem.Allocator) ![]const []const []const u8 {
    var builder = nostr.TagBuilder.init(allocator);
    defer builder.deinit();
    
    // Simple, type-safe tag creation
    try builder.addEventTag("event_id_here");
    try builder.addPubkeyTag("pubkey_here");
    
    // Add relay tags
    const relays = [_][]const u8{ "wss://relay1.com", "wss://relay2.com" };
    for (relays) |relay| {
        try builder.addRelayTag(relay);
    }
    
    // Custom tag with multiple values
    try builder.add(&.{ "custom", "value1", "value2", "value3" });
    
    return try builder.build();
}

// Example: Using createTagBatch for efficiency
fn createTagsBatch(allocator: std.mem.Allocator) ![]const []const []const u8 {
    const tags_data = [_][]const []const u8{
        &[_][]const u8{ "e", "event_id_here" },
        &[_][]const u8{ "p", "pubkey_here" },
        &[_][]const u8{ "r", "wss://relay1.com" },
        &[_][]const u8{ "r", "wss://relay2.com" },
        &[_][]const u8{ "custom", "value1", "value2", "value3" },
    };
    
    // Efficient batch allocation
    return try nostr.createTagBatch(allocator, &tags_data);
}

// Example: Using TagBuilder with EventBuilder
fn createEventWithTags(allocator: std.mem.Allocator, private_key: [32]u8) !nostr.Event {
    var tag_builder = nostr.TagBuilder.init(allocator);
    defer tag_builder.deinit();
    
    // Build tags
    try tag_builder.addEventTag("replying_to_this_event");
    try tag_builder.addPubkeyTag("mentioning_this_user");
    try tag_builder.addSubjectTag("Re: Important Topic");
    
    // Create event with the tags
    const builder = nostr.EventBuilder.initWithKey(allocator, private_key);
    return try builder.build(.{
        .kind = 1, // Text note
        .content = "This is a reply with proper tags!",
        .tags = try tag_builder.build(),
    });
}

test "compare old vs new tag creation" {
    const allocator = std.testing.allocator;
    
    // Old way
    const old_tags = try createTagsOldWay(allocator);
    defer {
        // Manual cleanup is error-prone
        for (old_tags) |tag| {
            for (tag) |value| {
                allocator.free(value);
            }
            allocator.free(tag);
        }
        allocator.free(old_tags);
    }
    
    // New way
    const new_tags = try createTagsNewWay(allocator);
    defer allocator.free(new_tags); // Much simpler cleanup!
    
    // Batch way
    const batch_tags = try createTagsBatch(allocator);
    defer nostr.freeTagBatch(allocator, batch_tags); // Batch cleanup!
    
    // All produce the same result
    try std.testing.expectEqual(old_tags.len, new_tags.len);
    try std.testing.expectEqual(old_tags.len, batch_tags.len);
}