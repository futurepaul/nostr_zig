const std = @import("std");
const nostr = @import("nostr.zig");

// Test cases for various Nostr event types
// Based on NIPs from https://github.com/nostr-protocol/nips

pub const TestEvent = struct {
    name: []const u8,
    kind: u32,
    content: []const u8,
    tags: []const []const []const u8,
    expected_valid: bool,
};

pub const test_events = [_]TestEvent{
    // Kind 0: User Metadata
    .{
        .name = "user_metadata",
        .kind = 0,
        .content = 
        \\{"name":"alice","about":"Nostr enthusiast","picture":"https://example.com/alice.jpg","nip05":"alice@example.com"}
        ,
        .tags = &[_][]const []const u8{},
        .expected_valid = true,
    },
    .{
        .name = "user_metadata_minimal",
        .kind = 0,
        .content = 
        \\{"name":"bob"}
        ,
        .tags = &[_][]const []const u8{},
        .expected_valid = true,
    },

    // Kind 1: Short Text Note
    .{
        .name = "simple_text_note",
        .kind = 1,
        .content = "Hello, Nostr!",
        .tags = &[_][]const []const u8{},
        .expected_valid = true,
    },
    .{
        .name = "text_note_with_hashtag",
        .kind = 1,
        .content = "Building on Nostr is fun! #nostr #zig",
        .tags = &[_][]const []const u8{
            &[_][]const u8{ "t", "nostr" },
            &[_][]const u8{ "t", "zig" },
        },
        .expected_valid = true,
    },
    .{
        .name = "text_note_with_mention",
        .kind = 1,
        .content = "Hey nostr:npub1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsxlf9e3, check this out!",
        .tags = &[_][]const []const u8{
            &[_][]const u8{ "p", "000000000000000000000000000000000000000000000000000000000001d269", "wss://relay.example.com" },
        },
        .expected_valid = true,
    },
    .{
        .name = "reply_text_note",
        .kind = 1,
        .content = "I agree with this!",
        .tags = &[_][]const []const u8{
            &[_][]const u8{ "e", "5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36", "wss://relay.example.com", "root" },
            &[_][]const u8{ "e", "a3c5ce848013ff4d89c9be2afa0ca2b67c66a73a4179fcf0c45e8438195de69f", "wss://relay.example.com", "reply" },
            &[_][]const u8{ "p", "85672b1d7cd7fb35881e91ec5083dc4f8dc6b8d3f44b02bf99c172d67da70645" },
        },
        .expected_valid = true,
    },

    // Kind 3: Follows (Contact List)
    .{
        .name = "follow_list",
        .kind = 3,
        .content = "",
        .tags = &[_][]const []const u8{
            &[_][]const u8{ "p", "85672b1d7cd7fb35881e91ec5083dc4f8dc6b8d3f44b02bf99c172d67da70645", "wss://relay.damus.io", "alice" },
            &[_][]const u8{ "p", "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d", "wss://nos.lol", "bob" },
        },
        .expected_valid = true,
    },

    // Kind 4: Encrypted Direct Message (deprecated, but still common)
    .{
        .name = "encrypted_dm",
        .kind = 4,
        .content = "hH1HlQWY3dz7IzJlgnEgW1WNtA0KlvGgo2kquC2DOLkwAAAAAAAAAABhwx9BpFYJZhV+9wZfbVzBP0vYz5k55Lh5IyeVwrWqUQ==?iv=7/1uHitFVfKKVhFhXBYh3g==",
        .tags = &[_][]const []const u8{
            &[_][]const u8{ "p", "85672b1d7cd7fb35881e91ec5083dc4f8dc6b8d3f44b02bf99c172d67da70645" },
        },
        .expected_valid = true,
    },

    // Kind 5: Event Deletion Request
    .{
        .name = "delete_event",
        .kind = 5,
        .content = "Deleted by author",
        .tags = &[_][]const []const u8{
            &[_][]const u8{ "e", "5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36" },
            &[_][]const u8{ "e", "a3c5ce848013ff4d89c9be2afa0ca2b67c66a73a4179fcf0c45e8438195de69f" },
        },
        .expected_valid = true,
    },

    // Kind 6: Repost
    .{
        .name = "repost",
        .kind = 6,
        .content = "",
        .tags = &[_][]const []const u8{
            &[_][]const u8{ "e", "5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36", "wss://relay.example.com" },
            &[_][]const u8{ "p", "85672b1d7cd7fb35881e91ec5083dc4f8dc6b8d3f44b02bf99c172d67da70645" },
        },
        .expected_valid = true,
    },

    // Kind 7: Reaction
    .{
        .name = "reaction_like",
        .kind = 7,
        .content = "+",
        .tags = &[_][]const []const u8{
            &[_][]const u8{ "e", "5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36" },
            &[_][]const u8{ "p", "85672b1d7cd7fb35881e91ec5083dc4f8dc6b8d3f44b02bf99c172d67da70645" },
        },
        .expected_valid = true,
    },
    .{
        .name = "reaction_emoji",
        .kind = 7,
        .content = "🚀",
        .tags = &[_][]const []const u8{
            &[_][]const u8{ "e", "5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36" },
            &[_][]const u8{ "p", "85672b1d7cd7fb35881e91ec5083dc4f8dc6b8d3f44b02bf99c172d67da70645" },
        },
        .expected_valid = true,
    },

    // Kind 14: Direct Message (NIP-17)
    .{
        .name = "direct_message",
        .kind = 14,
        .content = "This is a private message",
        .tags = &[_][]const []const u8{
            &[_][]const u8{ "p", "85672b1d7cd7fb35881e91ec5083dc4f8dc6b8d3f44b02bf99c172d67da70645" },
            &[_][]const u8{ "subject", "Important update" },
        },
        .expected_valid = true,
    },

    // Kind 42: Channel Message
    .{
        .name = "channel_message",
        .kind = 42,
        .content = "Welcome to the Zig channel!",
        .tags = &[_][]const []const u8{
            &[_][]const u8{ "e", "5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36", "wss://relay.example.com", "root" },
        },
        .expected_valid = true,
    },

    // Kind 1063: File Metadata
    .{
        .name = "file_metadata",
        .kind = 1063,
        .content = "My vacation photo",
        .tags = &[_][]const []const u8{
            &[_][]const u8{ "url", "https://example.com/vacation.jpg" },
            &[_][]const u8{ "m", "image/jpeg" },
            &[_][]const u8{ "x", "7d7e4c29a8a8b7e8f19d7f2e8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b" },
            &[_][]const u8{ "size", "2048576" },
            &[_][]const u8{ "blurhash", "L6PZfRjD00ayoMayWBay00ay~qay" },
        },
        .expected_valid = true,
    },

    // Kind 1984: Reporting
    .{
        .name = "report_spam",
        .kind = 1984,
        .content = "spam",
        .tags = &[_][]const []const u8{
            &[_][]const u8{ "e", "5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36" },
            &[_][]const u8{ "p", "85672b1d7cd7fb35881e91ec5083dc4f8dc6b8d3f44b02bf99c172d67da70645" },
        },
        .expected_valid = true,
    },

    // Kind 9734: Zap Request
    .{
        .name = "zap_request",
        .kind = 9734,
        .content = "Great post! ⚡",
        .tags = &[_][]const []const u8{
            &[_][]const u8{ "e", "5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36" },
            &[_][]const u8{ "p", "85672b1d7cd7fb35881e91ec5083dc4f8dc6b8d3f44b02bf99c172d67da70645" },
            &[_][]const u8{ "amount", "1000" },
            &[_][]const u8{ "relays", "wss://relay.damus.io", "wss://nos.lol" },
        },
        .expected_valid = true,
    },

    // Kind 30023: Long-form Content
    .{
        .name = "long_form_article",
        .kind = 30023,
        .content = 
        \\# Building with Nostr and Zig
        \\
        \\This is a longer article about building Nostr clients with Zig.
        \\
        \\## Introduction
        \\
        \\Zig provides excellent performance and safety guarantees...
        ,
        .tags = &[_][]const []const u8{
            &[_][]const u8{ "d", "building-with-nostr-zig" },
            &[_][]const u8{ "title", "Building with Nostr and Zig" },
            &[_][]const u8{ "summary", "An introduction to building Nostr clients with Zig" },
            &[_][]const u8{ "published_at", "1720800000" },
            &[_][]const u8{ "t", "programming" },
            &[_][]const u8{ "t", "zig" },
            &[_][]const u8{ "t", "nostr" },
        },
        .expected_valid = true,
    },

    // Invalid event examples
    .{
        .name = "invalid_empty_content_metadata",
        .kind = 0,
        .content = "",
        .tags = &[_][]const []const u8{},
        .expected_valid = false,
    },
    .{
        .name = "invalid_malformed_json_metadata",
        .kind = 0,
        .content = "{not valid json",
        .tags = &[_][]const []const u8{},
        .expected_valid = false,
    },
};

test "create test events" {
    const allocator = std.testing.allocator;
    
    // Test creating events from our test cases
    for (test_events) |test_event| {
        std.debug.print("\nTesting event: {s}\n", .{test_event.name});
        
        // Here we would create actual Nostr events once we have the full implementation
        // For now, just validate the structure
        try std.testing.expect(test_event.kind >= 0);
        try std.testing.expect(test_event.content.len >= 0);
        
        // Validate JSON content for metadata events
        if (test_event.kind == 0 and test_event.expected_valid) {
            const parsed = std.json.parseFromSlice(std.json.Value, allocator, test_event.content, .{}) catch |err| {
                std.debug.print("Failed to parse JSON for {s}: {}\n", .{ test_event.name, err });
                return err;
            };
            defer parsed.deinit();
            
            // Metadata should have at least a name field
            try std.testing.expect(parsed.value.object.contains("name"));
        }
    }
}

test "event serialization" {
    // Test that we can properly serialize events to JSON
    // This will be implemented once we have the Event struct working
}

test "event signature verification" {
    // Test that we can verify event signatures
    // This will be implemented once we have crypto support
}