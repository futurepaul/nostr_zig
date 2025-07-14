const std = @import("std");
const nostr = @import("nostr");

const log = std.log.scoped(.publish_kp);

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    log.info("🚀 Generating test KeyPackages", .{});

    // Initialize MLS provider
    var provider = nostr.mls.provider.MlsProvider.init(allocator);

    // Generate a few test KeyPackages
    const num_keypackages = 3;
    var i: u32 = 0;
    while (i < num_keypackages) : (i += 1) {
        // Generate a test Nostr private key
        var prng = std.Random.DefaultPrng.init(@intCast(std.time.milliTimestamp() + i));
        const random = prng.random();
        
        var nostr_private_key: [32]u8 = undefined;
        random.bytes(&nostr_private_key);
        
        // Generate KeyPackage
        const keypackage = try nostr.mls.key_packages.generateKeyPackage(
            allocator,
            &provider,
            nostr_private_key,
            .{
                .cipher_suite = .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                .lifetime_seconds = 7 * 24 * 60 * 60, // 7 days
            },
        );
        defer deallocateKeyPackage(allocator, keypackage);

        // Serialize for Nostr
        const keypackage_hex = try nostr.mls.key_packages.serializeForNostrEvent(allocator, keypackage);
        defer allocator.free(keypackage_hex);

        // Get public key
        const nostr_pubkey = try nostr.crypto.getPublicKey(nostr_private_key);
        const pubkey_hex = std.fmt.bytesToHex(nostr_pubkey, .lower);

        // Create simple event
        const event_json = try std.fmt.allocPrint(allocator,
            \\{{"id":"{s}","pubkey":"{s}","created_at":{},"kind":443,"tags":[],"content":"{s}","sig":"{s}"}}
        , .{
            &pubkey_hex,
            &pubkey_hex,
            std.time.timestamp(),
            keypackage_hex,
            &([_]u8{'0'} ** 128),
        });
        defer allocator.free(event_json);

        // Save to file for manual publishing
        const filename = try std.fmt.allocPrint(allocator, "keypackage_{}.json", .{i});
        defer allocator.free(filename);
        
        const file = try std.fs.cwd().createFile(filename, .{});
        defer file.close();
        
        try file.writeAll(event_json);
        log.info("✅ KeyPackage #{} saved to {s}", .{i + 1, filename});
    }

    log.info("🎉 Generated {} test KeyPackages!", .{num_keypackages});
    log.info("You can publish them with: cat keypackage_*.json | nak publish", .{});
}

fn deallocateKeyPackage(allocator: std.mem.Allocator, keypackage: nostr.mls.types.KeyPackage) void {
    // Free allocated fields
    if (keypackage.init_key.data.len > 0) {
        allocator.free(keypackage.init_key.data);
    }
    
    // Free leaf node fields
    if (keypackage.leaf_node.encryption_key.data.len > 0) {
        allocator.free(keypackage.leaf_node.encryption_key.data);
    }
    if (keypackage.leaf_node.signature_key.data.len > 0) {
        allocator.free(keypackage.leaf_node.signature_key.data);
    }
    
    // Free credential
    switch (keypackage.leaf_node.credential) {
        .basic => |basic| {
            if (basic.identity.len > 0) {
                allocator.free(basic.identity);
            }
        },
        else => {},
    }
    
    // Free capabilities arrays
    if (keypackage.leaf_node.capabilities.versions.len > 0) {
        allocator.free(keypackage.leaf_node.capabilities.versions);
    }
    if (keypackage.leaf_node.capabilities.ciphersuites.len > 0) {
        allocator.free(keypackage.leaf_node.capabilities.ciphersuites);
    }
    if (keypackage.leaf_node.capabilities.extensions.len > 0) {
        allocator.free(keypackage.leaf_node.capabilities.extensions);
    }
    if (keypackage.leaf_node.capabilities.proposals.len > 0) {
        allocator.free(keypackage.leaf_node.capabilities.proposals);
    }
    if (keypackage.leaf_node.capabilities.credentials.len > 0) {
        allocator.free(keypackage.leaf_node.capabilities.credentials);
    }
    
    // Free extensions
    for (keypackage.leaf_node.extensions) |ext| {
        if (ext.extension_data.len > 0) {
            allocator.free(ext.extension_data);
        }
    }
    if (keypackage.leaf_node.extensions.len > 0) {
        allocator.free(keypackage.leaf_node.extensions);
    }
    
    // Free signature
    if (keypackage.leaf_node.signature.len > 0) {
        allocator.free(keypackage.leaf_node.signature);
    }
    
    // Free keypackage extensions and signature
    for (keypackage.extensions) |ext| {
        if (ext.extension_data.len > 0) {
            allocator.free(ext.extension_data);
        }
    }
    if (keypackage.extensions.len > 0) {
        allocator.free(keypackage.extensions);
    }
    
    if (keypackage.signature.len > 0) {
        allocator.free(keypackage.signature);
    }
}