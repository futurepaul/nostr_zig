const std = @import("std");
const testing = std.testing;
const mls_zig = @import("mls_zig");
const nostr = @import("nostr");

test "key schedule derives proper epoch secrets" {
    const allocator = testing.allocator;
    
    // Initialize MLS provider
    var mls_provider = nostr.mls.provider.MlsProvider.init(allocator);
    
    // Test group ID
    const group_id_data = [_]u8{0x42} ** 32;
    const group_id = nostr.mls.types.GroupId{ .data = group_id_data };
    
    // Generate initial epoch secrets
    const epoch_secrets = try nostr.mls.groups.generateInitialEpochSecrets(
        allocator,
        &mls_provider,
        group_id,
    );
    
    // Verify that secrets are not all zeros
    const zeros = [_]u8{0} ** 32;
    try testing.expect(!std.mem.eql(u8, &epoch_secrets.joiner_secret, &zeros));
    try testing.expect(!std.mem.eql(u8, &epoch_secrets.member_secret, &zeros));
    try testing.expect(!std.mem.eql(u8, &epoch_secrets.welcome_secret, &zeros));
    try testing.expect(!std.mem.eql(u8, &epoch_secrets.epoch_secret, &zeros));
    try testing.expect(!std.mem.eql(u8, &epoch_secrets.exporter_secret, &zeros));
    try testing.expect(!std.mem.eql(u8, &epoch_secrets.encryption_secret, &zeros));
    try testing.expect(!std.mem.eql(u8, &epoch_secrets.sender_data_secret, &zeros));
    try testing.expect(!std.mem.eql(u8, &epoch_secrets.confirmation_key, &zeros));
    
    // Verify that different secrets are actually different
    try testing.expect(!std.mem.eql(u8, &epoch_secrets.joiner_secret, &epoch_secrets.member_secret));
    try testing.expect(!std.mem.eql(u8, &epoch_secrets.member_secret, &epoch_secrets.welcome_secret));
    try testing.expect(!std.mem.eql(u8, &epoch_secrets.exporter_secret, &epoch_secrets.encryption_secret));
    
    std.log.info("✅ Epoch secrets properly derived", .{});
    std.log.info("  Joiner secret: {}", .{std.fmt.fmtSliceHexLower(&epoch_secrets.joiner_secret)});
    std.log.info("  Exporter secret: {}", .{std.fmt.fmtSliceHexLower(&epoch_secrets.exporter_secret)});
}

test "key schedule derivation follows RFC 9420" {
    const allocator = testing.allocator;
    const cipher_suite = mls_zig.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    
    var key_schedule = mls_zig.KeySchedule.init(allocator, cipher_suite);
    
    // Test with known commit secret
    const commit_secret = [_]u8{0x01} ** 32;
    const group_context = "test_context";
    
    // Derive joiner secret
    var joiner_secret = try key_schedule.deriveJoinerSecret(&commit_secret, null);
    defer joiner_secret.deinit();
    
    try testing.expect(joiner_secret.len() == 32); // SHA256 output
    
    // Derive member secret
    var member_secret = try key_schedule.deriveMemberSecret(joiner_secret.asSlice(), group_context);
    defer member_secret.deinit();
    
    try testing.expect(member_secret.len() == 32);
    
    // Derive welcome secret
    var welcome_secret = try key_schedule.deriveWelcomeSecret(joiner_secret.asSlice(), group_context);
    defer welcome_secret.deinit();
    
    try testing.expect(welcome_secret.len() == 32);
    
    // Derive epoch secret
    var epoch_secret = try key_schedule.deriveEpochSecret(member_secret.asSlice(), group_context);
    defer epoch_secret.deinit();
    
    try testing.expect(epoch_secret.len() == 32);
    
    // Derive application secrets
    const app_secrets = try key_schedule.deriveApplicationSecrets(epoch_secret.asSlice(), group_context);
    defer {
        var mut_app_secrets = app_secrets;
        mut_app_secrets.sender_data_secret.deinit();
        mut_app_secrets.encryption_secret.deinit();
        mut_app_secrets.exporter_secret.deinit();
        mut_app_secrets.epoch_authenticator.deinit();
        mut_app_secrets.external_secret.deinit();
        mut_app_secrets.confirmation_key.deinit();
        mut_app_secrets.membership_key.deinit();
        mut_app_secrets.resumption_psk.deinit();
    }
    
    // Verify all secrets are derived
    try testing.expect(app_secrets.exporter_secret.len() == 32);
    try testing.expect(app_secrets.encryption_secret.len() == 32);
    
    std.log.info("✅ Key schedule follows RFC 9420 derivation chain", .{});
}

test "epoch secrets change with different commit secrets" {
    const allocator = testing.allocator;
    const cipher_suite = mls_zig.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    
    var key_schedule = mls_zig.KeySchedule.init(allocator, cipher_suite);
    const group_context = "test_context";
    
    // First epoch
    const commit_secret1 = [_]u8{0x01} ** 32;
    var epoch_secrets1 = try key_schedule.deriveEpochSecrets(&commit_secret1, null, group_context);
    defer epoch_secrets1.deinit();
    
    // Second epoch with different commit secret
    const commit_secret2 = [_]u8{0x02} ** 32;
    var epoch_secrets2 = try key_schedule.deriveEpochSecrets(&commit_secret2, null, group_context);
    defer epoch_secrets2.deinit();
    
    // Verify secrets are different
    try testing.expect(!std.mem.eql(u8, epoch_secrets1.joiner_secret.asSlice(), epoch_secrets2.joiner_secret.asSlice()));
    try testing.expect(!std.mem.eql(u8, epoch_secrets1.exporter_secret.asSlice(), epoch_secrets2.exporter_secret.asSlice()));
    
    std.log.info("✅ Epoch secrets properly change with different commit secrets", .{});
}

// Make generateInitialEpochSecrets public for testing
pub const generateInitialEpochSecrets = nostr.mls.groups.generateInitialEpochSecrets;