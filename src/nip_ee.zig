const std = @import("std");
const mls_messages = @import("mls/mls_messages.zig");
const nip44 = @import("nip44/v2.zig");
const crypto = @import("crypto.zig");

/// Errors specific to NIP-EE operations
pub const NipEEError = error{
    InvalidExporterSecret,
    MLSSerializationFailed,
    NIP44EncryptionFailed,
    NIP44DecryptionFailed,
    MLSDeserializationFailed,
    InvalidGroupState,
};

/// Create and encrypt a NIP-EE group message
/// This combines MLS message creation with NIP-44 encryption per the spec
pub fn createEncryptedGroupMessage(
    allocator: std.mem.Allocator,
    mls_allocator: std.mem.Allocator,
    group_id: [32]u8,
    epoch: u64,
    sender_index: u32,
    message_content: []const u8,
    mls_signature: []const u8,
    exporter_secret: [32]u8,
) ![]u8 {
    // Step 1: Create MLS message using the provided MLS allocator
    const mls_message = try mls_messages.createGroupEventMLSMessage(
        mls_allocator,
        group_id,
        epoch,
        sender_index,
        message_content,
        mls_signature,
    );
    // Note: Caller is responsible for MLS allocator cleanup
    
    // Step 2: Serialize MLS message to TLS wire format
    const serialized_mls = try mls_messages.serializeMLSMessageForEncryption(mls_allocator, mls_message);
    // Note: Caller is responsible for MLS allocator cleanup
    
    // Step 3: Encrypt with NIP-44 using exporter secret as private key
    // Use the main allocator for the final result that will be returned
    const encrypted = try encryptWithExporterSecret(allocator, exporter_secret, serialized_mls);
    
    return encrypted;
}

/// Decrypt and deserialize a NIP-EE group message
/// Returns the decrypted message content - caller must free it
pub fn decryptGroupMessage(
    allocator: std.mem.Allocator,
    mls_allocator: std.mem.Allocator,
    encrypted_content: []const u8,
    exporter_secret: [32]u8,
) ![]u8 {
    // Step 1: Decrypt NIP-44 layer using exporter secret
    const decrypted_mls = try decryptWithExporterSecret(allocator, exporter_secret, encrypted_content);
    defer allocator.free(decrypted_mls);
    
    // Step 2: Deserialize MLS message from TLS wire format using the provided MLS allocator
    const mls_message = try mls_messages.deserializeMLSMessageFromDecryption(mls_allocator, decrypted_mls);
    // Note: Caller is responsible for MLS allocator cleanup
    
    // Step 3: Extract the application data and return a copy allocated with the main allocator
    const app_data = mls_message.plaintext.content.application.data;
    const result = try allocator.dupe(u8, app_data);
    
    return result;
}

/// Encrypt data with NIP-44 using exporter secret as per NIP-EE spec
fn encryptWithExporterSecret(
    allocator: std.mem.Allocator,
    exporter_secret: [32]u8,
    plaintext: []const u8,
) ![]u8 {
    // Per NIP-EE spec: use exporter_secret as private key
    var private_key = exporter_secret;
    
    // Ensure valid secp256k1 key
    private_key = crypto.generateValidSecp256k1Key(private_key) catch return NipEEError.InvalidExporterSecret;
    
    // Calculate public key for self-encryption
    const public_key = crypto.getPublicKeyForNip44(private_key) catch return NipEEError.InvalidExporterSecret;
    
    // Use NIP-44 v2 encryption (raw bytes for WASM compatibility)
    return nip44.encryptRaw(allocator, private_key, public_key, plaintext) catch NipEEError.NIP44EncryptionFailed;
}

/// Decrypt data with NIP-44 using exporter secret
fn decryptWithExporterSecret(
    allocator: std.mem.Allocator,
    exporter_secret: [32]u8,
    ciphertext: []const u8,
) ![]u8 {
    // Same key derivation as encryption
    var private_key = exporter_secret;
    private_key = crypto.generateValidSecp256k1Key(private_key) catch return NipEEError.InvalidExporterSecret;
    const public_key = crypto.getPublicKeyForNip44(private_key) catch return NipEEError.InvalidExporterSecret;
    
    // Use NIP-44 v2 decryption (raw bytes)
    return nip44.decryptBytes(allocator, private_key, public_key, ciphertext) catch NipEEError.NIP44DecryptionFailed;
}

/// Generate MLS exporter secret with "nostr" label as per spec
pub fn generateExporterSecret(
    allocator: std.mem.Allocator,
    group_state: []const u8,
) ![32]u8 {
    // This is a simplified version - in real implementation, this would
    // use MLS protocol to derive exporter secret with "nostr" label
    _ = allocator;
    
    var exporter_secret: [32]u8 = undefined;
    
    // For now, hash the group state to get a deterministic secret
    // Real implementation would use MLS exporter with "nostr" label
    std.crypto.hash.sha2.Sha256.hash(group_state, &exporter_secret, .{});
    
    return exporter_secret;
}

// Tests
test "NIP-EE round trip" {
    const allocator = std.testing.allocator;
    
    // Test data
    const group_id: [32]u8 = [_]u8{0x01} ** 32;
    const epoch: u64 = 1;
    const sender_index: u32 = 0;
    const message = "Hello, NIP-EE!";
    const signature = [_]u8{0x00} ** 64;
    const exporter_secret: [32]u8 = [_]u8{0x42} ** 32;
    
    // Encrypt
    const encrypted = try createEncryptedGroupMessage(
        allocator,
        group_id,
        epoch,
        sender_index,
        message,
        &signature,
        exporter_secret,
    );
    defer allocator.free(encrypted);
    
    // Decrypt
    var decrypted = try decryptGroupMessage(allocator, encrypted, exporter_secret);
    defer decrypted.deinit(allocator);
    
    // Verify
    try std.testing.expectEqual(epoch, decrypted.confirmed_transcript_hash.epoch);
    try std.testing.expectEqualSlices(u8, &group_id, &decrypted.confirmed_transcript_hash.group_id);
    
    if (decrypted.content) |content| {
        switch (content) {
            .application => |app| {
                try std.testing.expectEqualSlices(u8, message, app.data);
            },
            else => return error.UnexpectedContentType,
        }
    }
}