const std = @import("std");
const testing = std.testing;
const tls_encode = @import("tls_encode.zig");
const tls = std.crypto.tls;

/// Credential type as defined in MLS protocol
pub const CredentialType = enum(u16) {
    /// Basic credential containing only an identity
    basic = 1,
    /// X.509 certificate (not yet supported)
    x509 = 2,
    
    /// Convert from u16
    pub fn fromU16(value: u16) !CredentialType {
        return switch (value) {
            1 => .basic,
            2 => .x509,
            else => error.UnsupportedCredentialType,
        };
    }
    
    /// Convert to u16
    pub fn toU16(self: CredentialType) u16 {
        return @intFromEnum(self);
    }
    
    /// Get the serialized length
    pub fn tlsSerializedLen(self: *const CredentialType) usize {
        _ = self;
        return 2; // u16
    }
    
    /// Serialize to TLS format
    pub fn tlsSerialize(self: *const CredentialType, writer: anytype) !void {
        try writer.writeInt(u16, self.toU16(), .big);
    }

    /// Serialize to ArrayList (manual TLS format)
    pub fn tlsSerializeToList(self: *const CredentialType, list: *std.ArrayList(u8)) !void {
        try tls_encode.encodeInt(list, u16, self.toU16());
    }
    
    /// Deserialize from TLS format
    pub fn tlsDeserialize(reader: anytype, allocator: std.mem.Allocator) !CredentialType {
        _ = allocator;
        // Read enough bytes for u16
        var buf: [2]u8 = undefined;
        _ = try reader.readAll(&buf);
        var decoder = tls.Decoder.init(&buf);
        const value = decoder.decode(u16);
        return try CredentialType.fromU16(value);
    }
};

/// Basic credential containing only an identity
pub const BasicCredential = struct {
    identity: []u8,
    allocator: std.mem.Allocator,
    
    /// Create a new basic credential
    pub fn init(allocator: std.mem.Allocator, identity: []const u8) !BasicCredential {
        return BasicCredential{
            .identity = try allocator.dupe(u8, identity),
            .allocator = allocator,
        };
    }
    
    /// Clean up allocated memory
    pub fn deinit(self: *BasicCredential) void {
        self.allocator.free(self.identity);
    }
    
    /// Get the identity as a byte slice
    pub fn getIdentity(self: *const BasicCredential) []const u8 {
        return self.identity;
    }
    
    /// Get the serialized length (for TLS encoding)
    pub fn tlsSerializedLen(self: *const BasicCredential) usize {
        // Length prefix (1 byte for u8) + identity data
        return 1 + self.identity.len;
    }
    
    /// Serialize to TLS format (just the identity as variable-length bytes)
    pub fn tlsSerialize(self: *const BasicCredential, writer: anytype) !void {
        try tls_encode.writeVarBytes(writer, u8, self.identity);
    }
    
    /// Deserialize from TLS format
    pub fn tlsDeserialize(reader: anytype, allocator: std.mem.Allocator) !BasicCredential {
        // For backward compatibility, create decoder from reader
        // This assumes reader has enough data
        var buf: [1024]u8 = undefined; // Should be enough for basic credential
        const bytes_read = try reader.read(&buf);
        var decoder = tls.Decoder.fromTheirSlice(buf[0..bytes_read]);
        return try tlsDeserializeDecoder(&decoder, allocator);
    }
    
    pub fn tlsDeserializeDecoder(decoder: *tls.Decoder, allocator: std.mem.Allocator) !BasicCredential {
        const identity_data = try tls_encode.readVarBytes(decoder, u8, allocator);
        errdefer allocator.free(identity_data);
        
        return BasicCredential{
            .identity = identity_data,
            .allocator = allocator,
        };
    }
};

/// X.509 Certificate (placeholder - not fully implemented)
pub const Certificate = struct {
    cert_data: []u8,
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, cert_data: []const u8) !Certificate {
        return Certificate{
            .cert_data = try allocator.dupe(u8, cert_data),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *Certificate) void {
        self.allocator.free(self.cert_data);
    }
};

/// Generic credential that can contain different credential types
pub const Credential = struct {
    credential_type: CredentialType,
    serialized_content: []u8,
    allocator: std.mem.Allocator,
    
    /// Create a new credential from a basic credential
    pub fn fromBasic(allocator: std.mem.Allocator, basic: *const BasicCredential) !Credential {
        // Serialize manually to avoid TlsWriter/ArrayList incompatibility
        var content_buf = std.ArrayList(u8).init(allocator);
        defer content_buf.deinit();
        
        // Serialize BasicCredential manually (writeVarBytes with u8 length prefix)
        const identity_data = basic.identity;
        try tls_encode.encodeVarBytes(&content_buf, u8, identity_data);
        
        return Credential{
            .credential_type = .basic,
            .serialized_content = try content_buf.toOwnedSlice(),
            .allocator = allocator,
        };
    }
    
    /// Create a credential with raw serialized content
    pub fn init(allocator: std.mem.Allocator, credential_type: CredentialType, serialized_content: []const u8) !Credential {
        return Credential{
            .credential_type = credential_type,
            .serialized_content = try allocator.dupe(u8, serialized_content),
            .allocator = allocator,
        };
    }
    
    /// Clean up allocated memory
    pub fn deinit(self: *Credential) void {
        self.allocator.free(self.serialized_content);
    }
    
    /// Get the credential type
    pub fn getType(self: *const Credential) CredentialType {
        return self.credential_type;
    }
    
    /// Get the serialized content
    pub fn getSerializedContent(self: *const Credential) []const u8 {
        return self.serialized_content;
    }
    
    /// Try to extract a basic credential
    pub fn toBasic(self: *const Credential, allocator: std.mem.Allocator) !BasicCredential {
        if (self.credential_type != .basic) {
            return error.WrongCredentialType;
        }
        
        var decoder = tls.Decoder.fromTheirSlice(@constCast(self.serialized_content));
        return try BasicCredential.tlsDeserializeDecoder(&decoder, allocator);
    }
    
    /// Get the serialized length
    pub fn tlsSerializedLen(self: *const Credential) usize {
        // credential_type (2 bytes) + serialized_content length prefix (1 byte) + content
        return 2 + 1 + self.serialized_content.len;
    }
    
    /// Serialize to TLS format
    pub fn tlsSerialize(self: *const Credential, writer: anytype) !void {
        try self.credential_type.tlsSerialize(writer);
        try tls_encode.writeVarBytes(writer, u8, self.serialized_content);
    }

    /// Serialize to ArrayList (manual TLS format)
    pub fn tlsSerializeToList(self: *const Credential, list: *std.ArrayList(u8)) !void {
        try self.credential_type.tlsSerializeToList(list);
        try tls_encode.encodeVarBytes(list, u8, self.serialized_content);
    }
    
    /// Deserialize from TLS format
    pub fn tlsDeserialize(reader: anytype, allocator: std.mem.Allocator) !Credential {
        // Read the credential type first
        const credential_type = try CredentialType.tlsDeserialize(reader, allocator);
        
        // Read the length byte for content
        var len_buf: [1]u8 = undefined;
        _ = try reader.readAll(&len_buf);
        const content_len = len_buf[0];
        
        // Read the content
        const serialized_content = try allocator.alloc(u8, content_len);
        defer allocator.free(serialized_content);
        _ = try reader.readAll(serialized_content);
        
        return Credential{
            .credential_type = credential_type,
            .serialized_content = try allocator.dupe(u8, serialized_content),
            .allocator = allocator,
        };
    }
    
    /// Create a deep copy of this credential
    pub fn clone(self: Credential, allocator: std.mem.Allocator) !Credential {
        return Credential.init(allocator, self.credential_type, self.serialized_content);
    }
    
    /// Create a copy of this credential using arena pattern
    pub fn shareAsCow(self: Credential, allocator: std.mem.Allocator) !Credential {
        return Credential{
            .credential_type = self.credential_type,
            .serialized_content = try allocator.dupe(u8, self.serialized_content),
            .allocator = allocator,
        };
    }
};

// Tests

test "BasicCredential creation and serialization" {
    const allocator = testing.allocator;
    
    const identity = "alice@example.com";
    var basic = try BasicCredential.init(allocator, identity);
    defer basic.deinit();
    
    try testing.expectEqualSlices(u8, identity, basic.getIdentity());
    
    // Test serialization
    var buf: [100]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    
    try basic.tlsSerialize(stream.writer());
    
    // Check serialized format: [length][identity]
    try testing.expectEqual(@as(u8, identity.len), buf[0]);
    try testing.expectEqualSlices(u8, identity, buf[1..1 + identity.len]);
    
    // Test deserialization
    var decoder = tls.Decoder.fromTheirSlice(buf[0..1 + identity.len]);
    
    var deserialized = try BasicCredential.tlsDeserializeDecoder(&decoder, allocator);
    defer deserialized.deinit();
    
    try testing.expectEqualSlices(u8, identity, deserialized.getIdentity());
}

test "Credential with BasicCredential" {
    const allocator = testing.allocator;
    
    const identity = "bob@example.com";
    var basic = try BasicCredential.init(allocator, identity);
    defer basic.deinit();
    
    var credential = try Credential.fromBasic(allocator, &basic);
    defer credential.deinit();
    
    try testing.expectEqual(CredentialType.basic, credential.getType());
    
    // Extract basic credential back
    var extracted = try credential.toBasic(allocator);
    defer extracted.deinit();
    
    try testing.expectEqualSlices(u8, identity, extracted.getIdentity());
}

test "Credential serialization" {
    const allocator = testing.allocator;
    
    const identity = "charlie@example.com";
    var basic = try BasicCredential.init(allocator, identity);
    defer basic.deinit();
    
    var credential = try Credential.fromBasic(allocator, &basic);
    defer credential.deinit();
    
    // Serialize
    var buf: [200]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    
    try credential.tlsSerialize(stream.writer());
    
    // Deserialize
    stream.reset();
    
    var deserialized = try Credential.tlsDeserialize(stream.reader(), allocator);
    defer deserialized.deinit();
    
    try testing.expectEqual(CredentialType.basic, deserialized.getType());
    
    var extracted = try deserialized.toBasic(allocator);
    defer extracted.deinit();
    
    try testing.expectEqualSlices(u8, identity, extracted.getIdentity());
}

test "CredentialType encoding" {
    var buf: [10]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    
    const cred_type = CredentialType.basic;
    try cred_type.tlsSerialize(stream.writer());
    
    try testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, buf[0..2], .big));
    
    stream.reset();
    const decoded = try CredentialType.tlsDeserialize(stream.reader(), testing.allocator);
    try testing.expectEqual(CredentialType.basic, decoded);
}