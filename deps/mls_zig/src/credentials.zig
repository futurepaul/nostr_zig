const std = @import("std");
const testing = std.testing;
const tls_codec = @import("tls_codec.zig");
const TlsWriter = tls_codec.TlsWriter;
const TlsReader = tls_codec.TlsReader;
const VarBytes = tls_codec.VarBytes;

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
        var tls_writer = TlsWriter(@TypeOf(writer)).init(writer);
        try tls_writer.writeU16(self.toU16());
    }

    /// Serialize to ArrayList (manual TLS format)
    pub fn tlsSerializeToList(self: *const CredentialType, list: *std.ArrayList(u8)) !void {
        try tls_codec.writeU16ToList(list, self.toU16());
    }
    
    /// Deserialize from TLS format
    pub fn tlsDeserialize(reader: anytype, allocator: std.mem.Allocator) !CredentialType {
        _ = allocator;
        var tls_reader = TlsReader(@TypeOf(reader)).init(reader);
        const value = try tls_reader.readU16();
        return try CredentialType.fromU16(value);
    }
};

/// Basic credential containing only an identity
pub const BasicCredential = struct {
    identity: VarBytes,
    
    /// Create a new basic credential
    pub fn init(allocator: std.mem.Allocator, identity: []const u8) !BasicCredential {
        return BasicCredential{
            .identity = try VarBytes.init(allocator, identity),
        };
    }
    
    /// Clean up allocated memory
    pub fn deinit(self: *BasicCredential) void {
        self.identity.deinit();
    }
    
    /// Get the identity as a byte slice
    pub fn getIdentity(self: *const BasicCredential) []const u8 {
        return self.identity.asSlice();
    }
    
    /// Get the serialized length (for TLS encoding)
    pub fn tlsSerializedLen(self: *const BasicCredential) usize {
        // Length prefix (1 byte for u8) + identity data
        return 1 + self.identity.asSlice().len;
    }
    
    /// Serialize to TLS format (just the identity as variable-length bytes)
    pub fn tlsSerialize(self: *const BasicCredential, writer: anytype) !void {
        try writer.writeVarBytes(u8, self.identity.asSlice());
    }
    
    /// Deserialize from TLS format
    pub fn tlsDeserialize(reader: anytype, allocator: std.mem.Allocator) !BasicCredential {
        const identity_data = try reader.readVarBytes(u8, allocator);
        errdefer allocator.free(identity_data);
        
        const identity = try VarBytes.init(allocator, identity_data);
        allocator.free(identity_data); // VarBytes makes its own copy
        
        return BasicCredential{
            .identity = identity,
        };
    }
};

/// X.509 Certificate (placeholder - not fully implemented)
pub const Certificate = struct {
    cert_data: VarBytes,
    
    pub fn init(allocator: std.mem.Allocator, cert_data: []const u8) !Certificate {
        return Certificate{
            .cert_data = try VarBytes.init(allocator, cert_data),
        };
    }
    
    pub fn deinit(self: *Certificate) void {
        self.cert_data.deinit();
    }
};

/// Generic credential that can contain different credential types
pub const Credential = struct {
    credential_type: CredentialType,
    serialized_content: VarBytes,
    
    /// Create a new credential from a basic credential
    pub fn fromBasic(allocator: std.mem.Allocator, basic: *const BasicCredential) !Credential {
        // Serialize manually to avoid TlsWriter/ArrayList incompatibility
        var content_buf = std.ArrayList(u8).init(allocator);
        defer content_buf.deinit();
        
        // Serialize BasicCredential manually (writeVarBytes with u8 length prefix)
        const identity_data = basic.identity.asSlice();
        if (identity_data.len > 255) return error.ValueTooLarge;
        try content_buf.append(@intCast(identity_data.len));
        try content_buf.appendSlice(identity_data);
        
        const serialized = try content_buf.toOwnedSlice();
        defer allocator.free(serialized);
        
        return Credential{
            .credential_type = .basic,
            .serialized_content = try VarBytes.init(allocator, serialized),
        };
    }
    
    /// Create a credential with raw serialized content
    pub fn init(allocator: std.mem.Allocator, credential_type: CredentialType, serialized_content: []const u8) !Credential {
        return Credential{
            .credential_type = credential_type,
            .serialized_content = try VarBytes.init(allocator, serialized_content),
        };
    }
    
    /// Clean up allocated memory
    pub fn deinit(self: *Credential) void {
        self.serialized_content.deinit();
    }
    
    /// Get the credential type
    pub fn getType(self: *const Credential) CredentialType {
        return self.credential_type;
    }
    
    /// Get the serialized content
    pub fn getSerializedContent(self: *const Credential) []const u8 {
        return self.serialized_content.asSlice();
    }
    
    /// Try to extract a basic credential
    pub fn toBasic(self: *const Credential, allocator: std.mem.Allocator) !BasicCredential {
        if (self.credential_type != .basic) {
            return error.WrongCredentialType;
        }
        
        var stream = std.io.fixedBufferStream(self.serialized_content.asSlice());
        var reader = TlsReader(@TypeOf(stream.reader())).init(stream.reader());
        
        return try BasicCredential.tlsDeserialize(&reader, allocator);
    }
    
    /// Get the serialized length
    pub fn tlsSerializedLen(self: *const Credential) usize {
        // credential_type (2 bytes) + serialized_content length prefix (1 byte) + content
        return 2 + 1 + self.serialized_content.asSlice().len;
    }
    
    /// Serialize to TLS format
    pub fn tlsSerialize(self: *const Credential, writer: anytype) !void {
        try self.credential_type.tlsSerialize(writer);
        try writer.writeVarBytes(u8, self.serialized_content.asSlice());
    }

    /// Serialize to ArrayList (manual TLS format)
    pub fn tlsSerializeToList(self: *const Credential, list: *std.ArrayList(u8)) !void {
        try self.credential_type.tlsSerializeToList(list);
        try tls_codec.writeVarBytesToList(list, u8, self.serialized_content.asSlice());
    }
    
    /// Deserialize from TLS format
    pub fn tlsDeserialize(reader: anytype, allocator: std.mem.Allocator) !Credential {
        const credential_type = try CredentialType.tlsDeserialize(reader, allocator);
        const serialized_content = try reader.readVarBytes(u8, allocator);
        errdefer allocator.free(serialized_content);
        
        const content = try VarBytes.init(allocator, serialized_content);
        allocator.free(serialized_content); // VarBytes makes its own copy
        
        return Credential{
            .credential_type = credential_type,
            .serialized_content = content,
        };
    }
    
    /// Create a deep copy of this credential
    pub fn clone(self: Credential, allocator: std.mem.Allocator) !Credential {
        return Credential.init(allocator, self.credential_type, self.serialized_content.asSlice());
    }
    
    /// Create a copy of this credential using arena pattern
    pub fn shareAsCow(self: Credential, allocator: std.mem.Allocator) !Credential {
        return Credential{
            .credential_type = self.credential_type,
            .serialized_content = try self.serialized_content.clone(allocator),
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
    var writer = TlsWriter(@TypeOf(stream.writer())).init(stream.writer());
    
    try basic.tlsSerialize(&writer);
    
    // Check serialized format: [length][identity]
    try testing.expectEqual(@as(u8, identity.len), buf[0]);
    try testing.expectEqualSlices(u8, identity, buf[1..1 + identity.len]);
    
    // Test deserialization
    stream.reset();
    var reader = TlsReader(@TypeOf(stream.reader())).init(stream.reader());
    
    var deserialized = try BasicCredential.tlsDeserialize(&reader, allocator);
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
    var writer = TlsWriter(@TypeOf(stream.writer())).init(stream.writer());
    
    try credential.tlsSerialize(&writer);
    
    // Deserialize
    stream.reset();
    var reader = TlsReader(@TypeOf(stream.reader())).init(stream.reader());
    
    var deserialized = try Credential.tlsDeserialize(&reader, allocator);
    defer deserialized.deinit();
    
    try testing.expectEqual(CredentialType.basic, deserialized.getType());
    
    var extracted = try deserialized.toBasic(allocator);
    defer extracted.deinit();
    
    try testing.expectEqualSlices(u8, identity, extracted.getIdentity());
}

test "CredentialType encoding" {
    var buf: [10]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    var writer = TlsWriter(@TypeOf(stream.writer())).init(stream.writer());
    
    const cred_type = CredentialType.basic;
    try cred_type.tlsSerialize(&writer);
    
    try testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, buf[0..2], .big));
    
    stream.reset();
    var reader = TlsReader(@TypeOf(stream.reader())).init(stream.reader());
    
    const decoded = try CredentialType.tlsDeserialize(&reader, testing.allocator);
    try testing.expectEqual(CredentialType.basic, decoded);
}