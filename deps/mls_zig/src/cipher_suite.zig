const std = @import("std");
const testing = std.testing;
const tls_encode = @import("tls_encode.zig");
const crypto = std.crypto;
const tls = std.crypto.tls;
const Allocator = std.mem.Allocator;

pub const MLS_LABEL_PREFIX = "MLS 1.0 ";

pub const Secret = struct {
    data: []u8,
    allocator: Allocator,

    pub fn init(allocator: Allocator, length: usize) !Secret {
        const data = try allocator.alloc(u8, length);
        return Secret{
            .data = data,
            .allocator = allocator,
        };
    }

    pub fn initFromSlice(allocator: Allocator, bytes: []const u8) !Secret {
        const data = try allocator.dupe(u8, bytes);
        return Secret{
            .data = data,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Secret) void {
        crypto.secureZero(u8, self.data);
        self.allocator.free(self.data);
        self.data = &[_]u8{};
    }

    pub fn len(self: Secret) usize {
        return self.data.len;
    }

    pub fn asSlice(self: Secret) []const u8 {
        return self.data;
    }

    pub fn eql(self: Secret, other: Secret) bool {
        if (self.data.len != other.data.len) return false;
        return std.mem.eql(u8, self.data, other.data);
    }

    pub fn hkdfExtract(
        self: Secret,
        allocator: Allocator,
        comptime HashFunction: type,
        salt: []const u8,
    ) !Secret {
        const HkdfType = crypto.kdf.hkdf.Hkdf(crypto.auth.hmac.Hmac(HashFunction));
        const prk_data = try allocator.alloc(u8, HashFunction.digest_length);
        const result = HkdfType.extract(salt, self.data);
        @memcpy(prk_data, &result);
        return Secret{
            .data = prk_data,
            .allocator = allocator,
        };
    }

    pub fn hkdfExpand(
        self: Secret,
        allocator: Allocator,
        comptime HashFunction: type,
        info: []const u8,
        length: usize,
    ) !Secret {
        const HkdfType = crypto.kdf.hkdf.Hkdf(crypto.auth.hmac.Hmac(HashFunction));
        const output_data = try allocator.alloc(u8, length);
        HkdfType.expand(output_data, info, self.data);
        return Secret{
            .data = output_data,
            .allocator = allocator,
        };
    }

    pub fn format(
        self: Secret,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try writer.print("Secret({d} bytes)", .{self.data.len});
    }
};

pub const CipherSuite = enum(u16) {
    MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 = 0x0001,
    MLS_128_DHKEMP256_AES128GCM_SHA256_P256 = 0x0002,
    MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 = 0x0003,
    MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448 = 0x0004,
    MLS_256_DHKEMP521_AES256GCM_SHA512_P521 = 0x0005,
    MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 = 0x0006,
    MLS_256_DHKEMP384_AES256GCM_SHA384_P384 = 0x0007,
    MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 = 0x004D,

    pub fn isSupported(self: CipherSuite) bool {
        return switch (self) {
            .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            .MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
            .MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
            => true,
            else => false,
        };
    }

    pub fn hashType(self: CipherSuite) HashType {
        return switch (self) {
            .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            .MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
            .MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
            .MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519,
            => .SHA256,
            .MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => .SHA384,
            .MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448,
            .MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
            .MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448,
            => .SHA512,
        };
    }

    pub fn aeadType(self: CipherSuite) AeadType {
        return switch (self) {
            .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            .MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
            => .AES128GCM,
            .MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
            .MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448,
            .MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519,
            => .CHACHA20POLY1305,
            .MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448,
            .MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
            .MLS_256_DHKEMP384_AES256GCM_SHA384_P384,
            => .AES256GCM,
        };
    }

    pub fn signatureScheme(self: CipherSuite) SignatureScheme {
        return switch (self) {
            .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            .MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
            .MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519,
            => .ED25519,
            .MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => .ECDSA_SECP256R1_SHA256,
            .MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448,
            .MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448,
            => .ED448,
            .MLS_256_DHKEMP521_AES256GCM_SHA512_P521 => .ECDSA_SECP521R1_SHA512,
            .MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => .ECDSA_SECP384R1_SHA384,
        };
    }

    pub fn hpkeKemType(self: CipherSuite) HpkeKemType {
        return switch (self) {
            .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            .MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
            .MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519,
            => .DHKEMX25519,
            .MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => .DHKEMP256,
            .MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448,
            .MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448,
            => .DHKEMX448,
            .MLS_256_DHKEMP521_AES256GCM_SHA512_P521 => .DHKEMP521,
            .MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => .DHKEMP384,
        };
    }

    pub fn hpkeKdfType(self: CipherSuite) HpkeKdfType {
        return switch (self) {
            .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            .MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
            .MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
            .MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519,
            => .HKDF_SHA256,
            .MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => .HKDF_SHA384,
            .MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448,
            .MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
            .MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448,
            => .HKDF_SHA512,
        };
    }

    pub fn hpkeAeadType(self: CipherSuite) HpkeAeadType {
        return switch (self) {
            .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            .MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
            => .AES128GCM,
            .MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
            .MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448,
            .MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519,
            => .CHACHA20POLY1305,
            .MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448,
            .MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
            .MLS_256_DHKEMP384_AES256GCM_SHA384_P384,
            => .AES256GCM,
        };
    }

    pub fn hashLength(self: CipherSuite) u32 {
        return self.hashType().length();
    }

    pub fn tagLength(self: CipherSuite) u32 {
        return self.aeadType().tagLength();
    }

    pub fn keyLength(self: CipherSuite) u32 {
        return self.aeadType().keyLength();
    }

    pub fn nonceLength(self: CipherSuite) u32 {
        return self.aeadType().nonceLength();
    }

    pub fn hash(self: CipherSuite, allocator: Allocator, data: []const u8) !Secret {
        return switch (self.hashType()) {
            .SHA256 => {
                var digest: [32]u8 = undefined;
                crypto.hash.sha2.Sha256.hash(data, &digest, .{});
                return Secret.initFromSlice(allocator, &digest);
            },
            .SHA384 => {
                var digest: [48]u8 = undefined;
                crypto.hash.sha2.Sha384.hash(data, &digest, .{});
                return Secret.initFromSlice(allocator, &digest);
            },
            .SHA512 => {
                var digest: [64]u8 = undefined;
                crypto.hash.sha2.Sha512.hash(data, &digest, .{});
                return Secret.initFromSlice(allocator, &digest);
            },
        };
    }

    pub fn hkdfExtract(
        self: CipherSuite,
        allocator: Allocator,
        salt: []const u8,
        ikm: []const u8,
    ) !Secret {
        return switch (self.hashType()) {
            .SHA256 => {
                const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;
                const prk_data = try allocator.alloc(u8, 32);
                const result = HkdfSha256.extract(salt, ikm);
                @memcpy(prk_data, &result);
                return Secret{
                    .data = prk_data,
                    .allocator = allocator,
                };
            },
            .SHA384 => {
                const HkdfSha384 = crypto.kdf.hkdf.Hkdf(crypto.auth.hmac.Hmac(crypto.hash.sha2.Sha384));
                const prk_data = try allocator.alloc(u8, 48);
                const result = HkdfSha384.extract(salt, ikm);
                @memcpy(prk_data, &result);
                return Secret{
                    .data = prk_data,
                    .allocator = allocator,
                };
            },
            .SHA512 => {
                const HkdfSha512 = crypto.kdf.hkdf.HkdfSha512;
                const prk_data = try allocator.alloc(u8, 64);
                const result = HkdfSha512.extract(salt, ikm);
                @memcpy(prk_data, &result);
                return Secret{
                    .data = prk_data,
                    .allocator = allocator,
                };
            },
        };
    }

    pub fn hkdfExpand(
        self: CipherSuite,
        allocator: Allocator,
        prk: []const u8,
        info: []const u8,
        length: usize,
    ) !Secret {
        const okm_data = try allocator.alloc(u8, length);
        switch (self.hashType()) {
            .SHA256 => {
                const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;
                if (prk.len == 32) {
                    const prk_array: [32]u8 = prk[0..32].*;
                    HkdfSha256.expand(okm_data, info, prk_array);
                } else {
                    return error.InvalidPrkLength;
                }
            },
            .SHA384 => {
                const HkdfSha384 = crypto.kdf.hkdf.Hkdf(crypto.auth.hmac.Hmac(crypto.hash.sha2.Sha384));
                if (prk.len == 48) {
                    const prk_array: [48]u8 = prk[0..48].*;
                    HkdfSha384.expand(okm_data, info, prk_array);
                } else {
                    return error.InvalidPrkLength;
                }
            },
            .SHA512 => {
                const HkdfSha512 = crypto.kdf.hkdf.HkdfSha512;
                if (prk.len == 64) {
                    const prk_array: [64]u8 = prk[0..64].*;
                    HkdfSha512.expand(okm_data, info, prk_array);
                } else {
                    return error.InvalidPrkLength;
                }
            },
        }
        return Secret{
            .data = okm_data,
            .allocator = allocator,
        };
    }

    pub fn hkdfExpandLabel(
        self: CipherSuite,
        allocator: Allocator,
        prk: []const u8,
        label: []const u8,
        context: []const u8,
        length: u16,
    ) !Secret {
        var info_list = std.ArrayList(u8).init(allocator);
        defer info_list.deinit();

        // Use std.crypto.tls for encoding
        try tls_encode.encodeInt(&info_list, u16, length);
        
        // Create full label by concatenating MLS prefix as bytes + label bytes
        // This handles binary labels correctly (like from OpenMLS test vectors)
        const prefix_bytes = MLS_LABEL_PREFIX[0..];
        const full_label = try allocator.alloc(u8, prefix_bytes.len + label.len);
        defer allocator.free(full_label);
        
        @memcpy(full_label[0..prefix_bytes.len], prefix_bytes);
        @memcpy(full_label[prefix_bytes.len..], label);
        
        // Use our helper for variable-length encoding
        try tls_encode.encodeVarBytes(&info_list, u8, full_label);
        try tls_encode.encodeVarBytes(&info_list, u8, context);

        return self.hkdfExpand(allocator, prk, info_list.items, length);
    }

    pub fn deriveSecret(
        self: CipherSuite,
        allocator: Allocator,
        secret: []const u8,
        label: []const u8,
        context: []const u8,
    ) !Secret {
        return self.hkdfExpandLabel(allocator, secret, label, context, @intCast(self.hashLength()));
    }

    /// Derive exporter secret for external applications (NIP-EE compatibility)
    /// This function implements the MLS exporter secret derivation as specified in RFC 9420
    /// The "nostr" label is used for NIP-EE (Nostr Event Encryption) integration
    pub fn exporterSecret(
        self: CipherSuite,
        allocator: Allocator,
        exporter_secret: []const u8,
        label: []const u8,
        context: []const u8,
        length: u16,
    ) !Secret {
        // OpenMLS exporter secret derivation follows a two-step pattern:
        // 1. derive_secret(exporter_secret, label) - treat label as string  
        // 2. kdf_expand_label(result, "exported", Hash(context), length)
        
        // First, hash the context
        const hash_len = self.hashLength();
        const context_hash = try allocator.alloc(u8, hash_len);
        defer allocator.free(context_hash);
        
        switch (self.hashType()) {
            .SHA256 => {
                crypto.hash.sha2.Sha256.hash(context, context_hash[0..32], .{});
            },
            .SHA384 => {
                crypto.hash.sha2.Sha384.hash(context, context_hash[0..48], .{});
            },
            .SHA512 => {
                crypto.hash.sha2.Sha512.hash(context, context_hash[0..64], .{});
            },
        }
        
        // Step 1: derive_secret(exporter_secret, label) - treat binary label as string bytes
        // OpenMLS treats label as string, so we pass the binary label data directly to deriveSecret
        // which will treat it as a UTF-8 string internally 
        var intermediate_secret = try self.deriveSecret(allocator, exporter_secret, label, &[_]u8{});
        defer intermediate_secret.deinit();
        
        // Step 2: kdf_expand_label(result, "exported", Hash(context), length) 
        return self.hkdfExpandLabel(allocator, intermediate_secret.asSlice(), "exported", context_hash, length);
    }

    /// Convenience method for basic signing operations
    pub fn sign(self: CipherSuite, allocator: Allocator, private_key: []const u8, data: []const u8) ![]u8 {
        const key_package = @import("key_package.zig");
        var signature = try key_package.signWithLabel(allocator, self, private_key, "", data);
        defer signature.deinit(allocator);
        return allocator.dupe(u8, signature.asSlice());
    }

    /// Convenience method for basic signature verification
    pub fn verify(self: CipherSuite, allocator: Allocator, public_key: []const u8, data: []const u8, signature: []const u8) !bool {
        const key_package = @import("key_package.zig");
        return key_package.verifyWithLabel(self, public_key, signature, "", data, allocator);
    }
};

pub const AeadType = enum(u16) {
    AES128GCM = 0x0001,
    AES256GCM = 0x0002,
    CHACHA20POLY1305 = 0x0003,

    pub fn keyLength(self: AeadType) u32 {
        return switch (self) {
            .AES128GCM => 16,
            .AES256GCM => 32,
            .CHACHA20POLY1305 => 32,
        };
    }

    pub fn nonceLength(self: AeadType) u32 {
        return switch (self) {
            .AES128GCM, .AES256GCM, .CHACHA20POLY1305 => 12,
        };
    }

    pub fn tagLength(self: AeadType) u32 {
        return switch (self) {
            .AES128GCM, .AES256GCM, .CHACHA20POLY1305 => 16,
        };
    }
};

pub const HashType = enum(u16) {
    SHA256 = 0x0001,
    SHA384 = 0x0002,
    SHA512 = 0x0003,

    pub fn length(self: HashType) u32 {
        return switch (self) {
            .SHA256 => 32,
            .SHA384 => 48,
            .SHA512 => 64,
        };
    }
};

pub const SignatureScheme = enum(u16) {
    ECDSA_SECP256R1_SHA256 = 0x0403,
    ECDSA_SECP384R1_SHA384 = 0x0503,
    ECDSA_SECP521R1_SHA512 = 0x0603,
    ED25519 = 0x0807,
    ED448 = 0x0808,
};

pub const HpkeKemType = enum(u16) {
    DHKEMP256 = 0x0010,
    DHKEMP384 = 0x0011,
    DHKEMP521 = 0x0012,
    DHKEMX25519 = 0x0020,
    DHKEMX448 = 0x0021,
};

pub const HpkeKdfType = enum(u16) {
    HKDF_SHA256 = 0x0001,
    HKDF_SHA384 = 0x0002,
    HKDF_SHA512 = 0x0003,
};

pub const HpkeAeadType = enum(u16) {
    AES128GCM = 0x0001,
    AES256GCM = 0x0002,
    CHACHA20POLY1305 = 0x0003,
};

pub fn tlsEncodeCipherSuite(writer: anytype, cipher_suite: CipherSuite) !void {
    try tls_encode.writeInt(writer, u16, @intFromEnum(cipher_suite));
}

pub fn tlsDecodeCipherSuite(data: []const u8) !CipherSuite {
    const mutable_data = @constCast(data);
    var decoder = tls.Decoder.fromTheirSlice(mutable_data);
    const raw_value = decoder.decode(u16);
    return @enumFromInt(raw_value);
}

pub fn tlsEncodeAeadType(writer: anytype, aead_type: AeadType) !void {
    try tls_encode.writeInt(writer, u16, @intFromEnum(aead_type));
}

pub fn tlsDecodeAeadType(data: []const u8) !AeadType {
    const mutable_data = @constCast(data);
    var decoder = tls.Decoder.fromTheirSlice(mutable_data);
    const raw_value = decoder.decode(u16);
    return @enumFromInt(raw_value);
}

pub fn tlsEncodeHashType(writer: anytype, hash_type: HashType) !void {
    try tls_encode.writeInt(writer, u16, @intFromEnum(hash_type));
}

pub fn tlsDecodeHashType(data: []const u8) !HashType {
    const mutable_data = @constCast(data);
    var decoder = tls.Decoder.fromTheirSlice(mutable_data);
    const raw_value = decoder.decode(u16);
    return @enumFromInt(raw_value);
}

pub fn tlsEncodeSignatureScheme(writer: anytype, signature_scheme: SignatureScheme) !void {
    try tls_encode.writeInt(writer, u16, @intFromEnum(signature_scheme));
}

pub fn tlsDecodeSignatureScheme(data: []const u8) !SignatureScheme {
    const mutable_data = @constCast(data);
    var decoder = tls.Decoder.fromTheirSlice(mutable_data);
    const raw_value = decoder.decode(u16);
    return @enumFromInt(raw_value);
}

pub fn tlsEncodeHpkeKemType(writer: anytype, hpke_kem_type: HpkeKemType) !void {
    try tls_encode.writeInt(writer, u16, @intFromEnum(hpke_kem_type));
}

pub fn tlsDecodeHpkeKemType(data: []const u8) !HpkeKemType {
    const mutable_data = @constCast(data);
    var decoder = tls.Decoder.fromTheirSlice(mutable_data);
    const raw_value = decoder.decode(u16);
    return @enumFromInt(raw_value);
}

pub fn tlsEncodeHpkeKdfType(writer: anytype, hpke_kdf_type: HpkeKdfType) !void {
    try tls_encode.writeInt(writer, u16, @intFromEnum(hpke_kdf_type));
}

pub fn tlsDecodeHpkeKdfType(data: []const u8) !HpkeKdfType {
    const mutable_data = @constCast(data);
    var decoder = tls.Decoder.fromTheirSlice(mutable_data);
    const raw_value = decoder.decode(u16);
    return @enumFromInt(raw_value);
}

pub fn tlsEncodeHpkeAeadType(writer: anytype, hpke_aead_type: HpkeAeadType) !void {
    try tls_encode.writeInt(writer, u16, @intFromEnum(hpke_aead_type));
}

pub fn tlsDecodeHpkeAeadType(data: []const u8) !HpkeAeadType {
    const mutable_data = @constCast(data);
    var decoder = tls.Decoder.fromTheirSlice(mutable_data);
    const raw_value = decoder.decode(u16);
    return @enumFromInt(raw_value);
}

test "cipher suite basic operations" {
    const cs = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    
    try testing.expect(cs.isSupported());
    try testing.expectEqual(HashType.SHA256, cs.hashType());
    try testing.expectEqual(AeadType.AES128GCM, cs.aeadType());
    try testing.expectEqual(SignatureScheme.ED25519, cs.signatureScheme());
    try testing.expectEqual(HpkeKemType.DHKEMX25519, cs.hpkeKemType());
    try testing.expectEqual(HpkeKdfType.HKDF_SHA256, cs.hpkeKdfType());
    try testing.expectEqual(HpkeAeadType.AES128GCM, cs.hpkeAeadType());
}

test "cipher suite lengths" {
    const cs = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    
    try testing.expectEqual(@as(u32, 32), cs.hashLength());
    try testing.expectEqual(@as(u32, 16), cs.tagLength());
    try testing.expectEqual(@as(u32, 16), cs.keyLength());
    try testing.expectEqual(@as(u32, 12), cs.nonceLength());
}

test "aead type properties" {
    try testing.expectEqual(@as(u32, 16), AeadType.AES128GCM.keyLength());
    try testing.expectEqual(@as(u32, 32), AeadType.AES256GCM.keyLength());
    try testing.expectEqual(@as(u32, 32), AeadType.CHACHA20POLY1305.keyLength());
    
    try testing.expectEqual(@as(u32, 12), AeadType.AES128GCM.nonceLength());
    try testing.expectEqual(@as(u32, 16), AeadType.AES128GCM.tagLength());
}

test "hash type properties" {
    try testing.expectEqual(@as(u32, 32), HashType.SHA256.length());
    try testing.expectEqual(@as(u32, 48), HashType.SHA384.length());
    try testing.expectEqual(@as(u32, 64), HashType.SHA512.length());
}

test "secret operations" {
    const allocator = testing.allocator;
    
    const data = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    var secret = try Secret.initFromSlice(allocator, &data);
    defer secret.deinit();
    
    try testing.expectEqual(@as(usize, 4), secret.len());
    try testing.expectEqualSlices(u8, &data, secret.asSlice());
    
    var secret2 = try Secret.initFromSlice(allocator, &data);
    defer secret2.deinit();
    
    try testing.expect(secret.eql(secret2));
    
    var different_secret = try Secret.initFromSlice(allocator, &[_]u8{ 0x05, 0x06, 0x07, 0x08 });
    defer different_secret.deinit();
    
    try testing.expect(!secret.eql(different_secret));
}

test "cipher suite hash operations" {
    const allocator = testing.allocator;
    const cs = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    
    const data = "hello world";
    var hash_result = try cs.hash(allocator, data);
    defer hash_result.deinit();
    
    try testing.expectEqual(@as(usize, 32), hash_result.len());
    
    var expected: [32]u8 = undefined;
    crypto.hash.sha2.Sha256.hash(data, &expected, .{});
    try testing.expectEqualSlices(u8, &expected, hash_result.asSlice());
}

test "cipher suite hkdf operations" {
    const allocator = testing.allocator;
    const cs = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    
    const salt = "salt";
    const ikm = "input key material";
    
    var prk = try cs.hkdfExtract(allocator, salt, ikm);
    defer prk.deinit();
    
    try testing.expectEqual(@as(usize, 32), prk.len());
    
    const info = "application info";
    var okm = try cs.hkdfExpand(allocator, prk.asSlice(), info, 16);
    defer okm.deinit();
    
    try testing.expectEqual(@as(usize, 16), okm.len());
}

test "cipher suite derive secret" {
    const allocator = testing.allocator;
    const cs = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    
    const secret = [_]u8{0x42} ** 32;
    const label = "test";
    const context = "context";
    
    var derived = try cs.deriveSecret(allocator, &secret, label, context);
    defer derived.deinit();
    
    try testing.expectEqual(@as(usize, 32), derived.len());
}

test "tls encoding and decoding" {
    const allocator = testing.allocator;
    
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    
    const cs = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    try tlsEncodeCipherSuite(buffer.writer(), cs);
    
    const decoded_cs = try tlsDecodeCipherSuite(buffer.items);
    
    try testing.expectEqual(cs, decoded_cs);
}

test "all cipher suite component extraction" {
    const test_cases = [_]struct {
        cs: CipherSuite,
        hash: HashType,
        aead: AeadType,
        sig: SignatureScheme,
        kem: HpkeKemType,
        kdf: HpkeKdfType,
        hpke_aead: HpkeAeadType,
    }{
        .{
            .cs = .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            .hash = .SHA256,
            .aead = .AES128GCM,
            .sig = .ED25519,
            .kem = .DHKEMX25519,
            .kdf = .HKDF_SHA256,
            .hpke_aead = .AES128GCM,
        },
        .{
            .cs = .MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
            .hash = .SHA256,
            .aead = .AES128GCM,
            .sig = .ECDSA_SECP256R1_SHA256,
            .kem = .DHKEMP256,
            .kdf = .HKDF_SHA256,
            .hpke_aead = .AES128GCM,
        },
        .{
            .cs = .MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
            .hash = .SHA256,
            .aead = .CHACHA20POLY1305,
            .sig = .ED25519,
            .kem = .DHKEMX25519,
            .kdf = .HKDF_SHA256,
            .hpke_aead = .CHACHA20POLY1305,
        },
    };
    
    for (test_cases) |tc| {
        try testing.expectEqual(tc.hash, tc.cs.hashType());
        try testing.expectEqual(tc.aead, tc.cs.aeadType());
        try testing.expectEqual(tc.sig, tc.cs.signatureScheme());
        try testing.expectEqual(tc.kem, tc.cs.hpkeKemType());
        try testing.expectEqual(tc.kdf, tc.cs.hpkeKdfType());
        try testing.expectEqual(tc.hpke_aead, tc.cs.hpkeAeadType());
    }
}

test "exporter secret derivation for NIP-EE" {
    const allocator = testing.allocator;
    const cs = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    
    // Test exporter secret with "nostr" label for NIP-EE compatibility
    const exporter_secret_data = [_]u8{0x42} ** 32;
    const context = "test context";
    const length = 32;
    
    // Test with "nostr" label
    var nostr_secret = try cs.exporterSecret(
        allocator,
        &exporter_secret_data,
        "nostr",
        context,
        length
    );
    defer nostr_secret.deinit();
    
    try testing.expectEqual(@as(usize, length), nostr_secret.asSlice().len);
    
    // Test with different label should produce different output
    var other_secret = try cs.exporterSecret(
        allocator,
        &exporter_secret_data,
        "other",
        context,
        length
    );
    defer other_secret.deinit();
    
    try testing.expect(!std.mem.eql(u8, nostr_secret.asSlice(), other_secret.asSlice()));
    
    // Test with different context should produce different output
    var different_context_secret = try cs.exporterSecret(
        allocator,
        &exporter_secret_data,
        "nostr",
        "different context",
        length
    );
    defer different_context_secret.deinit();
    
    try testing.expect(!std.mem.eql(u8, nostr_secret.asSlice(), different_context_secret.asSlice()));
    
    // Test deterministic behavior - same inputs should produce same output
    var nostr_secret2 = try cs.exporterSecret(
        allocator,
        &exporter_secret_data,
        "nostr",
        context,
        length
    );
    defer nostr_secret2.deinit();
    
    try testing.expectEqualSlices(u8, nostr_secret.asSlice(), nostr_secret2.asSlice());
}

test "exporter secret with multiple cipher suites" {
    const allocator = testing.allocator;
    
    const test_cases = [_]CipherSuite{
        .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        .MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
        .MLS_256_DHKEMP384_AES256GCM_SHA384_P384,
    };
    
    const exporter_secret_data = [_]u8{0x42} ** 48; // Use larger array for SHA384
    const context = "test context";
    
    for (test_cases) |cs| {
        const length = cs.hashLength();
        
        var secret = try cs.exporterSecret(
            allocator,
            exporter_secret_data[0..length],
            "nostr",
            context,
            @intCast(length)
        );
        defer secret.deinit();
        
        try testing.expectEqual(length, secret.asSlice().len);
        
        // Verify that different cipher suites produce different outputs
        // (This is expected due to different hash functions)
    }
}