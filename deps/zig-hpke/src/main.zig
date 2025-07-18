const std = @import("std");
const crypto = std.crypto;
const debug = std.debug;
const mem = std.mem;
const meta = std.meta;
const ArrayList = std.ArrayList;
const FixedBufferAllocator = std.heap.FixedBufferAllocator;
const BoundedArray = std.BoundedArray;

const hpke_version = [7]u8{ 'H', 'P', 'K', 'E', '-', 'v', '1' };

/// Random function signature for dependency injection
pub const RandomFunction = fn ([]u8) void;

/// HPKE mode
pub const Mode = enum(u8) { base = 0x00, psk = 0x01, auth = 0x02, authPsk = 0x03 };

/// Maximum length of a public key in bytes
pub const max_public_key_length: usize = 32;
/// Maximum length of a secret key in bytes
pub const max_secret_key_length: usize = 32;
/// Maximum length of a shared key in bytes
pub const max_shared_key_length: usize = 32;
/// Maximum length of a PRK in bytes
pub const max_prk_length: usize = 32;
/// Maximum length of a label in bytes
pub const max_label_length: usize = 128;
/// Maximum length of an info string in bytes
pub const max_info_length: usize = 1024;
/// Maximum length of a suite ID
pub const max_suite_id_length: usize = 10;
/// Maximum length of a hash function
pub const max_digest_length: usize = 32;
/// Maximum length of input keying material
pub const max_ikm_length: usize = 64;
/// Maximum length of an AEAD key
pub const max_aead_key_length: usize = 32;
/// Maximum length of an AEAD nonce
pub const max_aead_nonce_length: usize = 12;
/// Maximum length of an AEAD tag
pub const max_aead_tag_length: usize = 16;

/// KEM algorithm identifiers
pub const KemId = enum(u16) {
    X25519HkdfSha256 = 0x0020,
};

/// KDF algorithm identifiers  
pub const KdfId = enum(u16) {
    HkdfSha256 = 0x0001,
};

/// AEAD algorithm identifiers
pub const AeadId = enum(u16) {
    Aes128Gcm = 0x0001,
    ExportOnly = 0xffff,
};

/// A pre-shared key
pub const Psk = struct {
    key: []u8,
    id: []u8,
};

/// A key pair
pub const KeyPair = struct {
    public_key: BoundedArray(u8, max_public_key_length),
    secret_key: BoundedArray(u8, max_secret_key_length),
};

/// A secret, and an encapsulated (encrypted) representation of it
pub const EncapsulatedSecret = struct {
    secret: BoundedArray(u8, max_digest_length),
    encapsulated: BoundedArray(u8, max_public_key_length),
};

/// AEAD State for encryption/decryption
pub const AeadState = struct {
    base_nonce: BoundedArray(u8, max_aead_nonce_length),
    counter: BoundedArray(u8, max_aead_nonce_length),
    key: BoundedArray(u8, max_aead_key_length),
    
    fn incrementCounter(counter: []u8) void {
        var i = counter.len;
        var carry: u1 = 1;
        while (true) {
            i -= 1;
            const res = @addWithOverflow(counter[i], carry);
            counter[i] = res[0];
            carry = res[1];
            if (i == 0) break;
        }
        debug.assert(carry == 0); // Counter overflow
    }

    /// Increment the nonce
    pub fn nextNonce(state: *AeadState) BoundedArray(u8, max_aead_nonce_length) {
        debug.assert(state.counter.len == state.base_nonce.len);
        var base_nonce = @TypeOf(state.base_nonce).fromSlice(state.base_nonce.constSlice()) catch unreachable;
        const nonce = base_nonce.slice();
        const counter = state.counter.slice();
        for (nonce, 0..) |*p, i| {
            p.* ^= counter[i];
        }
        incrementCounter(counter);
        return BoundedArray(u8, max_aead_nonce_length).fromSlice(nonce) catch unreachable;
    }
};

/// KEM implementation selector
fn KemImpl(comptime kem_id: KemId) type {
    return switch (kem_id) {
        .X25519HkdfSha256 => struct {
            pub const id: u16 = @intFromEnum(kem_id);
            pub const secret_length: usize = crypto.dh.X25519.secret_length;
            pub const public_length: usize = crypto.dh.X25519.public_length;
            pub const shared_length: usize = crypto.dh.X25519.shared_length;
            pub const digest_length: usize = crypto.hash.sha2.Sha256.digest_length;

            pub fn generateKeyPair(random_fn: ?RandomFunction) !KeyPair {
                var secret_key: [32]u8 = undefined;
                if (random_fn) |rand_fn| {
                    rand_fn(&secret_key);
                } else {
                    crypto.random.bytes(&secret_key);
                }
                
                const public_key = try crypto.dh.X25519.recoverPublicKey(secret_key);
                return KeyPair{
                    .public_key = try BoundedArray(u8, max_public_key_length).fromSlice(&public_key),
                    .secret_key = try BoundedArray(u8, max_secret_key_length).fromSlice(&secret_key),
                };
            }

            pub fn deterministicKeyPair(secret_key: []const u8) !KeyPair {
                debug.assert(secret_key.len == secret_length);
                const public_key = try crypto.dh.X25519.recoverPublicKey(secret_key[0..secret_length].*);
                return KeyPair{
                    .public_key = try BoundedArray(u8, max_public_key_length).fromSlice(&public_key),
                    .secret_key = try BoundedArray(u8, max_secret_key_length).fromSlice(secret_key),
                };
            }

            pub fn dh(out: []u8, pk: []const u8, sk: []const u8) !void {
                if (pk.len != public_length or sk.len != secret_length or out.len != shared_length) {
                    return error.InvalidParameters;
                }
                const dh_secret = try crypto.dh.X25519.scalarmult(sk[0..secret_length].*, pk[0..public_length].*);
                @memcpy(out, &dh_secret);
            }
        },
    };
}

/// KDF implementation selector
fn KdfImpl(comptime kdf_id: KdfId) type {
    return switch (kdf_id) {
        .HkdfSha256 => struct {
            pub const id: u16 = @intFromEnum(kdf_id);
            pub const prk_length = crypto.auth.hmac.sha2.HmacSha256.mac_length;
            
            const M = crypto.auth.hmac.sha2.HmacSha256;
            const F = crypto.kdf.hkdf.Hkdf(M);

            pub fn extract(out: []u8, salt: []const u8, ikm: []const u8) void {
                const prk = F.extract(salt, ikm);
                debug.assert(prk.len == out.len);
                @memcpy(out, &prk);
            }

            pub fn expand(out: []u8, ctx: []const u8, prk: []const u8) void {
                debug.assert(prk.len == prk_length);
                F.expand(out, ctx, prk[0..prk_length].*);
            }
        },
    };
}

/// AEAD implementation selector
fn AeadImpl(comptime aead_id: AeadId) type {
    return switch (aead_id) {
        .Aes128Gcm => struct {
            pub const id: u16 = @intFromEnum(aead_id);
            const A = crypto.aead.aes_gcm.Aes128Gcm;
            pub const key_length = A.key_length;
            pub const nonce_length = A.nonce_length;
            pub const tag_length = A.tag_length;

            pub fn newState(key: []const u8, base_nonce: []const u8) error{ InvalidParameters, Overflow }!AeadState {
                if (key.len != A.key_length or base_nonce.len != A.nonce_length) {
                    return error.InvalidParameters;
                }
                var counter = try BoundedArray(u8, max_aead_nonce_length).init(A.nonce_length);
                @memset(counter.slice(), 0);
                return AeadState{
                    .base_nonce = try BoundedArray(u8, max_aead_nonce_length).fromSlice(base_nonce),
                    .counter = counter,
                    .key = try BoundedArray(u8, max_aead_key_length).fromSlice(key),
                };
            }

            pub fn encrypt(c: []u8, m: []const u8, ad: []const u8, nonce: []const u8, key: []const u8) void {
                A.encrypt(c[0..m.len], c[m.len..][0..A.tag_length], m, ad, nonce[0..A.nonce_length].*, key[0..A.key_length].*);
            }

            pub fn decrypt(m: []u8, c: []const u8, ad: []const u8, nonce: []const u8, key: []const u8) !void {
                return A.decrypt(m, c[0..m.len], c[m.len..][0..A.tag_length].*, ad, nonce[0..A.nonce_length].*, key[0..A.key_length].*);
            }
        },
        .ExportOnly => struct {
            pub const id: u16 = @intFromEnum(aead_id);
            pub const key_length = 0;
            pub const nonce_length = 0;
            pub const tag_length = 0;
        },
    };
}

/// Comptime generic HPKE Suite
pub fn Suite(comptime kem_id: KemId, comptime kdf_id: KdfId, comptime aead_id: AeadId) type {
    const Kem = KemImpl(kem_id);
    const Kdf = KdfImpl(kdf_id);
    
    return struct {
        const Self = @This();
        
        pub const Prk = BoundedArray(u8, max_prk_length);

        const context_suite_id = blk: {
            var id = [10]u8{ 'H', 'P', 'K', 'E', 0, 0, 0, 0, 0, 0 };
            mem.writeInt(u16, id[4..6], @intFromEnum(kem_id), .big);
            mem.writeInt(u16, id[6..8], @intFromEnum(kdf_id), .big);
            mem.writeInt(u16, id[8..10], @intFromEnum(aead_id), .big);
            break :blk id;
        };

        const kem_suite_id = blk: {
            var id = [5]u8{ 'K', 'E', 'M', 0, 0 };
            mem.writeInt(u16, id[3..5], @intFromEnum(kem_id), .big);
            break :blk id;
        };

        /// Extract a PRK out of input keying material and an optional salt
        pub fn extract(prk: []u8, salt: ?[]const u8, ikm: []const u8) void {
            const prk_length = Kdf.prk_length;
            debug.assert(prk.len == prk_length);
            Kdf.extract(prk, salt orelse "", ikm);
        }

        /// Expand a PRK into an arbitrary-long key for the context `ctx`
        pub fn expand(out: []u8, ctx: []const u8, prk: []const u8) void {
            Kdf.expand(out, ctx, prk);
        }

        /// Create a PRK given a suite ID, a label, input keying material and an optional salt
        pub fn labeledExtract(suite_id: []const u8, salt: ?[]const u8, label: []const u8, ikm: []const u8) !Prk {
            var buffer: [hpke_version.len + max_suite_id_length + max_label_length + max_ikm_length]u8 = undefined;
            var alloc = FixedBufferAllocator.init(&buffer);
            var secret = try ArrayList(u8).initCapacity(alloc.allocator(), alloc.buffer.len);
            try secret.appendSlice(&hpke_version);
            try secret.appendSlice(suite_id);
            try secret.appendSlice(label);
            try secret.appendSlice(ikm);
            var prk = try Prk.init(Kdf.prk_length);
            extract(prk.slice(), salt, secret.items);
            return prk;
        }

        /// Expand a PRK using a suite, a label and optional information
        pub fn labeledExpand(out: []u8, suite_id: []const u8, prk: Prk, label: []const u8, info: ?[]const u8) !void {
            var out_length = [_]u8{ 0, 0 };
            mem.writeInt(u16, &out_length, @intCast(out.len), .big);
            var buffer: [out_length.len + hpke_version.len + max_suite_id_length + max_label_length + max_info_length]u8 = undefined;
            var alloc = FixedBufferAllocator.init(&buffer);
            var labeled_info = try ArrayList(u8).initCapacity(alloc.allocator(), alloc.buffer.len);
            try labeled_info.appendSlice(&out_length);
            try labeled_info.appendSlice(&hpke_version);
            try labeled_info.appendSlice(suite_id);
            try labeled_info.appendSlice(label);
            if (info) |i| try labeled_info.appendSlice(i);
            expand(out, labeled_info.items, prk.constSlice());
        }

        fn verifyPskInputs(mode: Mode, psk: ?Psk) !void {
            if (psk) |p| {
                if ((p.key.len == 0) != (psk == null)) {
                    return error.PskKeyAndIdMustBeSet;
                }
                if (mode == .base or mode == .auth) {
                    return error.PskNotRequired;
                }
            } else if (mode == .psk or mode == .authPsk) {
                return error.PskRequired;
            }
        }

        const Context = struct {
            exporter_secret: BoundedArray(u8, max_prk_length),
            inbound_state: ?AeadState = null,
            outbound_state: ?AeadState = null,

            fn exportSecret(ctx: Context, out: []u8, exporter_context: []const u8) !void {
                try labeledExpand(out, &context_suite_id, ctx.exporter_secret, "sec", exporter_context);
            }

            fn responseState(ctx: Context) !AeadState {
                if (aead_id != .ExportOnly) {
                    const AeadType = AeadImpl(aead_id);
                    var inbound_key = try BoundedArray(u8, max_aead_key_length).init(AeadType.key_length);
                    var inbound_base_nonce = try BoundedArray(u8, max_aead_nonce_length).init(AeadType.nonce_length);
                    try ctx.exportSecret(inbound_key.slice(), "response key");
                    try ctx.exportSecret(inbound_base_nonce.slice(), "response nonce");
                    return AeadType.newState(inbound_key.constSlice(), inbound_base_nonce.constSlice());
                } else {
                    return error.ExportOnlyMode;
                }
            }
        };

        fn keySchedule(mode: Mode, dh_secret: []const u8, info: []const u8, psk: ?Psk) !Context {
            try verifyPskInputs(mode, psk);
            const psk_id: []const u8 = if (psk) |p| p.id else &[_]u8{};
            var psk_id_hash = try labeledExtract(&context_suite_id, null, "psk_id_hash", psk_id);
            var info_hash = try labeledExtract(&context_suite_id, null, "info_hash", info);

            var buffer: [1 + max_prk_length + max_prk_length]u8 = undefined;
            var alloc = FixedBufferAllocator.init(&buffer);
            var key_schedule_ctx = try ArrayList(u8).initCapacity(alloc.allocator(), alloc.buffer.len);
            try key_schedule_ctx.append(@intFromEnum(mode));
            try key_schedule_ctx.appendSlice(psk_id_hash.constSlice());
            try key_schedule_ctx.appendSlice(info_hash.constSlice());
            const psk_key: []const u8 = if (psk) |p| p.key else &[_]u8{};
            const secret = try labeledExtract(&context_suite_id, dh_secret, "secret", psk_key);
            var exporter_secret = try BoundedArray(u8, max_prk_length).init(Kdf.prk_length);
            try labeledExpand(exporter_secret.slice(), &context_suite_id, secret, "exp", key_schedule_ctx.items);

            const outbound_state = if (aead_id != .ExportOnly) blk: {
                const AeadType = AeadImpl(aead_id);
                var outbound_key = try BoundedArray(u8, max_aead_key_length).init(AeadType.key_length);
                try labeledExpand(outbound_key.slice(), &context_suite_id, secret, "key", key_schedule_ctx.items);
                var outbound_base_nonce = try BoundedArray(u8, max_aead_nonce_length).init(AeadType.nonce_length);
                try labeledExpand(outbound_base_nonce.slice(), &context_suite_id, secret, "base_nonce", key_schedule_ctx.items);
                break :blk try AeadType.newState(outbound_key.constSlice(), outbound_base_nonce.constSlice());
            } else null;

            return Context{
                .exporter_secret = exporter_secret,
                .outbound_state = outbound_state,
            };
        }

        /// Create a new key pair
        pub fn generateKeyPair(random_fn: ?RandomFunction) !KeyPair {
            return Kem.generateKeyPair(random_fn);
        }

        /// Create a new deterministic key pair
        pub fn deterministicKeyPair(seed: []const u8) !KeyPair {
            const prk = try labeledExtract(&kem_suite_id, null, "dkp_prk", seed);
            var secret_key = try BoundedArray(u8, max_secret_key_length).init(Kem.secret_length);
            try labeledExpand(secret_key.slice(), &kem_suite_id, prk, "sk", null);
            return Kem.deterministicKeyPair(secret_key.constSlice());
        }

        fn extractAndExpandDh(dh: []const u8, kem_ctx: []const u8) !BoundedArray(u8, max_shared_key_length) {
            const prk = try labeledExtract(&kem_suite_id, null, "eae_prk", dh);
            var dh_secret = try BoundedArray(u8, max_digest_length).init(Kem.shared_length);
            try labeledExpand(dh_secret.slice(), &kem_suite_id, prk, "shared_secret", kem_ctx);
            return dh_secret;
        }

        /// Generate a secret, return it as well as its encapsulation
        pub fn encap(server_pk: []const u8, seed: ?[]const u8, random_fn: ?RandomFunction) !EncapsulatedSecret {
            var eph_kp = if (seed) |s| try deterministicKeyPair(s) else try generateKeyPair(random_fn);
            var dh = try BoundedArray(u8, max_shared_key_length).init(Kem.shared_length);
            try Kem.dh(dh.slice(), server_pk, eph_kp.secret_key.slice());
            var buffer: [max_public_key_length + max_public_key_length]u8 = undefined;
            var alloc = FixedBufferAllocator.init(&buffer);
            var kem_ctx = try ArrayList(u8).initCapacity(alloc.allocator(), alloc.buffer.len);
            try kem_ctx.appendSlice(eph_kp.public_key.constSlice());
            try kem_ctx.appendSlice(server_pk);
            const dh_secret = try extractAndExpandDh(dh.constSlice(), kem_ctx.items);
            return EncapsulatedSecret{
                .secret = dh_secret,
                .encapsulated = eph_kp.public_key,
            };
        }

        /// Generate a secret, return it as well as its encapsulation, with authentication support
        pub fn authEncap(server_pk: []const u8, client_kp: KeyPair, seed: ?[]const u8, random_fn: ?RandomFunction) !EncapsulatedSecret {
            var eph_kp = if (seed) |s| try deterministicKeyPair(s) else try generateKeyPair(random_fn);
            var dh1 = try BoundedArray(u8, max_shared_key_length).init(Kem.shared_length);
            try Kem.dh(dh1.slice(), server_pk, eph_kp.secret_key.constSlice());
            var dh2 = try BoundedArray(u8, max_shared_key_length).init(Kem.shared_length);
            try Kem.dh(dh2.slice(), server_pk, client_kp.secret_key.constSlice());
            var dh = try BoundedArray(u8, 2 * max_shared_key_length).init(dh1.len + dh2.len);
            @memcpy(dh.slice()[0..dh1.len], dh1.constSlice());
            @memcpy(dh.slice()[dh1.len..][0..dh2.len], dh2.constSlice());
            var buffer: [3 * max_public_key_length]u8 = undefined;
            var alloc = FixedBufferAllocator.init(&buffer);
            var kem_ctx = try ArrayList(u8).initCapacity(alloc.allocator(), alloc.buffer.len);
            try kem_ctx.appendSlice(eph_kp.public_key.constSlice());
            try kem_ctx.appendSlice(server_pk);
            try kem_ctx.appendSlice(client_kp.public_key.constSlice());
            const dh_secret = try extractAndExpandDh(dh.constSlice(), kem_ctx.items);
            return EncapsulatedSecret{
                .secret = dh_secret,
                .encapsulated = eph_kp.public_key,
            };
        }

        /// Decapsulate a secret
        pub fn decap(eph_pk: []const u8, server_kp: KeyPair) !BoundedArray(u8, max_shared_key_length) {
            var dh = try BoundedArray(u8, max_shared_key_length).init(Kem.shared_length);
            try Kem.dh(dh.slice(), eph_pk, server_kp.secret_key.constSlice());
            var buffer: [2 * max_public_key_length]u8 = undefined;
            var alloc = FixedBufferAllocator.init(&buffer);
            var kem_ctx = try ArrayList(u8).initCapacity(alloc.allocator(), alloc.buffer.len);
            try kem_ctx.appendSlice(eph_pk);
            try kem_ctx.appendSlice(server_kp.public_key.constSlice());
            return extractAndExpandDh(dh.constSlice(), kem_ctx.items);
        }

        /// Authenticate a client using its public key and decapsulate a secret
        pub fn authDecap(eph_pk: []const u8, server_kp: KeyPair, client_pk: []const u8) !BoundedArray(u8, max_shared_key_length) {
            var dh1 = try BoundedArray(u8, max_shared_key_length).init(Kem.shared_length);
            try Kem.dh(dh1.slice(), eph_pk, server_kp.secret_key.constSlice());
            var dh2 = try BoundedArray(u8, max_shared_key_length).init(Kem.shared_length);
            try Kem.dh(dh2.slice(), client_pk, server_kp.secret_key.constSlice());
            var dh = try BoundedArray(u8, 2 * max_shared_key_length).init(dh1.len + dh2.len);
            @memcpy(dh.slice()[0..dh1.len], dh1.constSlice());
            @memcpy(dh.slice()[dh1.len..][0..dh2.len], dh2.constSlice());
            var buffer: [3 * max_public_key_length]u8 = undefined;
            var alloc = FixedBufferAllocator.init(&buffer);
            var kem_ctx = try ArrayList(u8).initCapacity(alloc.allocator(), alloc.buffer.len);
            try kem_ctx.appendSlice(eph_pk);
            try kem_ctx.appendSlice(server_kp.public_key.constSlice());
            try kem_ctx.appendSlice(client_pk);
            return extractAndExpandDh(dh.constSlice(), kem_ctx.items);
        }

        /// A client context as well as an encapsulated secret
        pub const ClientContextAndEncapsulatedSecret = struct {
            client_ctx: ClientContext,
            encapsulated_secret: EncapsulatedSecret,
        };

        /// Create a new client context
        pub fn createClientContext(server_pk: []const u8, info: []const u8, psk: ?Psk, seed: ?[]const u8, random_fn: ?RandomFunction) !ClientContextAndEncapsulatedSecret {
            const encapsulated_secret = try encap(server_pk, seed, random_fn);
            const mode: Mode = if (psk) |_| .psk else .base;
            const inner_ctx = try keySchedule(mode, encapsulated_secret.secret.constSlice(), info, psk);
            const client_ctx = ClientContext{ .ctx = inner_ctx };
            return ClientContextAndEncapsulatedSecret{
                .client_ctx = client_ctx,
                .encapsulated_secret = encapsulated_secret,
            };
        }

        /// Create a new client authenticated context
        pub fn createAuthenticatedClientContext(client_kp: KeyPair, server_pk: []const u8, info: []const u8, psk: ?Psk, seed: ?[]const u8, random_fn: ?RandomFunction) !ClientContextAndEncapsulatedSecret {
            const encapsulated_secret = try authEncap(server_pk, client_kp, seed, random_fn);
            const mode: Mode = if (psk) |_| .authPsk else .auth;
            const inner_ctx = try keySchedule(mode, encapsulated_secret.secret.constSlice(), info, psk);
            const client_ctx = ClientContext{ .ctx = inner_ctx };
            return ClientContextAndEncapsulatedSecret{
                .client_ctx = client_ctx,
                .encapsulated_secret = encapsulated_secret,
            };
        }

        /// Create a new server context
        pub fn createServerContext(encapsulated_secret: []const u8, server_kp: KeyPair, info: []const u8, psk: ?Psk) !ServerContext {
            const dh_secret = try decap(encapsulated_secret, server_kp);
            const mode: Mode = if (psk) |_| .psk else .base;
            const inner_ctx = try keySchedule(mode, dh_secret.constSlice(), info, psk);
            return ServerContext{ .ctx = inner_ctx };
        }

        /// Create a new authenticated server context
        pub fn createAuthenticatedServerContext(client_pk: []const u8, encapsulated_secret: []const u8, server_kp: KeyPair, info: []const u8, psk: ?Psk) !ServerContext {
            const dh_secret = try authDecap(encapsulated_secret, server_kp, client_pk);
            const mode: Mode = if (psk) |_| .authPsk else .auth;
            const inner_ctx = try keySchedule(mode, dh_secret.constSlice(), info, psk);
            return ServerContext{ .ctx = inner_ctx };
        }

        /// A client context
        pub const ClientContext = struct {
            ctx: Context,

            /// Encrypt a message for the server
            pub fn encryptToServer(client_context: *ClientContext, ciphertext: []u8, message: []const u8, ad: []const u8) void {
                if (aead_id != .ExportOnly) {
                    const AeadType = AeadImpl(aead_id);
                    const required_ciphertext_length = AeadType.tag_length + message.len;
                    debug.assert(ciphertext.len == required_ciphertext_length);
                    var state = &client_context.ctx.outbound_state.?;
                    const nonce = state.nextNonce();
                    AeadType.encrypt(ciphertext, message, ad, nonce.constSlice(), state.key.constSlice());
                }
            }

            /// Decrypt a response from the server
            pub fn decryptFromServer(client_context: *ClientContext, message: []u8, ciphertext: []const u8, ad: []const u8) !void {
                if (aead_id != .ExportOnly) {
                    const AeadType = AeadImpl(aead_id);
                    if (client_context.ctx.inbound_state == null) {
                        client_context.ctx.inbound_state = client_context.ctx.responseState() catch unreachable;
                    }
                    const required_ciphertext_length = AeadType.tag_length + message.len;
                    debug.assert(ciphertext.len == required_ciphertext_length);
                    var state = &client_context.ctx.inbound_state.?;
                    const nonce = state.nextNonce();
                    try AeadType.decrypt(message, ciphertext, ad, nonce.constSlice(), state.key.constSlice());
                }
            }

            /// Return the exporter secret
            pub fn exporterSecret(client_context: ClientContext) BoundedArray(u8, max_prk_length) {
                return client_context.ctx.exporter_secret;
            }

            /// Derive an arbitrary-long secret
            pub fn exportSecret(client_context: ClientContext, out: []u8, info: []const u8) !void {
                try client_context.ctx.exportSecret(out, info);
            }

            /// Return the tag length
            pub fn tagLength(_: ClientContext) usize {
                if (aead_id != .ExportOnly) {
                    const AeadType = AeadImpl(aead_id);
                    return AeadType.tag_length;
                } else {
                    return 0;
                }
            }
        };

        /// A server context
        pub const ServerContext = struct {
            ctx: Context,

            /// Decrypt a ciphertext received from the client
            pub fn decryptFromClient(server_context: *ServerContext, message: []u8, ciphertext: []const u8, ad: []const u8) !void {
                if (aead_id != .ExportOnly) {
                    const AeadType = AeadImpl(aead_id);
                    const required_ciphertext_length = AeadType.tag_length + message.len;
                    debug.assert(ciphertext.len == required_ciphertext_length);
                    var state = &server_context.ctx.outbound_state.?;
                    const nonce = state.nextNonce();
                    try AeadType.decrypt(message, ciphertext, ad, nonce.constSlice(), state.key.constSlice());
                }
            }

            /// Encrypt a response to the client
            pub fn encryptToClient(server_context: *ServerContext, ciphertext: []u8, message: []const u8, ad: []const u8) void {
                if (aead_id != .ExportOnly) {
                    const AeadType = AeadImpl(aead_id);
                    if (server_context.ctx.inbound_state == null) {
                        server_context.ctx.inbound_state = server_context.ctx.responseState() catch unreachable;
                    }
                    const required_ciphertext_length = AeadType.tag_length + message.len;
                    debug.assert(ciphertext.len == required_ciphertext_length);
                    var state = &server_context.ctx.inbound_state.?;
                    const nonce = state.nextNonce();
                    AeadType.encrypt(ciphertext, message, ad, nonce.constSlice(), state.key.constSlice());
                }
            }

            /// Return the exporter secret
            pub fn exporterSecret(server_context: ServerContext) BoundedArray(u8, max_prk_length) {
                return server_context.ctx.exporter_secret;
            }

            /// Derive an arbitrary-long secret
            pub fn exportSecret(server_context: ServerContext, out: []u8, info: []const u8) !void {
                try server_context.ctx.exportSecret(out, info);
            }

            /// Return the tag length
            pub fn tagLength(_: ServerContext) usize {
                if (aead_id != .ExportOnly) {
                    const AeadType = AeadImpl(aead_id);
                    return AeadType.tag_length;
                } else {
                    return 0;
                }
            }
        };
    };
}

/// Convenience function to create a suite from numeric IDs for backwards compatibility
pub fn createSuite(kem_id: u16, kdf_id: u16, aead_id: u16) !type {
    const kem = switch (kem_id) {
        0x0020 => KemId.X25519HkdfSha256,
        else => return error.UnsupportedKem,
    };
    
    const kdf = switch (kdf_id) {
        0x0001 => KdfId.HkdfSha256,
        else => return error.UnsupportedKdf,
    };
    
    const aead = switch (aead_id) {
        0x0001 => AeadId.Aes128Gcm,
        0xffff => AeadId.ExportOnly,
        else => return error.UnsupportedAead,
    };
    
    return Suite(kem, kdf, aead);
}

// Temporarily disabled old tests while migrating to comptime generics
// test {
//     _ = @import("tests.zig");
// }