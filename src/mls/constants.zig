const std = @import("std");

/// MLS/Nostr Integration Constants
/// 
/// These constants define the domain separation strings used in key derivation
/// functions throughout the NIP-EE implementation. Domain separation ensures
/// that keys derived for different purposes cannot be confused or misused.

/// HKDF Salt Constants
/// These are used as the "salt" parameter in HKDF-extract operations
pub const HKDF_SALT = struct {
    /// Used when deriving MLS signing keys from Nostr private keys
    /// This ensures that MLS signing keys are cryptographically separated
    /// from the original Nostr keys, preventing cross-protocol attacks
    pub const NOSTR_TO_MLS_SIGNING = "nostr-mls-signing";
    
    /// Used when deriving a deterministic identifier from a Nostr public key
    /// Since we cannot mathematically convert between secp256k1 and Ed25519
    /// public keys, this creates a deterministic identifier instead
    pub const NOSTR_TO_MLS_ID = "nostr-to-mls-id";
};

/// HKDF Info/Context Constants  
/// These are used as the "info" parameter in HKDF-expand operations
pub const HKDF_INFO = struct {
    /// Context string for expanding the PRK into the final MLS signing key
    /// This provides an additional layer of domain separation
    pub const MLS_SIGNING_KEY = "mls-signing-key";
    
    /// Context string for expanding the PRK into an MLS identifier
    /// Used when we need a deterministic 32-byte identifier derived from
    /// a Nostr public key (not a valid Ed25519 public key)
    pub const MLS_IDENTIFIER = "mls-identifier";
};

/// MLS Protocol Constants
pub const MLS_PROTOCOL = struct {
    /// Label used for exporter secret in MLS protocol
    /// As specified in NIP-EE, this label is used when deriving
    /// the exporter secret that will be used for NIP-44 encryption
    pub const EXPORTER_LABEL = "nostr";
    
    /// MLS protocol version we support
    pub const VERSION = @import("types.zig").ProtocolVersion.mls10;
};

/// Ephemeral Key Constants
pub const EPHEMERAL = struct {
    /// Tag used to mark events as using ephemeral keys in the visualizer
    pub const EVENT_TAG = "ephemeral";
    
    /// Value for the ephemeral tag
    pub const TAG_VALUE = "true";
};

/// Key Size Constants
pub const KEY_SIZES = struct {
    /// Size of secp256k1 private/public keys used in Nostr
    pub const SECP256K1 = 32;
    
    /// Size of Ed25519 private seeds and public keys used in MLS
    pub const ED25519_SEED = 32;
    pub const ED25519_PUBLIC = 32;
    
    /// Size of X25519 keys used in HPKE
    pub const X25519 = 32;
    
    /// Standard output size for HKDF operations
    pub const HKDF_OUTPUT = 32;
};

// Why these specific strings?
// 
// 1. Domain Separation: Using different strings for different purposes ensures
//    that keys derived for one purpose cannot be accidentally or maliciously
//    used for another purpose.
// 
// 2. Protocol Clarity: The strings clearly indicate the transformation being
//    performed (e.g., "nostr-mls-signing" shows we're going from Nostr to MLS).
// 
// 3. Future Compatibility: If we need to change the derivation method in the
//    future, we can use different strings to ensure backward compatibility.
// 
// 4. Security: These strings act as "firewalls" between different uses of the
//    same cryptographic primitives, preventing cross-protocol attacks.
// 
// Example usage:
// ```zig
// const hkdf = std.crypto.kdf.hkdf.Hkdf(std.crypto.hash.sha2.Sha256);
// var prk: [32]u8 = undefined;
// hkdf.extract(&prk, HKDF_SALT.NOSTR_TO_MLS_SIGNING, &nostr_private_key);
// 
// const signing_key = try allocator.alloc(u8, 32);
// hkdf.expand(signing_key, HKDF_INFO.MLS_SIGNING_KEY, &prk);
// ```