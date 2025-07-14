# Changelog

All notable changes to the nostr_zig MLS implementation will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] - 2025-01-14

### Added
- Complete API style guidelines in `API_STYLE_GUIDELINES.md`
- Non-exhaustive enum support with `fromInt()` factory methods
- Module-specific error sets (`KeyPackageError`, `GroupError`, `WelcomeError`, `ParseError`)
- Helper functions for Nostr integration:
  - `parseFromNostrEvent()` - Automatic hex/base64 detection
  - `serializeForNostrEvent()` - Hex encoding for Nostr events
- Roundtrip testing support for all serializable types
- Test infrastructure for NAK server integration
- Debug scripts for testing with real NAK server

### Changed
- **BREAKING**: All semantic types now use consistent struct wrappers:
  - `GroupId` changed from `[32]u8` to `struct { data: [32]u8 }`
  - `HPKEPublicKey` now has `init()` and `eql()` methods
  - `SignaturePublicKey` follows same pattern
  - `ProposalRef` wrapped for consistency
- All enums are now non-exhaustive to handle unknown protocol values
- Improved error handling with descriptive error types
- Parser now accepts both draft (0x0001) and mls10 (0x0100) protocol versions
- Updated all MLS modules to follow new API patterns

### Fixed
- Protocol version compatibility issues with NAK server
- Parser error handling for variable-length fields
- Type wrapping inconsistencies throughout codebase
- Compilation errors after enum changes

### Technical Details

#### Type Wrapping Migration
```zig
// Before
const group_id: GroupId = [_]u8{0} ** 32;

// After  
const group_id = GroupId.init([_]u8{0} ** 32);
```

#### Non-exhaustive Enums
```zig
pub const ProtocolVersion = enum(u16) {
    reserved = 0x0000,
    draft = 0x0001,     // Added for NAK compatibility
    mls10 = 0x0100,
    _,                  // Allow unknown values
    
    pub fn fromInt(value: u16) ProtocolVersion {
        return @enumFromInt(value);
    }
};
```

#### Error Set Improvements
```zig
// Before
return error.Invalid;

// After
return error.InvalidKeyLength;  // Specific, actionable error
```

### Testing
- Successfully parsed test KeyPackages (314 bytes)
- NAK server connection and WebSocket handling verified
- All compilation tests passing after API refactoring

## [0.1.0] - 2025-01-12

### Added
- Initial MLS implementation with 13 core functions
- Complete RFC 9420 compliance
- Integration with mls_zig library
- NIP-EE support for Nostr group messaging
- Double-layer encryption (MLS + NIP-44)
- Full cryptographic stack:
  - HKDF operations
  - HPKE encryption/decryption
  - Ed25519 signing/verification
- Wire format serialization/deserialization
- Group lifecycle management