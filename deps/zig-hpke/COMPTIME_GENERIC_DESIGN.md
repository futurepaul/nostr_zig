# HPKE Comptime Generic Architecture Design

## Problem
The current HPKE implementation uses function pointers in structs, making them comptime-only and incompatible with WASM builds.

## Solution: Comptime Generic Architecture

### Core Principle
Replace runtime function pointers with comptime generics where algorithm types are known at compile time.

### Design Changes

#### 1. Algorithm Type Enums (Replace Runtime Function Pointers)
```zig
pub const KemId = enum(u16) {
    X25519HkdfSha256 = 0x0020,
};

pub const KdfId = enum(u16) {
    HkdfSha256 = 0x0001,
};

pub const AeadId = enum(u16) {
    Aes128Gcm = 0x0001,
    ExportOnly = 0xffff,
};
```

#### 2. Comptime Generic Suite Function
```zig
pub fn Suite(comptime kem_id: KemId, comptime kdf_id: KdfId, comptime aead_id: AeadId) type {
    return struct {
        const Self = @This();
        
        // Comptime-selected implementations
        const KemImpl = kemImplementation(kem_id);
        const KdfImpl = kdfImplementation(kdf_id);
        const AeadImpl = if (aead_id == .ExportOnly) null else aeadImplementation(aead_id);
        
        // Static methods that dispatch to correct implementation
        pub fn generateKeyPair(random_fn: ?RandomFunction) !KeyPair {
            return KemImpl.generateKeyPair(random_fn);
        }
        
        pub fn createClientContext(
            server_pk: []const u8, 
            info: []const u8, 
            psk: ?Psk, 
            seed: ?[]const u8, 
            random_fn: ?RandomFunction
        ) !ClientContextAndEncapsulatedSecret {
            // Implementation using comptime-selected algorithms
        }
    };
}
```

#### 3. Algorithm Implementation Functions
```zig
fn kemImplementation(comptime id: KemId) type {
    return switch (id) {
        .X25519HkdfSha256 => struct {
            pub fn generateKeyPair(random_fn: ?RandomFunction) !KeyPair {
                // X25519 implementation
            }
            pub fn deterministicKeyPair(secret_key: []const u8) !KeyPair {
                // X25519 implementation  
            }
            pub fn dh(out: []u8, pk: []const u8, sk: []const u8) !void {
                // X25519 implementation
            }
        },
    };
}
```

### API Usage Example
```zig
// Old API (function pointers, WASM-incompatible)
const suite = try Suite.init(0x0020, 0x0001, 0x0001);
const kp = try suite.generateKeyPair(random_fn);

// New API (comptime generics, WASM-compatible)
const SuiteType = Suite(.X25519HkdfSha256, .HkdfSha256, .Aes128Gcm);
const kp = try SuiteType.generateKeyPair(random_fn);
```

### Benefits

1. **WASM Compatible**: No runtime function pointers
2. **Zero Runtime Cost**: All dispatch resolved at compile time
3. **Type Safety**: Compile-time verification of algorithm combinations
4. **Performance**: Inlined implementations, no indirection
5. **Memory Efficient**: No function pointer storage

### Migration Strategy

1. **Phase 1**: Implement new comptime generic API alongside existing API
2. **Phase 2**: Update mls_zig to use new API
3. **Phase 3**: Remove old function pointer API

### Backward Compatibility

Provide convenience functions that match the old API:
```zig
pub fn createSuite(kem_id: u16, kdf_id: u16, aead_id: u16) !type {
    return switch (kem_id) {
        0x0020 => switch (kdf_id) {
            0x0001 => switch (aead_id) {
                0x0001 => Suite(.X25519HkdfSha256, .HkdfSha256, .Aes128Gcm),
                0xffff => Suite(.X25519HkdfSha256, .HkdfSha256, .ExportOnly),
                else => error.UnsupportedAead,
            },
            else => error.UnsupportedKdf,
        },
        else => error.UnsupportedKem,
    };
}
```