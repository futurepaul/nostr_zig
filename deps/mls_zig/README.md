# mls_zig (vendored in nostr_zig)

THIS IS ALL VIBES, NOT ACTUAL CRYPTOGRAPHY. I AM A FRONTEND DEVELOPER. DO NOT USE THIS FOR ANYTHING SERIOUS.

The plan is to vibe it until it works, then read the code and see if the tests are real. The tests are all modeled on / stolen from [OpenMLS](https://github.com/openmls/openmls/).

Use OpenMLS if you want cryptography. Use mls_zig if you want vibes.

## What This Actually Is

Despite the vibes-based development approach, this has somehow evolved into what looks like a complete MLS implementation that might even work for NIP-EE integration. It has all the parts you'd expect and the tests seem to pass, but we haven't actually used it for anything real yet. The tests are modeled on OpenMLS so they might even be correct!

### What We Think We Built

- **MLS Protocol** - Claims to follow RFC 9420, tests suggest it might be true
- **8 Cipher Suites** - Ed25519, P-256, X25519, ChaCha20-Poly1305, AES-GCM variants  
- **TreeKEM** - Seems to do the tree crypto thing with actual HPKE
- **Group Management** - Can create groups, add people, remove people, advance epochs
- **NIP-EE Extensions** - Custom stuff for Nostr that might work
- **HKDF Support** - Complete HKDF-Extract/Expand for NIP-44 vibes
- **Memory Probably Safe** - Allocators everywhere, tests don't crash
- **Type Safe** - Zig's compiler made us do it right

## Quick Start

### 1. Add as Dependency

Add to your `build.zig.zon`:

```zig
.dependencies = .{
    .mls_zig = .{
        .url = "https://github.com/futurepaul/mls_zig/archive/main.tar.gz",
        .hash = "...", // zig will provide this
    },
},
```

Add to your `build.zig`:

```zig
const mls_dep = b.dependency("mls_zig", .{
    .target = target,
    .optimize = optimize,
});

exe.root_module.addImport("mls_zig", mls_dep.module("mls_zig"));
```

### 2. NIP-EE Integration (Maybe Works?)

```zig
const std = @import("std");
const mls = @import("mls_zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // 1. Select cipher suite for your application
    const cipher_suite = mls.cipher_suite.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    // 2. Derive NIP-44 keys from group exporter secret
    // (In practice, exporter_secret comes from your MLS group state)
    const exporter_secret = [_]u8{0x5a, 0x09, 0x7e, /* ... 32 bytes */};
    
    var nip44_key = try cipher_suite.exporterSecret(
        allocator,
        &exporter_secret,
        "nostr",                    // Standard NIP-EE label
        "conversation_key_v1",      // Context for this chat
        32                          // NIP-44 key length
    );
    defer nip44_key.deinit();

    // 3. Add Nostr-specific extensions
    var extensions = mls.key_package.Extensions.init(allocator);
    defer extensions.deinit();
    
    try mls.nostr_extensions.addNostrGroupData(
        &extensions,
        "deadbeef1234567890abcdef", // nostr group id
        &[_][]const u8{"wss://relay.example.com"}, // relay URLs
        "npub1creator...", // creator's nostr pubkey
        "{\"name\":\"My Group\"}" // group metadata JSON
    );

    // Ready for integration with nostr_zig! (probably)
    std.log.info("NIP-44 key: {x}", .{nip44_key.asSlice()});
}
```

**Try it**: `zig build example` (fingers crossed)

## API Reference

### Core Types

#### `CipherSuite`
Cryptographic algorithm configuration:
```zig
const cipher_suite = mls.cipher_suite.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
```

#### `MlsGroup`
Main group management interface:
```zig
// Create new group
var group = try mls.mls_group.MlsGroup.createGroup(allocator, cipher_suite, bundle);

// Add member (returns Welcome message for new member)
const welcome = try group.addMember(allocator, new_member_key_package);

// Remove member
try group.removeMember(member_index);

// Get current group secret for key derivation
const exporter_secret = group.getExporterSecret(); // Returns ?[]const u8

// Derive NIP-44 key directly (recommended)
if (try group.deriveNipeeKey(allocator, "context", 32)) |key| {
    defer key.deinit();
    // Use key.asSlice()
}
```

#### `KeyPackageBundle`
Identity and cryptographic keys for group membership:
```zig
var bundle = try mls.key_package.KeyPackageBundle.init(allocator, cipher_suite, credential);
```

### NIP-EE Specific Functions

#### Exporter Secret Derivation
```zig
// Derive keys for NIP-44 encryption from MLS group secrets
var nip44_key = try cipher_suite.exporterSecret(
    allocator,
    group_exporter_secret,
    "nostr",           // Standard label for NIP-EE
    context_data,      // Application-specific context
    32                 // Key length in bytes
);
defer nip44_key.deinit();
```

#### HKDF for Direct NIP-44 Key Derivation
```zig
// Standard NIP-44 key derivation from shared secrets
var prk = try cipher_suite.hkdfExtract(allocator, "", shared_secret);
defer prk.deinit();

var nip44_key = try cipher_suite.hkdfExpand(allocator, prk.asSlice(), "nip44-v2", 32);
defer nip44_key.deinit();
```

#### Nostr Extensions
```zig
// Add Nostr group metadata
try mls.nostr_extensions.addNostrGroupData(
    &extensions,
    group_id,      // Nostr group identifier
    relay_urls,    // Array of relay URLs
    creator_key,   // Creator's Nostr pubkey
    metadata_json  // Group metadata as JSON string
);

// Prevent key package reuse
try mls.nostr_extensions.addLastResort(&extensions);
```

## Advanced Usage

### Custom Group Context
```zig
// Create group with specific context for key derivation
var group_context = try mls.GroupContext.init(allocator, cipher_suite, &group_id);
group_context.addCustomData("conversation_type", "dm");

var group = try mls.mls_group.MlsGroup.createGroupWithContext(
    allocator,
    cipher_suite,
    bundle,
    group_context
);
```

### Epoch Management
```zig
// Advance epoch (generates new group secrets)
try group.advanceEpoch(allocator);

// Get epoch-specific exporter secret
const current_epoch = group.getCurrentEpoch();
var epoch_key = try group.getEpochExporterSecret(allocator, current_epoch, "nostr");
defer epoch_key.deinit();
```

### Error Handling
```zig
const group_result = mls.mls_group.MlsGroup.createGroup(allocator, cipher_suite, bundle);
switch (group_result) {
    .Ok => |group| {
        defer group.deinit();
        // Use group...
    },
    .InvalidCipherSuite => {
        std.log.err("Cipher suite not supported");
        return;
    },
    .InvalidCredential => {
        std.log.err("Invalid credential provided");
        return;
    },
    .OutOfMemory => {
        std.log.err("Insufficient memory");
        return;
    },
}
```

## NIP-EE Integration Pattern

Here's the recommended pattern for integrating MLS-Zig with NIP-EE:

```zig
const NipEEGroup = struct {
    mls_group: mls.mls_group.MlsGroup,
    nostr_group_id: []const u8,
    relay_urls: [][]const u8,
    
    const Self = @This();
    
    pub fn createNostrGroup(
        allocator: Allocator,
        creator_credential: mls.credentials.BasicCredential,
        nostr_group_id: []const u8,
        relay_urls: [][]const u8,
        metadata: []const u8,
    ) !Self {
        // 1. Create key package with Nostr extensions
        var bundle = try mls.key_package.KeyPackageBundle.init(
            allocator,
            .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            creator_credential
        );
        
        // Add last_resort extension to prevent key package reuse
        try mls.nostr_extensions.addLastResort(&bundle.key_package.extensions);
        
        // 2. Create MLS group
        var group = try mls.mls_group.MlsGroup.createGroup(allocator, cipher_suite, bundle);
        
        // 3. Add Nostr-specific group data
        try mls.nostr_extensions.addNostrGroupData(
            &group.extensions,
            nostr_group_id,
            relay_urls,
            creator_credential.identity,
            metadata
        );
        
        return Self{
            .mls_group = group,
            .nostr_group_id = try allocator.dupe(u8, nostr_group_id),
            .relay_urls = try allocator.dupe([]const u8, relay_urls),
        };
    }
    
    pub fn deriveNip44Key(self: *Self, allocator: Allocator, context: []const u8) !?mls.cipher_suite.Secret {
        return self.mls_group.deriveNipeeKey(allocator, context, 32);
    }
    
    pub fn deinit(self: *Self) void {
        self.mls_group.deinit();
        self.allocator.free(self.nostr_group_id);
        for (self.relay_urls) |url| {
            self.allocator.free(url);
        }
        self.allocator.free(self.relay_urls);
    }
};
```

### Testing

Lots of tests that seem to work:

```bash
zig build              # Builds, hopefully
zig test src/root.zig  # Run tests, pray they pass

# Test specific modules
zig test src/cipher_suite.zig     # 16 tests - Crypto stuff  
zig test src/nostr_extensions.zig # 35 tests - Nostr things

# Try examples
zig build example                 # NIP-EE vibes functionality
zig build example-nip44          # NIP-44 HKDF vibes

# OpenMLS compatibility validation  
zig build test-vectors            # Full test suite (scary)
```

## Build Configuration

Add to your `build.zig`:

```zig
const mls_dep = b.dependency("mls_zig", .{
    .target = target,
    .optimize = optimize,
});

exe.root_module.addImport("mls_zig", mls_dep.module("mls_zig"));
```

### Dependencies

- **Zig 0.14.1** - Works on my machine
- **zig-hpke** - Someone else's crypto that seems legit

### Security (Maybe?)

- **Real Cryptography** - We're using actual crypto libraries, not just `return 42`
- **Memory Safety** - Zig makes it hard to mess up, tests don't crash
- **Forward Secrecy** - TreeKEM says it does this, we believe it
- **RFC Compliance** - We read the RFC and tried our best

### Should You Use This?

Maybe for:
- Experimenting with MLS in Zig
- Learning how the protocol works
- Building a Nostr group chat prototype
- Having fun with cryptography (safely)

Probably not for:
- Anything important
- Production systems
- Protecting actual secrets
- Your cryptocurrency wallet

## License

MIT License - see LICENSE file for details.

## Contributing

See DEVELOPMENT.md for implementation details and contribution guidelines.

The vibes were strong, and somehow we ended up with what looks like real cryptography. But remember: THIS IS ALL VIBES! 🎉