# Nostr Zig

A Zig implementation of the Nostr protocol for building decentralized social applications.

## Features

- 🔌 **WebSocket Client**: Connect to Nostr relays
- 📤 **Event Publishing**: Create and publish Nostr events
- 📥 **Subscriptions**: Subscribe to event streams with filters
- 🔐 **Cryptography**: Event ID calculation with SHA256
- 📋 **Event Types**: Support for various Nostr event kinds
- 🧪 **Testing**: Comprehensive test suite

## Quick Start

### Prerequisites

- Zig 0.14.1 or later
- A Nostr relay (or use `nak serve --verbose` for testing)

### Building

```bash
zig build
```

### Running Examples

Start a local relay for testing:
```bash
nak serve --verbose
```

Run the basic example:
```bash
zig build example
```

Run the realistic example (with proper event IDs):
```bash
zig build example-realistic
```

### Running Tests

```bash
zig build test
```

Run the roundtrip test:
```bash
zig build test-roundtrip
```

## Usage

```zig
const std = @import("std");
const nostr_zig = @import("nostr_zig");

// Create a client
var client = nostr_zig.Client.init(allocator, "ws://localhost:10547");
defer client.deinit();

// Connect to relay
try client.connect();
defer client.disconnect();

// Create and publish an event
const event = nostr_zig.Event{
    .id = event_id,
    .pubkey = pubkey,
    .created_at = std.time.timestamp(),
    .kind = 1,  // Text note
    .tags = &[_][]const []const u8{},
    .content = "Hello, Nostr!",
    .sig = signature,
};

try client.publish_event(event, null);

// Subscribe to events
const filters = [_]nostr_zig.Filter{
    .{
        .kinds = &[_]u32{1},  // Text notes
        .limit = 10,
    },
};

try client.subscribe("my-sub", &filters, null);
```

## Architecture

```
src/
├── main.zig           # CLI entry point
├── root.zig           # Library exports
├── nostr.zig          # Core Nostr types
├── nostr/
│   └── event.zig      # Event structure and parsing
├── client.zig         # WebSocket client implementation
├── crypto.zig         # Cryptographic operations
├── test_events.zig    # Test event examples
└── test_roundtrip.zig # Integration tests
```

## Current Limitations

- **Signatures**: Currently uses placeholder signatures. Proper BIP340 Schnorr signatures require the [secp256k1-zig](https://github.com/Syndica/secp256k1-zig) library.
- **Event Parsing**: Incoming EVENT messages need full parsing implementation
- **Reconnection**: No automatic reconnection on disconnect
- **NIP Coverage**: Basic NIPs only, more to be implemented

## Next Steps

1. Integrate secp256k1-zig for proper signatures
2. Complete EVENT message parsing
3. Add NIP-19 encoding/decoding (npub, nsec, etc.)
4. Implement more NIPs (NIP-44 encryption, etc.)
5. Add relay pool management
6. Create higher-level abstractions

## Development

See [DEVELOPMENT.md](DEVELOPMENT.md) for detailed development guidelines and [PROGRESS.md](PROGRESS.md) for current status.

## License

MIT