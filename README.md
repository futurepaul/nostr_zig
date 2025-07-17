# Nostr Zig

A Zig implementation of the Nostr protocol for building decentralized social applications.

## Features

- 🔌 **WebSocket Client**: Connect to Nostr relays
- 📤 **Event Publishing**: Create and publish Nostr events
- 📥 **Subscriptions**: Subscribe to event streams with filters
- 🔐 **Production Cryptography**: BIP340 Schnorr signatures using bitcoin-core/secp256k1
- 🏷️ **NIP-19 Support**: Full bech32 encoding/decoding for nsec1/npub1 keys
- 🔒 **NIP-44 v2 Encryption**: Real encrypted direct messages with proper HMAC validation
- 🔐 **NIP-EE Compliant**: Double-layer encryption with MLS (inner) + NIP-44 (outer)
- 🔑 **MLS Signing Keys**: Separate Ed25519/P256 keys for MLS operations (not Nostr identity)
- 📦 **TLS Wire Format**: Proper MLSMessage serialization per RFC 9420
- 🔄 **Two-Stage Decryption**: Full encrypt → send → receive → decrypt cycle
- 🎨 **Interactive Visualizer**: React-based UI demonstrating NIP-EE message flow
- 🛠️ **CLI Tool**: nak-compatible command-line interface
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

### CLI Usage

The CLI tool provides nak-compatible functionality for creating and publishing Nostr events.

#### Basic Commands

```bash
# Show help
zig build run -- help

# Create a basic event (outputs JSON)
zig build run -- event

# Create event with custom content
zig build run -- event -c 'Hello, Nostr!'

# Publish to relays
zig build run -- event -c 'Hello world!' relay.damus.io nos.lol
```

#### Secret Key Formats

**Environment Variable (Recommended):**
```bash
export NOSTR_SECRET_KEY="nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5"
zig build run -- event -c 'Hello from environment!'
```

**Command Line Options:**
```bash
# NIP-19 bech32 format (nsec1...)
zig build run -- event --sec nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5 -c 'Hello!'

# 64-character hex format
zig build run -- event --sec 67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa -c 'Hello!'

# Test key (like nak)
zig build run -- event --sec 01 -c 'Hello from test key!'
```

#### Advanced Usage

```bash
# Add tags
zig build run -- event --sec 01 -c 'Good morning!' --tag t=gm

# Set event kind
zig build run -- event --sec 01 -c 'Profile update' -k 0

# Publish to multiple relays
zig build run -- event --sec 01 -c 'Hello Nostr!' \
  wss://relay.damus.io \
  wss://nos.lol \
  wss://nostr.wine \
  wss://relay.snort.social

# Parse existing events from stdin
echo '{"id":"...","pubkey":"..."}' | zig build run -- parse
```

#### Smart Relay URLs

The CLI automatically adds the correct protocol:
- `localhost:8080` → `ws://localhost:8080` (local development)
- `relay.damus.io` → `wss://relay.damus.io` (production)

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
├── crypto.zig         # BIP340 Schnorr cryptography (secp256k1)
├── bech32.zig         # NIP-19 bech32 encoding/decoding
├── nip44/             # NIP-44 encrypted messages
│   ├── v2.zig         # Main implementation
│   └── ...            # Supporting modules
├── mls/               # MLS/NIP-EE group messaging
│   ├── types.zig      # Core MLS types
│   └── ...            # MLS modules
├── secp256k1/         # Custom secp256k1 wrapper
│   ├── secp256k1.zig  # Zig bindings
│   └── callbacks.c    # C callbacks
└── test_*.zig         # Test files

deps/
├── secp256k1/         # bitcoin-core/secp256k1 (git submodule)
└── bech32/            # sipa/bech32 reference (git submodule)

debug_scripts/         # Debug utilities (not for production use)
```

## CLI Commands Reference

| Command | Description |
|---------|-------------|
| `event` | Create and optionally publish a Nostr event |
| `parse` | Parse and validate a Nostr event from stdin |
| `help`  | Show help information |

### CLI Options

| Option | Description | Example |
|--------|-------------|---------|
| `--sec <key>` | Secret key (nsec1, hex, or '01' for test) | `--sec nsec1...` |
| `-c <content>` | Event content text | `-c 'Hello world!'` |
| `--tag <tag>` | Add tag in 'key=value' format | `--tag t=gm` |
| `-k <kind>` | Event kind number (default: 1) | `-k 0` |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `NOSTR_SECRET_KEY` | Secret key (nsec1 or hex format) |

## Current Limitations

- **Event Parsing**: Incoming EVENT messages need full parsing implementation
- **Reconnection**: No automatic reconnection on disconnect  
- **NIP Coverage**: Basic NIPs only, more to be implemented

## Next Steps

1. ✅ ~~Integrate secp256k1 for proper signatures~~ **COMPLETED**
2. ✅ ~~Add NIP-19 encoding/decoding (npub, nsec, etc.)~~ **COMPLETED**
3. ✅ ~~Implement NIP-44 encryption~~ **COMPLETED**
4. Complete EVENT message parsing
5. Finish MLS/NIP-EE integration (HPKE, Ed25519)
6. Add relay pool management
7. Create higher-level abstractions
8. Add encode commands (npub, nevent, etc.)

## Development

See [DEVELOPMENT.md](DEVELOPMENT.md) for detailed development guidelines and [PROGRESS.md](PROGRESS.md) for current status.

### Testing

The project includes comprehensive tests:
- Unit tests: `zig build test`
- Integration tests: `zig build test-roundtrip`
- NIP-44 tests: Included in main test suite (18/18 passing)
- MLS tests: Included in main test suite (39/41 passing)

### Project Structure

The codebase is organized for clarity:
- Production code in `src/`
- Debug utilities in `debug_scripts/` (not for production use)
- Dependencies in `deps/` as git submodules
- Examples accessible via `zig build example*` commands

## License

MIT