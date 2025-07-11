# Nostr Zig Examples

## Running the examples

First, make sure you have a Nostr relay running locally:

```bash
nak serve --verbose
```

This will start a relay on `ws://localhost:10547`.

## Basic Client Example

The `basic_client.zig` example demonstrates:
- Connecting to a relay
- Publishing an event
- Creating a subscription
- Processing incoming messages

To run:

```bash
zig build example
```

## Test Examples

### Roundtrip Test

The roundtrip test demonstrates publishing an event in one thread and receiving it in another:

```bash
zig build test-roundtrip
```

### All Tests

Run all unit tests:

```bash
zig build test
```