# MLS Integration & Migration Plan

## Summary of Current Issues

Based on the audit, the MLS implementation has significant duplication and misalignment with the core Nostr infrastructure:

### 1. **Event Creation Duplication**
- `src/mls/event_signing.zig` implements its own `EventBuilder` instead of extending the core `Event` struct
- The core `Event` struct lacks essential methods like `calculateId()`, `sign()`, and `verify()`
- MLS creates events in isolation from the standard Nostr event pipeline

### 2. **Missing Infrastructure Usage**
- MLS does not use `src/client.zig` for relay communication
- No integration with existing websocket/relay infrastructure
- No usage of `src/test_events.zig` patterns for testing

### 3. **Correct Integrations**
- ✅ Properly uses `src/crypto.zig` for all cryptographic operations
- ✅ Uses `src/nip44/mod.zig` for NIP-44 encryption
- ✅ Imports and uses `nostr.Event` struct (but doesn't extend it)
- ✅ Uses platform abstractions (`wasm_random.zig`, `wasm_time.zig`)

## Migration Plan

### Phase 1: Extend Core Event Infrastructure (High Priority)

#### 1.1 Enhance the Event struct in `src/nostr/event.zig`:
```zig
pub const Event = struct {
    // ... existing fields ...
    
    /// Calculate the event ID according to NIP-01
    pub fn calculateId(self: *Event, allocator: Allocator) !void {
        const crypto = @import("../crypto.zig");
        self.id = try crypto.calculateEventId(
            allocator,
            self.pubkey,
            self.created_at,
            self.kind,
            self.tags,
            self.content,
        );
    }
    
    /// Sign the event with a private key
    pub fn sign(self: *Event, allocator: Allocator, private_key: [32]u8) !void {
        const crypto = @import("../crypto.zig");
        // Ensure ID is calculated
        if (self.id.len == 0) {
            try self.calculateId(allocator);
        }
        const sig_bytes = try crypto.signEvent(self.id, private_key);
        self.sig = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(&sig_bytes)});
    }
    
    /// Verify the event signature
    pub fn verify(self: *const Event) !bool {
        const crypto = @import("../crypto.zig");
        return try crypto.verifySignature(self.id, self.sig, self.pubkey);
    }
    
    /// Create a new unsigned event (for NIP-59 rumors)
    pub fn initUnsigned(allocator: Allocator, kind: u32, content: []const u8, tags: []const []const []const u8) !Event {
        // Implementation
    }
};
```

#### 1.2 Create a unified EventBuilder in core:
Create `src/nostr/builder.zig`:
```zig
pub const EventBuilder = struct {
    allocator: Allocator,
    
    pub fn init(allocator: Allocator) EventBuilder {
        return .{ .allocator = allocator };
    }
    
    pub fn build(self: *EventBuilder, params: EventParams) !Event {
        // Unified event creation logic
    }
};
```

### Phase 2: Migrate MLS to Use Core Infrastructure

#### 2.1 Replace `event_signing.zig` with core usage:
- Remove custom `EventBuilder` implementation
- Update all MLS code to use core `Event` methods
- Keep only NIP-EE specific helpers (createKeyPackageEvent, etc.)

#### 2.2 Integration points to update:
1. `nip_ee.zig` - Use core Event.sign() instead of custom signing
2. `welcome_events.zig` - Use core Event struct methods
3. `keypackage_discovery.zig` - Use core Event creation
4. All other files using event_signing.zig

### Phase 3: Relay Infrastructure Integration

#### 3.1 Create MLS relay client wrapper:
Create `src/mls/relay_client.zig`:
```zig
const client = @import("../client.zig");

pub const MLSRelayClient = struct {
    base_client: client.Client,
    
    pub fn publishKeyPackage(self: *MLSRelayClient, event: Event) !void {
        // Use base_client to publish
    }
    
    pub fn subscribeToGroupMessages(self: *MLSRelayClient, group_id: []const u8) !void {
        // Set up subscription with proper filters
    }
};
```

### Phase 4: Test Infrastructure Integration

#### 4.1 Extend test_events.zig:
Add MLS-specific test events to the existing test infrastructure:
```zig
// In test_events.zig
pub const mls_test_events = [_]TestEvent{
    .{
        .name = "keypackage_event",
        .kind = 443,
        .content = "base64keypackage",
        .tags = &[_][]const []const u8{
            &[_][]const u8{ "cs", "1" },
            &[_][]const u8{ "pv", "1" },
        },
        .expected_valid = true,
    },
    // ... more MLS events
};
```

## Implementation Priority

1. **Immediate (Critical)**:
   - Extend core Event struct with essential methods
   - Start migrating event_signing.zig to use core infrastructure

2. **Short-term (1-2 weeks)**:
   - Complete migration of all MLS event creation to core
   - Remove duplicate implementations
   - Add relay client integration

3. **Medium-term (3-4 weeks)**:
   - Full test infrastructure integration
   - Documentation of API boundaries
   - Performance optimization

## Benefits of Migration

1. **Code Reduction**: ~300-400 lines of duplicate code removed
2. **Consistency**: All events follow same creation/validation patterns
3. **Maintainability**: Single source of truth for event handling
4. **Testability**: Leverage existing test infrastructure
5. **Future-proofing**: New NIPs can extend core Event struct

## Risks & Mitigation

1. **Risk**: Breaking existing MLS functionality
   - **Mitigation**: Comprehensive test coverage before migration

2. **Risk**: Performance regression
   - **Mitigation**: Benchmark before/after migration

3. **Risk**: WASM compatibility issues
   - **Mitigation**: Test in WASM environment at each step

## Success Criteria

- [ ] All MLS tests pass after migration
- [ ] No duplicate event creation code
- [ ] MLS uses standard relay infrastructure
- [ ] Clear API boundaries documented
- [ ] Performance benchmarks show no regression