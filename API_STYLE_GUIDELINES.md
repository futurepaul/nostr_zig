# API Style Guidelines for Nostr Zig

## 🎯 Overview

This document outlines API design guidelines to ensure consistency across the nostr_zig codebase. Following these guidelines will help maintain a predictable and user-friendly API.

## 🔍 Current Issues Identified

Through implementation of the NAK test script, several API consistency issues have been identified:

### 1. **Inconsistent Type Wrapping**
**Problem**: Some types use struct wrappers while others don't, leading to inconsistent access patterns.

**Examples of inconsistency**:
```zig
// Wrapped types (requires .data access)
pub const HPKEPublicKey = struct {
    data: []const u8,
};

// Unwrapped types (direct access)
const init_key = try allocator.alloc(u8, init_key_len);  // Returns []u8
// Later needs to be wrapped: 
.init_key = types.HPKEPublicKey{ .data = init_key }
```

### 2. **Limited Enum Values**
**Problem**: Enums with insufficient values for real-world usage.

**Example**:
```zig
pub const ProtocolVersion = enum(u16) {
    mls10 = 0x0100,  // Only one value, but wire format has others
};
```

### 3. **JSON API Changes**
**Problem**: Zig's JSON API changes between versions causing field access inconsistencies.

**Example**:
```zig
// Old API
const array = root.Array;
const msg_type = array.items[0].String;

// New API  
const array = root.array;
const msg_type = array.items[0].string;
```

### 4. **Union vs Enum Confusion**
**Problem**: Tagged unions being treated as enums in parsing code.

**Example**:
```zig
// Type definition
pub const LeafNodeSource = union(enum) { ... };

// Incorrect usage
.leaf_node_source = @enumFromInt(source),  // Won't compile!

// Correct usage
.leaf_node_source = switch (source) { ... }
```

## 📋 Proposed Guidelines

### 1. **Type Wrapping Policy**

**Guideline**: Use consistent wrapping for all semantic types to provide type safety and clear API boundaries.

**Chosen Approach - Consistent Wrapping (Option B)**:
```zig
// Wrap all semantic types for type safety and clarity
pub const HPKEPublicKey = struct { 
    data: []const u8,
    
    pub fn init(data: []const u8) HPKEPublicKey {
        return .{ .data = data };
    }
    
    pub fn eql(self: HPKEPublicKey, other: HPKEPublicKey) bool {
        return std.mem.eql(u8, self.data, other.data);
    }
};

pub const SignaturePublicKey = struct { 
    data: []const u8,
    
    pub fn init(data: []const u8) SignaturePublicKey {
        return .{ .data = data };
    }
};

pub const GroupId = struct { 
    data: [32]u8,
    
    pub fn init(data: [32]u8) GroupId {
        return .{ .data = data };
    }
};
```

**Benefits**:
- Type safety prevents mixing different key types
- Clear semantic meaning in function signatures
- Consistent access pattern (.data) across all types
- Room for adding validation or methods later

### 2. **Enum Completeness**

**Guideline**: Enums should handle all known values or provide fallback.

```zig
pub const ProtocolVersion = enum(u16) {
    reserved = 0x0000,
    mls10 = 0x0100,
    _,  // Allow unknown values
    
    pub fn fromInt(value: u16) ProtocolVersion {
        return @enumFromInt(value);
    }
};
```

### 3. **Parsing Functions**

**Guideline**: Parsing functions should handle multiple formats gracefully.

```zig
pub fn parseFromEvent(allocator: Allocator, event: Event) !KeyPackage {
    const data = try decodeEventContent(allocator, event.content);
    defer allocator.free(data);
    return parse(allocator, data);
}

fn decodeEventContent(allocator: Allocator, content: []const u8) ![]u8 {
    // Try hex first (most common in Nostr)
    if (isHex(content)) return decodeHex(allocator, content);
    // Try base64
    if (isBase64(content)) return decodeBase64(allocator, content);
    // Assume raw binary
    return allocator.dupe(u8, content);
}
```

### 4. **Builder Pattern for Complex Types (Idiomatic Zig)**

**Guideline**: Use init functions with default parameters instead of traditional builder pattern.

```zig
// Idiomatic Zig approach - NOT a separate builder type
pub const KeyPackage = struct {
    version: ProtocolVersion,
    cipher_suite: Ciphersuite,
    init_key: HPKEPublicKey,
    leaf_node: LeafNode,
    // ... other fields
    
    pub const InitOptions = struct {
        version: ProtocolVersion = .mls10,
        cipher_suite: Ciphersuite = .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        // other optional fields with defaults
    };
    
    pub fn init(
        allocator: Allocator,
        init_key: []const u8,
        leaf_node: LeafNode,
        options: InitOptions,
    ) !KeyPackage {
        // Validation
        if (init_key.len != 32) return error.InvalidKeyLength;
        
        return KeyPackage{
            .version = options.version,
            .cipher_suite = options.cipher_suite,
            .init_key = HPKEPublicKey.init(try allocator.dupe(u8, init_key)),
            .leaf_node = leaf_node,
        };
    }
};

// Usage:
const kp = try KeyPackage.init(
    allocator,
    init_key_data,
    leaf_node,
    .{}, // Use defaults
);

// Or with custom options:
const kp2 = try KeyPackage.init(
    allocator,
    init_key_data,
    leaf_node,
    .{ .version = .mls10, .cipher_suite = custom_suite },
);
```

### 5. **Error Handling**

**Guideline**: Use descriptive error sets with clear naming.

```zig
pub const KeyPackageError = error{
    InvalidVersion,
    UnsupportedCipherSuite,
    InvalidKeyLength,
    InvalidSignature,
    MalformedWireFormat,
    UnexpectedEndOfStream,
    ProtocolVersionMismatch,
};

pub const GroupError = error{
    InvalidGroupId,
    MemberNotFound,
    InvalidEpoch,
    StaleMessage,
    InvalidTreeHash,
};

// Functions should return specific error sets
pub fn parseKeyPackage(allocator: Allocator, data: []const u8) KeyPackageError!KeyPackage {
    // Implementation
}

// Or use error unions for flexibility
pub fn processMessage(allocator: Allocator, msg: []const u8) (KeyPackageError || GroupError)!Message {
    // Implementation
}
```

### 6. **Serialization Symmetry**

**Guideline**: Every parseable type must have symmetric serialization.

```zig
pub const KeyPackage = struct {
    // ... fields ...
    
    pub fn parse(allocator: Allocator, reader: anytype) !KeyPackage {
        // Parse from reader
    }
    
    pub fn serialize(self: KeyPackage, writer: anytype) !void {
        // Write to writer
    }
    
    // Convenience functions for []u8
    pub fn parseBytes(allocator: Allocator, data: []const u8) !KeyPackage {
        var stream = std.io.fixedBufferStream(data);
        return parse(allocator, stream.reader());
    }
    
    pub fn serializeAlloc(self: KeyPackage, allocator: Allocator) ![]u8 {
        var list = std.ArrayList(u8).init(allocator);
        try self.serialize(list.writer());
        return list.toOwnedSlice();
    }
    
    // Test helper
    pub fn testRoundtrip(self: KeyPackage, allocator: Allocator) !void {
        const serialized = try self.serializeAlloc(allocator);
        defer allocator.free(serialized);
        
        const reparsed = try parseBytes(allocator, serialized);
        try std.testing.expect(self.eql(reparsed));
    }
};
```

**Testing Pattern**:
```zig
test "KeyPackage roundtrip" {
    const allocator = std.testing.allocator;
    const original = try KeyPackage.init(allocator, test_data, .{});
    try original.testRoundtrip(allocator);
}
```

## 🛠️ Implementation Plan

### Phase 1: Core API Updates ✅ READY TO IMPLEMENT
1. **Type Wrapping**: Convert all semantic types to consistent struct wrappers
   - HPKEPublicKey, SignaturePublicKey, GroupId, etc.
   - Add init() and eql() methods to each
2. **Error Sets**: Define specific error sets for each module
   - KeyPackageError, GroupError, WelcomeError, etc.
3. **Enum Handling**: Update all enums to be non-exhaustive
   - ProtocolVersion, Ciphersuite, LeafNodeSource, etc.

### Phase 2: Serialization & Parsing
1. **Symmetric Functions**: Add serialize() for every parse()
2. **Stream-based I/O**: Use readers/writers for flexibility
3. **Test Helpers**: Add testRoundtrip() to all types
4. **Encoding Support**: Handle hex/base64 in parseFromEvent()

### Phase 3: API Polish
1. **Init Functions**: Replace builders with init + options
2. **Validation**: Add validate() methods where needed
3. **Documentation**: Doc comments on all public APIs
4. **Examples**: Add usage examples in doc tests

## 📝 Examples of Good API Design

### Good: Predictable and Consistent
```zig
pub const KeyPackage = struct {
    version: ProtocolVersion,
    cipher_suite: Ciphersuite,
    init_key: HPKEPublicKey,
    
    pub fn parse(allocator: Allocator, data: []const u8) !KeyPackage { }
    pub fn serialize(self: KeyPackage, allocator: Allocator) ![]u8 { }
    pub fn validate(self: KeyPackage) !void { }
};
```

### Bad: Inconsistent and Surprising
```zig
pub fn parseKeyPackage(data: []const u8) !KeyPackage { }  // Where's allocator?
pub fn keyPackageToBytes(kp: *const KeyPackage) []u8 { }  // Different naming
pub fn isValid(kp: KeyPackage) bool { }  // No error details
```

## 🎯 Goals

1. **Consistency**: Similar operations should have similar APIs
2. **Predictability**: Users should be able to guess API patterns
3. **Type Safety**: Use Zig's type system to prevent errors
4. **Simplicity**: Don't over-engineer, keep it simple
5. **Performance**: Zero-cost abstractions where possible

## 🔄 Migration Strategy

When updating APIs to follow these guidelines:

1. **Deprecate, don't break**: Mark old APIs as deprecated
2. **Provide migration path**: Document how to update code
3. **Update incrementally**: Fix one module at a time
4. **Test thoroughly**: Ensure compatibility

## 📊 Decision Record

| Issue | Decision | Rationale |
|-------|----------|-----------|
| Type wrapping | Use Option B (consistent wrapping) | Type safety, clear API boundaries |
| Unknown enum values | Use non-exhaustive enums | Handle future protocol versions |
| Parsing functions | Support multiple encodings | Common in Nostr ecosystem |
| Builder pattern | Use init functions with options | Idiomatic Zig, avoids separate builder types |
| Error handling | Descriptive error sets | Clear error messages, better debugging |
| Serialization | Symmetric parse/serialize | Essential for testing and roundtrips |

This is a living document and should be updated as new patterns emerge or decisions are made.

## 📌 Concrete Example: Applying Guidelines to KeyPackage

Here's how to transform the current KeyPackage implementation to follow these guidelines:

### Before (Current Implementation):
```zig
pub fn parseKeyPackage(allocator: std.mem.Allocator, data: []const u8) !KeyPackage {
    var stream = std.io.fixedBufferStream(data);
    const reader = stream.reader();
    
    const version = try reader.readInt(u16, .big);
    // ... parsing logic ...
    
    return KeyPackage{
        .version = @enumFromInt(version),
        .init_key = init_key_data, // Raw []u8
        // ...
    };
}
```

### After (Following Guidelines):
```zig
pub const KeyPackage = struct {
    version: ProtocolVersion,
    cipher_suite: Ciphersuite,
    init_key: HPKEPublicKey,
    leaf_node: LeafNode,
    extensions: Extensions,
    signature: Signature,
    
    pub const ParseError = error{
        InvalidVersion,
        UnsupportedCipherSuite,
        InvalidKeyLength,
        MalformedExtensions,
        InvalidSignature,
        UnexpectedEndOfStream,
    };
    
    pub fn parse(allocator: Allocator, reader: anytype) ParseError!KeyPackage {
        const version_raw = try reader.readInt(u16, .big);
        const version = ProtocolVersion.fromInt(version_raw) catch return error.InvalidVersion;
        
        const cipher_suite_raw = try reader.readInt(u16, .big);
        const cipher_suite = Ciphersuite.fromInt(cipher_suite_raw) catch return error.UnsupportedCipherSuite;
        
        const init_key_len = try reader.readInt(u16, .big);
        if (init_key_len != 32) return error.InvalidKeyLength;
        
        const init_key_data = try allocator.alloc(u8, init_key_len);
        try reader.readNoEof(init_key_data);
        
        // ... more parsing ...
        
        return KeyPackage{
            .version = version,
            .cipher_suite = cipher_suite,
            .init_key = HPKEPublicKey.init(init_key_data),
            // ...
        };
    }
    
    pub fn serialize(self: KeyPackage, writer: anytype) !void {
        try writer.writeInt(u16, @intFromEnum(self.version), .big);
        try writer.writeInt(u16, @intFromEnum(self.cipher_suite), .big);
        
        try writer.writeInt(u16, @intCast(self.init_key.data.len), .big);
        try writer.writeAll(self.init_key.data);
        
        // ... more serialization ...
    }
    
    pub fn parseBytes(allocator: Allocator, data: []const u8) ParseError!KeyPackage {
        var stream = std.io.fixedBufferStream(data);
        return parse(allocator, stream.reader());
    }
    
    pub fn serializeAlloc(self: KeyPackage, allocator: Allocator) ![]u8 {
        var list = std.ArrayList(u8).init(allocator);
        try self.serialize(list.writer());
        return list.toOwnedSlice();
    }
    
    pub fn parseFromNostrEvent(allocator: Allocator, event: Event) !KeyPackage {
        const data = try decodeEventContent(allocator, event.content);
        defer allocator.free(data);
        return parseBytes(allocator, data);
    }
    
    pub fn eql(self: KeyPackage, other: KeyPackage) bool {
        return self.version == other.version and
               self.cipher_suite == other.cipher_suite and
               self.init_key.eql(other.init_key) and
               self.leaf_node.eql(other.leaf_node);
    }
    
    pub fn validate(self: KeyPackage) !void {
        if (self.version != .mls10) return error.UnsupportedVersion;
        try self.leaf_node.validate();
        // More validation...
    }
};
```

This example demonstrates:
- ✅ Consistent type wrapping (HPKEPublicKey)
- ✅ Descriptive error sets (ParseError)
- ✅ Symmetric serialization (parse/serialize)
- ✅ Multiple parsing entry points (reader/bytes/event)
- ✅ Validation and equality methods
- ✅ Clear, predictable API