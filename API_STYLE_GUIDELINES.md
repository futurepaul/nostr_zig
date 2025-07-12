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

**Guideline**: Use consistent wrapping strategy for semantic types.

**Option A - Minimal Wrapping** (Recommended):
```zig
// Only wrap when adding methods or validation
pub const HPKEPublicKey = []const u8;
pub const SignaturePublicKey = []const u8;
pub const GroupId = [32]u8;
```

**Option B - Consistent Wrapping**:
```zig
// Wrap all semantic types for type safety
pub const HPKEPublicKey = struct { data: []const u8 };
pub const SignaturePublicKey = struct { data: []const u8 };
pub const GroupId = struct { data: [32]u8 };
```

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

### 4. **Builder Pattern for Complex Types**

**Guideline**: Use builder pattern for types with many fields.

```zig
pub const KeyPackageBuilder = struct {
    allocator: Allocator,
    version: ProtocolVersion = .mls10,
    cipher_suite: Ciphersuite = .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
    // ... other fields
    
    pub fn build(self: *const KeyPackageBuilder) !KeyPackage {
        // Validation and construction
    }
};
```

### 5. **Error Handling**

**Guideline**: Use descriptive error types.

```zig
pub const ParseError = error{
    InvalidVersion,
    InvalidCipherSuite,
    InvalidWireFormat,
    UnexpectedEof,
    // Not just: error.Invalid
};
```

### 6. **Serialization Symmetry**

**Guideline**: Parse and serialize functions should be symmetric.

```zig
// If we have:
pub fn parse(allocator: Allocator, data: []const u8) !KeyPackage

// We should have:
pub fn serialize(allocator: Allocator, key_package: KeyPackage) ![]u8

// And this should always work:
const original = try parse(allocator, data);
const serialized = try serialize(allocator, original);
const reparsed = try parse(allocator, serialized);
// original should equal reparsed
```

## 🛠️ Implementation Plan

### Phase 1: Immediate Fixes
1. Fix ProtocolVersion enum to handle wire format values
2. Standardize type wrapping (choose Option A or B)
3. Update parsing functions to handle common Nostr encodings

### Phase 2: API Refinement  
1. Add builder patterns for complex types
2. Improve error messages
3. Add validation helpers

### Phase 3: Documentation
1. Document all public APIs
2. Add usage examples
3. Create migration guide for API changes

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
| Type wrapping | Use Option A (minimal) | Simpler, less boilerplate |
| Unknown enum values | Use non-exhaustive enums | Handle future protocol versions |
| Parsing functions | Support multiple encodings | Common in Nostr ecosystem |

This is a living document and should be updated as new patterns emerge or decisions are made.