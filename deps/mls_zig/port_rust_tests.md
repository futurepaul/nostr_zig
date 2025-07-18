# OpenMLS to Zig Test Porting Plan

## Overview
This document outlines the plan for porting OpenMLS tests from Rust to Zig, following a red-green cycle approach. We'll start with the simplest tests and gradually build up to more complex ones, identifying dependencies as we go.

## Test Porting Strategy

1. **Identify the simplest possible test** - Start with tests that have minimal dependencies
2. **Port to Zig (Red)** - Write the test in Zig, expecting it to fail
3. **Make it work (Green)** - Implement the necessary functionality to make the test pass
4. **Rinse and repeat** - Move to progressively more complex tests

## Test Priority Order

### Phase 1: Basic Data Structures (No Crypto)

#### 1.1 TreeMath Index Types (SIMPLEST START)
- **Source**: `samples/openmls/openmls/src/binary_tree/array_representation/treemath.rs`
- **Tests to port**:
  - `LeafNodeIndex::new()` and basic operations
  - `ParentNodeIndex::new()` and basic operations
  - `TreeNodeIndex` conversions between leaf/parent
- **Dependencies**: None (just basic integer wrapping)
- **Why first**: These are simple wrapper types around u32 with no external dependencies

#### 1.2 TreeMath Operations
- **Source**: Same file as above
- **Tests to port**:
  - `log2()` function
  - `level()` function for nodes
  - `tree_size()` calculation
  - `is_leaf()` and `is_parent()` checks
- **Dependencies**: Basic math operations
- **Why second**: Simple mathematical functions with clear inputs/outputs

#### 1.3 TreeMath Relationships
- **Source**: Same file
- **Tests to port**:
  - `parent()` calculations
  - `left()` and `right()` child calculations
  - `sibling()` calculations
- **Dependencies**: Previous TreeMath functions
- **Why third**: Builds on previous functions but still pure math

### Phase 2: Binary Tree Structure

#### 2.1 Basic Binary Tree
- **Source**: `samples/openmls/openmls/src/binary_tree/tests.rs`
- **Tests to port**:
  - Tree creation
  - Tree size reporting
  - Node access by index
- **Dependencies**: TreeMath from Phase 1
- **Notes**: Will need to implement a basic tree structure

### Phase 3: Credentials (Introduction to Serialization)

#### 3.1 Basic Credential Type
- **Source**: `samples/openmls/openmls/src/credentials/mod.rs`
- **Tests to port**:
  - Creating a basic credential with identity
  - Credential type enum
- **Dependencies**: Will need basic serialization (TLS codec equivalent)
- **Notes**: This introduces our first external dependency need

### Phase 4: Protocol Version and Extensions
- Basic protocol version handling
- Extension types (without crypto operations)

## Dependencies to Research/Implement

### Immediate Needs (Phase 1-2)
- None! Just standard Zig features

### Near-term Needs (Phase 3+)
- **TLS Codec equivalent**: For serialization/deserialization
  - Research: Does Zig have a TLS codec library?
  - Alternative: Implement basic TLS encoding/decoding functions
- **Error handling patterns**: Zig's error unions vs Rust's Result type

### Future Needs (Later phases)
- **Crypto libraries** (GREAT NEWS - mostly available in std.crypto!):
  - ✅ Signature algorithms (Ed25519, ECDSA) - Available in std.crypto
  - ✅ Hash functions (SHA256, SHA384, SHA512) - Available in std.crypto
  - ✅ HMAC - Available in std.crypto
  - ✅ KDF (Key Derivation Functions) - Available in std.crypto
  - ❓ HPKE (Hybrid Public Key Encryption) - Need to check if available or implement
- **Random number generation** - std.crypto.random available
- **Time/DateTime handling** - std.time available

## First Test Implementation Plan

### Test 1: LeafNodeIndex Creation and Access
```rust
// Rust version
#[test]
fn test_leaf_node_index() {
    let index = LeafNodeIndex::new(5);
    assert_eq!(index.u32(), 5);
    assert_eq!(index.usize(), 5);
}
```

```zig
// Zig version (to implement)
test "LeafNodeIndex creation and access" {
    const index = LeafNodeIndex.new(5);
    try testing.expectEqual(index.u32(), 5);
    try testing.expectEqual(index.usize(), 5);
}
```

**Implementation needed**:
1. Create `src/tree_math.zig`
2. Define `LeafNodeIndex` struct with:
   - Internal u32 field
   - `new()` function
   - `u32()` method
   - `usize()` method

## Success Metrics
- Each test passes in Zig
- Code follows Zig idioms and best practices
- Dependencies are properly identified and documented
- Performance is comparable to Rust implementation

## Notes
- Start with the absolutely simplest tests first
- Don't worry about perfect API compatibility initially
- Focus on understanding the core concepts
- Document any Zig-specific design decisions