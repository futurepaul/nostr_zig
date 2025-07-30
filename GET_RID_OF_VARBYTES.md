# GET RID OF VARBYTES - Migration Plan

## Why Replace VarBytes?
- VarBytes is an unnecessary abstraction over ArrayList
- It causes memory ownership confusion
- ArrayList is standard Zig with clear semantics
- The allocator field issue shows VarBytes is poorly designed

## Migration Strategy

### Phase 1: Core Crypto Types
1. **key_schedule.zig** - Replace all VarBytes returns with ArrayList(u8)
2. **cipher_suite.zig** - Update Secret type if it uses VarBytes
3. **tree_kem.zig** - Replace VarBytes in ParentNode, HpkeCiphertext, and return types

### Phase 2: MLS Core Types  
1. **mls_group.zig** - Replace VarBytes in GroupContext, Welcome, ProposalRef
2. **leaf_node.zig** - Replace VarBytes in LeafNode fields
3. **key_package.zig** - Replace VarBytes in KeyPackage fields
4. **key_package_flat.zig** - Update flat representations

### Phase 3: Extensions and Utils
1. **credentials.zig** - Replace VarBytes in Credential types
2. **nostr_extensions.zig** - Update any VarBytes usage
3. **test_vectors.zig** - Update test code

### Phase 4: Our Codebase
1. Update any code that expects VarBytes from mls_zig
2. Change to use .items instead of .asSlice()
3. Update any deinit() calls to use ArrayList's deinit()

## Key Changes

### Before (VarBytes):
```zig
pub fn deriveSecret() !VarBytes {
    return VarBytes{
        .data = data,
        .allocator = allocator,
    };
}
// Usage:
var secret = try deriveSecret();
defer secret.deinit();
const bytes = secret.asSlice();
```

### After (ArrayList):
```zig
pub fn deriveSecret() !std.ArrayList(u8) {
    var result = std.ArrayList(u8).init(allocator);
    try result.appendSlice(data);
    return result;
}
// Usage:
var secret = try deriveSecret();
defer secret.deinit();
const bytes = secret.items;
```

## Common Patterns to Replace

1. **VarBytes.init(allocator, data)**
   ```zig
   // Before
   return VarBytes.init(allocator, data);
   // After
   var list = std.ArrayList(u8).init(allocator);
   try list.appendSlice(data);
   return list;
   ```

2. **VarBytes literal construction**
   ```zig
   // Before
   return VarBytes{ .data = data, .allocator = allocator };
   // After
   var list = std.ArrayList(u8).init(allocator);
   try list.appendSlice(data);
   return list;
   ```

3. **Empty VarBytes**
   ```zig
   // Before
   return VarBytes{ .data = &[_]u8{}, .allocator = allocator };
   // After
   return std.ArrayList(u8).init(allocator);
   ```

4. **VarBytes.asSlice()**
   ```zig
   // Before
   secret.asSlice()
   // After
   secret.items
   ```

5. **VarBytes.len()**
   ```zig
   // Before
   secret.len()
   // After
   secret.items.len
   ```

## Execution Order
1. Start with key_schedule.zig (already partially done)
2. Fix tree_kem.zig next (it's causing current build errors)
3. Work through mls_group.zig
4. Continue with remaining files
5. Update our codebase last

## Testing Strategy
- Run `zig build` after each file to catch errors early
- Look for any remaining VarBytes usage with grep
- Ensure all tests still pass

Let's get rid of this unnecessary abstraction!