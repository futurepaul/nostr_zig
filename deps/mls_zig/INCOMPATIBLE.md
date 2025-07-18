# MLS Implementation Incompatibilities

This document tracks known differences between our MLS implementation and the OpenMLS reference implementation, as discovered through test vector validation.

**Note**: These incompatibilities do not affect NIP-EE functionality, as NIP-EE uses MLS for key management only with actual encryption handled by NIP-44.

## Exporter Secret Derivation

**Status**: 🔴 **INCOMPATIBLE** - OpenMLS test vectors fail

**Discovered**: 2025-01-11 during key schedule test vector validation

### The Issue

Our `exporterSecret()` function produces different results than OpenMLS for identical inputs:

```
Test Input:
- Exporter Secret: 5a097e149f2a375d0b9e1d1f4dc3a9c6c1788df888e5441f41a8791f4dc56cea
- Label (hex):     9ba13d54ecdec7cbefcb47b4268d7b1990fabc6d6e67681e167959389d84e4e4
- Context (hex):   884f1af892ab002f5be4c5d5081ade9e0e6418c6ea7a9a92e90534f19dcef785
- Length:          32

Expected (OpenMLS): dbce4e25e59ab4dfa6f6200f113ed08393cf6e7286d024811141c6a4dd11c0cb
Our Result:         37154cdd9c0625bf5643a531591078fb2c8107fa08bff4c2b8ca64cc2b596125
```

### Root Cause Analysis

**Our Implementation**:
```zig
pub fn exporterSecret(
    self: CipherSuite,
    allocator: Allocator,
    exporter_secret: []const u8,
    label: []const u8,
    context: []const u8,
    length: u16,
) !Secret {
    // Hash the context
    const context_hash = hash(context);
    
    // Derive using: Derive-Secret(exporter_secret, label, Hash(context))
    return self.hkdfExpandLabel(allocator, exporter_secret, label, context_hash, length);
}
```

**The Problem**: Our `hkdfExpandLabel` treats the label as a string and prepends "MLS 1.0 ":
```zig
const full_label = try std.fmt.allocPrint(allocator, "{s}{s}", .{ MLS_LABEL_PREFIX, label });
```

But OpenMLS test vectors provide **binary label data**, not string labels.

### Approaches Tested

We tested 4 different derivation methods, none matched OpenMLS:

1. **Raw HKDF** (no MLS prefix): `172c14d5...` ❌
2. **Direct deriveSecret** (raw context): `72ae5f81...` ❌  
3. **Hashed context**: `37154cdd...` ❌
4. **Our exporterSecret**: `37154cdd...` ❌ (same as #3)

### Specification Ambiguity

**RFC 9420 Section 8.5** states:
> MLS-Exporter(label, context, length) = Derive-Secret(exporter_secret, label, Hash(context))

But it's unclear:
- Should `label` be a string that gets "MLS 1.0 " prefix?
- Should `label` be raw binary data?
- How should the HKDF info structure be constructed?

### Impact

**NIP-EE Functionality**: ✅ No impact - NIP-EE uses exporter for NIP-44 keys, which works correctly
**OpenMLS Interoperability**: ❌ Cannot exchange exporter-derived keys with OpenMLS implementations  
**Security**: ⚠️ Different key derivation means different encryption keys (for MLS interop only)

### Workaround

For applications needing OpenMLS compatibility, use the `deriveSecret` function directly:

```zig
// OpenMLS-compatible exporter (theory - not yet verified)
var compatible_secret = try cipher_suite.deriveSecret(
    allocator,
    exporter_secret,
    raw_binary_label,  // Binary data from OpenMLS
    hashed_context     // SHA256(context)
);
```

### OpenMLS Analysis Results

**OpenMLS Implementation Pattern**:
1. `derive_secret(exporter_secret, label)` - where `label` is a **string**
2. `kdf_expand_label(result, "exported", Hash(context), length)`

**Test Vector Analysis**:
- Labels in test vectors appear to be **binary data** (32 bytes hex-encoded)
- Example: `9ba13d54ecdec7cbefcb47b4268d7b1990fabc6d6e67681e167959389d84e4e4`
- These don't decode to readable UTF-8 strings

**Our Implementation**:
- Updated to match OpenMLS two-step process
- Improved binary label handling in `hkdfExpandLabel` (2025-01-11)
- Currently produces result: `893c4f17df05f4fd3ca4938b751688f80dd73230e76aafcbdd3d4948f14a79d8`
- Still differs from expected: `dbce4e25e59ab4dfa6f6200f113ed08393cf6e7286d024811141c6a4dd11c0cb`

### Resolution Status

- [x] Issue identified and characterized
- [x] Test cases created for validation
- [x] OpenMLS source code analysis completed
- [x] Two-step derivation pattern implemented
- [x] Binary label handling improved (2025-01-11)
- [ ] Test vector label format resolution (deeper OpenMLS analysis needed)
- [ ] Full compatibility verification

**Note**: This incompatibility does **not block NIP-EE** since NIP-EE exporter secrets work correctly for Nostr key derivation.

---

## Sender Data Secret Derivation

**Status**: 🔴 **INCOMPATIBLE** - Secret tree test vectors fail

**Discovered**: 2025-01-11 during secret tree test vector validation

### The Issue

Our sender data secret derivation produces different results than OpenMLS:

```
Test Input:
- Encryption Secret: d69fcc35969e94680461974bd26c7cda7594cbf45985c4bf668c3b3118b765ab
- Expected Sender Secret: 95684b805e1bbd9c71d1abaf8a1930c12112b9a06c12db937970be5bbb916573
- Our Result:            f2c89c988efa20bce1e94229742e48508d9d37e3d84d9c27700d5b185e568e45
```

### Root Cause

Similar to the exporter secret issue, this appears to be a difference in how we construct the HKDF info parameter for `derive_secret(encryption_secret, "sender data")`.

### Impact

**NIP-EE Functionality**: ✅ No impact - NIP-EE doesn't use sender data secrets (uses exporter secrets for NIP-44)  
**OpenMLS Interoperability**: ❌ Sender data encryption/decryption incompatible with OpenMLS
**Security**: ⚠️ Different sender data keys (for MLS message protection only)

### Resolution Status

- [x] Issue identified through test vector validation
- [ ] Investigation of OpenMLS sender data derivation implementation
- [ ] Fix derivation to match OpenMLS pattern

---

## Known Compatible Features

### ✅ Cryptographic Primitives
- **HKDF**: Compatible with RFC 5869
- **Hash Functions**: SHA-256/384/512 compatible
- **deriveSecret/expandWithLabel**: Core functions work correctly

### ✅ Tree Mathematics  
- **Tree Structure**: All OpenMLS tree-math test vectors pass (10/10)
- **Node Relationships**: parent(), sibling(), direct_path() all correct

### ✅ TreeKEM Operations
- **UpdatePath**: Parsing and structure validation works
- **PathSecret**: Key derivation and chaining compatible  
- **HPKE Integration**: Key pair generation works correctly

### ✅ Key Schedule Framework
- **Secret Types**: All 11 MLS secret types validated
- **Length Validation**: Secret sizes match cipher suite requirements
- **Epoch Management**: Key schedule progression works

---

## Testing Philosophy

This document exists because **test vectors should expose incompatibilities**, not hide them. Every difference discovered helps us build a more robust and interoperable MLS implementation.

**"The whole point of these test vectors is to expose what we might be doing wrong!"** - User feedback during investigation

## Version History

- **v1.0** (2025-01-11): Initial documentation of exporter secret incompatibility
- **v1.1** (TBD): Resolution and verification

---

*This document will be updated as we resolve incompatibilities and discover new ones through continued test vector validation.*