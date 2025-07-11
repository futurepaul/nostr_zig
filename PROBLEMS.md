# NIP-44 Implementation Issues

## Current Status (2025-01-11)

**✅ Major Progress:** NIP-44 implementation is **15/17 tests passing** with critical ECDH fix!

### Test Results Summary
```
test
+- run test 15/17 passed, 2 failed
Build Summary: 8/10 steps succeeded; 1 failed; 16/18 tests passed; 2 failed
```

---

## 🚨 **Critical Issues to Fix**

### 1. **HMAC Verification Failure** (HIGH PRIORITY)

**Problem:** HMAC verification fails during decryption even though conversation key is now correct.

**Test Failure:**
```
❌ Decrypt test 0 FAILED: error.InvalidHmac
/Users/futurepaul/dev/heavy/nostr_zig/src/nip44/v2.zig:274:9
```

**Current Status:**
- ✅ Conversation key generation is FIXED and matches test vectors perfectly
- ✅ ECDH shared secret now uses correct x-coordinate-only approach
- ❌ HMAC verification still failing

**Investigation Needed:**
- Verify HMAC calculation matches NIP-44 spec exactly
- Check if there's an issue with salt/nonce handling in HMAC
- Ensure payload parsing extracts HMAC bytes correctly
- Compare HMAC input data ordering with reference implementations

### 2. **Bech32 Test Failure** (LOW PRIORITY - UNRELATED)

**Problem:** Unrelated bech32 test failing.

**Test Failure:**
```
❌ bech32 encode/decode test FAILED
  /src/bech32.zig:97:9: return Bech32Error.InvalidData;
```

**Note:** This is not related to NIP-44 implementation and can be addressed separately.

---

## 🎯 **Next Session Action Plan**

### Priority Order:
1. **Debug HMAC verification** - Add logging to see what data is being HMACed
2. **Compare with reference** - Check Go/Rust implementations for HMAC calculation
3. **Fix bech32 issue** - Separate from NIP-44 work

### Key Files to Focus On:
- `src/nip44/v2.zig` - decryptBytes function around line 274
- Reference implementations in `samples/nip44/go` and `samples/nip44/rust`

---

## 🏆 **Completed Successfully**

### Major Breakthrough - ECDH Fix!
- ✅ **Fixed ECDH shared secret generation** - The issue was that `secp256k1_ecdh` by default applies SHA256 to the shared point, but NIP-44 requires the raw x-coordinate
- ✅ **Implemented custom ECDH hash function** - `nip44EcdhHashFunction` that returns x-coordinate directly without hashing
- ✅ **Fixed x-only public key handling** - Always use even y-coordinate (0x02) when converting from x-only to compressed format, as per Nostr/NIP-44 convention
- ✅ **Conversation keys now match test vectors perfectly!**
  - sec1+pub1: `3b4610cb7189beb9cc29eb3716ecc6102f1247e8f3101a03a1787d8908aeb54e` ✅
  - sec1+pub2: `c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d` ✅

### Previously Fixed Issues:
- ✅ **HKDF implementation** - Using paulmillr test vectors, HKDF now works perfectly
- ✅ **Padding algorithm** - Fixed to match exact Rust reference implementation (129→160, not 192)
- ✅ Module structure (`src/nip44/`)
- ✅ Test vector integration with official JSON
- ✅ Real ChaCha20IETF integration
- ✅ Base64 encoding/decoding
- ✅ HMAC-SHA256 authentication
- ✅ Main encrypt/decrypt API structure
- ✅ JSON test vector runner
- ✅ 15/17 tests passing (up from 13/17!)

## 📚 **Technical Notes**

### Key Fix - Custom ECDH Hash Function
```zig
fn nip44EcdhHashFunction(
    output: [*c]u8,
    x32: [*c]const u8,
    y32: [*c]const u8,
    data: ?*anyopaque,
) callconv(.C) c_int {
    _ = y32; // y-coordinate is not used in NIP-44
    _ = data; // no additional data needed
    
    // Copy x-coordinate directly to output
    @memcpy(output[0..32], x32[0..32]);
    
    return 32; // Return number of bytes written
}
```

### X-Only Public Key Convention
- NIP-44/Nostr always treats x-only public keys as having even y-coordinate
- When converting 32-byte x-only to 33-byte compressed: always prefix with 0x02
- Reference: Go implementation `hex.DecodeString("02" + pub2)`
- Reference: Rust implementation `PublicKey::from_x_only_public_key(x_only_public_key_b, Parity::Even)`

### Remaining HMAC Issue
The HMAC verification is the last major hurdle. The conversation key is correct, so the issue must be in:
1. How we compute the HMAC during decryption
2. The order or format of data being HMACed
3. How we extract the HMAC from the payload

### Test Environment
- Zig 0.14.1
- Test vectors from paulmillr/nip44
- Test command: `zig build test`

---

## 🔄 **Latest Session Updates (2025-01-11)**

### Major Fixes Applied:
1. **ECDH Custom Hash Function** - Implemented to return raw x-coordinate instead of SHA256 hash
2. **X-Only Public Key Handling** - Fixed to always use even y-coordinate (0x02)
3. **Test Vector Update** - Using paulmillr's comprehensive test suite

### Progress Summary:
- Started: 13/17 tests passing
- Current: 15/17 tests passing
- Fixed: HKDF, padding, ECDH shared secret generation
- Remaining: HMAC verification, unrelated bech32 test

*Last updated: 2025-01-11 - After fixing ECDH shared secret generation*