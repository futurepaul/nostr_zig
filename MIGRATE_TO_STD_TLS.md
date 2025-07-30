# Migrate to std.crypto.tls

## What Zig's std.crypto.tls Provides

### Wire Format Encoding
- `array()` function for encoding length-prefixed arrays
- Built-in big-endian integer encoding
- Proper TLS record framing

### Decoding
- `Decoder` type with methods like:
  - `decode()` for reading integers in network byte order
  - `array()` for reading fixed-size arrays
  - `slice()` for reading variable-length data
  - `readAtLeast()` for ensuring enough data is available

### Types
- All standard TLS enums (ContentType, HandshakeType, ExtensionType, etc.)
- Cipher suite definitions
- Alert types
- Protocol versions

## What We're Currently Doing

### Our tls_codec.zig
- `writeU8ToList`, `writeU16ToList`, etc. - manual big-endian encoding
- `TlsReader` - custom reader with the same functionality as Decoder
- `VarBytes` - unnecessary wrapper around byte arrays
- Manual length-prefix encoding

### Benefits of Switching

1. **Less Code**: Remove our entire tls_codec.zig
2. **Better Tested**: std.crypto.tls is used by Zig's HTTP client
3. **More Features**: Includes proper TLS record layer handling
4. **Standard Patterns**: Uses Zig idioms instead of custom abstractions

## Migration Examples

### Before (our code):
```zig
// Writing
var list = std.ArrayList(u8).init(allocator);
try tls_codec.writeU16ToList(&list, value);
try tls_codec.writeVarBytesToList(&list, u16, data);

// Reading
var reader = TlsReader(@TypeOf(stream.reader())).init(stream.reader());
const value = try reader.readU16();
const data = try reader.readVarBytes(u16, allocator);
```

### After (using std.crypto.tls):
```zig
// Writing
var list = std.ArrayList(u8).init(allocator);
try list.appendSlice(&std.crypto.tls.int(u16, value));
try list.appendSlice(&std.crypto.tls.array(u16, u8, data));

// Reading
var decoder = std.crypto.tls.Decoder.init(data);
const value = decoder.decode(u16);
const len = decoder.decode(u16);
const data = decoder.slice(len);
```

## What We'd Still Need

1. **MLS-specific encoding**: Some MLS types have custom encoding rules
2. **Integration work**: Update all serialization code
3. **Testing**: Ensure wire format compatibility

## Recommendation

Yes, we should definitely use std.crypto.tls! It would:
- Eliminate our VarBytes abstraction
- Remove most of tls_codec.zig
- Give us battle-tested TLS encoding/decoding
- Make the code more idiomatic Zig

The only reason to keep some custom code would be for MLS-specific encoding rules that don't follow standard TLS patterns.