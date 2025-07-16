// WASM-safe secp256k1 context management
const secp256k1 = @import("secp256k1");

// External declaration of the static context from the C library
extern const secp256k1_context_no_precomp: secp256k1.secp256k1_context;

// Get the static context pointer for WASM
// This avoids the need for dynamic allocation
pub fn getStaticContext() *const secp256k1.secp256k1_context {
    // Use the no-precomp static context which is available as a global
    // This context can be used for all operations
    return &secp256k1_context_no_precomp;
}