// WASM-compatible callbacks for secp256k1
// These avoid stdio and stdlib functions that aren't available in WASM

// External function provided by the WASM runtime
extern void wasm_log_error(const char* str, int len);

static int string_length(const char* str) {
    int len = 0;
    while (str[len] != '\0') len++;
    return len;
}

// Default error callback for WASM - logs to console and traps
void secp256k1_default_error_callback_fn(const char* str, void* data) {
    (void)data;
    wasm_log_error(str, string_length(str));
    __builtin_trap(); // WASM trap instead of abort()
}

// Default illegal callback for WASM - logs to console and traps  
void secp256k1_default_illegal_callback_fn(const char* str, void* data) {
    (void)data;
    wasm_log_error(str, string_length(str));
    __builtin_trap(); // WASM trap instead of abort()
}

// Provide a dummy stderr for compatibility
typedef struct {
    // Empty struct for FILE type
} FILE;

FILE _stderr_dummy;
FILE* stderr = &_stderr_dummy;