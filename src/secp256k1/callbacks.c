#include <stdio.h>
#include <stdlib.h>

// Default error callback - just prints to stderr and aborts
void secp256k1_default_error_callback_fn(const char* str, void* data) {
    (void)data;
    fprintf(stderr, "secp256k1 error: %s\n", str);
    abort();
}

// Default illegal callback - just prints to stderr and aborts
void secp256k1_default_illegal_callback_fn(const char* str, void* data) {
    (void)data;
    fprintf(stderr, "secp256k1 illegal argument: %s\n", str);
    abort();
}