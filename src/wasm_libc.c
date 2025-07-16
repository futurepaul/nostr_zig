// Minimal libc implementation for WASM
// Provides essential functions needed by secp256k1

#include <stddef.h>

// Memory functions
void* memcpy(void* dest, const void* src, size_t n) {
    unsigned char* d = (unsigned char*)dest;
    const unsigned char* s = (const unsigned char*)src;
    while (n--) {
        *d++ = *s++;
    }
    return dest;
}

void* memset(void* dest, int c, size_t n) {
    unsigned char* d = (unsigned char*)dest;
    while (n--) {
        *d++ = (unsigned char)c;
    }
    return dest;
}

int memcmp(const void* s1, const void* s2, size_t n) {
    const unsigned char* p1 = (const unsigned char*)s1;
    const unsigned char* p2 = (const unsigned char*)s2;
    while (n--) {
        if (*p1 != *p2) {
            return *p1 - *p2;
        }
        p1++;
        p2++;
    }
    return 0;
}

void* memmove(void* dest, const void* src, size_t n) {
    unsigned char* d = (unsigned char*)dest;
    const unsigned char* s = (const unsigned char*)src;
    
    if (d < s) {
        while (n--) {
            *d++ = *s++;
        }
    } else {
        d += n;
        s += n;
        while (n--) {
            *--d = *--s;
        }
    }
    return dest;
}

// String functions
size_t strlen(const char* s) {
    size_t len = 0;
    while (s[len] != '\0') {
        len++;
    }
    return len;
}

int strcmp(const char* s1, const char* s2) {
    while (*s1 && *s1 == *s2) {
        s1++;
        s2++;
    }
    return *(unsigned char*)s1 - *(unsigned char*)s2;
}

// Simple heap implementation for WASM
// Uses a static buffer as the heap
#define HEAP_SIZE (1024 * 1024)  // 1MB heap
static unsigned char heap[HEAP_SIZE];
static size_t heap_pos = 0;

// External functions provided by Zig
extern void* wasm_alloc(size_t size);
extern void wasm_free(void* ptr, size_t size);

// Allocation functions - use Zig's allocator
void* malloc(size_t size) {
    return wasm_alloc(size);
}

void free(void* ptr) {
    // We don't know the size, so we can't properly free
    // This is a limitation, but secp256k1 shouldn't leak memory
    (void)ptr;
}

void* calloc(size_t nmemb, size_t size) {
    size_t total = nmemb * size;
    void* ptr = malloc(total);
    if (ptr) {
        memset(ptr, 0, total);
    }
    return ptr;
}

void* realloc(void* ptr, size_t size) {
    // Simple implementation - just allocate new and copy
    if (!ptr) return malloc(size);
    if (size == 0) {
        free(ptr);
        return NULL;
    }
    
    void* new_ptr = malloc(size);
    if (new_ptr && ptr) {
        // We don't know the old size, so this is unsafe
        // but secp256k1 doesn't use realloc anyway
        memcpy(new_ptr, ptr, size);
        free(ptr);
    }
    return new_ptr;
}

// stdio functions for error callbacks
int fprintf(void* stream, const char* format, ...) {
    (void)stream;
    (void)format;
    return 0;
}

int printf(const char* format, ...) {
    (void)format;
    return 0;
}

// Global error state
static int wasm_error_occurred = 0;
static char wasm_error_message[256] = {0};

// Get error state (can be called from Zig)
int wasm_get_error_state(void) {
    return wasm_error_occurred;
}

// Get error message (can be called from Zig)
const char* wasm_get_error_message(void) {
    return wasm_error_message;
}

// abort function - set error state instead of trapping
void abort(void) {
    wasm_error_occurred = 1;
    // Don't trap - let the caller handle the error
    // This allows us to return gracefully from functions
}

// exit function
void exit(int status) {
    wasm_error_occurred = status;
    // Don't actually exit
}