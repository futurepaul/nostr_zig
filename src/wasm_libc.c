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

// Allocation functions (not used by secp256k1, but might be needed)
void* malloc(size_t size) {
    (void)size;
    return NULL;
}

void free(void* ptr) {
    (void)ptr;
}

void* calloc(size_t nmemb, size_t size) {
    (void)nmemb;
    (void)size;
    return NULL;
}

void* realloc(void* ptr, size_t size) {
    (void)ptr;
    (void)size;
    return NULL;
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

// abort function
void abort(void) {
    __builtin_trap();
}