#ifndef _STDIO_H
#define _STDIO_H

#include <stddef.h>

// Minimal stdio for secp256k1 error callbacks
typedef struct {
    // Empty struct for FILE type
} FILE;

extern FILE* stderr;

int fprintf(FILE* stream, const char* format, ...);
int printf(const char* format, ...);

#endif