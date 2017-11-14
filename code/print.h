#ifndef SM3PRINT_H
#define SM3PRINT_H
#include <inttypes.h>

void print_bytes(unsigned* buf, int n);
void print_block(unsigned* buf, int n);
void print_af(int i, uint32_t A, uint32_t B, uint32_t C, uint32_t D,
    uint32_t E, uint32_t F, uint32_t G, uint32_t H);
void print_hash(unsigned* buf);

#endif
