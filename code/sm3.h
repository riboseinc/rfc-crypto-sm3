#ifndef SM3_H
#define SM3_H
#include <stdio.h>
#include <inttypes.h>

typedef struct {
  uint32_t state[8];
  uint64_t bitcount;
  uint32_t buffer[24];
} sm3_context;

void sm3(
    unsigned char *message,
    int message_length,
    unsigned char *digest,
    int *digest_length);

#endif
