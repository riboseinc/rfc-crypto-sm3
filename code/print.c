#include <stdio.h>
#include "print.h"

void print_bytes(unsigned* buf, int n)
{
  uint8_t* ptr = (uint8_t*)buf;
  int i, j;

  for (i = 0; i <= n/4; i++) {
    if (i > 0 && i % 8 == 0) {
      printf("\n");
    }
    for (j = 1; j <= 4; j++) {
      if ((i*4+4-j) < n) {
        printf("%.2X", ptr[(i*4)+4-j]);
      }
    }
    printf(" ");
  }
  printf("\n");
}

void print_block(unsigned* buf, int n)
{
  print_bytes(buf, n * 4);
}

void print_af(int i,
    uint32_t A, uint32_t B,
    uint32_t C, uint32_t D,
    uint32_t E, uint32_t F,
    uint32_t G, uint32_t H)
{
    if (i % 10 == 0) {
      printf("\n");
      printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ j = %2d ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n", i);
    }
    printf("%.8X ", (unsigned)A);
    printf("%.8X ", (unsigned)B);
    printf("%.8X ", (unsigned)C);
    printf("%.8X ", (unsigned)D);
    printf("%.8X ", (unsigned)E);
    printf("%.8X ", (unsigned)F);
    printf("%.8X ", (unsigned)G);
    printf("%.8X",  (unsigned)H);
    printf("\n");
}

void print_hash(unsigned* buf)
{
  print_block(buf, 8);
}

