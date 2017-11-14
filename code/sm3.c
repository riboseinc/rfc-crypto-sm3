/* A sample implementation of SM3 */

#include <stdlib.h>
#include <string.h>
#include "sm3.h"
#include "print.h"

/* Operations */
/* Rotate Left 32-bit number */
#define ROTL32(X, n) (((X) << (n)) | ((X) >> (32 - (n))))

/* Functions for SM3 algorithm */
#define FF1(X,Y,Z) ((X) ^ (Y) ^ (Z))
#define FF2(X,Y,Z) (((X) & (Y)) | ((X) & (Z)) | ((Y) & (Z)))
#define GG1(X,Y,Z) ((X) ^ (Y) ^ (Z))
#define GG2(X,Y,Z) (((X) & (Y)) | ((~X) & (Z)))
#define P0(X) (X ^ ROTL32((X),  9) ^ ROTL32((X), 17))
#define P1(X) (X ^ ROTL32((X), 15) ^ ROTL32((X), 23))

/* Initialize the context */

static void sm3_init(sm3_context *ctx)
{
  uint32_t IV[8] = {
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
    0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
  };
  int i;

  for (i = 0; i < 8; i++)
  {
    ctx->state[i] = IV[i];
  }

  debug_print("IV:\n");
  print_hash((unsigned*)ctx->state);

  memset(ctx->buffer, 0, sizeof(uint32_t) * 24);

  ctx->bitcount=0;
}

/*
 * Processes a single 512b block and updates context state
 */
static void sm3_block(sm3_context *ctx)
{
  uint32_t A, B, C, D, E, F, G, H, temp;
  uint32_t SS1, SS2, TT1, TT2, Tj;
  uint32_t W[68] = {0},
           WP[64] = {0};
  int i;

  debug_print("Context initial state:\n");
  print_block((unsigned*)ctx->state, 8);

  debug_print("Block input:\n");
  print_block((unsigned*)ctx->buffer, 16);

  A = ctx->state[0];
  B = ctx->state[1];
  C = ctx->state[2];
  D = ctx->state[3];
  E = ctx->state[4];
  F = ctx->state[5];
  G = ctx->state[6];
  H = ctx->state[7];

  /* Message Expansion ME */
  W[0]  = ctx->buffer[0];
  W[1]  = ctx->buffer[1];
  W[2]  = ctx->buffer[2];
  W[3]  = ctx->buffer[3];
  W[4]  = ctx->buffer[4];
  W[5]  = ctx->buffer[5];
  W[6]  = ctx->buffer[6];
  W[7]  = ctx->buffer[7];
  W[8]  = ctx->buffer[8];
  W[9]  = ctx->buffer[9];
  W[10] = ctx->buffer[10];
  W[11] = ctx->buffer[11];
  W[12] = ctx->buffer[12];
  W[13] = ctx->buffer[13];
  W[14] = ctx->buffer[14];
  W[15] = ctx->buffer[15];

  for (i = 16; i < 68; i++)
  {
    temp = W[i - 16] ^
           W[i - 9]  ^
           ROTL32(W[i - 3], 15);

    W[i] = P1(temp) ^
           ROTL32(W[i - 13], 7) ^
           W[i - 6];
  }

  for (i = 0; i < 64; i++)
  {
    WP[i] = W[i] ^ W[i + 4];
  }

  debug_print("\nME(m'): W_0 W_1 ... W_67:\n");

  print_block((unsigned*)W, 68);

  debug_print("\nME(m'): W'_0 W'_1 ... W'_63:\n");
  print_block((unsigned*)WP, 64);

  debug_print("\nCF:\n");
  debug_print("   A        B        C        D        "
      "E        F        G        H\n");
  debug_print("~~~~~~~~~~~~~~~~~~~~~~~~~~~"
      " initial value "
      "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
  print_af(i, A, B, C, D, E, F, G, H);

  /* Compression Function */
  for (i = 0; i < 64; i++)
  {
    if (i < 16)
    {
      Tj = 0x79cc4519;
      SS1 = ROTL32(ROTL32(A, 12) + E + ROTL32(Tj, i), 7);
      SS2 = SS1 ^ ROTL32(A, 12);
      TT1 = FF1(A, B, C) + D + SS2 + WP[i];
      TT2 = GG1(E, F, G) + H + SS1 + W[i];
    }
    else
    {
      Tj = 0x7a879d8a;
      SS1 = ROTL32(ROTL32(A, 12) + E + ROTL32(Tj, i), 7);
      SS2 = SS1 ^ ROTL32(A, 12);
      TT1 = FF2(A, B, C) + D + SS2 + WP[i];
      TT2 = GG2(E, F, G) + H + SS1 + W[i];
    }

    D = C;
    C = ROTL32(B, 9);
    B = A;
    A = TT1;
    H = G;
    G = ROTL32(F, 19);
    F = E;
    E = P0(TT2);

    print_af(i, A, B, C, D, E, F, G, H);

    //debug_print("V_%d: ", i);
    //print_block((unsigned*)ctx->state, 8);
  }

  /* Update Context */
  ctx->state[0] ^= A;
  ctx->state[1] ^= B;
  ctx->state[2] ^= C;
  ctx->state[3] ^= D;
  ctx->state[4] ^= E;
  ctx->state[5] ^= F;
  ctx->state[6] ^= G;
  ctx->state[7] ^= H;

  debug_print("\n~~~~~~~~~~~~~~~~~~~"
      " final block hash value (V_64) "
      "~~~~~~~~~~~~~~~~~~~~~\n");
  A = ctx->state[0];
  B = ctx->state[1];
  C = ctx->state[2];
  D = ctx->state[3];
  E = ctx->state[4];
  F = ctx->state[5];
  G = ctx->state[6];
  H = ctx->state[7];
  //print_af(i, A, B, C, D, E, F, G, H);

  print_block((unsigned*)ctx->state, 8);
}

/*
 * The SM3 256 Hash Function
 * message : input message
 * message_length : length of input message, in bytes
 * digest : final hash
 * digest_length : length of hash, in bytes
 */
void SM3(
    unsigned char *message,
    int message_length,
    unsigned char *digest,
    int *digest_length
    )
{
  sm3_context ctx;
  uint32_t* p_data = (uint32_t*)message;
  int i, block = 0;

  //debug_print("SM3: message_length: %i\n", message_length);
  sm3_init(&ctx);

  if (message_length == 0)
  {
    return;
  }

  while (message_length >= 64)
  {
    /* Process 512 bit blocks that don't need padding */
    for (i = 0; i < 16; i++) {
      ctx.buffer[i] = *p_data;
      p_data++;
    }

    block++;
    debug_print("-------- Message Block %i Begin --------\n", block);
    sm3_block(&ctx);
    debug_print("-------- Message Block %i End --------\n", block);
    ctx.bitcount += 512;
    message_length -= 64;
  }

  /* Padding */
  for (i = 0; i < (message_length / 4); i++)
  {
    ctx.buffer[i] = *p_data;
    p_data++;
  }

  message_length -= 4 * i;
  ctx.bitcount += 32 * i;

  switch (message_length) {

    case 0:
      ctx.buffer[i] = (0x80) << 24;
      break;

    case 1:
      ctx.buffer[i] = ((*((uint8_t*)p_data)) << 24) |
                      (0x80 << 16);
      ctx.bitcount += 8;
      break;

    case 2:
      ctx.buffer[i] = ((*((uint8_t*)p_data)) << 24) |
                      ((*((uint8_t*)p_data + 1)) << 16) |
                      (0x80 << 8);
      ctx.bitcount += 16;
      break;

    case 3:

      ctx.buffer[i] = ((*((uint8_t*)p_data)) << 24) |
                      ((*((uint8_t*)p_data + 1)) << 16) |
                      ((*((uint8_t*)p_data + 2)) << 8) |
                      0x80;
      ctx.bitcount += 24;
      break;
  }

  //debug_print("SM3: pad to (%llu)\n", ctx.bitcount);
  memset(&ctx.buffer[i + 1], 0, sizeof(uint32_t) * (15 - i));

  /*
   * Message padding
   * If there is not enough space for bitlength, extend.
   */
  if (i < 56)
  {
    ctx.buffer[14] = ctx.bitcount >> 32;
    ctx.buffer[15] = ctx.bitcount & 0xffffffff;

    debug_print("--------- Padded Mesage m' Begin ----------\n");
    print_block((unsigned*)ctx.buffer, 16);
    debug_print("---------- Padded Mesage m' End -----------\n\n");

    block++;
    debug_print("-------- Message Block %i Begin --------\n", block);
    sm3_block(&ctx);
    debug_print("-------- Message Block %i End --------\n", block);
  }
  else
  {
    block++;
    debug_print("-------- Message Block %i Begin --------\n", block);
    sm3_block(&ctx);
    debug_print("-------- Message Block %i End --------\n", block);
    memset(ctx.buffer, 0, sizeof(uint32_t) * 16);
    *(uint64_t*)(&ctx.buffer[15]) = ctx.bitcount;
  }

  debug_print("\n++++++++++++++++++++++"
      " hash value of all blocks "
      "+++++++++++++++++++++++\n");
  print_hash((unsigned*)ctx.state);

  memcpy(digest, ctx.state, sizeof(uint32_t) * 8);

  *digest_length = 32;
}

