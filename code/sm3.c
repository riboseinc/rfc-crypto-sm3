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
#define P0(X) ((X) ^ ROTL32((X),  9) ^ ROTL32((X), 17))
#define P1(X) ((X) ^ ROTL32((X), 15) ^ ROTL32((X), 23))

typedef union sm3_block {
  uint32_t content[16];
  struct {
    uint32_t content[14];
    uint64_t length;
  } last_block;
} sm3_block_t;

typedef struct sm3_padded_blocks {
  sm3_block_t** blocks;
  int bitcount;
  int n;
  sm3_block_t last_blocks[2];
} sm3_pb_t;

/* Initialize the context */
static void sm3_init(sm3_context *ctx)
{
  const uint32_t IV[8] = {
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

  memset(ctx->buffer, 0, sizeof(uint32_t) * 16);

  ctx->bitcount = 0;
}

static void sm3_me(sm3_context *ctx, uint32_t W[], uint32_t WP[])
{
  int i;

  debug_print("\n=== SM3 Message Expansion ME (sm3_me):\n");

  /* Message Expansion ME */
  for (i = 0; i < 16; i++)
  {
    W[i] = ctx->buffer[i];
  }

  for (i = 16; i < 68; i++)
  {
    W[i] = P1(W[i - 16] ^ W[i - 9] ^ ROTL32(W[i - 3], 15)) ^
           ROTL32(W[i - 13], 7) ^ W[i - 6];
  }

  for (i = 0; i < 64; i++)
  {
    WP[i] = W[i] ^ W[i + 4];
  }

  debug_print("\nME(m'): W_0 W_1 ... W_67:\n");
  print_block((unsigned*)W, 68);

  debug_print("\nME(m'): W'_0 W'_1 ... W'_63:\n");
  print_block((unsigned*)WP, 64);
}

static void sm3_cf(sm3_context *ctx, uint32_t W[], uint32_t WP[])
{
  uint32_t A, B, C, D, E, F, G, H;
  uint32_t SS1, SS2, TT1, TT2, Tj;

  int i;

  debug_print("\n=== SM3 Compression Function CF (sm3_cf):\n");

  A = ctx->state[0];
  B = ctx->state[1];
  C = ctx->state[2];
  D = ctx->state[3];
  E = ctx->state[4];
  F = ctx->state[5];
  G = ctx->state[6];
  H = ctx->state[7];

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

// tag::skipdoc[]
    print_af(i, A, B, C, D, E, F, G, H);
    //debug_print("V_%d: ", i);
    print_block((unsigned*)ctx->state, 8);
// end::skipdoc[]
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

// tag::skipdoc[]
    //print_block((unsigned*)ctx->state, 8);
// end::skipdoc[]
}

/*
 * Processes a single 512b block and updates context state
 */
static void sm3_block(sm3_context *ctx)
{
  uint32_t W[68] = {0},
           WP[64] = {0};

  debug_print("\n== ----- SM3 Process Block (sm3_block) begin ----\n");
  debug_print("Context Initial State:\n");
  print_block((unsigned*)ctx->state, 8);

  debug_print("Block Input:\n");
  print_block((unsigned*)ctx->buffer, 16);

  sm3_me(ctx, W, WP);
  sm3_cf(ctx, W, WP);

  debug_print("\n~~~~~~~~~~~~~~~~~~~"
      " final block hash value (V_64) "
      "~~~~~~~~~~~~~~~~~~~~~\n");
  print_block((unsigned*)ctx->state, 8);
  debug_print("== ----- SM3 Process Block (sm3_block) end -----\n\n");
}

uint32_t sm3_end_bytes(uint32_t *input, int length)
{
  uint32_t output = 0;
  uint8_t *b;

  // Apply the "1" right after the message
  b = (uint8_t*)&output;
  switch (length) {

    case 0:
      b[3] = (0x80);
      break;

    case 1:
      b[3] = (uint8_t)*input;
      b[2] = (0x80);
      break;

    case 2:
      b[3] = *(uint8_t*)input;
      b[2] = *((uint8_t*)input + 1);
      b[1] = (0x80);
      break;

    case 3:
      b[3] = *(uint8_t*)input;
      b[2] = *((uint8_t*)input + 1);
      b[1] = *((uint8_t*)input + 2);
      b[0] = (0x80);
      break;
  }

  /*
  debug_print("\n~~~~~~~~~~~~~~~~~~~"
      " sm3_end_bytes input(len(%i), %0.8x), output(%0.8x)"
      "~~~~~~~~~~~~~~~~~~~~~\n", length, *input, output);
   */

  return output;
}


/*
 * Splits a message into blocks and adds padding into blocks of
 * 512 bits. `length` is in bytes (64 => 512 bits).
 */
static int *sm3_pad_blocks(sm3_pb_t* result,
  unsigned char *message,
  int length,
  sm3_context *ctx)
{
  uint32_t *read_p = 0;
  uint32_t *write_p = 0;
  int i, n, remaining_bytes;

  debug_print("\n=== SM3 Pad Input Into Blocks (sm3_pad_blocks):\n");

  /* number of blocks */
  /* 512, 512, last block is max 446 */
  remaining_bytes = length;
  n = remaining_bytes / 64;

  read_p = (uint32_t*)message;
  write_p = (uint32_t*)(result->last_blocks[0].content);

  debug_print("\n==== Full Blocks (%i)\n", n);

  /* process and gather full 512-bit blocks */
  for (i = 0; i < n; i++)
  {
    result->blocks[i] = (sm3_block_t*)read_p;
    read_p += SM3_BLOCK_SIZE_IN_32;
    remaining_bytes -= SM3_BLOCK_SIZE_IN_BYTES;
    result->bitcount += SM3_BLOCK_SIZE_IN_BYTES * 8;
    result->n = i+1;
// tag::skipdoc[]
    //debug_print("BLOCK i: %i\n", i);
    //print_block((unsigned*)result.blocks[i], 16);
    //debug_print("DONE BLOCK i: %i\n", i);
    //debug_print("Done Handle %i full blocks\n", result.n);
// end::skipdoc[]
  }

  /*
   * This is a block less than 512 but more than 446.
   * Copy out the last blocks to because we have to pad them.
   */
  for (i = 0; i < remaining_bytes / 4 /* u32 */; i++)
  {
    result->last_blocks[0].content[i] = read_p[i];
  }

  /* write "10" bit */
  read_p = &read_p[i];
  result->last_blocks[0].content[i] = sm3_end_bytes(read_p, remaining_bytes % 4);

  result->blocks[n] = &(result->last_blocks[0]);
  i++;
  result->n++;

  /*
   * Set bitcount even though we haven't finished processing
   * the two blocks.
   */
  result->bitcount += remaining_bytes * 8;

// tag::skipdoc[]
  //debug_print("BLOCK N %i:\n", i);
  //print_bytes((unsigned*)last_blocks[0], 64);
  //debug_print("DONE BLOCK N %i:\n", i);
// end::skipdoc[]

  /* no overflow, just add length and return */
  if (remaining_bytes < 56) {
    debug_print("==== Padded Block (%i), last block (%i-bytes)\n",
        1, remaining_bytes);
    result->last_blocks[0].last_block.length = (uint64_t)(length * 8) << 32;
    /* write length in bits */
    result->blocks[i] = &(result->last_blocks[0]);
// tag::skipdoc[]
    // debug_print("BLOCK N %i:\n", i);
    // print_bytes((unsigned*)&result->last_blocks[0], 64);
    // debug_print("-------------------------\n");
    // debug_print("last_block %u, result->blocks[i %i] %u\n", result->last_blocks[0], result->blocks[i]);
    // print_bytes((unsigned*)result->blocks[i], 64);
    // debug_print("DONE BLOCK N %i:\n", i);
// end::skipdoc[]

    return 0;
  }

  debug_print("==== Padded Blocks (%i), with "
      "overflow block (%i-bytes)\n",
      2, remaining_bytes);

  /*
   * With overflow, we pad the last packet with the x80,
   * then 0's, and move the length to the next packet.
   */

  i++;
  result->n++;
  result->blocks[i] = &(result->last_blocks[1]);
  /* write length in bits */
  result->last_blocks[1].last_block.length = (uint64_t)(length * 8) << 32;

// tag::skipdoc[]
  //debug_print("BLOCK N+1 %i:\n", i);
  //print_bytes((unsigned*)last_blocks[1], 64);
  //debug_print("DONE BLOCK N+1 %i:\n", i);
// end::skipdoc[]

  return 0;
}

/*
 * The SM3 256 Hash Function
 * message: input message
 * message_length: length of input message, in bytes
 * digest: final hash of 256-bits
 */
void sm3(
  unsigned char *message,
  int message_length,
  unsigned char *digest /* 256-bits */
)
{
  sm3_context ctx;
  sm3_pb_t result = {0}; /* array of blocks to return */
  int i = 0, j = 0, block = 0;

  //debug_print("SM3: message_length: %i\n", message_length);
  if (message_length == 0)
  {
    return;
  }

  debug_print("= Stage 0: Initialize Context.");
  sm3_init(&ctx);

  debug_print("= Stage 1: Pad Message...\n");

  /* number of full blocks */
  result.blocks = calloc((message_length + 2), sizeof(uint32_t*));

  sm3_pad_blocks(&result, message, message_length, &ctx);
  ctx.bitcount = result.bitcount;

  debug_print("==> Split/result into (N=%i) blocks.\n", result.n);
  for (i = 0; i < result.n; i++)
  {
    debug_print("\n== -------- result BLOCK %i of %i --------\n",
        i+1, result.n);
    print_bytes((unsigned*)(result.blocks[i]), 64);
    debug_print("== -------- END result BLOCK %i of %i --------\n",
        i+1, result.n);
  }

  debug_print("= Stage 2: Processing blocks.\n");
  for (i = 0; i < result.n; i++)
  {
    /* Load block into memory */
    for (j = 0; j < 16; j++)
    {
      ctx.buffer[j] = (uint32_t)(result.blocks[i]->content[j]);
    }
    block++;
    debug_print("== Processing block %i of N(%i) blocks.\n",
      i, result.n);
    sm3_block(&ctx);
  }

  free(result.blocks);

  debug_print("== Stage 2: Processing blocks done.");

  debug_print("\n++++++++++++++++++++++"
      " hash value of all blocks "
      "+++++++++++++++++++++++\n");
  print_hash((unsigned*)ctx.state);

  memcpy(digest, ctx.state, sizeof(uint32_t) * 8);
}
