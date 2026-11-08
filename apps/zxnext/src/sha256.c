// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// SHA-256 (FIPS 180-4), written for this program.

#include "sha256.h"

#include <string.h>

#ifdef __Z88DK
// On the Next, in .cbb's screen page with sha_run() (cbb.c), as only the
// install uses it (README.md, "Memory").
#pragma codeseg PAGE_15
#pragma constseg PAGE_15
#pragma bssseg PAGE_15
#pragma dataseg PAGE_15
#endif

#ifdef __Z88DK
// The compression in assembly (sha256.asm), with its scratch in text[]'s
// upper half (sha_run(), cbb.c).
extern void sha256_compress(struct sha256 *s) __z88dk_fastcall;
#define compress sha256_compress
#else
static const uint32_t k[64] = {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL, 0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
    0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL, 0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
    0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL, 0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
    0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL, 0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
    0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL, 0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL, 0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
    0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL, 0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
    0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL, 0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL,
};

// The rotations and mixes are functions, not macros: on the Z80 each
// 32-bit operation is a call into the library, and inline copies of them
// would not fit the dot command's 32 KiB.
static uint32_t ror(uint32_t x, uint8_t n)
{
    return x >> n | x << (32 - n);
}

static uint32_t mix(uint32_t x, uint8_t a, uint8_t b, uint8_t c)
{
    return ror(x, a) ^ ror(x, b) ^ ror(x, c);
}

static uint32_t small(uint32_t x, uint8_t a, uint8_t b, uint8_t c)
{
    return ror(x, a) ^ ror(x, b) ^ x >> c;
}

static void compress(struct sha256 *s)
{
    // The schedule is kept as a ring of 16 words, to spare the Z80's memory,
    // and the working variables a to h as v[0] to v[7].
    static uint32_t w[16], v[8];
    uint32_t t1, t2;
    uint8_t i;
    for (i = 0; i < 16; i++) {
        const uint8_t *p = s->block + 4 * i;
        w[i] = (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
    }
    memcpy(v, s->h, sizeof v);
    for (i = 0; i < 64; i++) {
        if (i >= 16)
            w[i & 15] += small(w[(i + 1) & 15], 7, 18, 3) + w[(i + 9) & 15] + small(w[(i + 14) & 15], 17, 19, 10);
        t1 = v[7] + mix(v[4], 6, 11, 25) + ((v[4] & v[5]) ^ (~v[4] & v[6])) + k[i] + w[i & 15];
        t2 = mix(v[0], 2, 13, 22) + ((v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]));
        memmove(v + 1, v, 7 * sizeof v[0]);
        v[4] += t1;
        v[0] = t1 + t2;
    }
    for (i = 0; i < 8; i++) s->h[i] += v[i];
}
#endif

// At file scope: in a page that holds code and data alike, z88dk would put
// a function's own static data at the function's address (mapcheck.sh).
static const uint32_t h0[8] = {0x6a09e667UL, 0xbb67ae85UL, 0x3c6ef372UL, 0xa54ff53aUL,
                               0x510e527fUL, 0x9b05688cUL, 0x1f83d9abUL, 0x5be0cd19UL};

void sha256_init(struct sha256 *s)
{
    memcpy(s->h, h0, sizeof h0);
    s->used = 0;
    s->bytes_lo = s->bytes_hi = 0;
}

void sha256_add(struct sha256 *s, const uint8_t *p, uint16_t n)
{
    uint32_t lo = s->bytes_lo;
    s->bytes_lo += n;
    if (s->bytes_lo < lo) s->bytes_hi++;
    while (n) {
        uint8_t take = 64 - s->used;
        if (n < take) take = (uint8_t)n;
        memcpy(s->block + s->used, p, take);
        s->used += take;
        p += take;
        n -= take;
        if (s->used == 64) {
            compress(s);
            s->used = 0;
        }
    }
}

void sha256_end(struct sha256 *s, uint8_t out[32])
{
    // The length in bits, big-endian, after the 0x80 and the zeros.
    uint32_t hi = s->bytes_hi << 3 | s->bytes_lo >> 29, lo = s->bytes_lo << 3;
    uint8_t i;
    s->block[s->used++] = 0x80;
    if (s->used > 56) {
        memset(s->block + s->used, 0, 64 - s->used);
        compress(s);
        s->used = 0;
    }
    memset(s->block + s->used, 0, 56 - s->used);
    for (i = 0; i < 4; i++) {
        s->block[56 + i] = (uint8_t)(hi >> (24 - 8 * i));
        s->block[60 + i] = (uint8_t)(lo >> (24 - 8 * i));
    }
    compress(s);
    for (i = 0; i < 32; i++) out[i] = (uint8_t)(s->h[i >> 2] >> (24 - 8 * (i & 3)));
}
