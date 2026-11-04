// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// SHA-256 (FIPS 180-4) for the files .cbb install checks on the Next: small,
// in plain C for z88dk and the host's tests alike.

#ifndef CBB_SHA256_H
#define CBB_SHA256_H

#include <stdint.h>

struct sha256 {
    uint32_t h[8];
    uint8_t block[64];
    uint8_t used;
    uint32_t bytes_lo, bytes_hi;
};

void sha256_init(struct sha256 *s);
void sha256_add(struct sha256 *s, const uint8_t *p, uint16_t n);
void sha256_end(struct sha256 *s, uint8_t out[32]);

#endif
