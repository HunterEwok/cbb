// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Host tests for sha256.c against FIPS 180-4's examples and a long input
// fed in uneven pieces.

#include <stdio.h>
#include <string.h>

#include "sha256.h"

static int failed;

static void hex(const uint8_t *d, char *out)
{
    int i;
    for (i = 0; i < 32; i++) sprintf(out + 2 * i, "%02x", d[i]);
}

static void check(const char *name, const uint8_t *data, unsigned long n, unsigned step, const char *want)
{
    struct sha256 s;
    uint8_t d[32];
    char got[65];
    unsigned long i;
    sha256_init(&s);
    for (i = 0; i < n; i += step) sha256_add(&s, data + i, (uint16_t)(n - i < step ? n - i : step));
    sha256_end(&s, d);
    hex(d, got);
    if (strcmp(got, want) != 0) {
        printf("FAIL %s (pieces of %u): %s, want %s\n", name, step, got, want);
        failed = 1;
    }
}

int main(void)
{
    static uint8_t million[1000000];
    const char *two = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    unsigned steps[] = {1, 3, 55, 64, 65, 4096};
    unsigned i;
    memset(million, 'a', sizeof million);
    for (i = 0; i < sizeof steps / sizeof steps[0]; i++) {
        check("empty", (const uint8_t *)"", 0, steps[i], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        check("abc", (const uint8_t *)"abc", 3, steps[i], "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        check("two blocks", (const uint8_t *)two, strlen(two), steps[i],
              "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    }
    check("a million a", million, sizeof million, 4096, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    check("a million a", million, sizeof million, 1000, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    if (!failed) printf("sha256: ok\n");
    return failed;
}
