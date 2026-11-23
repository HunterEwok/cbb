// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The core's cbb_call for the tests under Node (run.sh): reads one request
// on standard input and writes the core's answer on standard output, as
// libcbb_napi.so's call answers the app.

#include <cbb_core.h>

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    (void)argv;
    if (argc == 2) { // abi
        printf("%u", (unsigned)cbb_abi());
        return 0;
    }
    size_t cap = 1 << 16, len = 0;
    unsigned char *in = malloc(cap);
    size_t n;
    while (in && (n = fread(in + len, 1, cap - len, stdin)) > 0) {
        len += n;
        if (len == cap)
            in = realloc(in, cap *= 2);
    }
    if (!in)
        return 1;
    size_t out_len = 0;
    unsigned char *out = cbb_call(in, len, &out_len);
    if (!out)
        return 1;
    fwrite(out, 1, out_len, stdout);
    cbb_free(out, out_len);
    free(in);
    return 0;
}
