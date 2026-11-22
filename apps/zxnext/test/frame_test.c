// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Host tests for frame.c: cc -I../src ../src/frame.c frame_test.c && ./a.out

#include <stdio.h>
#include <string.h>

#include "frame.h"

static int failed;

#define CHECK(cond) \
    do { \
        if (!(cond)) { \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            failed = 1; \
        } \
    } while (0)

int main(void)
{
    uint32_t len = 0, crc = 0;
    const uint8_t check[] = "123456789";

    CHECK(crc32_update(0, check, 9) == 0xCBF43926UL);
    CHECK(crc32_update(crc32_update(0, check, 4), check + 4, 5) == 0xCBF43926UL);
    CHECK(crc32_update(0, check, 0) == 0);

    CHECK(frame_line("CBB1 9 cbf43926", &len, &crc) == LINE_TEXT);
    CHECK(len == 9 && crc == 0xCBF43926UL);
    CHECK(frame_line("CBB1 0 00000000", &len, &crc) == LINE_TEXT && len == 0 && crc == 0);
    CHECK(frame_line("CBB1 9", &len, &crc) == LINE_OTHER);
    CHECK(frame_line("CBB1 x 0", &len, &crc) == LINE_OTHER);
    CHECK(frame_line("CBB1 9 cbf43926 extra", &len, &crc) == LINE_OTHER);
    CHECK(frame_line("CBBQ 41", &len, &crc) == LINE_OTHER);
    CHECK(frame_line("CBBGO", &len, &crc) == LINE_GO);
    CHECK(frame_line("CBBOK", &len, &crc) == LINE_OK);
    CHECK(frame_line("CBBERR the service is not running", &len, &crc) == LINE_ERR);
    CHECK(frame_line("CBBERR", &len, &crc) == LINE_ERR);
    CHECK(frame_line("CBBERRX", &len, &crc) == LINE_OTHER);
    CHECK(frame_line("CBB# joined", &len, &crc) == LINE_OTHER);
    CHECK(frame_line("cbb next paste", &len, &crc) == LINE_OTHER);
    CHECK(frame_line("SUP>", &len, &crc) == LINE_OTHER);

    CHECK(hex_digit('0') == 0 && hex_digit('f') == 15 && hex_digit('F') == 15 && hex_digit('g') == 255);

    if (!failed) printf("ok\n");
    return failed;
}
