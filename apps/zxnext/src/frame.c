// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

#include <string.h>

#include "frame.h"

uint8_t hex_digit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 255;
}

// Reads a number in base 10 or 16 that ends at a space or the end of the
// string; returns the rest, or 0 if there is no digit or a stray character.
static const char *number(const char *p, uint8_t base, uint32_t *out)
{
    uint32_t v = 0;
    uint8_t d, any = 0;
    while (*p && *p != ' ') {
        d = hex_digit(*p);
        if (d >= base) return 0;
        v = v * base + d;
        any = 1;
        p++;
    }
    if (!any) return 0;
    *out = v;
    return p;
}

uint8_t frame_line(const char *line, uint32_t *len, uint32_t *crc)
{
    const char *p;
    if (strncmp(line, "CBB1 ", 5) == 0) {
        p = number(line + 5, 10, len);
        if (!p || *p != ' ') return LINE_OTHER;
        p = number(p + 1, 16, crc);
        if (!p || *p) return LINE_OTHER;
        return LINE_TEXT;
    }
    if (strcmp(line, "CBBGO") == 0) return LINE_GO;
    if (strcmp(line, "CBBOK") == 0) return LINE_OK;
    if (strncmp(line, "CBBERR", 6) == 0 && (line[6] == ' ' || line[6] == 0)) return LINE_ERR;
    return LINE_OTHER;
}

uint32_t crc32_update(uint32_t crc, const uint8_t *p, uint16_t n)
{
    uint8_t i;
    crc = ~crc;
    while (n--) {
        crc ^= *p++;
        for (i = 0; i < 8; i++) {
            if (crc & 1) crc = (crc >> 1) ^ 0xEDB88320UL;
            else crc >>= 1;
        }
    }
    return ~crc;
}
