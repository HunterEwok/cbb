// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The frames cbb next on the lite member answers in (member/README.md, "ZX Spectrum Next"),
// without any I/O, so the host compiler tests them too.

#ifndef CBB_FRAME_H
#define CBB_FRAME_H

#include <stdint.h>

// What a line from the lite member is.
enum {
    LINE_OTHER, // the echo of the command, a prompt, a note (CBB#): skipped
    LINE_TEXT,  // CBB1 <len> <crc32>: len bytes of text follow, then CR
    LINE_QR,    // CBBQ <size>: size rows of hex digits follow
    LINE_GO,    // CBBGO: send the text now
    LINE_OK,    // CBBOK
    LINE_ERR    // CBBERR <message>
};

// The kind of line, and for LINE_TEXT its length and CRC-32, for LINE_QR its
// size; a malformed CBB1 or CBBQ line is LINE_OTHER.
uint8_t frame_line(const char *line, uint32_t *len, uint32_t *crc);

// CRC-32 (IEEE 802.3), continued from crc (start with 0).
uint32_t crc32_update(uint32_t crc, const uint8_t *p, uint16_t n);

// The value of a hex digit, or 255.
uint8_t hex_digit(char c);

#endif
