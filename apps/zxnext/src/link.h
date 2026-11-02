// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The UART between the Next and its Raspberry Pi, and NextPi's shell on it.

#ifndef CBB_LINK_H
#define CBB_LINK_H

#include <stdint.h>

// Why a link call failed.
enum {
    LINK_OK,
    LINK_TIMEOUT, // nothing arrived in time
    LINK_BREAK    // the user pressed SPACE
};

// The two UARTs, as the select port's bit 6 names them.
#define LINK_ESP 0x00
#define LINK_PI 0x40

// Points the UART at the Pi at the speed NextPi uses (from NR 0x7F, which
// .pisend -q sets, else 115200).
void link_open(void);

// Sets the ESP8266's UART to speed and leaves it selected.
void link_open_esp(uint32_t speed);

// Selects the UART that the calls below use (LINK_ESP or LINK_PI); each
// keeps its own speed and receive buffer.
void link_use(uint8_t uart);

// Whether a byte has arrived, without waiting, and that byte.
uint8_t link_ready(void);
uint8_t link_get(void);

// Whether the selected UART takes a byte now, and that byte, without waiting.
uint8_t link_can_send(void);
void link_put(uint8_t c);

// How many times link_ready found a receive buffer full.
uint16_t link_overflows(void);

// Makes NextPi's shell (SUP>) ready for a command; 0 if the Pi answers.
uint8_t link_shell(void);

void link_send(uint8_t c);
void link_send_str(const char *s);

// One byte, waiting up to seconds; LINK_OK with the byte in *c.
uint8_t link_recv(uint8_t *c, uint16_t seconds);

// One line up to CR, without it (LF and NUL are dropped), cut to max-1
// characters; waits up to seconds for each byte.
uint8_t link_line(char *buf, uint8_t max, uint16_t seconds);

// Reads until the shell prompt comes back, so the next command starts clean.
void link_prompt(void);

#endif
