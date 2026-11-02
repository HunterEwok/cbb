// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The registers are in the Next's manual (UART, ports 0x133B-0x163B; NR
// 0xA0); the sequence that selects the Pi and wakes NextPi's shell follows
// what NextPi's own tools do (PiTools, .pisend).

#include <arch/zxn.h>
#include <input.h>
#include <z80.h>

#include "link.h"

#define PORT_TX_STATUS 0x133B // write: send a byte; read: status
#define PORT_RX_BAUD 0x143B   // read: a byte; write: the baud prescaler
#define PORT_SELECT 0x153B    // bit 6: the Pi's UART instead of the ESP's
#define STATUS_RX_AVAIL 0x01
#define STATUS_TX_BUSY 0x02
#define STATUS_RX_FULL 0x04

#define NR_VIDEO_TIMING 0x11
#define NR_PI_PERIPHERALS 0xA0
#define NR_USER 0x7F

// The UART's clock for each video timing (NR 0x11), from the manual.
static const uint32_t clocks[8] = {
    28000000UL, 28571429UL, 29464286UL, 30000000UL, 31000000UL, 32000000UL, 33000000UL, 27000000UL
};

// Busy-wait rounds per second of link_recv's loop, roughly, at 28 MHz.
#define ROUNDS_PER_SECOND 40000UL

static uint8_t nextreg(uint8_t reg)
{
    z80_outp(0x243B, reg);
    return z80_inp(0x253B);
}

// Sets the selected UART's speed.
static void set_speed(uint32_t speed)
{
    uint32_t prescaler = clocks[nextreg(NR_VIDEO_TIMING) & 7] / speed;
    z80_outp(PORT_RX_BAUD, (uint8_t)(prescaler & 0x7F));
    z80_outp(PORT_RX_BAUD, (uint8_t)(((prescaler >> 7) & 0x7F) | 0x80));
}

void link_open(void)
{
    uint32_t speed = 115200UL;
    ZXN_NEXTREG(NR_PI_PERIPHERALS, 0x30); // the UART on the Pi's GPIO 14 and 15
    z80_outp(PORT_SELECT, LINK_PI);
    // .pisend -q stores 2 for 2 Mbit/s and 8 for 115200 [check on the Next].
    if (nextreg(NR_USER) == 2) speed = 2000000UL;
    set_speed(speed);
}

void link_open_esp(uint32_t speed)
{
    z80_outp(PORT_SELECT, LINK_ESP);
    set_speed(speed);
}

void link_use(uint8_t uart)
{
    z80_outp(PORT_SELECT, uart);
}

static uint16_t overflows;

uint8_t link_ready(void)
{
    uint8_t status = z80_inp(PORT_TX_STATUS);
    // A full receive buffer drops what comes next [check on the Next].
    if (status & STATUS_RX_FULL) overflows++;
    return status & STATUS_RX_AVAIL;
}

uint8_t link_get(void)
{
    return z80_inp(PORT_RX_BAUD);
}

uint8_t link_can_send(void)
{
    return !(z80_inp(PORT_TX_STATUS) & STATUS_TX_BUSY);
}

void link_put(uint8_t c)
{
    z80_outp(PORT_TX_STATUS, c);
}

uint16_t link_overflows(void)
{
    return overflows;
}

void link_send(uint8_t c)
{
    while (z80_inp(PORT_TX_STATUS) & STATUS_TX_BUSY) {
    }
    z80_outp(PORT_TX_STATUS, c);
}

void link_send_str(const char *s)
{
    while (*s) link_send(*s++);
}

uint8_t link_recv(uint8_t *c, uint16_t seconds)
{
    uint32_t rounds = seconds * ROUNDS_PER_SECOND;
    for (;;) {
        if (z80_inp(PORT_TX_STATUS) & STATUS_RX_AVAIL) {
            *c = z80_inp(PORT_RX_BAUD);
            return LINK_OK;
        }
        if (in_key_pressed(IN_KEY_SCANCODE_SPACE)) return LINK_BREAK;
        if (rounds-- == 0) return LINK_TIMEOUT;
    }
}

uint8_t link_line(char *buf, uint8_t max, uint16_t seconds)
{
    uint8_t n = 0, c, err;
    for (;;) {
        err = link_recv(&c, seconds);
        if (err) return err;
        if (c == '\r') break;
        if (c == '\n' || c == 0) continue;
        if (n + 1 < max) buf[n++] = c; // the rest of a long line is dropped
    }
    buf[n] = 0;
    return LINK_OK;
}

// Throws away what is waiting, until the line is quiet for a moment.
static void drain(void)
{
    uint8_t c;
    while (link_recv(&c, 1) == LINK_OK) {
    }
}

// Waits for "SUP>" within seconds.
static uint8_t wait_prompt(uint16_t seconds)
{
    static const char want[] = "SUP>";
    uint8_t got = 0, c;
    while (link_recv(&c, seconds) == LINK_OK) {
        if (c == want[got]) {
            if (++got == 4) return 1;
        } else {
            got = c == want[0];
        }
    }
    return 0;
}

uint8_t link_shell(void)
{
    uint8_t tries;
    for (tries = 0; tries < 3; tries++) {
        drain();
        if (tries) {
            link_send(3); // Ctrl-C: stop what runs
            link_send(4); // Ctrl-D: NextPi restarts its supervisor shell
        }
        link_send('\n');
        if (wait_prompt(3)) {
            drain();
            return 0;
        }
    }
    return 1;
}

void link_prompt(void)
{
    wait_prompt(2);
    drain();
}
