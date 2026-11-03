// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// .pibridge: a test tool that opens NextPi's shell (SUP>) to a computer on
// the home network. The Next's ESP8266 dials the computer in its stock AT
// firmware's passthrough mode, and the Z80 copies bytes between the Pi's
// UART and the ESP's until SPACE is pressed. It carries the Pi's root shell
// in the clear, so it is for a test bench only (README.md, "Test bench").
// It is also the first step of the Pi's network through the ESP8266
// (docs/roadmap.md, item 14), and it counts the times a receive buffer
// filled up, which tells whether the Z80 keeps up.
//
// It remembers the computer's address in PIBRIDGE.CFG, and the computer can
// replace a file in the bridge's own folder while it runs (an update, see
// update() below), so a test needs no card taken out.

#include <arch/zxn.h>
#include <arch/zxn/esxdos.h>
#include <errno.h>
#include <input.h>
#include <stdio.h>
#include <string.h>
#include <z80.h>

#include "frame.h"
#include "link.h"

#define VERSION "0.4.3"
// Rings for each direction: the UARTs' own buffers are small, so the Z80
// takes in what arrives at once and passes it on as the other side has
// room, one byte at a time, without waiting on either.
#define TO_ESP 2048 // the Pi's output, which comes in long runs
#define TO_PI 1024  // what the computer types

static uint8_t ring_esp[TO_ESP], ring_pi[TO_PI];
static uint16_t esp_in, esp_out, pi_in, pi_out;
static char line[80];
static uint8_t debug;
static uint32_t to_pi, to_esp;

// The ROM's frame counter, 50 a second while interrupts run.
#define FRAMES (*(volatile uint8_t *)23672)
// The ROM's scroll count: kept high, the screen scrolls on without asking
// "scroll?", which would hold the bridge until a key is pressed.
#define SCR_CT (*(volatile uint8_t *)23692)
#define NO_SCROLL_PROMPT() (SCR_CT = 255)

static void usage(void)
{
    printf("pibridge " VERSION "\n\n"
           "Opens the Pi's shell to a\n"
           "computer on the network, over\n"
           "the Next's Wi-Fi. TEST ONLY: the\n"
           "shell travels in the clear.\n\n"
           ".pibridge HOST PORT\n"
           ".pibridge         the last ones\n"
           ".pibridge -d ...  details\n"
           "SPACE stops.\n");
}

static int fail(const char *msg, const char *detail)
{
    NO_SCROLL_PROMPT();
    printf("pibridge: %s\n", msg);
    if (debug && detail && *detail) printf("  (%s)\n", detail);
    return 1;
}

// Reads the ESP's lines until one starts with want or an error; 0 when it
// is want. In debug mode every line is shown.
static uint8_t esp_expect(const char *want, uint16_t seconds)
{
    uint8_t n = strlen(want);
    for (;;) {
        if (link_line(line, sizeof line, seconds) != LINK_OK) {
            strcpy(line, "no answer");
            return 1;
        }
        if (!line[0]) continue;
        if (debug) {
            NO_SCROLL_PROMPT();
            printf("  esp: %s\n", line);
        }
        if (strncmp(line, want, n) == 0) return 0;
        if (strcmp(line, "ALREADY CONNECTED") == 0) return 0; // CIPSTART, still open
        if (strcmp(line, "ERROR") == 0 || strcmp(line, "FAIL") == 0 || strncmp(line, "busy", 4) == 0) return 1;
    }
}


// Waits ticks frames; a cap on the rounds ends it if interrupts are off.
static void wait_frames(uint8_t ticks)
{
    uint8_t last = FRAMES;
    uint32_t rounds = 4000000UL;
    while (ticks && --rounds) {
        if (FRAMES != last) {
            last = FRAMES;
            ticks--;
        }
    }
}

// Reads and drops what the ESP still sends (the late answer to an earlier
// command) until it is quiet for ticks frames.
static void esp_quiet(uint8_t ticks)
{
    uint8_t last = FRAMES, left = ticks;
    uint32_t rounds = 4000000UL;
    while (left && --rounds) {
        if (link_ready()) {
            uint8_t c = link_get();
            if (debug && c >= 32 && c < 127) {
                NO_SCROLL_PROMPT();
                putchar(c);
            }
            left = ticks;
        } else if (FRAMES != last) {
            last = FRAMES;
            left--;
        }
    }
}

static uint8_t esp_command(const char *cmd, const char *want, uint16_t seconds)
{
    esp_quiet(10);
    link_send_str(cmd);
    link_send_str("\r\n");
    return esp_expect(want, seconds);
}

// Waits for the '>' that starts passthrough.
static uint8_t esp_prompt(void)
{
    uint8_t c;
    while (link_recv(&c, 5) == LINK_OK) {
        if (c == '>') return 0;
    }
    return 1;
}

// Software flow control towards the Pi: its shell's terminal stops writing
// on XOFF and goes on at XON (stty ixon), so a burst longer than the ring
// waits on the Pi instead of overflowing the Next's small UART buffer.
#define XOFF 0x13
#define XON 0x11
#define PAUSE_AT (TO_ESP * 3 / 4)
#define RESUME_AT (TO_ESP / 4)

static uint8_t paused, control; // control: XOFF or XON still to send
static uint8_t update_due;      // the marker of an update arrived
// The start of an update from the computer (update() below).
static const uint8_t marker[] = {0x00, 0x1B, 'C', 'B', 'B', 'U'};
#define MARKER_LEN sizeof marker
static uint8_t matched; // bytes of the marker seen so far
static uint16_t fill_max, pauses, over_pi, over_esp;

// One round in each direction.
static void pump(void)
{
    uint16_t fill, over;
    link_use(LINK_PI);
    over = link_overflows();
    while (((esp_in + 1) & (TO_ESP - 1)) != esp_out && link_ready()) {
        ring_esp[esp_in] = link_get();
        esp_in = (esp_in + 1) & (TO_ESP - 1);
    }
    over_pi += link_overflows() - over;
    fill = (esp_in - esp_out) & (TO_ESP - 1);
    if (fill > fill_max) fill_max = fill;
    if (!paused && fill >= PAUSE_AT) {
        paused = 1;
        control = XOFF;
        pauses++;
    } else if (paused && fill <= RESUME_AT) {
        paused = 0;
        control = XON;
    }
    if (control && link_can_send()) {
        link_put(control);
        control = 0;
    }
    while (!control && pi_out != pi_in && link_can_send()) {
        link_put(ring_pi[pi_out]);
        pi_out = (pi_out + 1) & (TO_PI - 1);
        to_pi++;
    }
    link_use(LINK_ESP);
    over = link_overflows();
    while (((pi_in + 1) & (TO_PI - 1)) != pi_out && link_ready()) {
        uint8_t c = link_get();
        if (c == marker[matched]) {
            if (++matched == MARKER_LEN) {
                matched = 0;
                update_due = 1;
                break;
            }
            continue;
        }
        if (matched) { // not the marker after all: pass on what was held
            uint8_t k;
            for (k = 0; k < matched; k++) {
                ring_pi[pi_in] = marker[k];
                pi_in = (pi_in + 1) & (TO_PI - 1);
                if (((pi_in + 1) & (TO_PI - 1)) == pi_out) break;
            }
            matched = 0;
            if (c == marker[0]) {
                matched = 1;
                continue;
            }
        }
        ring_pi[pi_in] = c;
        pi_in = (pi_in + 1) & (TO_PI - 1);
    }
    over_esp += link_overflows() - over;
    while (esp_out != esp_in && link_can_send()) {
        link_put(ring_esp[esp_out]);
        esp_out = (esp_out + 1) & (TO_ESP - 1);
        to_esp++;
    }
}


// An update from the computer: the marker (above), then a line
// "NAME LENGTH CRC32" ending in CR (CRC-32 in 8 hex digits, as zlib's), and
// once the bridge answers "CBBU GO", the file in blocks of
// up to BLOCK bytes. The bridge answers '+' after each block it has written,
// so the computer sends the next one only then, and the UART's buffer never
// fills while the card is written. The file goes to UPDATE.TMP first and
// replaces NAME only when its CRC-32 matches; NAME is a plain 8.3 name, so
// it lands in the folder the bridge runs in and nowhere else. The answer is
// a line "CBBU OK" or "CBBU ERR <cause>".
#define BLOCK 256
#define TEMP_NAME "UPDATE.TMP"
#define CFG_NAME "PIBRIDGE.CFG"
static uint8_t block[BLOCK];
static uint16_t updates;

// A plain 8.3 name: letters, digits, '-' and '_', one dot at most.
static uint8_t name_ok(const char *name)
{
    const char *s;
    uint8_t base = 0, ext = 0, dot = 0;
    for (s = name; *s; s++) {
        char c = *s;
        if (c == '.') {
            if (dot || !base) return 0;
            dot = 1;
            continue;
        }
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_')) return 0;
        if (dot ? ++ext > 3 : ++base > 8) return 0;
    }
    return base && strcmp(name, CFG_NAME) != 0 && strcmp(name, TEMP_NAME) != 0;
}

static uint8_t hex_value(const char *s, uint32_t *v)
{
    uint8_t i;
    *v = 0;
    for (i = 0; i < 8; i++) {
        char c = s[i];
        uint8_t d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else return 0;
        *v = (*v << 4) | d;
    }
    return s[8] == 0;
}

static void esp_answer(const char *s)
{
    link_use(LINK_ESP);
    link_send_str(s);
    link_send_str("\r\n");
}

// Copies `from` over `to` (or only reads `to` when from is 0) and returns
// the CRC-32 of what `to` holds afterwards, or 1 with err set on a failure.
static const char *copy_err;
static uint8_t kept; // UPDATE.TMP is the only good copy: keep it

static uint32_t copy_file(const char *from, const char *to)
{
    uint8_t in = 0, out;
    uint16_t n;
    uint32_t crc = 0;
    copy_err = 0;
    errno = 0;
    if (from) {
        in = esx_f_open(from, ESX_MODE_R | ESX_MODE_OPEN_EXIST);
        if (errno) {
            copy_err = "cannot read " TEMP_NAME;
            return 1;
        }
        out = esx_f_open(to, ESX_MODE_W | ESX_MODE_OPEN_CREAT_TRUNC);
        if (errno) {
            esx_f_close(in);
            copy_err = "cannot open the old file";
            return 1;
        }
        while ((n = esx_f_read(in, block, BLOCK)) != 0) {
            if (esx_f_write(out, block, n) != n) {
                copy_err = "cannot write the old file";
                break;
            }
        }
        esx_f_close(in);
        esx_f_close(out);
        if (copy_err) return 1;
    }
    in = esx_f_open(to, ESX_MODE_R | ESX_MODE_OPEN_EXIST);
    if (errno) {
        copy_err = "cannot read the new file back";
        return 1;
    }
    while ((n = esx_f_read(in, block, BLOCK)) != 0) crc = crc32_update(crc, block, n);
    esx_f_close(in);
    return crc;
}

// When the file exists and cannot be renamed over, its contents are
// replaced instead and read back;
// UPDATE.TMP goes only once the copy checks out, so a failure never leaves
// the folder without either file.
static const char *replace(const char *name, uint32_t want)
{
    uint32_t crc = copy_file(TEMP_NAME, name);
    if (copy_err) {
        kept = 1;
        return copy_err;
    }
    if (crc != want) {
        kept = 1; // the old file may be half written: keep the good one
        return "the copy did not check out; the new file is in " TEMP_NAME;
    }
    esx_f_unlink(TEMP_NAME);
    return 0;
}

static const char *receive(const char *name, uint32_t len, uint32_t want)
{
    uint8_t fh, c;
    uint16_t n, i;
    uint32_t crc = 0;
    errno = 0;
    fh = esx_f_open(TEMP_NAME, ESX_MODE_W | ESX_MODE_OPEN_CREAT_TRUNC);
    if (errno) return "cannot create " TEMP_NAME;
    while (len) {
        n = len > BLOCK ? BLOCK : (uint16_t)len;
        link_use(LINK_ESP);
        for (i = 0; i < n; i++) {
            if (link_recv(&c, 10) != LINK_OK) {
                esx_f_close(fh);
                return "the computer stopped sending";
            }
            block[i] = c;
        }
        if (esx_f_write(fh, block, n) != n) {
            esx_f_close(fh);
            return "cannot write the card";
        }
        crc = crc32_update(crc, block, n);
        len -= n;
        link_use(LINK_ESP);
        link_send('+');
    }
    esx_f_close(fh);
    if (crc != want) return "CRC-32 mismatch";
    errno = 0;
    esx_f_rename(TEMP_NAME, name); // works when name does not exist yet
    if (!errno) return 0;
    return replace(name, want);
}

static void update(void)
{
    char *p, *name, *num, *hex;
    uint32_t len, want;
    const char *err;
    link_use(LINK_ESP);
    if (link_line(line, sizeof line, 5) != LINK_OK) return;
    name = line;
    p = strchr(name, ' ');
    if (!p) goto bad;
    *p++ = 0;
    num = p;
    p = strchr(num, ' ');
    if (!p) goto bad;
    *p++ = 0;
    hex = p;
    len = 0;
    for (p = num; *p; p++) {
        if (*p < '0' || *p > '9' || len > 1000000UL) goto bad;
        len = len * 10 + (*p - '0');
    }
    if (!name_ok(name) || !*num || !hex_value(hex, &want)) goto bad;
    NO_SCROLL_PROMPT();
    printf("Update %s, %lu bytes...\n", name, len);
    esp_answer("CBBU GO");
    kept = 0;
    err = receive(name, len, want);
    if (err) {
        if (!kept) esx_f_unlink(TEMP_NAME);
        NO_SCROLL_PROMPT();
        printf("  failed: %s\n", err);
        sprintf(line, "CBBU ERR %s", err);
        esp_answer(line);
        return;
    }
    updates++;
    NO_SCROLL_PROMPT();
    printf("  done.\n");
    esp_answer("CBBU OK");
    return;
bad:
    esp_answer("CBBU ERR bad header");
}

static void esp_hang_up(void)
{
    link_use(LINK_ESP);
    wait_frames(60); // the ESP takes +++ only after a second of quiet
    link_send_str("+++");
    wait_frames(60);
    esp_command("AT+CIPMODE=0", "OK", 2);
    esp_command("AT+CIPCLOSE", "OK", 2);
}

// The port, or 0 if s is not a number from 1 to 65535.
static uint16_t parse_port(const char *s)
{
    uint32_t n = 0;
    if (!*s) return 0;
    for (; *s; s++) {
        if (*s < '0' || *s > '9') return 0;
        n = n * 10 + (*s - '0');
        if (n > 65535UL) return 0;
    }
    return (uint16_t)n;
}

// The computer's address, kept next to the bridge so that a plain
// .pibridge dials it again.
static uint16_t saved_port;
static char host_buf[60];

static uint8_t load_address(char *host)
{
    uint8_t fh;
    uint16_t n;
    char *p;
    errno = 0;
    fh = esx_f_open(CFG_NAME, ESX_MODE_R | ESX_MODE_OPEN_EXIST);
    if (errno) return 0;
    n = esx_f_read(fh, host, 60);
    esx_f_close(fh);
    host[n < 60 ? n : 59] = 0;
    p = strchr(host, ' ');
    if (!p) return 0;
    *p++ = 0;
    if (strchr(p, '\n')) *strchr(p, '\n') = 0;
    saved_port = parse_port(p);
    return saved_port && *host;
}

static void save_address(const char *host, uint16_t port)
{
    uint8_t fh;
    char buf[60];
    sprintf(buf, "%s %u\n", host, port);
    errno = 0;
    fh = esx_f_open(CFG_NAME, ESX_MODE_W | ESX_MODE_OPEN_CREAT_TRUNC);
    if (errno) return;
    esx_f_write(fh, buf, strlen(buf));
    esx_f_close(fh);
}

#define NR_CPU_SPEED 0x07

static uint8_t nextreg_get(uint8_t reg)
{
    z80_outp(0x243B, reg);
    return z80_inp(0x253B);
}

static void nextreg_set(uint8_t reg, uint8_t value)
{
    z80_outp(0x243B, reg);
    z80_outp(0x253B, value);
}

static uint8_t speed; // the CPU speed it found, restored at the end

// Whether CBB.DRV (id 124, function 3) has the network on: it would take
// the ESP's bytes before the bridge sees them.
static uint8_t net_on(void)
{
    static struct esx_drvapi drv;
    drv.call.driver = 124;
    drv.call.function = 3;
    drv.de = 0;
    drv.hl = 0;
    return esx_m_drvapi(&drv) == 0 && drv.de != 0;
}

static int run(int argc, char **argv)
{
    uint8_t i = 1;
    uint16_t port;
    char cmd[80];
    const char *host;
    if (i < argc && strcmp(argv[i], "-d") == 0) {
        debug = 1;
        i++;
    }
    if (argc - i == 2) {
        host = argv[i];
        port = parse_port(argv[i + 1]);
        if (!port || strlen(host) > 40) return fail("give a host and a port", argv[i + 1]);
    } else if (argc == i) {
        if (!load_address(host_buf)) {
            usage();
            return 1;
        }
        host = host_buf;
        port = saved_port;
    } else {
        usage();
        return 1;
    }

    if (net_on()) return fail("the network runs through the ESP; stop it first with .cbb net off", "CBB.DRV is on");
    speed = nextreg_get(NR_CPU_SPEED) & 3;
    nextreg_set(NR_CPU_SPEED, 3); // 28 MHz while it runs
    link_open();            // the Pi's UART, at NextPi's speed
    link_open_esp(115200UL); // the ESP's, at its stock speed
    link_use(LINK_ESP);
    // A run that ended without its hang-up can leave the ESP in passthrough,
    // where AT would go to the old connection: leave it first.
    wait_frames(60);
    link_send_str("+++");
    wait_frames(60);
    if (esp_command("AT", "OK", 2) && esp_command("AT", "OK", 2)) {
        return fail("the Wi-Fi module does not answer", line);
    }
    esp_command("ATE0", "OK", 2);
    if (debug) esp_command("AT+GMR", "OK", 2);
    esp_command("AT+CIPMODE=0", "OK", 2);
    // .cbb net leaves the ESP serving with several connections; one
    // connection needs that undone first (failures here are fine).
    esp_command("AT+CIPSERVER=0", "OK", 2);
    esp_command("AT+CIPCLOSE=5", "OK", 5);
    esp_command("AT+CIPMUX=0", "OK", 2);
    esp_command("AT+CIPCLOSE", "OK", 5); // an old connection, if any
    esp_quiet(50); // old firmware (AT 1.2) can answer late
    sprintf(cmd, "AT+CIPSTART=\"TCP\",\"%s\",%u", host, port);
    if (esp_command(cmd, "OK", 15)) {
        esp_command("AT+CIPCLOSE", "OK", 5); // it may have connected anyway
        return fail("could not reach the computer; is Wi-Fi joined and the port open?", line);
    }
    if (esp_command("AT+CIPMODE=1", "OK", 2) || (link_send_str("AT+CIPSEND\r\n"), esp_prompt())) {
        esp_hang_up();
        return fail("the Wi-Fi module did not start passthrough", line);
    }
    NO_SCROLL_PROMPT();
    printf("Connected to %s:%u.\nSPACE stops.\n", host, port);
    save_address(host, port);

    link_use(LINK_PI);
    link_send('\n'); // so the computer sees SUP> at once
    while (!in_key_pressed(IN_KEY_SCANCODE_SPACE)) {
        pump();
        if (update_due) {
            update_due = 0;
            link_use(LINK_PI);
            if (!paused) link_send(XOFF); // the Pi waits while the card is written
            update();
            link_use(LINK_PI);
            if (!paused) link_send(XON);
        }
    }
    if (paused) link_send(XON);
    esp_hang_up();
    link_use(LINK_PI);
    NO_SCROLL_PROMPT();
    printf("Stopped. %lu bytes to the Pi,\n%lu from it.\n", to_pi, to_esp);
    printf("Ring to the ESP: up to %u of %u,\n%u pauses (XOFF).\n", fill_max, TO_ESP, pauses);
    if (updates) printf("%u files updated.\n", updates);
    if (over_pi || over_esp) printf("A receive buffer filled up:\nPi %u, ESP %u times;\nbytes may be lost.\n", over_pi, over_esp);
    return 0;
}

int main(int argc, char **argv)
{
    // NextZXOS leaves a dot command's file open while it runs, and an open
    // file cannot be renamed, deleted or written; the startup code has
    // loaded every page by now, so the bridge lets its file go, and an
    // update can replace the bridge itself.
    esx_f_close(esx_m_gethandle());
    speed = 0xFF;
    run(argc, argv);
    if (speed != 0xFF) nextreg_set(NR_CPU_SPEED, speed);
    return 0;
}
