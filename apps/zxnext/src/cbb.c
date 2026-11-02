// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// .cbb: the clipboardbridge dot command for the ZX Spectrum Next. It talks
// to the lite member on the Next's own Raspberry Pi over the UART between
// them, by typing `cbb next ...` at NextPi's shell (docs/roadmap.md, item 14;
// the frames are in lite/README.md, "ZX Spectrum Next").

#include <arch/zxn.h>
#include <arch/zxn/esxdos.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "frame.h"
#include "link.h"

#define VERSION "0.2.0"
// The lite member on the Pi; the NextPi set-up puts it on the shell's PATH.
#define CBB_LITE "cbb"
// The longest text pasted or copied.
#define MAX_TEXT 8192
// How long the lite member may take to answer, in seconds; join waits for the phone.
#define ANSWER_SECONDS 20
#define JOIN_SECONDS 330

static uint8_t text[MAX_TEXT];
static char line[200];
static uint8_t debug;

static void usage(void)
{
    printf("clipboardbridge " VERSION "\n\n"
           ".cbb paste [FILE]  show the group's\n"
           "                   text, or save it\n"
           ".cbb copy FILE     send a file\n"
           ".cbb text WORDS    send the words\n"
           ".cbb copy -s FILE  send a secret,\n"
           ".cbb text -s WORDS such as a password\n"
           ".cbb join          join the group:\n"
           "                   scan the code with\n"
           "                   the phone app\n"
           ".cbb net on [-to HOST:PORT]\n"
           "   [-serve ESP:PORT] [-zone +HH:MM]\n"
           "                   the Pi's network\n"
           "                   through the ESP,\n"
           "                   in the background\n"
           ".cbb net off       stop it\n"
           ".cbb net           how it stands\n"
           ".cbb -d ...        show error details\n");
}

// Shows a short message, and in debug mode the cause under it.
static int fail(const char *msg, const char *detail)
{
    printf("cbb: %s\n", msg);
    if (debug && detail && *detail) printf("  (%s)\n", detail);
    return 1;
}

static int link_fail(uint8_t err)
{
    if (err == LINK_BREAK) {
        link_send(3); // Ctrl-C stops the lite member on the Pi
        return fail("stopped", 0);
    }
    return fail("the Pi stopped answering", "timeout");
}

// CBB.DRV (drv/): its id, and where .cbb net keeps the link's settings.
#define DRIVER_ID 124
#define NET_CFG "/cbb/NET.CFG"
#define DRV_COUNTERS 1
#define DRV_SWITCH 2
#define DRV_STATE 3

static struct esx_drvapi drv;

// Calls the driver; 0 when it answered (its values in drv), 1 when it is
// not installed.
static uint8_t driver(uint8_t function, uint16_t de)
{
    drv.call.driver = DRIVER_ID;
    drv.call.function = function;
    drv.de = de;
    drv.hl = 0;
    return esx_m_drvapi(&drv) != 0;
}

// Whether the driver holds the Pi's UART for the network.
static uint8_t net_on(void)
{
    return driver(DRV_STATE, 0) == 0 && drv.de != 0;
}

// Types a command for the lite member at NextPi's shell.
static int command(const char *args)
{
    if (net_on()) {
        return fail("the network uses the Pi's line; stop it first with .cbb net off", "CBB.DRV is on");
    }
    if (link_shell()) {
        return fail("the Pi does not answer; is NextPi running? (.pisend -q)", "no SUP> prompt");
    }
    link_send_str(CBB_LITE);
    if (debug) link_send_str(" -debug");
    link_send_str(" next ");
    link_send_str(args);
    link_send('\n');
    return 0;
}

// Reads lines until a frame of one of the kinds wanted, an OK or an error;
// LINE_OK or the kind, or 255 when it failed (and said why).
static uint8_t expect(uint8_t want, uint32_t *len, uint32_t *crc, uint16_t seconds)
{
    uint8_t kind, err;
    for (;;) {
        err = link_line(line, sizeof line, seconds);
        if (err) {
            link_fail(err);
            return 255;
        }
        kind = frame_line(line, len, crc);
        if (kind == LINE_ERR) {
            fail(line[6] ? line + 7 : "cbb failed", 0);
            link_prompt();
            return 255;
        }
        if (kind == want || kind == LINE_OK) return kind;
    }
}

// Eight lowercase hex digits, as the lite member writes a CRC-32.
static void hex8(char *out, uint32_t v)
{
    int8_t i;
    for (i = 7; i >= 0; i--) {
        out[i] = "0123456789abcdef"[v & 15];
        v >>= 4;
    }
    out[8] = 0;
}

static void show(const uint8_t *p, uint16_t n)
{
    while (n--) {
        uint8_t c = *p++;
        putchar(c == '\r' ? '\n' : c);
    }
    putchar('\n');
}

static int paste(const char *file)
{
    uint32_t len, crc;
    uint16_t got;
    uint8_t c, err, fh;
    sprintf(line, "paste -max %u", MAX_TEXT);
    if (command(line)) return 1;
    if (expect(LINE_TEXT, &len, &crc, ANSWER_SECONDS) != LINE_TEXT) return 1;
    if (len > MAX_TEXT) {
        link_send(3);
        return fail("the text is too long", "longer than -max");
    }
    for (got = 0; got < len; got++) {
        err = link_recv(&c, ANSWER_SECONDS);
        if (err) return link_fail(err);
        text[got] = c;
    }
    if (expect(LINE_OK, &len, &crc, ANSWER_SECONDS) != LINE_OK) return 1;
    link_prompt();
    if (crc32_update(0, text, got) != crc) return fail("the text arrived damaged; try again", "CRC-32 mismatch");
    if (!file) {
        show(text, got);
        return 0;
    }
    errno = 0;
    fh = esx_f_open(file, ESX_MODE_W | ESX_MODE_OPEN_CREAT_TRUNC);
    if (errno) return fail("cannot create the file", file);
    if (esx_f_write(fh, text, got) != got) {
        esx_f_close(fh);
        return fail("cannot write the file", file);
    }
    esx_f_close(fh);
    printf("%u bytes saved to %s\n", got, file);
    return 0;
}

// Whether copy and text send a secret: the group's devices keep it out of
// their histories and clear it from their clipboards after a while.
static uint8_t secret;

static int copy(uint16_t len)
{
    uint32_t n, crc;
    uint16_t i;
    char crc_hex[9];
    hex8(crc_hex, crc32_update(0, text, len));
    sprintf(line, secret ? "copy -secret %u %s" : "copy %u %s", len, crc_hex);
    if (command(line)) return 1;
    if (expect(LINE_GO, &n, &crc, ANSWER_SECONDS) != LINE_GO) return 1;
    for (i = 0; i < len; i++) link_send(text[i]);
    if (expect(LINE_OK, &n, &crc, ANSWER_SECONDS) != LINE_OK) return 1;
    link_prompt();
    printf(secret ? "%u bytes sent to the group as a secret\n" : "%u bytes sent to the group\n", len);
    return 0;
}

static int copy_file(const char *file)
{
    uint8_t fh;
    uint16_t len;
    errno = 0;
    fh = esx_f_open(file, ESX_MODE_R | ESX_MODE_OPEN_EXIST);
    if (errno) return fail("cannot open the file", file);
    len = esx_f_read(fh, text, MAX_TEXT);
    esx_f_close(fh);
    return copy(len);
}

static int copy_words(int argc, char **argv)
{
    uint16_t len = 0, n;
    int i;
    for (i = 0; i < argc; i++) {
        n = strlen(argv[i]);
        if (len + n + 1 > MAX_TEXT) return fail("the text is too long", 0);
        if (i) text[len++] = ' ';
        memcpy(text + len, argv[i], n);
        len += n;
    }
    return copy(len);
}

// Sets one pixel of the ULA screen.
static void plot(uint8_t x, uint8_t y)
{
    *zx_pxy2saddr(x, y) |= zx_px2bitmask(x);
}

// Draws a QR code row by row as it arrives, dark modules in black on white,
// centred, as large as the screen allows.
static int qr(uint8_t size)
{
    uint8_t scale = 184 / size, x0, y0, row, col, d, px, py, err;
    if (scale > 4) scale = 4;
    if (scale == 0) return fail("the QR code is too large for the screen", 0);
    x0 = (256 - size * scale) / 2;
    y0 = (192 - size * scale) / 2;
    zx_border(INK_WHITE);
    zx_cls(PAPER_WHITE | INK_BLACK);
    for (row = 0; row < size; row++) {
        err = link_line(line, sizeof line, ANSWER_SECONDS);
        if (err) return link_fail(err);
        for (col = 0; col < size; col++) {
            d = hex_digit(line[col >> 2]);
            if (d == 255) return fail("the Pi sent a damaged QR code", line);
            if (!(d & (8 >> (col & 3)))) continue;
            for (py = 0; py < scale; py++)
                for (px = 0; px < scale; px++) plot(x0 + col * scale + px, y0 + row * scale + py);
        }
    }
    return 0;
}

static int join(void)
{
    uint32_t len, crc;
    if (command("join")) return 1;
    if (expect(LINE_QR, &len, &crc, ANSWER_SECONDS) != LINE_QR) return 1;
    if (qr((uint8_t)len)) return 1;
    // The phone scans; the pairing ends with CBBOK. SPACE cancels.
    if (expect(LINE_OK, &len, &crc, JOIN_SECONDS) != LINE_OK) return 1;
    link_prompt();
    zx_border(INK_BLACK);
    zx_cls(PAPER_WHITE | INK_BLACK);
    printf("Joined the group.\n");
    return 0;
}

// The link's settings: the -to, -serve and -zone of `cbb next link`.
static char net_args[120];

static uint8_t net_load(void)
{
    uint8_t fh;
    uint16_t n;
    errno = 0;
    fh = esx_f_open(NET_CFG, ESX_MODE_R | ESX_MODE_OPEN_EXIST);
    if (errno) return 1;
    n = esx_f_read(fh, net_args, sizeof net_args - 1);
    esx_f_close(fh);
    net_args[n] = 0;
    return n == 0;
}

static int net_save(void)
{
    uint8_t fh;
    uint16_t n = strlen(net_args);
    errno = 0;
    fh = esx_f_open(NET_CFG, ESX_MODE_W | ESX_MODE_OPEN_CREAT_TRUNC);
    if (errno) return fail("cannot save the settings; is there a folder /cbb?", NET_CFG);
    if (esx_f_write(fh, net_args, n) != n) {
        esx_f_close(fh);
        return fail("cannot save the settings", NET_CFG);
    }
    esx_f_close(fh);
    return 0;
}

// Only characters that NextPi's shell takes as they are: a setting cannot
// run a command of its own on the Pi.
static uint8_t plain(const char *s)
{
    for (; *s; s++) {
        char c = *s;
        if (!(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') &&
            !strchr(".:-+[]", c)) {
            return 0;
        }
    }
    return 1;
}

static int net_start(int argc, char **argv)
{
    int i;
    uint16_t n = 0;
    if (driver(DRV_STATE, 0)) {
        return fail("the driver is not installed: .install /cbb/CBB.DRV", "M_DRVAPI 124 failed");
    }
    if (drv.de) return fail("the network runs already", 0);
    if (argc) {
        for (i = 0; i < argc; i++) {
            if (!plain(argv[i])) return fail("a setting has a character the Pi's shell would take", argv[i]);
            if (n + strlen(argv[i]) + 2 > sizeof net_args) return fail("the settings are too long", 0);
            if (n) net_args[n++] = ' ';
            strcpy(net_args + n, argv[i]);
            n += strlen(argv[i]);
        }
        if (!strstr(net_args, "-to ")) return fail("the computer to dial is missing: -to HOST:PORT", 0);
        if (net_save()) return 1;
    } else if (net_load()) {
        return fail("no settings yet: .cbb net on -to HOST:PORT", NET_CFG);
    }
    if (link_shell()) {
        return fail("the Pi does not answer; is NextPi running? (.pisend -q)", "no SUP> prompt");
    }
    link_send_str(CBB_LITE " next link ");
    link_send_str(net_args);
    link_send_str(" -log /ram/link.log\n");
    // The link waits for the driver's hello, and the driver reads past the
    // shell's echo to the first frame.
    if (driver(DRV_SWITCH, 1)) return fail("the driver did not start", "M_DRVAPI 124 failed");
    printf("The Pi's network runs through\nthe ESP in the background.\n");
    return 0;
}

static int net_stop(void)
{
    // The quit frame: the start byte, Q, no data, the sum.
    static const uint8_t quit[] = {0x7E, 'Q', 0, 'Q'};
    uint8_t i;
    if (!net_on()) return fail("the network does not run", 0);
    driver(DRV_SWITCH, 0);
    for (i = 0; i < sizeof quit; i++) link_send(quit[i]);
    if (link_shell()) return fail("the network stopped, but the Pi does not answer", "no SUP> prompt");
    printf("The network stopped.\n");
    return 0;
}

static int net_show(void)
{
    if (driver(DRV_STATE, 0)) {
        printf("The driver is not installed:\n.install /cbb/CBB.DRV\n");
        return 0;
    }
    printf(drv.de ? "The network runs.\n" : "The network does not run.\n");
    if (!net_load()) printf("Settings: %s\n", net_args);
    if (driver(DRV_COUNTERS, 0) == 0) {
        printf("Taken from the Pi: %u bytes\n", drv.hl);
        printf("Frames dropped: %u\n", drv.de);
        printf("ESP overflows: %u\n", drv.bc);
    }
    return 0;
}

static int net(int argc, char **argv)
{
    if (argc == 0) return net_show();
    if (strcmp(argv[0], "on") == 0) return net_start(argc - 1, argv + 1);
    if (strcmp(argv[0], "off") == 0 && argc == 1) return net_stop();
    usage();
    return 1;
}

static int run(int argc, char **argv)
{
    int i = 1;
    if (i < argc && strcmp(argv[i], "-d") == 0) {
        debug = 1;
        i++;
    }
    if (i >= argc) {
        usage();
        return 0;
    }
    link_open();
    // copy -s and text -s send a secret.
    if ((strcmp(argv[i], "copy") == 0 || strcmp(argv[i], "text") == 0) && i + 1 < argc && strcmp(argv[i + 1], "-s") == 0) {
        secret = 1;
        argv[i + 1] = argv[i];
        i++;
    }
    if (strcmp(argv[i], "paste") == 0 && argc - i <= 2) return paste(argc - i == 2 ? argv[i + 1] : 0);
    if (strcmp(argv[i], "copy") == 0 && argc - i == 2) return copy_file(argv[i + 1]);
    if (strcmp(argv[i], "text") == 0 && argc - i >= 2) return copy_words(argc - i - 1, argv + i + 1);
    if (strcmp(argv[i], "join") == 0 && argc - i == 1) return join();
    if (strcmp(argv[i], "net") == 0) return net(argc - i - 1, argv + i + 1);
    usage();
    return 1;
}

int main(int argc, char **argv)
{
    // Each command shows its own message; a nonzero result would make
    // NextZXOS add an unrelated error of its own.
    run(argc, argv);
    return 0;
}
