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

#define VERSION "0.5.0"
// The lite member on the Pi; the NextPi set-up puts it on the shell's PATH.
#define CBB_LITE "cbb"
// The longest text pasted or copied.
#define MAX_TEXT 8192
// How long the lite member may take to answer, in seconds; pair waits for the phone.
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
           ".cbb pair          join the group:\n"
           "                   scan the code with\n"
           "                   the phone app (with\n"
           "                   net settings: via\n"
           "                   the ESP)\n"
           ".cbb net on [-to \"HOST:PORT\"]\n"
           " [-serve \"ESP:PORT\"] [-zone \"+HH:MM\"]\n"
           "                   the Pi's network\n"
           "                   through the ESP,\n"
           "                   in the background\n"
           ".cbb net off       stop it\n"
           ".cbb net           how it stands\n"
           ".cbb install       fetch the rest\n"
           "                   from cbb.tools,\n"
           "                   the Pi's cbb too\n"
           ".cbb update        the same: newer\n"
           "                   files only\n"
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
#define DRV_ESP 4
#define DRV_DROP 5
#define DRV_CAP 6

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

static int pair(void)
{
    uint32_t len, crc;
    if (command("pair")) return 1;
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

// Sends cbb next link the quit frame: the start byte, Q, no data, the sum.
static void link_quit(void)
{
    static const uint8_t quit[] = {0x7E, 'Q', 0, 'Q'};
    uint8_t i;
    for (i = 0; i < sizeof quit; i++) link_send(quit[i]);
}

// The ESP's stock speed, and its speed while the network runs: the driver
// hands the Pi at most 48 of its bytes a frame (2400 a second), and the ESP
// has no flow control, so at 115200 a burst, such as a phone's TLS hello,
// overflows the Next's 512-byte buffer. 19200 is 1920 bytes a second.
#define ESP_SPEED 115200UL
#define ESP_NET_SPEED 19200UL

// Whether the ESP answers AT at speed; leaves it selected. The CR LF first
// ends whatever an earlier try at the other speed left in its line.
static uint8_t esp_at(uint32_t speed)
{
    link_open_esp(speed);
    while (link_line(line, sizeof line, 1) == LINK_OK) {
    }
    link_send_str("\r\nAT\r\n");
    while (link_line(line, sizeof line, 2) == LINK_OK) {
        if (strcmp(line, "OK") == 0) return 1;
    }
    return 0;
}

// Takes the ESP out of a transparent connection, as a .pibridge whose
// connection ended under it leaves it: a second of quiet, +++, a second,
// then back to normal sends.
static void esp_escape(uint32_t speed)
{
    uint8_t i;
    link_open_esp(speed);
    for (i = 0; i < 2; i++) {
        uint8_t n = 20;
        while (n-- && link_line(line, sizeof line, 1) == LINK_OK) {
        }
        if (!i) link_send_str("+++");
    }
    link_send_str("AT+CIPMODE=0\r\n");
}

// Puts the ESP's UART at speed, from either speed it may be at; 1 if it
// answers, the ESP selected.
static uint8_t esp_answers(uint32_t speed)
{
    if (esp_at(speed)) return 1;
    if (!esp_at(speed == ESP_SPEED ? ESP_NET_SPEED : ESP_SPEED)) return 0;
    link_send_str(speed == ESP_SPEED ? "AT+UART_CUR=115200,8,1,0,0\r\n" : "AT+UART_CUR=19200,8,1,0,0\r\n");
    // The OK comes at the old speed; then the ESP switches.
    while (link_line(line, sizeof line, 2) == LINK_OK) {
        if (strcmp(line, "OK") == 0) break;
    }
    return esp_at(speed);
}

// The same, first from the speed the ESP is at (a reset of the Next leaves
// the ESP as it was; AT+UART_CUR is not kept in its flash, so a power
// cycle brings back 115200), then out of a transparent connection at each.
static uint8_t esp_speed(uint32_t speed)
{
    if (esp_answers(speed)) return 1;
    esp_escape(ESP_NET_SPEED);
    if (esp_answers(speed)) return 1;
    esp_escape(ESP_SPEED);
    return esp_answers(speed);
}

// net_pair starts the network under its QR code, without a word.
static uint8_t quiet;

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
        if (!strstr(net_args, "-to ")) return fail("the computer to dial is missing: -to \"HOST:PORT\"", 0);
        if (net_save()) return 1;
    } else if (net_load()) {
        return fail("no settings yet: .cbb net on -to \"HOST:PORT\"", NET_CFG);
    }
    if (!esp_speed(ESP_NET_SPEED)) {
        link_use(LINK_PI);
        return fail("the ESP does not answer AT", line);
    }
    link_use(LINK_PI);
    if (link_shell()) {
        esp_speed(ESP_SPEED);
        link_use(LINK_PI);
        return fail("the Pi does not answer; is NextPi running? (.pisend -q)", "no SUP> prompt");
    }
    link_send_str(CBB_LITE " next link ");
    link_send_str(net_args);
    link_send_str(" -log /ram/link.log\n");
    // The driver may only start once the link has made the UART raw: the
    // shell would echo its frames, and a byte of them taken as XOFF stops
    // the Pi's output. The link says CBBLINK then; anything else is the
    // shell's echo or the link's error.
    for (i = 0;; i++) {
        uint8_t err = link_line(line, sizeof line, 15);
        if (err) {
            link_quit(); // it may run without having said so
            return fail("cbb next link did not start on the Pi", err == LINK_BREAK ? "stopped" : "no CBBLINK");
        }
        if (strstr(line, "CBBLINK")) {
            // The line's LF: the driver would count it, and the link,
            // which counts only its frames, would wait for the Next.
            uint8_t lf;
            link_recv(&lf, 1);
            break;
        }
        if (i > 0 && (strncmp(line, "cbb:", 4) == 0 || strncmp(line, "usage", 5) == 0)) {
            link_prompt();
            return fail("cbb next link failed on the Pi", line);
        }
        if (i == 8) {
            link_quit();
            return fail("cbb next link did not start on the Pi", line);
        }
    }
    if (driver(DRV_SWITCH, 1)) return fail("the driver did not start", "M_DRVAPI 124 failed");
    if (!quiet) printf("The Pi's network runs through\nthe ESP in the background.\n");
    return 0;
}

// The ESP's address on the Wi-Fi network, from AT+CIFSR, into ip.
static uint8_t esp_address(char *ip, uint8_t max)
{
    static const char want[] = "+CIFSR:STAIP,\"";
    uint8_t i, found = 0;
    if (!esp_speed(ESP_SPEED)) {
        link_use(LINK_PI);
        return 0;
    }
    link_send_str("AT+CIFSR\r\n");
    while (link_line(line, sizeof line, 3) == LINK_OK) {
        if (strncmp(line, want, sizeof want - 1) == 0) {
            const char *a = line + sizeof want - 1;
            for (i = 0; i + 1 < max && a[i] && a[i] != '"'; i++) ip[i] = a[i];
            ip[i] = 0;
            found = i > 0;
        }
        if (strcmp(line, "OK") == 0 || strcmp(line, "ERROR") == 0) break;
    }
    link_use(LINK_PI);
    return found && plain(ip);
}

// Joins the group through the ESP (.cbb pair when /cbb/NET.CFG holds the
// network's settings): cbb next pair waits on the Pi for the
// phone, at the ESP's address and the port -serve leads to, while the
// network runs under the QR code the phone scans.
static int net_pair(void)
{
    char ip[40], cmd[160], *serve, *colon = 0, *end;
    uint32_t len, crc;
    if (net_on()) return fail("the network runs; stop it first with .cbb net off", 0);
    if (net_load()) return fail("no settings yet: .cbb net on -to \"HOST:PORT\" -serve \"8764:8764\"", NET_CFG);
    serve = strstr(net_args, "-serve ");
    if (serve) colon = strchr(serve + 7, ':');
    if (!colon) return fail("the settings need -serve \"8764:8764\", where the phone reaches the Pi", net_args);
    if (!esp_address(ip, sizeof ip)) return fail("the ESP gave no address; is it on the Wi-Fi network?", line);
    // -addr the ESP's address and port, -port where -serve leads.
    *colon = 0;
    end = strchr(colon + 1, ' ');
    if (end) *end = 0;
    sprintf(cmd, CBB_LITE " next pair -addr %s:%s -port %s >/ram/cbbjoin 2>/dev/null &\n", ip, serve + 7,
            colon + 1);
    if (link_shell()) return fail("the Pi does not answer; is NextPi running? (.pisend -q)", "no SUP> prompt");
    link_send_str(cmd);
    link_prompt();
    link_send_str("until grep -q 'CBBQ\\|CBBERR' /ram/cbbjoin; do sleep 1; done; sleep 1; cat /ram/cbbjoin\n");
    if (expect(LINE_QR, &len, &crc, ANSWER_SECONDS) != LINE_QR) return 1;
    if (qr((uint8_t)len)) return 1;
    link_prompt();
    quiet = 1;
    if (net_start(0, 0)) return 1;
    return 0;
}

static int net_stop(void)
{
    if (!net_on()) return fail("the network does not run", 0);
    driver(DRV_SWITCH, 0);
    link_quit();
    // Back to the stock speed, for NextZXOS's own tools and .pibridge.
    if (!esp_speed(ESP_SPEED)) printf("The ESP did not answer AT.\n");
    link_use(LINK_PI);
    if (link_shell()) return fail("the network stopped, but the Pi does not answer", "no SUP> prompt");
    printf("The network stopped.\n");
    return 0;
}

// In debug mode: the last dropped frame and the last 64 bytes from the Pi,
// oldest first, in hex.
static uint8_t cap[66];

static void net_debug(void)
{
    uint8_t i, start;
    if (driver(DRV_DROP, 0)) return;
    printf("Last dropped: type %02x length %u\n sum %02x, ended by %02x\n", drv.bc & 0xFF, drv.bc >> 8,
           drv.de & 0xFF, drv.de >> 8);
    start = (uint8_t)(drv.hl + 1) & 63;
    for (i = 0; i < 64; i += 6) {
        if (driver(DRV_CAP, i)) return;
        cap[i] = drv.bc & 0xFF;
        cap[i + 1] = drv.bc >> 8;
        cap[i + 2] = drv.de & 0xFF;
        cap[i + 3] = drv.de >> 8;
        cap[i + 4] = drv.hl & 0xFF;
        cap[i + 5] = drv.hl >> 8;
    }
    printf("Last 64 bytes from the Pi:\n");
    for (i = 0; i < 64; i++) printf(i % 8 == 7 ? "%02x\n" : "%02x ", cap[(start + i) & 63]);
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
    if (driver(DRV_ESP, 0) == 0) {
        printf("To the ESP: %u bytes\n", drv.bc);
        printf("From the ESP: %u bytes\n", drv.de);
    }
    if (debug) net_debug();
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

// .cbb install: the files from cbb.tools, through the ESP (docs/roadmap.md,
// "Installing"). NextZXOS's .http has no TLS and neither has the ESP, so
// they come over plain HTTP; each is checked against the list before it
// replaces the old one, which guards against a damaged download.
#define SITE "cbb.tools"
#define SITE_DIR "/zxnext/"
#define SITE_LIST "LIST"
// The Pi's cbb: on the card, and where NextPi's shell finds it.
#define PI_CARD "/cbb/CBBPI.BIN"
#define PI_DIR "/NextPi/nextpi"
// Where NextZXOS looks for dot commands first.
#define DOT_CBB "c:/dot/CBB"
// A range is asked for at a time, kept in text[], and written while the
// server waits: the ESP has no flow control, and a card write runs with
// interrupts off for longer than the UART's buffer lasts.
#define CHUNK 4096

// The ROM's frame counter, 50 a second while interrupts run.
#define FRAMES_LO (*(volatile uint16_t *)23672)
// The ROM's scroll count: kept high, the screen scrolls without "scroll?".
#define SCR_CT (*(volatile uint8_t *)23692)

struct item {
    const char *name, *card, *part;
    uint32_t size, crc;
    char md5[33];
};

static struct item items[] = {
    {"CBB", "/cbb/CBB", "/cbb/CBB.PRT", 0, 0, ""},
    {"CBB.DRV", "/cbb/CBB.DRV", "/cbb/DRV.PRT", 0, 0, ""},
    {"cbb", PI_CARD, "/cbb/CBBPI.PRT", 0, 0, ""},
};
#define ITEMS (sizeof items / sizeof items[0])

// Asks for size bytes of name from offset on the open connection; 0 with
// the bytes in text[] when they all came.
static uint8_t http_range(const char *name, uint32_t from, uint16_t size)
{
    uint32_t length = 0;
    uint16_t i, status = 0;
    uint8_t c, err;
    sprintf(line, "GET " SITE_DIR "%s HTTP/1.1\r\nHost: " SITE "\r\nRange: bytes=%lu-%lu\r\n\r\n", name, from,
            from + size - 1);
    link_send_str(line);
    // The status line and the headers, up to the empty line.
    for (i = 0;; i++) {
        err = link_line(line, sizeof line, 10);
        if (err) return err;
        if (i == 0) {
            if (strncmp(line, "HTTP/1.", 7) != 0 || strlen(line) < 12) return 255;
            status = (uint16_t)strtoul(line + 9, 0, 10);
        } else if (!line[0]) {
            break;
        } else if (strncasecmp(line, "Content-Length:", 15) == 0) {
            length = strtoul(line + 15, 0, 10);
        }
    }
    if (status != 206 && !(status == 200 && from == 0)) return 254;
    if (length != size) return 253;
    for (i = 0; i < size; i++) {
        err = link_recv(&c, 10);
        if (err) return err;
        text[i] = c;
    }
    return 0;
}

// Opens a passthrough connection to the site through the ESP; 0 when open.
static uint8_t http_open(void)
{
    static const char *const cmds[] = {"AT+CIPMODE=0", "AT+CIPCLOSE", "AT+CIPMUX=0", "AT+CIPMODE=1",
                                       "AT+CIPSTART=\"TCP\",\"" SITE "\",80", "AT+CIPSEND"};
    uint8_t i, c;
    if (!esp_speed(ESP_SPEED)) return 1;
    for (i = 0; i < sizeof cmds / sizeof cmds[0]; i++) {
        link_send_str(cmds[i]);
        link_send_str("\r\n");
        if (i == 1) {
            // No connection to close answers ERROR: either will do.
            while (link_line(line, sizeof line, 2) == LINK_OK && strcmp(line, "OK") && strcmp(line, "ERROR")) {
            }
            continue;
        }
        if (i == 5) {
            while (link_recv(&c, 5) == LINK_OK) {
                if (c == '>') return 0;
            }
            return 1;
        }
        for (;;) {
            if (link_line(line, sizeof line, i == 4 ? 15 : 3)) return 1;
            if (strcmp(line, "OK") == 0 || strcmp(line, "ALREADY CONNECTED") == 0) break;
            if (strcmp(line, "ERROR") == 0 || strncmp(line, "FAIL", 4) == 0) return 1;
        }
    }
    return 0;
}

// Leaves the passthrough connection: a second of quiet, +++, a second.
static void http_close(void)
{
    esp_escape(ESP_SPEED);
    link_send_str("AT+CIPCLOSE\r\n");
    while (link_line(line, sizeof line, 2) == LINK_OK) {
    }
}

// Shows where a download stands on one line, overwritten in place.
static void progress(const char *name, uint32_t got, uint32_t size, uint16_t start)
{
    uint16_t secs = (uint16_t)(FRAMES_LO - start) / 50;
    uint32_t rate = secs ? got / secs : 0;
    uint16_t left = rate ? (uint16_t)((size - got) / rate) : 0;
    uint8_t pct = size ? (uint8_t)(got * 100 / size) : 100;
    SCR_CT = 255;
    printf("\r%-8s %3u%% %5luK %4luB/s %2u:%02u ", name, pct, got >> 10, rate, left / 60, left % 60);
}

// CRC-32 by a table: the Pi's cbb is megabytes, and frame.c's bit by bit
// takes minutes for it.
static uint32_t crc_table[256];

static void crc_init(void)
{
    uint16_t i;
    uint8_t k;
    uint32_t c;
    for (i = 0; i < 256; i++) {
        c = i;
        for (k = 0; k < 8; k++) c = c & 1 ? (c >> 1) ^ 0xEDB88320UL : c >> 1;
        crc_table[i] = c;
    }
}

static uint32_t crc_add(uint32_t crc, const uint8_t *p, uint16_t n)
{
    crc = ~crc;
    while (n--) crc = crc_table[(uint8_t)crc ^ *p++] ^ (crc >> 8);
    return ~crc;
}

// The CRC-32 of a file on the card, read in chunks; its size in *size.
static uint32_t file_crc(const char *path, uint32_t *size)
{
    uint8_t fh;
    uint16_t n;
    uint32_t crc = 0;
    *size = 0;
    errno = 0;
    fh = esx_f_open(path, ESX_MODE_R | ESX_MODE_OPEN_EXIST);
    if (errno) return 0;
    while ((n = esx_f_read(fh, text, CHUNK)) > 0) {
        crc = crc_add(crc, text, n);
        *size += n;
    }
    esx_f_close(fh);
    return crc;
}

// Fetches one item to its .PRT file, going on from what an earlier try
// left there, and puts it in place once it matches the list; 0 when done.
static int fetch(struct item *it)
{
    uint8_t fh, err, tries = 0;
    uint16_t n, start = FRAMES_LO;
    uint32_t got, crc;
    // What an earlier try left, with its CRC so far.
    crc = file_crc(it->part, &got);
    if (got > it->size) {
        esx_f_unlink(it->part);
        crc = got = 0;
    }
    errno = 0;
    fh = esx_f_open(it->part, ESX_MODE_W | ESX_MODE_OPEN_CREAT);
    if (errno) return fail("cannot write to /cbb", it->part);
    esx_f_seek(fh, got, ESX_SEEK_SET);
    if (got) printf("%-8s goes on from %luK\n", it->name, got >> 10);
    while (got < it->size) {
        n = it->size - got > CHUNK ? CHUNK : (uint16_t)(it->size - got);
        err = http_range(it->name, got, n);
        if (err == LINK_BREAK) {
            esx_f_close(fh);
            printf("\n");
            return fail("stopped; .cbb install goes on from here", 0);
        }
        if (err) {
            // The server may have closed the connection: open it again.
            if (++tries > 5) {
                esx_f_close(fh);
                printf("\n");
                return fail("the download broke off; .cbb install goes on from here", line);
            }
            http_close();
            http_open();
            continue;
        }
        tries = 0;
        if (esx_f_write(fh, text, n) != n) {
            esx_f_close(fh);
            return fail("cannot write to the card", it->part);
        }
        crc = crc_add(crc, text, n);
        got += n;
        zx_border((uint8_t)(got >> 12) & 7);
        progress(it->name, got, it->size, start);
    }
    esx_f_close(fh);
    zx_border(INK_BLACK);
    printf("\n");
    if (crc != it->crc) {
        esx_f_unlink(it->part);
        return fail("the file arrived damaged; run .cbb install again", it->name);
    }
    esx_f_unlink(it->card);
    if (esx_f_rename(it->part, it->card)) return fail("cannot put the file in place", it->card);
    return 0;
}

// Whether the file on the card is the list's.
static uint8_t up_to_date(struct item *it)
{
    uint32_t size, crc = file_crc(it->card, &size);
    return size == it->size && crc == it->crc;
}

// Reads the list: a line NAME SIZE CRC32 MD5 for each file.
static int read_list(void)
{
    char *p, *q;
    uint8_t i, err;
    uint16_t len;
    // The list is short: one range of up to CHUNK bytes, then cut to size.
    link_send_str("GET " SITE_DIR SITE_LIST " HTTP/1.1\r\nHost: " SITE "\r\n\r\n");
    len = 0;
    for (i = 0;; i++) {
        err = link_line(line, sizeof line, 10);
        if (err) return fail("the site did not answer", "no list");
        if (i == 0 && strncmp(line, "HTTP/1.1 200", 12) != 0) return fail("the site has no files for the Next yet", line);
        if (!line[0]) break;
        if (strncasecmp(line, "Content-Length:", 15) == 0) len = (uint16_t)strtoul(line + 15, 0, 10);
    }
    if (len == 0 || len >= CHUNK) return fail("the list is damaged", 0);
    {
        uint16_t k;
        uint8_t c;
        for (k = 0; k < len; k++) {
            if (link_recv(&c, 10)) return fail("the list broke off", 0);
            text[k] = c;
        }
        text[len] = 0;
    }
    for (p = (char *)text; *p; p = q) {
        char name[16], md5[40];
        uint32_t size;
        char crc[12];
        q = strchr(p, '\n');
        if (q) *q++ = 0;
        else q = p + strlen(p);
        if (sscanf(p, "%15s %lu %11s %39s", name, &size, crc, md5) != 4) continue;
        for (i = 0; i < ITEMS; i++) {
            if (strcmp(items[i].name, name) == 0 && strlen(crc) == 8 && strlen(md5) == 32) {
                items[i].size = size;
                items[i].crc = strtoul(crc, 0, 16);
                strcpy(items[i].md5, md5);
            }
        }
    }
    for (i = 0; i < ITEMS; i++) {
        if (!items[i].size) return fail("the list lacks a file", items[i].name);
    }
    return 0;
}

// Asks NextPi's shell for the MD5 of the Pi's cbb, into md5 ("none"
// without one); 0 when the Pi answered.
static uint8_t pi_md5(char *md5)
{
    if (link_shell()) return 1;
    link_send_str("{ md5sum " PI_DIR "/cbb.bin 2>/dev/null || echo none; } | cut -c1-32 | sed 's/^/CBBM /'\n");
    for (;;) {
        if (link_line(line, sizeof line, 10)) return 1;
        if (strncmp(line, "CBBM ", 5) == 0 && strlen(line) <= 37) {
            strcpy(md5, line + 5);
            link_prompt();
            return 0;
        }
    }
}

// Copies the Pi's cbb from the card to NextPi's user partition over the
// UART: the shell reads exactly its size, then checks its MD5 before it
// takes the place of the old one. The wrapper that NextPi's shell runs is
// written unless there is one.
static int to_pi(struct item *it)
{
    uint8_t fh, err;
    uint16_t n, start = FRAMES_LO;
    uint32_t sent = 0;
    if (link_shell()) return fail("the Pi does not answer; is NextPi running? (.pisend -q)", "no SUP> prompt");
    errno = 0;
    fh = esx_f_open(it->card, ESX_MODE_R | ESX_MODE_OPEN_EXIST);
    if (errno) return fail("the Pi's cbb is not on the card", it->card);
    // Raw: every byte as it is, none taken as a key or echoed.
    sprintf(line,
            "stty raw -echo -iexten; echo CBBGO; timeout 1800 head -c %lu >" PI_DIR "/cbb.new; stty sane\n",
            it->size);
    link_send_str(line);
    for (;;) {
        err = link_line(line, sizeof line, 5);
        if (err) {
            esx_f_close(fh);
            return fail("the Pi did not get ready", "no CBBGO");
        }
        if (strcmp(line, "CBBGO") == 0) break;
    }
    while ((n = esx_f_read(fh, text, CHUNK)) > 0) {
        uint16_t i;
        for (i = 0; i < n; i++) link_send(text[i]);
        sent += n;
        progress("to Pi", sent, it->size, start);
    }
    esx_f_close(fh);
    printf("\n");
    link_prompt();
    sprintf(line,
            "cd " PI_DIR " && [ \"$(md5sum <cbb.new | cut -c1-32)\" = %s ] && chmod 755 cbb.new && "
            "mv -f cbb.new cbb.bin && echo CBBOK || { rm -f cbb.new; echo CBBERR; }\n",
            it->md5);
    link_send_str(line);
    for (;;) {
        if (link_line(line, sizeof line, 60)) return fail("the Pi did not answer", "no CBBOK");
        if (strcmp(line, "CBBERR") == 0) return fail("the Pi got a damaged copy; run .cbb install again", 0);
        if (strcmp(line, "CBBOK") == 0) break;
    }
    link_prompt();
    // A service of the old cbb, which .cbb net on or a hand started, stops,
    // so that the next .cbb net on starts the new one.
    link_send_str("pkill -f ' service -peer 127\\.0\\.0\\.1:'\n");
    link_prompt();
    // The wrapper keeps the state in the user partition, since NextPi's
    // root is read-only; an older cbb that is the program itself is kept
    // as cbb.old.
    link_send_str("cd " PI_DIR " && [ \"$(head -c2 cbb 2>/dev/null)\" = '#!' ] || { [ -e cbb ] && mv -f cbb cbb.old; "
                  "printf '#!/bin/sh\\nexport CBB_STATE=" PI_DIR "/cbb-state\\nexec " PI_DIR
                  "/cbb.bin \"$@\"\\n' >cbb && chmod 755 cbb; }; cd\n");
    link_prompt();
    return 0;
}

// .cbb install and .cbb update: the Next's files to /cbb, the Pi's cbb
// through the card to the Pi; each only when the list has another.
static int install(void)
{
    static char pimd5[33];
    struct item *pi = &items[ITEMS - 1];
    uint8_t i, pi_answers, drv_new = 0;
    uint32_t size;
    int err = 0;
    if (net_on()) return fail("the network runs; stop it first with .cbb net off", 0);
    crc_init();
    esx_f_mkdir("/cbb");
    pi_answers = !pi_md5(pimd5);
    printf("From " SITE "; SPACE stops,\n.cbb install goes on.\n");
    if (http_open()) {
        http_close();
        link_use(LINK_PI);
        return fail("cannot reach " SITE "; is the ESP on Wi-Fi?", line);
    }
    err = read_list();
    for (i = 0; i < ITEMS && !err; i++) {
        struct item *it = &items[i];
        if (it == pi) {
            if (!pi_answers || strcmp(pimd5, it->md5) == 0) continue;
        } else if (up_to_date(it)) {
            printf("%-8s up to date\n", it->name);
            continue;
        }
        // The Pi's cbb may be on the card from a try that stopped later.
        if (it == pi && up_to_date(it)) continue;
        err = fetch(it);
        if (i == 1) drv_new = 1;
    }
    http_close();
    link_use(LINK_PI);
    if (err) return 1;
    if (!pi_answers) {
        printf("The Pi does not answer: its cbb\ncomes with .cbb update later.\n");
    } else if (strcmp(pimd5, pi->md5) == 0) {
        printf("%-8s up to date (Pi)\n", pi->name);
    } else {
        printf("To the Pi:\n");
        if (to_pi(pi)) return 1;
        // The card keeps no copy of the Pi's program.
        esx_f_unlink(pi->card);
        printf("The Pi's cbb is installed;\n.cbb net on starts it.\n");
    }
    // A driver installed earlier runs from memory until it is
    // uninstalled; the card's new file takes its place only then.
    if (driver(DRV_STATE, 0) != 0) {
        printf("Next: .install /cbb/CBB.DRV\n(again after each reset)\n");
    } else if (drv_new) {
        printf("CBB.DRV is new: .uninstall\n/cbb/CBB.DRV, then .install\n/cbb/CBB.DRV\n");
    }
    // An older .cbb in C:/DOT runs as .cbb before this one.
    if (file_crc(DOT_CBB, &size) != items[0].crc && size) {
        printf("C:/DOT/CBB is another .cbb;\n.cbb runs it, ../CBB the new\none: replace or delete it.\n");
    }
    printf("Done.\n");
    return 0;
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
    // With the network's settings, the Pi has no network but the ESP's.
    if (strcmp(argv[i], "pair") == 0 && argc - i == 1) return net_load() ? pair() : net_pair();
    if (strcmp(argv[i], "net") == 0) return net(argc - i - 1, argv + i + 1);
    if ((strcmp(argv[i], "install") == 0 || strcmp(argv[i], "update") == 0) && argc - i == 1) return install();
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
