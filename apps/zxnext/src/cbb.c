// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// .cbb: the CBB dot command for the ZX Spectrum Next. It talks
// to the lite member on the Next's own Raspberry Pi over the UART between
// them, by typing `cbb next ...` at NextPi's shell (docs/roadmap.md, item 14;
// the frames are in member/README.md, "ZX Spectrum Next").

#include <arch/zxn.h>
#include <arch/zxn/esxdos.h>
#include <ctype.h>
#include <errno.h>
#include <input.h>
#include <intrinsic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <z80.h>

#include "frame.h"
// The logo lives in the far data page.
#pragma constseg PAGE_15
#include "logo.h"
#pragma constseg rodata_compiler
#include "link.h"
#include "pins.h"
#include "sha256.h"

#define VERSION "0.5.0"
// The lite member on the Pi; the NextPi set-up puts it on the shell's PATH.
#define CBB_LITE "cbb"
// Stops the lite member's service that cbb next link started.
#define PKILL_SERVICE "pkill -f ' service -peer 127\\.0\\.0\\.1:'"
// The longest text pasted or copied.
#define MAX_TEXT 8192
// How long the lite member may take to answer, in seconds.
#define ANSWER_SECONDS 20
// The ROM's frame counter, 50 a second while interrupts run.
#define FRAMES_LO (*(volatile uint16_t *)23672)

static uint8_t text[MAX_TEXT];
static char line[200];
static uint8_t debug;

// The usage, in the far data page.
#pragma constseg PAGE_15
// 32 columns, the commands' words from column 14 (a tab), and few
// enough lines that nothing asks "scroll?".
static const char usage_text[] = "CBB " VERSION "  .cbb COMMAND\n\n"
           "paste [FILE]\tshow the group's\n"
           "\ttext, or save it\n"
           "copy FILE\tsend a file\n"
           "text WORDS\tsend the words\n"
           "copy -s FILE\tsend a password\n"
           "text -s WORDS\tor any secret\n"
           "pair [CODE]\tjoin: scan the QR\n"
           "\tor cbb pair CODE\n"
           "net on [HOST]\tthe network\n"
           "net [off]\tstate, or stop it\n"
           "install\tfetch the rest\n"
           "update\tget a newer CBB\n"
           "paste-receive on|off\n"
           "\tremote paste\n"
           "leave\tleave the group\n"
           "uninstall\tremove it all\n"
           "-d ...\terror details\n";
#pragma constseg rodata_compiler

// usage_run() prints it, in its page (far.asm: far_usage()).
extern void far_usage(void);
#define usage far_usage

// While .cbb install's screen shows, messages go to its lower rows
// (screen_row), one under the other, never scrolling the logo away: rows
// MESSAGE_ROW to 21, the ROM's upper screen ending at 21 (AT 22 stops
// the program with "Out of screen"), the oldest scrolled off when full.
#define MESSAGE_ROW 18
static uint8_t screen_row;

// A byte straight to the ROM's RST $10 (far.asm): stdout's driver turns
// 10 into 13 and drops 13, which AT's row and column must not have.
extern void rom_char(uint8_t c) __z88dk_fastcall;

static void at(uint8_t row, uint8_t col)
{
    rom_char(22); // the ROM's AT
    rom_char(row);
    rom_char(col);
}

// The QR code's line, as wide as its wait; the install screen's
// from PRESS.
static const char qr_key[] = "SCAN, THEN PRESS ANY KEY";

// After a key, a clear screen in BASIC's colours and border (BORDCR,
// ATTR_P), for what the QR code or the install screen showed.
static void key_clear(void)
{
    in_wait_nokey();
    in_wait_key();
    in_wait_nokey();
    zx_border(*(uint8_t *)23624 >> 3 & 7);
    zx_cls(*(uint8_t *)23693);
    at(0, 0);
}

// Puts the print position on the next message row for a text of len
// characters.
static void message_at(uint16_t len)
{
    uint8_t lines = (uint8_t)(len / 32 + 1), k;
    // The rows' pixels, in the screen's bottom third (rows 16-23): each
    // of their 8 lines 256 bytes on; one row up, the last cleared. The
    // rows' attributes are all the same.
    uint8_t *p;
    if (!screen_row) return;
    while (screen_row + lines > 22 && screen_row > MESSAGE_ROW) {
        p = (uint8_t *)(0x5000 + (MESSAGE_ROW - 16) * 32);
        for (k = 0; k < 8; k++, p += 256) {
            memmove(p, p + 32, (21 - MESSAGE_ROW) * 32);
            memset(p + (21 - MESSAGE_ROW) * 32, 0, 32);
        }
        screen_row--;
    }
    at(screen_row, 0);
    screen_row += lines;
}

// Ends a message's line; on the screen the next one is placed with AT, as
// a newline on row 21 would scroll the whole screen.
static void end_line(void)
{
    if (!screen_row) putchar('\n');
}

// Prints a text, in capitals while .cbb install's screen shows.
static void put_text(const char *s)
{
    while (*s) putchar(screen_row ? toupper(*s++) : *s++);
}

// Shows a short message, and in debug mode the cause under it.
static int fail(const char *msg, const char *detail)
{
    message_at(strlen(msg) + 5);
    put_text("cbb: ");
    put_text(msg);
    end_line();
    if (debug && detail && *detail) {
        message_at(strlen(detail) + 4);
        put_text("  (");
        put_text(detail);
        putchar(')');
        end_line();
    }
    return 1;
}

// Messages more than one place shows: kept once, as the compiler does
// not merge equal strings.
static const char no_prompt[] = "no SUP> prompt";
static const char not_start[] = "cbb next link did not start on the Pi";
static const char too_long[] = "the text is too long";

// The Pi's shell did not answer.
static int pi_silent(void)
{
    return fail("the Pi does not answer; is NextPi running? (.pisend -q)", no_prompt);
}

// Shows a line of .cbb install.
static void say(const char *msg)
{
    message_at(strlen(msg));
    put_text(msg);
    end_line();
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
// .cbb paste-receive's switch, which the next .cbb net on hands the link
// (-paste) once and erases: after that the Pi's setting stands, which an
// admin's paste-off changes too.
#define PASTE_CFG "/cbb/PASTE.CFG"
// The Pi's cbb: on the card, and where NextPi's shell finds it.
#define PI_CARD "/cbb/CBBPI.BIN"
#define PI_DIR "/NextPi/nextpi"
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

// Whether the card has the file.
static uint8_t card_has(const char *path)
{
    uint8_t fh;
    errno = 0;
    fh = esx_f_open(path, ESX_MODE_R | ESX_MODE_OPEN_EXIST);
    if (errno) return 0;
    esx_f_close(fh);
    return 1;
}

// Whether the driver holds the Pi's UART for the network.
static uint8_t net_on(void)
{
    return driver(DRV_STATE, 0) == 0 && drv.de != 0;
}

// Installing the driver as .install does, since a dot command cannot run
// another (M_EXECCMD): the driver API's calls for .install and .uninstall
// (M_DRVAPI with driver 0) and IDE_BANK for its 8K ZX bank. CBB.DRV holds
// the header, the 512 bytes and one bank with two patches, where its id
// goes (drv/drv.asm); anything else is left to .install.
#define DRV_FILE "/cbb/CBB.DRV"
#define NDRV_ID (DRIVER_ID | 0x80)
#define DRVAPI_INSTALL 1
#define DRVAPI_UNINSTALL 2
#define DRVAPI_IMAGE 4
#define NO_BANK 0xFF

static uint8_t drv_code[512];
static uint16_t drv_patch[2];

static uint8_t drvapi(uint8_t function, uint16_t de, void *hl)
{
    drv.call.driver = 0;
    drv.call.function = function;
    drv.de = de;
    drv.hl = (uint16_t)hl;
    return esx_m_drvapi(&drv) != 0;
}

// Reads CBB.DRV: its 512 bytes into drv_code, its bank into text[] (the
// size in *size), the patch offsets into drv_patch; 0 if it is one.
static uint8_t drv_read(uint16_t *size)
{
    uint8_t fh, h[8], bad = 1;
    errno = 0;
    fh = esx_f_open(DRV_FILE, ESX_MODE_R | ESX_MODE_OPEN_EXIST);
    if (errno) return 1;
    if (esx_f_read(fh, h, 8) == 8 && memcmp(h, "NDRV", 4) == 0 && h[4] == NDRV_ID && h[5] == 0 && h[6] == 0 &&
        h[7] == 1 && esx_f_read(fh, drv_code, 512) == 512 && esx_f_read(fh, h, 3) == 3 && h[0] == 2) {
        *size = h[1] | (uint16_t)h[2] << 8;
        if (*size <= MAX_TEXT && esx_f_read(fh, text, *size) == *size && esx_f_read(fh, drv_patch, 4) == 4 &&
            drv_patch[0] < 512 && drv_patch[1] < 512) {
            bad = 0;
        }
    }
    esx_f_close(fh);
    return bad;
}

// The bank of the driver installed, read from its image where CBB.DRV on
// the card says the id went; NO_BANK if it cannot tell.
static uint8_t drv_bank(void)
{
    uint16_t size;
    if (drv_read(&size)) return NO_BANK;
    if (drvapi(DRVAPI_IMAGE, DRIVER_ID, drv_code)) return NO_BANK;
    return drv_code[drv_patch[0]];
}

// Installs CBB.DRV from the card; 0 when it runs.
static uint8_t drv_install(void)
{
    uint16_t size;
    uint8_t bank, mmu7;
    if (drv_read(&size)) return 1;
    bank = esx_ide_bank_alloc(ESX_BANKTYPE_RAM);
    if (bank == NO_BANK) return 2;
    // The bank in at $E000 for a moment, the window of the command's own
    // overlays (far.asm), never BASIC's at $6000; this code and text[]
    // are in MAIN, below it, and MMU7 shows what it showed before after.
    intrinsic_di();
    mmu7 = ZXN_READ_MMU7();
    ZXN_WRITE_MMU7(bank);
    memset((void *)0xE000, 0, 8192);
    memcpy((void *)0xE000, text, size);
    ZXN_WRITE_MMU7(mmu7);
    intrinsic_ei();
    drv_code[drv_patch[0]] = bank;
    drv_code[drv_patch[1]] = bank;
    if (drvapi(DRVAPI_INSTALL, NDRV_ID, drv_code)) {
        esx_ide_bank_free(ESX_BANKTYPE_RAM, bank);
        return 3;
    }
    return 0;
}

// Uninstalls the driver and frees its bank; 0 when done.
static uint8_t drv_uninstall(uint8_t bank)
{
    if (drvapi(DRVAPI_UNINSTALL, DRIVER_ID, 0)) return 1;
    if (bank != NO_BANK) esx_ide_bank_free(ESX_BANKTYPE_RAM, bank);
    return 0;
}

// CBB.OVL: the pages from OVL_FIRST on, which ovl.sh cut out of CBB, so
// that CBB stays under 64K. NextZXOS allocates them empty, and far.asm's
// far_call() has ovl_load() read one before its first call there; the
// last four bytes of each are the stamp of the build, which CBB carries.
#define OVL_FILE "/cbb/CBB.OVL"
#define OVL_FIRST 19
#define OVL_CHUNK 512
extern uint8_t _z_page_table[];
#pragma codeseg code_dot
#pragma constseg code_dot
#pragma bssseg code_dot
static const char ovl_stamp[] = OVL_STAMP;
static const char ovl_missing[] = "CBB.OVL is missing: .cbb install";
static const char ovl_other[] = "CBB.OVL is not this CBB's: .cbb install";
static uint8_t ovl_loaded;

// Not static: far_call() (far.asm) calls it; 0 when the page is there.
uint8_t ovl_load(uint8_t page) __z88dk_fastcall
{
    uint8_t buf[OVL_CHUNK], fh, mmu7, bit = 1 << ((page - OVL_FIRST) >> 1), bad = 0;
    uint16_t at;
    if (ovl_loaded & bit) return 0;
    errno = 0;
    fh = esx_f_open(OVL_FILE, ESX_MODE_R | ESX_MODE_OPEN_EXIST);
    if (errno) return fail(ovl_missing, 0);
    esx_f_seek(fh, (uint32_t)((page - OVL_FIRST) >> 1) << 13, ESX_SEEK_SET);
    mmu7 = ZXN_READ_MMU7();
    // Through the stack, under 0xE000, the page in for each copy only.
    for (at = 0; at < 8192 && !bad; at += OVL_CHUNK) {
        bad = esx_f_read(fh, buf, OVL_CHUNK) != OVL_CHUNK;
        intrinsic_di();
        ZXN_WRITE_MMU7(_z_page_table[page]);
        memcpy((void *)(0xE000 + at), buf, OVL_CHUNK);
        ZXN_WRITE_MMU7(mmu7);
        intrinsic_ei();
    }
    esx_f_close(fh);
    // The stamp came with the last chunk.
    if (bad || memcmp(buf + OVL_CHUNK - 4, ovl_stamp, 4)) return fail(ovl_other, 0);
    ovl_loaded |= bit;
    return 0;
}
#pragma codeseg code_compiler
#pragma constseg rodata_compiler
#pragma bssseg bss_compiler

// Types a command for the lite member at NextPi's shell (the network
// stopped: cmd_run() and net_pair() see to it).
static int command(const char *args)
{
    if (link_shell()) {
        return pi_silent();
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

// The words of the command an overlay runs, which run() leaves in MAIN for
// it (cmd_run(), net_cmd()), and whether install runs as .cbb update.
static int far_argc;
static char **far_argv;
// .cbb pair CODE: the code from cbb pair on a computer of the group.
static char *pair_code;
static uint8_t install_update;
// sha_run()'s file, whether it takes the digest, and the digest in hex.
static const char *sha_path;
static uint8_t sha_digest;
static char sha_out[65];
extern uint32_t far_sha(void);
// The newest CBB's size and CRC-32 in the site's list (far_read_list()),
// and each file's size and SHA-256 there, in the order of items[] and the
// CBB last: a newer CBB comes with the files built with it.
static uint32_t list_size, list_crc;
// Which part of the list read_list() does: 0 fetches the site's signed
// files into text[], 1 reads the lines the Pi's cbb wrote of them.
static uint8_t list_checked;
#define LISTED 4
static uint32_t list_isize[LISTED];
static char list_isha[LISTED][65];
// Whether the CBB that cbb_swap() replaces is C:/DOT's.
static uint8_t swap_dot;
// What far_autoexec() does: 0 puts .cbb net on into AUTOEXEC.BAS, 1 takes
// it out.
static uint8_t ax_out;
extern int far_autoexec(void);
extern int far_cbb_swap(void);
// For install_end(): whether the Pi answered, and which end word: 0
// done, 1 no updates, 2 a newer CBB too, whose network this one does not
// start (the new one's may differ).
static uint8_t end_pi, end_word;
extern int far_install_end(void);
extern int far_read_list(void);

// pair_check() only finds whether the Pi is in a group, silently.
static uint8_t pair_probe;

// Whether copy and text send a secret: the group's devices keep it out of
// their histories and clear it from their clipboards after a while.
static uint8_t secret;

// .cbb paste, copy and text, from here to cmd_run(), are in CBB.OVL's page
// (far.asm, far_cmd()).
#pragma codeseg PAGE_19
#pragma constseg PAGE_19
#pragma bssseg PAGE_19
#pragma dataseg PAGE_19

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
        return fail(too_long, "longer than -max");
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
        if (len + n + 1 > MAX_TEXT) return fail(too_long, 0);
        if (i) text[len++] = ' ';
        memcpy(text + len, argv[i], n);
        len += n;
    }
    return copy(len);
}

// While the network runs, the commands go through the driver (calls 7
// and 8): it sends the Pi frames of what link_send() gets and keeps the
// Pi's frames for link_recv(), and the link on the Pi runs the command as
// NextPi's shell would (member/src/nextlink/link.rs). A driver without the
// calls has the network stop for them and start again after.
#define DRV_CBB_OUT 7
#define DRV_CBB_IN 8
#define VIA_OPEN 0
#define VIA_BYTE 1
#define VIA_STOP 3
#define VIA_CLOSE 4

static void via_send(uint8_t c)
{
    // 3, which stops a command at the shell, stops it at the link.
    driver(DRV_CBB_OUT, c == 3 ? VIA_STOP << 8 : VIA_BYTE << 8 | c);
}

static uint8_t via_recv(uint8_t *c, uint16_t seconds)
{
    uint16_t start = FRAMES_LO;
    for (;;) {
        driver(DRV_CBB_IN, 0);
        if (drv.de & 0x100) {
            *c = (uint8_t)drv.de;
            return LINK_OK;
        }
        if (in_key_pressed(IN_KEY_SCANCODE_SPACE)) {
            link_stopped = 1;
            return LINK_BREAK;
        }
        if ((uint16_t)(FRAMES_LO - start) / 50 >= seconds) return LINK_TIMEOUT;
    }
}

extern int far_net_halt(void);
extern int far_net_restart(void);

// Not static: far_cmd() (far.asm) calls it, with far_argc and far_argv
// set; run() has checked the number of words.
int cmd_run(void)
{
    char **argv = far_argv;
    uint8_t was = net_on(), via = 0;
    int err;
    if (was) {
        // A command the link still runs from before stops first.
        via = !driver(DRV_CBB_OUT, VIA_OPEN << 8);
        if (via) {
            driver(DRV_CBB_OUT, VIA_STOP << 8);
            link_via_send = via_send;
            link_via_recv = via_recv;
        } else if (far_net_halt()) {
            return 1;
        }
    }
    if (strcmp(argv[0], "paste") == 0) err = paste(far_argc == 2 ? argv[1] : 0);
    else if (strcmp(argv[0], "copy") == 0) err = copy_file(argv[1]);
    else err = copy_words(far_argc - 1, argv + 1);
    if (via) {
        link_via_send = 0;
        link_via_recv = 0;
        driver(DRV_CBB_OUT, VIA_CLOSE << 8);
    } else if (was) {
        err |= far_net_restart();
    }
    return err;
}

#pragma codeseg code_compiler
#pragma constseg rodata_compiler
#pragma bssseg bss_compiler
#pragma dataseg data_compiler

// The link's settings: the -to, -serve and -zone of `cbb next link`.
static char net_args[120];

// PASTE_CFG's setting; 1 when there is one.
static char paste_set[10];
static uint8_t plain(const char *s);

static uint8_t paste_load(void)
{
    uint8_t fh;
    uint16_t n;
    errno = 0;
    fh = esx_f_open(PASTE_CFG, ESX_MODE_R | ESX_MODE_OPEN_EXIST);
    if (errno) return 0;
    n = esx_f_read(fh, paste_set, sizeof paste_set - 1);
    esx_f_close(fh);
    paste_set[n] = 0;
    return n && plain(paste_set);
}

static int paste_save(void)
{
    uint8_t fh;
    errno = 0;
    fh = esx_f_open(PASTE_CFG, ESX_MODE_W | ESX_MODE_OPEN_CREAT_TRUNC);
    if (errno) return fail("cannot save the setting; is there a folder /cbb?", PASTE_CFG);
    esx_f_write(fh, paste_set, strlen(paste_set));
    esx_f_close(fh);
    return 0;
}

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
// Constant tables are kept outside the functions: zcc puts a function's own
// static data at the function's address when both go to one section, as
// they do in the overlay pages, and a call then runs the data (mapcheck.sh).
static const uint8_t quit[] = {0x7E, 'Q', 0, 'Q'};

static void link_quit(void)
{
    uint8_t i;
    for (i = 0; i < sizeof quit; i++) link_send(quit[i]);
}

// The ESP's stock speed, and its speed while the network runs: the driver
// hands the Pi at most 48 of its bytes a frame (2400 a second), and the ESP
// has no flow control, so at 115200 a burst, such as a phone's TLS hello,
// overflows the Next's 512-byte buffer. 19200 is 1920 bytes a second.
#define ESP_SPEED 115200UL
#define ESP_NET_SPEED 19200UL
// .cbb install's speed for the site's files: 23K a second, which .cbb at
// 28 MHz reads as it comes (at 460800 the played Next's UART overflowed);
// it asks for each chunk, so nothing more than one answer comes at a time.
#define ESP_FETCH_SPEED 230400UL

// The speeds the ESP may be at, which esp_answers() tries.
static const uint32_t esp_speeds[] = {ESP_SPEED, ESP_NET_SPEED, ESP_FETCH_SPEED};

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

// Restarts the ESP, for a mode it keeps until then (CIPMUX=1 with a
// server). It comes back at its stock speed and joins the Wi-Fi network
// again a few seconds after "ready": until "WIFI GOT IP" it connects
// nowhere.
static void esp_restart(void)
{
    uint8_t n = 0;
    link_send_str("AT+RST\r\n");
    link_open_esp(ESP_SPEED);
    while (n++ < 20 && link_line(line, sizeof line, 10) == LINK_OK && strcmp(line, "WIFI GOT IP")) {
    }
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

// Puts the ESP's UART at speed, from any speed it may be at; 1 if it
// answers, the ESP selected.
static uint8_t esp_answers(uint32_t speed)
{
    uint8_t i;
    if (esp_at(speed)) return 1;
    for (i = 0; i < sizeof esp_speeds / sizeof esp_speeds[0]; i++) {
        if (esp_speeds[i] == speed || !esp_at(esp_speeds[i])) continue;
        sprintf(line, "AT+UART_CUR=%lu,8,1,0,0\r\n", speed);
        link_send_str(line);
        // The OK comes at the old speed; then the ESP switches.
        while (link_line(line, sizeof line, 2) == LINK_OK) {
            if (strcmp(line, "OK") == 0) break;
        }
        return esp_at(speed);
    }
    return 0;
}

// The same, first from the speed the ESP is at (a reset of the Next leaves
// the ESP as it was; AT+UART_CUR is not kept in its flash, so a power
// cycle brings back 115200), then out of a transparent connection at each.
static uint8_t esp_speed(uint32_t speed)
{
    uint8_t i;
    if (esp_answers(speed)) return 1;
    for (i = 0; i < sizeof esp_speeds / sizeof esp_speeds[0]; i++) {
        esp_escape(esp_speeds[i]);
        if (esp_answers(speed)) return 1;
    }
    return 0;
}


// .cbb net and .cbb pair through the ESP, from here to net_cmd(), are an
// overlay of their own, as .cbb install is (far.asm, far_net()).
#pragma codeseg PAGE_17
#pragma constseg PAGE_17
#pragma bssseg PAGE_17
#pragma dataseg PAGE_17

// The short form's defaults: the member's port, and where the phones reach
// the Pi (the ESP's port, the lite member's own).
static const char net_port[] = ":8764";
static const char net_serve[] = " -serve 8764:8764";

// net_pair starts the network under its QR code, without a word.
static uint8_t quiet;

// Finds a computer of the group on the home network, as the lite members
// on a network of their own do with mDNS: the question for _cbb._tcp.local
// goes from the ESP's UDP port 5354, which the members answer to that port
// alone (a legacy unicast query, RFC 6762 section 6.7). The first answer
// from a computer, not a lite member nor a phone (TXT r=lite, r=phone),
// gives its address (the ESP names the sender) and port (its SRV record).
static const uint8_t mdns_query[] = {0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 4, '_', 'c', 'b', 'b', 4, '_', 't', 'c',
                                     'p', 5, 'l', 'o', 'c', 'a', 'l', 0, 0, 12, 0, 1};
// Several connections at once (CIPMUX=1), the ESP's mode while the
// network runs: a server on it keeps that mode until the ESP restarts, and
// the question goes on connection 4, which the network leaves alone.
static const char *const mdns_cmds[] = {"AT+CIPMODE=0", "AT+CIPMUX=1", "AT+CIPCLOSE=4", "AT+CIPDINFO=1",
                                        "AT+CIPSTART=4,\"UDP\",\"224.0.0.251\",5353,5354,2"};
static const char ipd[] = "+IPD,";
static char net_to[32];

// Whether the n bytes at p hold s.
static uint8_t holds(const uint8_t *p, uint16_t n, const char *s)
{
    uint8_t k = strlen(s);
    for (; n >= k; n--, p++) {
        if (memcmp(p, s, k) == 0) return 1;
    }
    return 0;
}

// The end of the name at i in the answer of n bytes.
static uint16_t skip_name(uint16_t i, uint16_t n)
{
    while (i < n) {
        uint8_t b = text[i];
        if (!b) return i + 1;
        if ((b & 0xC0) == 0xC0) return i + 2;
        i += b + 1;
    }
    return n;
}

// The port of the answer's SRV record, else 8764.
static uint16_t srv_port(uint16_t n)
{
    uint16_t i = 12, records, q = text[5];
    records = text[7] + text[9] + text[11];
    while (q--) i = skip_name(i, n) + 4;
    while (records-- && i < n) {
        uint16_t len;
        i = skip_name(i, n);
        if (i + 10 > n) break;
        len = (text[i + 8] << 8) | text[i + 9];
        if (text[i + 1] == 33 && text[i] == 0 && i + 16 <= n) return (text[i + 14] << 8) | text[i + 15];
        i += 10 + len;
    }
    return 8764;
}

// One +IPD of the ESP: "+IPD,ID,LEN,IP,PORT:" then the bytes. 0 with
// net_to set when it is a computer's answer.
static uint8_t mdns_answer(void)
{
    char head[40], *ip, *end, *p;
    uint8_t c, k = 0;
    uint16_t n, i;
    while (k < sizeof head - 1) {
        if (link_recv(&c, 3)) return 2;
        if (c == ':') break;
        head[k++] = c;
    }
    head[k] = 0;
    p = strchr(head, ',');
    if (!p) return 2;
    for (n = 0, p++; *p >= '0' && *p <= '9'; p++) n = n * 10 + *p - '0';
    if (n > sizeof text) return 2;
    for (i = 0; i < n; i++) {
        if (link_recv(text + i, 3)) return 2;
    }
    if (head[0] != '4') return 1;
    ip = strchr(p, ',');
    if (!ip) return 1;
    end = strchr(++ip, ',');
    if (!end) return 1;
    *end = 0;
    // A response (QR bit) about _cbb, from a computer.
    if (n < 12 || !(text[2] & 0x80) || !holds(text, n, "_cbb") || holds(text, n, "r=lite") ||
        holds(text, n, "r=phone") || !plain(ip) || strlen(ip) > 15)
        return 1;
    // A code is for the computer whose cbb pair shows it: its window is
    // open (TXT p=1).
    if (pair_code && !holds(text, n, "p=1")) return 1;
    sprintf(net_to, "-to %s:%u ", ip, srv_port(n));
    return 0;
}

static int net_find(void)
{
    uint8_t i, c, got = 0, match = 0, reset = 0;
    if (!esp_speed(ESP_SPEED)) {
        link_use(LINK_PI);
        return fail("the ESP does not answer AT", line);
    }
again:
    // A transparent connection of .cbb install's, if one is left; in
    // CIPMUX=1 this answers ERROR.
    link_send_str("AT+CIPCLOSE\r\n");
    while (link_line(line, sizeof line, 1) == LINK_OK && strcmp(line, "OK") && strcmp(line, "ERROR")) {
    }
    for (i = 0; i < sizeof mdns_cmds / sizeof mdns_cmds[0]; i++) {
        link_send_str(mdns_cmds[i]);
        link_send_str("\r\n");
        for (;;) {
            if (link_line(line, sizeof line, 5)) goto failed;
            // A connection 4 left over is closed; none answers ERROR.
            if (strcmp(line, "OK") == 0 || (i == 2 && strcmp(line, "ERROR") == 0)) break;
            if (strcmp(line, "ERROR") == 0 || strncmp(line, "FAIL", 4) == 0) goto failed;
        }
    }
    sprintf(line, "AT+CIPSEND=4,%u\r\n", sizeof mdns_query);
    link_send_str(line);
    while (link_recv(&c, 3) == LINK_OK && c != '>') {
    }
    for (i = 0; i < sizeof mdns_query; i++) link_send(mdns_query[i]);
    // The answers, for three seconds after the last byte.
    while (!got && link_recv(&c, 3) == LINK_OK) {
        match = c == ipd[match] ? match + 1 : c == ipd[0];
        if (match == sizeof ipd - 1) {
            match = 0;
            i = mdns_answer();
            if (i == 2) break;
            got = !i;
        }
    }
    // NextZXOS's own tools read +IPD without the sender, in CIPMUX=0
    // (refused while the network's server runs, which the link wants).
    for (i = 0; i < 3; i++) {
        link_send_str(i == 2 ? "AT+CIPMUX=0\r\n" : i ? "AT+CIPDINFO=0\r\n" : "AT+CIPCLOSE=4\r\n");
        while (link_line(line, sizeof line, 1) == LINK_OK && strcmp(line, "OK") && strcmp(line, "ERROR")) {
        }
    }
    link_use(LINK_PI);
    if (!got) return fail("found no computer of the group; .cbb net on HOST names one", 0);
    if (!quiet) printf("Found %s\n", net_to + 4);
    return 0;
failed:
    // A mode the network or an earlier tool left that the ESP keeps until
    // it restarts: once, a restart at its stock speed, then again.
    if (!reset) {
        reset = 1;
        esp_restart();
        if (esp_speed(ESP_SPEED)) goto again;
    }
    link_use(LINK_PI);
    if (i < sizeof mdns_cmds / sizeof mdns_cmds[0]) {
        sprintf((char *)text, "%s: %s", mdns_cmds[i], line);
        return fail("the ESP cannot ask the network", (char *)text);
    }
    return fail("the ESP cannot ask the network", line);
}


// The start in the background (the driver's call 9): just after power-on
// (AUTOEXEC.BAS), NextPi takes up to a minute to start, which BASIC should
// not wait for. The driver gets the line that starts the link and types it
// once NextPi's shell shows its prompt, then turns itself on when the link
// says CBBLINK (drv/bank.asm).
#define DRV_BOOT 9
#define BOOT_LINE 0x0000
#define BOOT_ADD 0x0100
#define BOOT_GO 0x0200
#define BOOT_STATE 0x0300
#define BOOT_LINK 4    // waits for the link: the states up to it are pending
#define BOOT_NO_PROMPT 5
#define BOOT_NO_LINK 6
static uint8_t esp_address(char *ip, uint8_t max);

static uint8_t boot_state(void)
{
    return driver(DRV_BOOT, BOOT_STATE) ? 0 : (uint8_t)drv.de;
}

static uint8_t booting;

// The line goes to the shell now, or to the driver for later.
static void start_send(const char *s)
{
    if (!booting) link_send_str(s);
    else while (*s) driver(DRV_BOOT, BOOT_ADD | (uint8_t)*s++);
}

static const char boot_wait[] = "The network starts in the\nbackground once the Pi is up\n(.cbb net says when).\n";
static const char boot_busy[] = "The network starts once the Pi\nis up; try again then, or stop\nthat: .cbb net off\n";
static const char boot_off[] = "off";
static const char boot_none[] = "The network will not start.\n";
static const char boot_later[] = "The network starts once the Pi\nis up.\n";
static const char boot_cannot[] = "the driver cannot start the network";
static const char boot_call[] = "call 9";
static const char boot_said[][44] = {"The Pi did not start in 3 minutes.\n", "cbb next link did not start on the Pi.\n"};

// Not static: far_boot_busy() (far.asm) calls it before each command,
// after opening the Pi's UART (link_open()). Only
// .cbb net and .cbb net off may run while a start in the background waits:
// the driver reads the Pi's line then.
int boot_busy_check(void)
{
    uint8_t b;
    link_open();
    b = boot_state();
    if (b == 0 || b > BOOT_LINK) return 0;
    // Of the commands only net starts with n.
    if (far_argv[0][0] == 'n' && (far_argc == 1 || strcmp(far_argv[1], boot_off) == 0)) return 0;
    printf(boot_busy);
    return 1;
}

static int net_start(int argc, char **argv)
{
    int i;
    uint16_t n = 0;
    // Just after power-on: the frame counter's top byte 0, under two
    // minutes. The line goes to the driver then, for later.
    booting = *(uint8_t *)23674 == 0 && FRAMES_LO < 50 * 120;
    // After a reset the driver is gone: install it from the card.
    if (driver(DRV_STATE, 0) && (drv_install() || driver(DRV_STATE, 0))) {
        return fail("cannot install the driver: .install /cbb/CBB.DRV", DRV_FILE);
    }
    if (drv.de) return fail("the network runs already", 0);
    if (argc) {
        // The short form, .cbb net on HOST, is -to HOST:8764; a HOST:PORT
        // keeps its port.
        i = 0;
        if (argv[0][0] != '-') {
            if (!plain(argv[0])) return fail("a setting has a character the Pi's shell would take", argv[0]);
            if (strlen(argv[0]) + 4 + sizeof net_port + sizeof net_serve > sizeof net_args) {
                return fail("the settings are too long", 0);
            }
            n = sprintf(net_args, "-to %s%s", argv[0], strchr(argv[0], ':') ? "" : net_port);
            i = 1;
        }
        for (; i < argc; i++) {
            if (!plain(argv[i])) return fail("a setting has a character the Pi's shell would take", argv[i]);
            if (n + strlen(argv[i]) + 2 + sizeof net_serve > sizeof net_args) return fail("the settings are too long", 0);
            if (n) net_args[n++] = ' ';
            strcpy(net_args + n, argv[i]);
            n += strlen(argv[i]);
        }
        // The phones reach the Pi at the ESP's 8764 unless -serve says
        // otherwise.
        if (!strstr(net_args, "-serve ")) strcpy(net_args + n, net_serve);
        if (net_save()) return 1;
    } else if (net_load()) {
        strcpy(net_args, net_serve + 1);
        if (net_save()) return 1;
    }
    // Without -to, a computer is found each time: its address may change.
    // Just after power-on the ESP may not be on the Wi-Fi network yet.
    net_to[0] = 0;
    if (booting) {
        for (i = 0; i < 20 && !esp_address(line, sizeof line); i++) {
            n = FRAMES_LO;
            while ((uint16_t)(FRAMES_LO - n) < 50) {
            }
        }
        n = 0;
    }
    if (!strstr(net_args, "-to ") && net_find()) return 1;
    if (!esp_speed(ESP_NET_SPEED)) {
        link_use(LINK_PI);
        return fail("the ESP does not answer AT", line);
    }
    link_use(LINK_PI);
    if (booting) {
        driver(DRV_BOOT, BOOT_LINE);
    } else if (link_shell()) {
        esp_speed(ESP_SPEED);
        link_use(LINK_PI);
        return pi_silent();
    }
    start_send(CBB_LITE " next link ");
    start_send(net_to);
    start_send(net_args);
    if (pair_code) {
        start_send(" -join ");
        start_send(pair_code);
    }
    if (paste_load()) {
        start_send(" -paste ");
        start_send(paste_set);
        esx_f_unlink(PASTE_CFG);
    }
    start_send(" -log /ram/link.log\n");
    if (booting) {
        if (driver(DRV_BOOT, BOOT_GO)) return fail(boot_cannot, boot_call);
        if (!quiet) printf(boot_wait);
        return 0;
    }
    // The driver may only start once the link has made the UART raw: the
    // shell would echo its frames, and a byte of them taken as XOFF stops
    // the Pi's output. The link says CBBLINK then; anything else is the
    // shell's echo or the link's error.
    for (i = 0;; i++) {
        uint8_t err = link_line(line, sizeof line, 15);
        if (err) {
            link_quit(); // it may run without having said so
            return fail(not_start, err == LINK_BREAK ? "stopped" : "no CBBLINK");
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
            return fail(not_start, line);
        }
    }
    if (driver(DRV_SWITCH, 1)) return fail("the driver did not start", "M_DRVAPI 124 failed");
    if (!quiet) printf("The Pi's network runs through\nthe ESP in the background.\n");
    return 0;
}

// The ESP's address on the Wi-Fi network, from AT+CIFSR, into ip.
static const char cifsr_ip[] = "+CIFSR:STAIP,\"";

static uint8_t esp_address(char *ip, uint8_t max)
{
    uint8_t i, found = 0;
    if (!esp_speed(ESP_SPEED)) {
        link_use(LINK_PI);
        return 0;
    }
    link_send_str("AT+CIFSR\r\n");
    while (link_line(line, sizeof line, 3) == LINK_OK) {
        if (strncmp(line, cifsr_ip, sizeof cifsr_ip - 1) == 0) {
            const char *a = line + sizeof cifsr_ip - 1;
            for (i = 0; i + 1 < max && a[i] && a[i] != '"'; i++) ip[i] = a[i];
            ip[i] = 0;
            found = i > 0;
        }
        if (strcmp(line, "OK") == 0 || strcmp(line, "ERROR") == 0) break;
    }
    link_use(LINK_PI);
    return found && plain(ip);
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
    // From the top, row 21 left for the key under it.
    // cbb next pair's codes are far under 168 modules.
    uint8_t scale = 168 / size, x, row, col, d, px, py, err;
    if (scale > 4) scale = 4;
    // White on white until the network runs (net_pair).
    zx_border(INK_WHITE);
    zx_cls(PAPER_WHITE | INK_WHITE);
    for (row = 0; row < size; row++) {
        err = link_line(line, sizeof line, ANSWER_SECONDS);
        if (err) return link_fail(err);
        x = 128 - size * scale / 2;
        for (col = 0; col < size; col++, x += scale) {
            d = hex_digit(line[col >> 2]);
            if (d == 255) return fail("the Pi sent a damaged QR code", line);
            if (!(d & (8 >> (col & 3)))) continue;
            for (py = 0; py < scale; py++)
                for (px = 0; px < scale; px++) plot(x + px, row * scale + py);
        }
    }
    return 0;
}

// Joins the group through the ESP (.cbb pair when /cbb/NET.CFG holds the
// network's settings): cbb next pair waits on the Pi for the
// phone, at the ESP's address and the port -serve leads to, while the
// network runs under the QR code the phone scans.
static int net_stop(void);
extern int far_pair_check(void);
static const char pair_cmd[] = "(%s; " CBB_LITE " next pair -addr %s:%s -port %s >/ram/cbbjoin 2>/dev/null; %s) &\n";
static const char pair_pkill[] = PKILL_SERVICE;
static const char qr_wait[] = "WAIT: THE NETWORK STARTS";
static const char qr_after[] = "The app shows the Next\nonce it joins.\n";

// Not static: far_net_pair() (far.asm) calls it.
int net_pair(void)
{
    char ip[40], cmd[224], *serve, *colon = 0, *end;
    uint32_t len, crc;
    int err;
    // The network holds the Pi's line: it stops for the pairing, and
    // starts again after it.
    if (net_on() && net_stop()) return 1;
    if (far_pair_check()) return 1;
    // Without settings, the defaults, as .cbb net on saves them.
    if (net_load()) {
        strcpy(net_args, net_serve + 1);
        if (net_save()) return 1;
    }
    // With a computer's code, the link joins through the ESP to that
    // computer, and the computer's cbb pair says when it is done.
    if (pair_code) {
        if (!plain(pair_code)) return fail("the code is digits and dashes", pair_code);
        if (net_start(0, 0)) return 1;
        printf("Joining with the code; cbb pair\non the computer says when it\nis done.\n");
        return 0;
    }
    serve = strstr(net_args, "-serve ");
    if (serve) colon = strchr(serve + 7, ':');
    if (!colon) return fail("the settings need -serve", net_args);
    if (!esp_address(ip, sizeof ip)) return fail("the ESP gave no address; is it on the Wi-Fi network?", line);
    // -addr the ESP's address and port, -port where -serve leads.
    *colon = 0;
    end = strchr(colon + 1, ' ');
    if (end) *end = 0;
    // Settings too long for the command are refused, never cut.
    // The service, which a network started, listens on the member port
    // that the phone reaches: it stops while cbb next pair waits there, and
    // once more after it, so that the link starts it again in the group.
    if (snprintf(cmd, sizeof cmd, pair_cmd, pair_pkill, ip, serve + 7, colon + 1, pair_pkill) >= (int)sizeof cmd)
        return fail("the -serve setting is too long", net_args);
    if (link_shell()) return pi_silent();
    link_send_str(cmd);
    link_prompt();
    link_send_str("until grep -q 'CBBQ\\|CBBERR' /ram/cbbjoin; do sleep 1; done; sleep 1; cat /ram/cbbjoin\n");
    if (expect(LINE_QR, &len, &crc, ANSWER_SECONDS) != LINE_QR) return 1;
    if (qr((uint8_t)len)) return 1;
    link_prompt();
    quiet = 1;
    // The phone reaches the Pi through the network, which takes some
    // seconds to start: a scan before that would be refused, so the code
    // stays white on white until it runs, under the line that says so
    // (in ATTR_T, BASIC's colours).
    at(21, 4);
    printf(qr_wait);
    // An error shows in black.
    err = net_start(0, 0);
    memset((uint8_t *)0x5800, PAPER_WHITE | INK_BLACK, 768);
    if (err) return err;
    // Nothing else on the screen while the phone scans: the rest after a
    // key, on a clear screen in BASIC's colours.
    at(21, 4);
    printf(qr_key);
    key_clear();
    printf(qr_after);
    return 0;
}

static int net_stop(void)
{
    uint8_t b = boot_state();
    if (b && b <= BOOT_LINK) {
        driver(DRV_SWITCH, 0);
        printf(boot_none);
        return 0;
    }
    if (!net_on()) return fail("the network does not run", 0);
    driver(DRV_SWITCH, 0);
    link_quit();
    // The ESP as NextZXOS's own tools (.http) and .pibridge expect it:
    // the network's server and its connections (a computer's stays open,
    // and the ESP has only five) keep CIPMUX=1 until a restart, which
    // also puts back the stock speed.
    if (!esp_speed(ESP_SPEED)) printf("The ESP did not answer AT.\n");
    else esp_restart();
    link_use(LINK_PI);
    if (link_shell()) return fail("the network stopped, but the Pi does not answer", no_prompt);
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

// Not static: far_net_halt() and far_net_restart() (far.asm) call them,
// for the commands of CBB.OVL's page with a driver that cannot carry them.
int net_halt(void)
{
    return net_stop();
}

int net_restart(void)
{
    return net_start(0, 0);
}

static int net_show(void)
{
    uint8_t i, b;
    if (driver(DRV_STATE, 0)) {
        printf("The driver is not installed:\n.install /cbb/CBB.DRV\n");
        return 0;
    }
    i = drv.de;
    b = boot_state();
    if (!i && b && b <= BOOT_LINK) printf(boot_later);
    else printf(i ? "The network runs.\n" : "The network does not run.\n");
    if (!i && b > BOOT_LINK && b <= BOOT_NO_LINK) printf(boot_said[b - BOOT_NO_PROMPT]);
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
#pragma bssseg bss_compiler

// Not static: far_net() (far.asm) calls it.
int net_cmd(void)
{
    return net(far_argc, far_argv);
}

#pragma codeseg code_compiler
#pragma constseg rodata_compiler
#pragma dataseg data_compiler

// .cbb install: the files from cbb.tools, through the ESP (docs/roadmap.md,
// "Installing"). NextZXOS's .http has no TLS and neither has the ESP, so
// they come over plain HTTP; each is checked against the list before it
// replaces the old one, which guards against a damaged download.
// All of .cbb install, from here to install(), is an overlay: its code,
// constants and variables are in a page of its own (far.asm), which shows
// at 0xE000 only while far_install() runs it. It uses MAIN freely, which
// therefore has to end below 0xE000 (the Makefile checks).
#pragma codeseg PAGE_13
#pragma constseg PAGE_13
#pragma bssseg PAGE_13
#pragma dataseg PAGE_13

#define SITE "cbb.tools"
#define SITE_DIR "/zxnext/"
// keys.json and zxnext.json, a line each, which the Pi's cbb checks.
#define SITE_LIST "SIGNED"
// Where NextZXOS looks for dot commands first.
#define DOT_CBB "c:/dot/CBB"
// A range is asked for at a time, kept in text[], and written while the
// server waits: the ESP has no flow control, and a card write runs with
// interrupts off for longer than the UART's buffer lasts.
#define CHUNK MAX_TEXT

// The ROM's frame counter, 50 a second while interrupts run.
// The ROM's scroll count: kept high, the screen scrolls without "scroll?".
#define SCR_CT (*(volatile uint8_t *)23692)

// name: on the server; label: on the screen. size and sha256 are those of
// the files built with this CBB (pins.h, from the Makefile): whatever the
// site serves, only they are installed. The Next checks the driver's
// SHA-256 itself; the Pi's cbb, megabytes, the Pi checks.
struct item {
    const char *name, *label, *card, *part;
    uint32_t size;
    const char *sha256;
    uint8_t pi;
};

static struct item items[] = {
    {"CBB.DRV", "CBB.DRV", "/cbb/CBB.DRV", "/cbb/DRV.PRT", PIN_DRV_SIZE, PIN_DRV_SHA256, 0},
    {"CBB.OVL", "CBB", OVL_FILE, "/cbb/OVL.PRT", PIN_OVL_SIZE, PIN_OVL_SHA256, 0},
    {"cbb", "SERVICE", PI_CARD, "/cbb/CBBPI.PRT", PIN_PI_SIZE, PIN_PI_SHA256, 1},
};
#define ITEMS (sizeof items / sizeof items[0])
// This CBB, as the install's own steps put it in /cbb.
#define CBB_CARD "/cbb/CBB"

// The status of the last answer http_range() read, and what fetch() says
// when the site has no such file: trying again does not help then.
static uint16_t http_status;
static const char no_file[] = SITE " has no such file; are its files in place?";

// Asks for size bytes of name from offset on the open connection; 0 with
// the bytes in text[] when they all came.
static uint8_t http_range(const char *name, uint32_t from, uint16_t size)
{
    uint32_t length = 0;
    uint16_t i, status = 0, got = 0;
    uint8_t c, err;
    http_status = 0;
    sprintf(line, "GET " SITE_DIR "%s HTTP/1.1\r\nHost: " SITE "\r\nRange: bytes=%lu-%lu\r\n\r\n", name, from,
            from + size - 1);
    link_send_str(line);
    // The status line and the headers, up to the empty line; empty lines
    // before the status line are the ESP's.
    for (i = 0;; i++) {
        err = link_line(line, sizeof line, 10);
        if (err) goto out;
        if (!status) {
            if (!line[0]) continue;
            err = 255;
            if (strncmp(line, "HTTP/1.", 7) != 0 || strlen(line) < 12) goto out;
            status = (uint16_t)strtoul(line + 9, 0, 10);
        } else if (!line[0]) {
            // link_line stops at the empty line's CR: its LF comes before
            // the body.
            err = link_recv(&c, 10);
            if (!err && c != '\n') err = 252;
            if (err) goto out;
            break;
        } else if (strncasecmp(line, "Content-Length:", 15) == 0) {
            length = strtoul(line + 15, 0, 10);
        }
    }
    err = 254;
    http_status = status;
    if (status != 206 && !(status == 200 && from == 0)) goto out;
    err = 253;
    if (length != size) goto out;
    for (; got < size; got++) {
        err = link_recv(&c, 10);
        if (err) goto out;
        text[got] = c;
    }
    return 0;
out:
    // What went wrong, for .cbb -d.
    if (err != LINK_BREAK && err != 255)
        sprintf(line, "error %u, status %u, length %lu, %u bytes", err, status, length, got);
    return err;
}

// The connection to the site, in MAIN, where the install's page has no
// room left.
#pragma codeseg code_compiler
#pragma constseg rodata_compiler
#pragma bssseg bss_compiler
#pragma dataseg data_compiler

// Opens a passthrough connection to the site through the ESP; 0 when open.
static const char *const http_cmds[] = {"AT+CIPMODE=0", "AT+CIPCLOSE", "AT+CIPMUX=0", "AT+CIPMODE=1",
                                        "AT+CIPSTART=\"TCP\",\"" SITE "\",80", "AT+CIPSEND"};

static uint8_t http_open(void)
{
    uint8_t i, c, reset = 0;
    if (!esp_speed(ESP_FETCH_SPEED)) return 1;
again:
    for (i = 0; i < sizeof http_cmds / sizeof http_cmds[0]; i++) {
        link_send_str(http_cmds[i]);
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
            if (i == 2 && !reset && strcmp(line, "ERROR") == 0) {
                // The network's server keeps CIPMUX=1 until the ESP
                // restarts, at its stock speed.
                reset = 1;
                esp_restart();
                if (!esp_speed(ESP_FETCH_SPEED)) return 1;
                goto again;
            }
            if (strcmp(line, "ERROR") == 0 || strncmp(line, "FAIL", 4) == 0) return 1;
        }
    }
    return 0;
}

// Leaves the passthrough connection: a second of quiet, +++, a second.
static void http_close(void)
{
    esp_escape(ESP_FETCH_SPEED);
    link_send_str("AT+CIPCLOSE\r\n");
    while (link_line(line, sizeof line, 2) == LINK_OK) {
    }
    // Back to the stock speed, which the other commands expect.
    esp_speed(ESP_SPEED);
}

#pragma codeseg PAGE_13
#pragma constseg PAGE_13
#pragma bssseg PAGE_13
#pragma dataseg PAGE_13

// The install screen, on black: the logo on the left (tools/icon), the
// files and their bars on the right, the messages under them.
//
//   rows 0-17, columns 0-13   the logo
//   rows 0-2, from column 15  the name and the version
//   rows 4-13                 a file's name and state, then its bar, each
//                             in one colour, in the order they are done:
//                             the stripes' red, yellow and green, the
//                             Pi's cbb on its way in cyan, a newer CBB
//                             (.cbb update) in white
//   rows 14-15                the file under way: kilobytes, speed
//   row 16, from column 15    SPACE STOPS, at the end PRESS ANY KEY
//   rows 18-21                messages
#define PANEL 15
#define FILE_ROW 4
#define NOW_ROW 14
// SPACE STOPS, at the end PRESS ANY KEY.
#define KEY_ROW 16
#define BAR_CELLS 12

// The ROM's colour codes, for what .cbb prints meanwhile; in the divMMC
// page, as both the install screen's page and the install's use it.
#pragma codeseg code_dot
static void colour(uint8_t ink)
{
    putchar(17); // PAPER
    putchar(0);
    putchar(16); // INK
    putchar(ink);
    putchar(19); // BRIGHT
    putchar(1);
}
#pragma codeseg PAGE_13

// palette() runs from the dot command's own 8K, as MAIN has no room left.
#pragma codeseg code_dot

// The logo's own colours, in the Next's palette while the screen shows: the
// ULA's entries (ink 0-7, bright ink 8-15, paper 16-23, bright paper 24-31)
// that it uses and nothing else on the screen does, each with its 9-bit
// colour RRRGGGBB,B (tools/icon, zx.go). The old ones come back after.
#define PALETTE_COLOURS 5
#pragma constseg code_dot
#pragma bssseg code_dot
static const uint8_t palette_new[PALETTE_COLOURS][3] = {
    {2, 0x8C, 1},  // red ink: the board's brown, 4,3,1
    {6, 0xD5, 1},  // yellow ink: the clip's tan, 6,5,3
    {31, 0xDB, 0}, // bright white paper: the page, light grey 6,6,6
    {8, 0x24, 1},  // bright black ink: the page's lines, 1,1,1
    {9, 0x73, 0},  // bright blue ink: the title, steel blue 3,4,6
};
static uint8_t palette_old[PALETTE_COLOURS][2];
#pragma constseg PAGE_13
#pragma bssseg PAGE_13

// Puts the logo's colours in the ULA palette that shows (restore 0), or
// the old ones back (restore 1).
static void palette(uint8_t restore)
{
    uint8_t control = ZXN_READ_REG(0x43), i;
    // No stepping on after a write; the ULA's first or second palette,
    // whichever shows.
    ZXN_WRITE_REG(0x43, (control & 0x0F) | 0x80 | (control & 0x02 ? 0x40 : 0));
    for (i = 0; i < PALETTE_COLOURS; i++) {
        ZXN_WRITE_REG(0x40, palette_new[i][0]);
        if (!restore) {
            palette_old[i][0] = ZXN_READ_REG(0x41);
            palette_old[i][1] = ZXN_READ_REG(0x44);
        }
        ZXN_WRITE_REG(0x44, restore ? palette_old[i][0] : palette_new[i][1]);
        ZXN_WRITE_REG(0x44, restore ? palette_old[i][1] & 1 : palette_new[i][2]);
    }
    ZXN_WRITE_REG(0x43, control);
}

// The bars and the states on the install screen, in the install's page.
#pragma codeseg PAGE_13
#pragma constseg PAGE_13
#pragma bssseg PAGE_13

// Shows a file's state on its row: "current", "fetching" and so on.
static void file_state(uint8_t row, const char *name, const char *state)
{
    at(FILE_ROW + 2 * row, PANEL);
    printf("%-8s%-9s", name, state);
}

// The bars' colours, a row each, from the first fetched to the last: the
// Next's stripes, and the Pi's cbb on its way in cyan.
static const uint8_t bar_ink[4] = {INK_RED, INK_YELLOW, INK_GREEN, INK_CYAN};
// A bar for more than one file (a newer CBB with its CBB.OVL): the bytes
// before the one under way, and of all of them; 0 for a file's own bar.
static uint32_t bar_base, bar_size;
// Draws a bar in half cells at a screen row, with the percentage.
static void bar(uint8_t screen_row, uint8_t pct, uint8_t ink)
{
    uint8_t halves = (uint8_t)((uint16_t)pct * (BAR_CELLS * 2) / 100), i, c;
    at(screen_row, PANEL);
    for (i = 0; i < BAR_CELLS; i++) {
        // The ROM's block graphics: 143 full, 138 the left half.
        c = halves >= 2 * i + 2 ? 143 : halves == 2 * i + 1 ? 138 : '-';
        colour(ink);
        putchar(c);
    }
    colour(INK_WHITE);
    printf(" %3u%%", pct);
}

static uint8_t percent(uint32_t got, uint32_t size)
{
    // The files are a few megabytes: got * 100 stays in 32 bits.
    return size && got < size ? (uint8_t)(got * 100 / size) : 100;
}

// Draws a file's bar, and the numbers of the one under way.
static void progress(uint8_t row, uint32_t got, uint32_t size, uint16_t start)
{
    uint16_t secs = (uint16_t)(FRAMES_LO - start) / 50, left;
    uint32_t rate = secs ? got / secs : 0;
    char speed[8];
    // One bar for more than one file: their sum.
    if (bar_size) {
        got += bar_base;
        size = bar_size;
    }
    left = rate ? (uint16_t)((size - got) / rate) : 0;
    bar(FILE_ROW + 2 * row + 1, percent(got, size), bar_ink[row]);
    at(NOW_ROW, PANEL);
    printf("%5luK OF %5luK", got >> 10, size >> 10);
    if (rate < 10240) sprintf(speed, "%u.%uK/S", (uint16_t)(rate >> 10), (uint16_t)((rate & 1023) * 10 >> 10));
    else sprintf(speed, "%uK/S", (uint16_t)(rate >> 10));
    if (left > 5999) left = 5999;
    at(NOW_ROW + 1, PANEL);
    printf("%-7s%2u:%02u LEFT", speed, left / 60, left % 60);
}

// In CBB.OVL's page, as .cbb leave and .cbb pair use it.
#pragma codeseg PAGE_19
#pragma constseg PAGE_19
#pragma bssseg PAGE_19

// Whether the Pi is in a group: cbb next pair and -join refuse then, the
// one in the Pi's background and the other in the link's log, which the
// Next would never show.
static const char in_group_cmd[] = "test -e " PI_DIR "/cbb-state/identity.json && echo CBB$((1))IN; echo CBB$((1))END\n";
static const char in_group_yes[] = "CBB1IN", in_group_end[] = "CBB1END";
static const char in_group[] = "the Pi is in a group\nalready: .cbb leave first";
static const char in_none[] = "the Pi is in no group:\nnothing to leave";

// Not static: far_pair_check() (far.asm) calls it, with the network off:
// for .cbb leave, the Pi must be in a group, for .cbb pair in none.
// With pair_probe, after .cbb install, it says nothing, and gives 0 only
// when the Pi answers and is in no group.
int pair_check(void)
{
    uint8_t in = 0;
    if (link_shell()) return pair_probe ? 1 : pi_silent();
    link_send_str(in_group_cmd);
    while (!link_line(line, sizeof line, 5) && strcmp(line, in_group_end)) {
        if (strcmp(line, in_group_yes) == 0) in = 1;
    }
    link_prompt();
    if (pair_probe) return in;
    if (far_argv[0][0] == 'l') return in ? 0 : fail(in_none, 0);
    return in ? fail(in_group, 0) : 0;
}

#pragma codeseg PAGE_13
#pragma constseg PAGE_13
#pragma bssseg PAGE_13

// CRC-32 by a table of 16, half a byte at a time: the Pi's cbb is
// megabytes, and frame.c's bit by bit takes minutes for it, while a table
// of 256 would take a kilobyte that .cbb does not have.
static const uint32_t crc_table[16] = {
    0x00000000UL, 0x1DB71064UL, 0x3B6E20C8UL, 0x26D930ACUL, 0x76DC4190UL, 0x6B6B51F4UL, 0x4DB26158UL, 0x5005713CUL,
    0xEDB88320UL, 0xF00F9344UL, 0xD6D6A3E8UL, 0xCB61B38CUL, 0x9B64C2B0UL, 0x86D3D2D4UL, 0xA00AE278UL, 0xBDBDF21CUL,
};

static uint32_t crc_add(uint32_t crc, const uint8_t *p, uint16_t n)
{
    crc = ~crc;
    while (n--) {
        crc ^= *p++;
        crc = crc_table[(uint8_t)crc & 15] ^ (crc >> 4);
        crc = crc_table[(uint8_t)crc & 15] ^ (crc >> 4);
    }
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

// The size of a file on the card (0 without it), and with digest 1 its
// SHA-256 in sha_out. SHA-256 is in the screen's page with sha_run(),
// whose arguments these are (far.asm, far_sha()).
static uint32_t file_sha(const char *path, uint8_t digest)
{
    sha_path = path;
    sha_digest = digest;
    return far_sha();
}

// Whether the file at path is the item's: its size, and on the Next its
// SHA-256 too.
static uint8_t matches(struct item *it, const char *path)
{
    if (file_sha(path, !it->pi) != it->size) return 0;
    return it->pi || strcmp(sha_out, it->sha256) == 0;
}

// Fetches one item to its .PRT file, going on from what an earlier try
// left there, and puts it in place once it is the one built with this CBB;
// 0 when done.
static int fetch(struct item *it, uint8_t row)
{
    uint8_t fh, err, tries = 0;
    uint16_t n, start = FRAMES_LO;
    uint32_t got;
    // What an earlier try left.
    got = file_sha(it->part, 0);
    if (got > it->size) {
        esx_f_unlink(it->part);
        got = 0;
    }
    errno = 0;
    fh = esx_f_open(it->part, ESX_MODE_W | ESX_MODE_OPEN_CREAT);
    if (errno) return fail("cannot write to /cbb", it->part);
    esx_f_seek(fh, got, ESX_SEEK_SET);
    file_state(row, it->label, got ? "GOES ON" : "FETCHING");
    while (got < it->size) {
        n = it->size - got > CHUNK ? CHUNK : (uint16_t)(it->size - got);
        err = http_range(it->name, got, n);
        if (err == LINK_BREAK) {
            esx_f_close(fh);
            file_state(row, it->label, "STOPPED");
            return fail("stopped; .cbb install goes on from here", 0);
        }
        if (err == 254 && http_status >= 400 && http_status < 500) {
            esx_f_close(fh);
            file_state(row, it->label, "NOT THERE");
            return fail(no_file, line);
        }
        if (err) {
            // The server may have closed the connection: open it again.
            if (++tries > 5) {
                esx_f_close(fh);
                file_state(row, it->label, "BROKE OFF");
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
        got += n;
        progress(row, got, it->size, start);
    }
    esx_f_close(fh);
    if (!matches(it, it->part)) {
        file_state(row, it->label, "DAMAGED");
        esx_f_unlink(it->part);
        return fail("the file arrived damaged; run .cbb install again", it->name);
    }
    // A newer CBB stays by the running one until the end (cbb_swap()).
    if (!it->card) return 0;
    esx_f_unlink(it->card);
    if (esx_f_rename(it->part, it->card)) return fail("cannot put the file in place", it->card);
    file_state(row, it->label, "FETCHED");
    return 0;
}

// Whether the file on the card is the one built with this CBB.
static uint8_t up_to_date(struct item *it)
{
    return matches(it, it->card);
}

// Asks NextPi's shell for the SHA-256 of the Pi's cbb, into sha ("none"
// without one); 0 when the Pi answered.
static uint8_t pi_sha(char *sha)
{
    if (link_shell()) return 1;
    link_send_str("{ sha256sum " PI_DIR "/cbb.bin 2>/dev/null || echo none; } | cut -c1-64 | sed 's/^/CBBS /'\n");
    for (;;) {
        if (link_line(line, sizeof line, 10)) return 1;
        if (strncmp(line, "CBBS ", 5) == 0 && strlen(line) <= 69) {
            strcpy(sha, line + 5);
            link_prompt();
            return 0;
        }
    }
}

// Copies the Pi's cbb from the card to NextPi's user partition over the
// UART: the shell reads exactly its size, then checks its SHA-256 against
// the one built with this CBB before it takes the place of the old one. The
// wrapper that NextPi's shell runs is written unless there is one.
// How long head may wait for the Pi's cbb: twice the time the copy takes
// at speed (0: 115200), and a minute.
static uint32_t pi_seconds(struct item *it, uint32_t speed)
{
    return it->size / ((speed ? speed : 115200UL) / 20) + 60;
}

// The speed the Pi's cbb goes at, which the Pi's tty takes for the copy
// only: four times NextPi's usual 115200.
#define PI_FAST_SPEED 460800UL

// Waits a few frames, for the UART to send what it holds.
static void wait_frames(uint8_t n)
{
    uint16_t frame;
    while (n--) {
        frame = FRAMES_LO;
        while (FRAMES_LO == frame) {
        }
    }
}

// The row of the Pi's cbb on its way to the Pi, under the files.
#define SEND_ROW ITEMS
#define SEND_LABEL "TO PI"

// Sends the Pi's cbb from the card to PI_DIR/cbb.new: at speed, which the
// Pi's tty takes for the copy and leaves after, or with speed 0 at the
// line's own. 0 when sent, 2 when the Pi did not say it was ready (its
// tty may not take the speed), else 1 with the message shown.
static int pi_send(struct item *it, uint8_t row, uint32_t speed)
{
    uint8_t fh, err;
    uint16_t n, start = FRAMES_LO;
    uint32_t sent = 0;
    errno = 0;
    fh = esx_f_open(it->card, ESX_MODE_R | ESX_MODE_OPEN_EXIST);
    if (errno) return fail("the Pi's cbb is not on the card", it->card);
    // Raw: every byte as it is, none taken as a key or echoed; head gives
    // up after twice the time the copy takes, and the tty gets its speed
    // back after either. The second's sleep lets the Next, which takes
    // the speed once the command has left, hear CBBGO at the new one; the
    // CR first ends the line the rest of the echo left, which the Next
    // hears garbled at that speed.
    sprintf(line,
            "s=$(stty -g); stty %lu raw -echo -iexten && sleep 1 && printf '\\r\\nCBBGO\\r\\n' && timeout %lu head -c %lu >" PI_DIR
            "/cbb.new; stty $s\n",
            speed ? speed : 115200UL, pi_seconds(it, speed), it->size);
    link_send_str(line);
    if (speed) {
        wait_frames(2);
        link_speed(speed);
    }
    for (;;) {
        err = link_line(line, sizeof line, 5);
        if (err) {
            esx_f_close(fh);
            link_open();
            if (err == LINK_BREAK) return fail("stopped; .cbb install goes on from here", 0);
            return 2;
        }
        if (strcmp(line, "CBBGO") == 0) break;
    }
    while ((n = esx_f_read(fh, text, CHUNK)) > 0) {
        uint16_t i;
        for (i = 0; i < n; i++) link_send(text[i]);
        sent += n;
        progress(row, sent, it->size, start);
    }
    esx_f_close(fh);
    wait_frames(2);
    link_open();
    link_prompt();
    return 0;
}

// Whether the Pi got the cbb built with this CBB: 0 yes, 3 another file,
// else 1 with the message shown.
static int pi_check(struct item *it)
{
    // The digest is pins.h's, 64 hex digits, never the site's.
    link_send_str("cd " PI_DIR " && if ! command -v sha256sum >/dev/null; then rm -f cbb.new; echo CBBNOSHA; "
                  "elif [ \"$(sha256sum <cbb.new | cut -c1-64)\" = '");
    link_send_str(it->sha256);
    link_send_str("' ]; then chmod 755 cbb.new && mv -f cbb.new cbb.bin && echo CBBOK; else rm -f cbb.new; "
                  "echo CBBERR; fi\n");
    for (;;) {
        if (link_line(line, sizeof line, 60)) return fail("the Pi did not answer", "no CBBOK");
        if (strcmp(line, "CBBNOSHA") == 0) return fail("the Pi has no sha256sum to check its cbb with", 0);
        if (strcmp(line, "CBBERR") == 0) return 3;
        if (strcmp(line, "CBBOK") == 0) return 0;
    }
}

// The Pi's cbb to the Pi: fast, else at the line's speed, when the Pi's
// tty does not take the speed or the copy came damaged.
static int to_pi(struct item *it, uint8_t row)
{
    uint8_t err;
    uint16_t start;
    if (link_shell()) return pi_silent();
    err = pi_send(it, row, PI_FAST_SPEED);
    if (err == 2) {
        // A tty that took the speed but lost CBBGO keeps head waiting,
        // until its timeout at the most.
        file_state(row, SEND_LABEL, "SLOWER");
        start = FRAMES_LO;
        while (link_shell()) {
            if (link_stopped || (uint16_t)(FRAMES_LO - start) / 50 > pi_seconds(it, PI_FAST_SPEED) + 10)
                return fail("the Pi did not get ready", "no CBBGO");
        }
    } else if (!err) {
        err = pi_check(it);
        if (err == 3) {
            link_prompt();
            file_state(row, SEND_LABEL, "SLOWER");
            err = 2;
        }
    }
    if (err == 2) {
        err = pi_send(it, row, 0);
        if (err == 2) return fail("the Pi did not get ready", "no CBBGO");
        if (!err) err = pi_check(it);
    }
    if (err == 3) {
        // The card's copy is not the one built with this CBB.
        esx_f_unlink(it->card);
        return fail("the Pi got another file than this CBB's; run .cbb install again", 0);
    }
    if (err) return 1;
    link_prompt();
    // A service of the old cbb, which .cbb net on or a hand started, stops,
    // so that the next .cbb net on starts the new one.
    link_send_str(PKILL_SERVICE "\n");
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
// through the card to the Pi; each only when the one in place is not the
// one built with this CBB. The rows of the screen, each in its stripe's
// colour: fetching CBB.DRV and the Pi's cbb (ITEM_ROW; the user fetched
// this CBB before), then sending the Pi's cbb to the Pi (SEND_ROW).
#define ITEM_ROW(i) (i)


// A newer CBB, fetched next to the running one: dot or /cbb, CBB.NEW.
static struct item cbb_new = {"CBB", "CBB", 0, 0, 0, 0, 0};
// It shares CBB.OVL's row, as the CBB part of the install.
#define CBB_ROW ITEM_ROW(1)

static int install_files(uint8_t update)
{
    static char pisha[65];
    struct item *pi = &items[ITEMS - 1];
    uint8_t i, pi_answers, dot = 0, newer = 0, nothing, drv_new = 0, drv_on, old_bank = NO_BANK, need[ITEMS] = {0};
    uint32_t size, crc;
    int err = 0;
    // The bank of a driver installed now, while the card has its file.
    drv_on = driver(DRV_STATE, 0) == 0;
    if (drv_on) old_bank = drv_bank();
    esx_f_mkdir("/cbb");
    // Every bar shows from the start in its colour, empty.
    for (i = 0; i < ITEMS; i++) {
        file_state(ITEM_ROW(i), items[i].label, "");
        bar(FILE_ROW + 2 * ITEM_ROW(i) + 1, 0, bar_ink[ITEM_ROW(i)]);
    }
    file_state(SEND_ROW, SEND_LABEL, "");
    bar(FILE_ROW + 2 * SEND_ROW + 1, 0, bar_ink[SEND_ROW]);
    pi_answers = !pi_sha(pisha);
    link_stopped = 0;
    // .cbb update first fetches the site's signed list, which the Pi's cbb
    // checks (read_list()), then opens the site again for the files.
    if (update && !pi_answers) return pi_silent();
    for (list_checked = !update;;) {
        if (http_open()) {
            http_close();
            link_use(LINK_PI);
            if (link_stopped) return fail("stopped; .cbb install goes on from here", 0);
            return fail("cannot reach " SITE "; is the ESP on Wi-Fi?", line);
        }
        if (list_checked) break;
        err = far_read_list();
        http_close();
        link_use(LINK_PI);
        list_checked = 1;
        if (err || (link_shell() && pi_silent()) || far_read_list()) return 1;
    }
    // .cbb update first looks for a newer CBB in the list: then it
    // installs the files the list names, as built with that one, and
    // last puts it in place of this one (cbb_swap()). This one is the
    // one in C:/DOT, where .cbb runs it from anywhere, else the one in
    // /cbb that an earlier install had run as ../CBB.
    if (update) {
        crc = file_crc(DOT_CBB, &size);
        dot = size != 0;
        if (!dot) crc = file_crc(CBB_CARD, &size);
        if (size != list_size || crc != list_crc) {
            newer = 1;
            for (i = 0; i < LISTED; i++)
                if (!list_isize[i]) err = fail("the list lacks a file", "for the new CBB");
            for (i = 0; i < ITEMS; i++) {
                items[i].size = list_isize[i];
                items[i].sha256 = list_isha[i];
            }
            cbb_new.part = dot ? DOT_CBB ".NEW" : CBB_CARD ".NEW";
            cbb_new.size = list_isize[LISTED - 1];
            cbb_new.sha256 = list_isha[LISTED - 1];
        }
    }
    // What is to do: the files to fetch, then the Pi's cbb to send.
    for (i = 0; i < ITEMS && !err; i++) {
        struct item *it = &items[i];
        const char *state = "CURRENT";
        if (it == pi) {
            if (!pi_answers) state = "NO PI";
            else if (strcmp(pisha, it->sha256) == 0) state = "CURRENT";
            // On the card from a try that stopped later.
            else if (up_to_date(it)) state = "FETCHED";
            else state = 0;
        } else if (!up_to_date(it)) {
            state = 0;
        }
        if (state) {
            file_state(ITEM_ROW(i), it->label, state);
            if (it != pi || pi_answers) bar(FILE_ROW + 2 * ITEM_ROW(i) + 1, 100, bar_ink[ITEM_ROW(i)]);
            // The Pi has it, or no Pi to send it to.
            if (it == pi && (!pi_answers || !strcmp(pisha, it->sha256))) {
                file_state(SEND_ROW, SEND_LABEL, state);
                if (pi_answers) bar(FILE_ROW + 2 * SEND_ROW + 1, 100, bar_ink[SEND_ROW]);
            }
        } else {
            need[i] = 1;
        }
    }
    // Nothing to fetch, nothing to send: .cbb update says so.
    nothing = !newer;
    if (pi_answers && strcmp(pisha, pi->sha256)) nothing = 0;
    for (i = 0; i < ITEMS; i++)
        if (need[i]) nothing = 0;
    for (i = 0; i < ITEMS && !err; i++) {
        // A newer CBB first, on one bar with its CBB.OVL.
        if (i == 1 && newer) {
            bar_size = cbb_new.size + (need[1] ? items[1].size : 0);
            if (!matches(&cbb_new, cbb_new.part)) err = fetch(&cbb_new, CBB_ROW);
            bar_base = cbb_new.size;
        }
        if (need[i] && !err) err = fetch(&items[i], ITEM_ROW(i));
        bar_size = 0;
        // CBB.DRV, which runs from memory once installed.
        if (i == 0 && need[i]) drv_new = 1;
    }
    http_close();
    link_use(LINK_PI);
    if (err) return 1;
    if (!pi_answers) {
        say("The Pi does not answer: its cbb comes with .cbb update later.");
    } else if (strcmp(pisha, pi->sha256) != 0) {
        file_state(SEND_ROW, SEND_LABEL, "SENDING");
        if (to_pi(pi, SEND_ROW)) return 1;
        // The card keeps no copy of the Pi's program.
        esx_f_unlink(pi->card);
        file_state(SEND_ROW, SEND_LABEL, "DONE");
    }
    // A driver installed earlier runs from memory: a new one takes its
    // place, with its bank. Without one, the driver is installed now (and
    // .cbb net on does it after a reset).
    if (drv_on && drv_new) {
        if (old_bank == NO_BANK || drv_uninstall(old_bank)) {
            say("CBB.DRV is new: .uninstall /cbb/CBB.DRV, then .install /cbb/CBB.DRV");
        } else {
            drv_on = 0;
        }
    }
    if (!drv_on) {
        i = drv_install();
        if (i) {
            sprintf(line, "step %u", i);
            fail("cannot install CBB.DRV; try .install /cbb/CBB.DRV", line);
        } else {
            say("CBB.DRV is installed.");
        }
    }
    if (newer) {
        swap_dot = dot;
        far_cbb_swap();
    }
    // Two different CBBs: .cbb runs the one in C:/DOT, ../CBB in /cbb the
    // other.
    crc = file_crc(CBB_CARD, &list_size);
    if ((file_crc(DOT_CBB, &size) != crc || size != list_size) && size && list_size) {
        say("C:/DOT/CBB and /cbb/CBB differ: .cbb runs the one in C:/DOT. Delete the other.");
    }
    end_pi = pi_answers;
    end_word = 0;
    if (newer) end_word = 2;
    if (update && nothing) end_word = 1;
    return far_install_end();
}

// Not static: far_install() (far.asm) calls it, with install_update set.
int install_run(void)
{
    return install_files(install_update);
}

// The install screen, opened and closed around the install's own page,
// is in the logo's page (far.asm, far_screen_open(), far_screen_close()).
#pragma codeseg PAGE_15

#pragma constseg PAGE_15

// The usage: each line after the first two a command's, but for a tab,
// which stands for the column of the commands' words.
// Not static: far_usage() (far.asm) calls it.
void usage_run(void)
{
    const char *p;
    uint8_t col = 0;
    // 19 lines fit the 22 of the upper screen; no "scroll?" all the same.
    SCR_CT = 255;
    for (p = usage_text; *p; p++) {
        if (*p == '\t') {
            for (; col < 14; col++) putchar(' ');
            continue;
        }
        col = *p == '\n' ? 0 : col + 1;
        putchar(*p);
    }
}

// .cbb uninstall, leave and paste-receive are in CBB.OVL's page.
#pragma codeseg PAGE_19
#pragma bssseg PAGE_19
// .cbb uninstall: everything .cbb install and .cbb net put anywhere, after
// a Y: the network and the driver, the Pi's cbb and its state, the files
// in /cbb and the folder when nothing else is left in it. The phone app
// still lists the Next until it is removed there.
// Its words are arrays of this page: zcc keeps string literals with the
// main program's.
#pragma constseg PAGE_19
static const char un_pi_cmd[] = "pkill -f '" PI_DIR "/cbb'; cd " PI_DIR " && rm -rf cbb cbb.bin cbb.old cbb.new "
                                "cbb-state /ram/link.log /ram/cbbjoin; cd; echo CBB$((1))GONE\n";
// The service stops first, so that cbb leave changes the files itself.
static const char lv_pi_cmd[] = "pkill -f '" PI_DIR "/cbb'; " CBB_LITE " leave -yes; rm -rf /ram/cbbjoin; echo CBB$((1))GONE\n";
static const char card_names[] = "CBB.DRV\0CBB.OVL\0OVL.PRT\0NET.CFG\0CBBPI.BIN\0DRV.PRT\0CBBPI.PRT\0PASTE.CFG\0CBB\0";
static const char un_ask[] = "Remove CBB: the network, the\ndriver, the Pi's cbb and its\ngroup, the files in /cbb? y/n\n";
static const char un_none[] = "Nothing removed.\n";
static const char un_drv_stays[] = "CBB.DRV stays: .uninstall it.\n";
static const char un_drv_gone[] = "CBB.DRV is uninstalled.\n";
static const char un_pi_silent[] = "The Pi did not answer: its cbb\nstays in " PI_DIR ".\n";
// .cbb leave: only the Pi's group, after a Y; its cbb stays, and
// .cbb pair joins this group or another one again.
static const char lv_ask[] = "Leave the group: the Pi forgets\nits keys? y/n\n";
static const char lv_done[] = "Left. Remove the Next in the app\ntoo; .cbb pair joins again.\n";
static const char un_pi_gone[] = "CBB1GONE";
static const char un_pi_quiet[] = "The Pi did not say it is done.\n";
static const char un_pi_done[] = "The Pi's cbb is removed.\n";
static const char un_dir[] = "/cbb/";
// /cbb/CBB, when it runs now, stays, as NextZXOS keeps it, with the
// folder; C:/DOT/CBB is the user's, who fetched it there.
static const char un_card[] = "Removed but CBB, which runs:\nCD \"/\": ERASE \"/cbb/CBB\"\n";
static const char un_dot[] = "Removed. C:/DOT/CBB stays: you\nfetched it, so erase it yourself:\nERASE \"C:/DOT/CBB\"\n";
static const char un_done[] = "Remove the Next in the app too.\n";

// Not static: far_uninstall() (far.asm) calls it.
// .cbb paste-receive on [-enter] | off: whether the group's admins may
// type on the Next. It is off until the Next's own user turns it on here;
// they turn it off here, or an admin in the app. The next .cbb net on
// hands it to the Pi once.
static const char pr_off[] = "off", pr_on[] = "on", pr_enter[] = "-enter", pr_on_enter[] = "on-enter";
static const char pr_said[] = "Remote paste %s from the next\n.cbb net on%s\n";
static const char pr_runs[] = " (net off first)";

// Not static: far_paste_receive() (far.asm) calls it.
int paste_receive(void)
{
    int argc = far_argc;
    char **argv = far_argv;
    if (argc == 1 && strcmp(argv[0], pr_off) == 0) strcpy(paste_set, pr_off);
    else if (argc == 1 && strcmp(argv[0], pr_on) == 0) strcpy(paste_set, pr_on);
    else if (argc == 2 && strcmp(argv[0], pr_on) == 0 && strcmp(argv[1], pr_enter) == 0) strcpy(paste_set, pr_on_enter);
    else {
        usage();
        return 1;
    }
    if (paste_save()) return 1;
    printf(pr_said, paste_set[1] == 'n' ? pr_on : pr_off, net_on() ? pr_runs : pr_off + 3);
    return 0;
}

// Not static: far_uninstall() (far.asm) calls it, for leave too.
// The network stops, for the Pi's shell.
static void un_net(void)
{
    if (net_on()) {
        driver(DRV_SWITCH, 0);
        link_quit();
        esp_speed(ESP_SPEED);
        link_use(LINK_PI);
    }
}

int uninstall(void)
{
    uint8_t i, leave = far_argv[0][0] == 'l';
    const char *p;
    // Leaving needs a group to leave, which the Pi's shell tells.
    if (leave) {
        un_net();
        if (far_pair_check()) return 1;
    }
    printf(leave ? lv_ask : un_ask);
    // Y is in the half-row of P to Y, port 0xDFFE, bit 4.
    in_wait_nokey();
    in_wait_key();
    i = z80_inp(0xDFFE) & 0x10;
    // A shift first (CAPS SHIFT 0xFEFE bit 0, SYMBOL SHIFT 0x7FFE bit 1)
    // waits for the Y with it: y and Y both answer yes.
    while (i && (!(z80_inp(0xFEFE) & 1) || !(z80_inp(0x7FFE) & 2))) i = z80_inp(0xDFFE) & 0x10;
    in_wait_nokey();
    if (i) {
        printf(un_none);
        return 0;
    }
    un_net();
    if (!leave && driver(DRV_STATE, 0) == 0) printf(drv_uninstall(drv_bank()) ? un_drv_stays : un_drv_gone);
    if (link_shell()) {
        printf(un_pi_silent);
        if (leave) return 1;
    } else {
        link_send_str(leave ? lv_pi_cmd : un_pi_cmd);
        for (;;) {
            if (link_line(line, sizeof line, 30)) {
                printf(un_pi_quiet);
                break;
            }
            if (strcmp(line, un_pi_gone) == 0) {
                printf(un_pi_done);
                break;
            }
        }
        link_prompt();
    }
    if (leave) {
        printf(lv_done);
        return 0;
    }
    strcpy(line, un_dir);
    for (p = card_names; *p; p += strlen(p) + 1) {
        strcpy(line + 5, p);
        esx_f_unlink(line);
    }
    line[4] = 0;
    esx_f_rmdir(line);
    ax_out = 1;
    autoexec();
    if (card_has(CBB_CARD)) printf(un_card);
    else if (card_has(DOT_CBB)) printf(un_dot);
    printf(un_done);
    return 0;
}

// NextZXOS runs C:/NEXTZXOS/AUTOEXEC.BAS at power-on: .cbb install puts
// .cbb net on in it as its last line, after the user's own, which may
// want the machine first, and .cbb uninstall takes it out. The file is a
// +3DOS one: a 128-byte header (PLUS3DOS, the file's length at 11, the
// program's with its variables at 16, its LINE at 18, where the variables
// start at 20, the checksum of the 127 bytes before at 127), then the
// lines, each its number (big-endian), its length, its text and 13, then
// the variables.
static const char ax_file[] = "c:/nextzxos/AUTOEXEC.BAS", ax_temp[] = "c:/nextzxos/AUTOEXEC.CBB";
#define AX_FILE ax_file
#define AX_TEMP ax_temp
#define AX_HEAD 128
static const char ax_cmd[] = ".cbb net on\r";
static const char ax_magic[] = "PLUS3DOS\x1A\x01";
static const char ax_cannot[] = "cannot write";
static const char ax_own[] = "Add .cbb net on to C:/NEXTZXOS/AUTOEXEC.BAS for the network at power-on.";
static const char ax_gone[] = ".cbb net on is out of C:/NEXTZXOS/AUTOEXEC.BAS.\n";

static uint16_t ax_word(uint16_t at)
{
    return text[at] | (uint16_t)text[at + 1] << 8;
}

static void ax_set(uint16_t at, uint16_t v)
{
    text[at] = (uint8_t)v;
    text[at + 1] = v >> 8;
}

// Writes the file of n bytes in text[], with the program's length d bytes
// longer (or shorter), and its checksum; 0 when written.
static int ax_write(uint16_t n, int d)
{
    uint8_t fh, sum = 0, i;
    ax_set(11, n);
    ax_set(13, 0);
    ax_set(16, ax_word(16) + d);
    ax_set(20, ax_word(20) + d);
    for (i = 0; i < 127; i++) sum += text[i];
    text[127] = sum;
    errno = 0;
    fh = esx_f_open(AX_TEMP, ESX_MODE_W | ESX_MODE_OPEN_CREAT_TRUNC);
    if (errno) return 1;
    i = esx_f_write(fh, text, n) != n;
    esx_f_close(fh);
    esx_f_unlink(AX_FILE);
    return i || esx_f_rename(AX_TEMP, AX_FILE);
}

// Not static: far_autoexec() (far.asm) calls it, and uninstall().
int autoexec(void)
{
    uint8_t fh;
    uint16_t n, at, end, len, last = 0, k = sizeof ax_cmd - 1;
    errno = 0;
    fh = esx_f_open(AX_FILE, ESX_MODE_R | ESX_MODE_OPEN_EXIST);
    if (errno) {
        if (ax_out) return 0;
        // None yet: one of our own, LINE 10.
        memset(text, 0, AX_HEAD);
        memcpy(text, ax_magic, 10);
        ax_set(18, 10);
        n = AX_HEAD;
        last = 0;
    } else {
        n = esx_f_read(fh, text, sizeof text);
        esx_f_close(fh);
        if (n < AX_HEAD || n == sizeof text || memcmp(text, ax_magic, 8) || text[15] != 0) {
            if (!ax_out) say(ax_own);
            return 0;
        }
    }
    // The lines end where the variables start.
    end = AX_HEAD + ax_word(20);
    if (end > n) end = n;
    for (at = AX_HEAD; at + 4 <= end; at += len) {
        len = ax_word(at + 2) + 4;
        last = (uint16_t)text[at] << 8 | text[at + 1];
        if (len == k + 4 && memcmp(text + at + 4, ax_cmd, k) == 0) {
            if (!ax_out) return 0;
            memmove(text + at, text + at + len, n - at - len);
            n -= len;
            // Ours alone: the file goes.
            if (n == AX_HEAD) esx_f_unlink(AX_FILE);
            else if (ax_write(n, -(int)len)) return fail(ax_cannot, AX_FILE);
            printf(ax_gone);
            return 0;
        }
    }
    if (ax_out) return 0;
    if (last > 9989 || n + k + 4 >= sizeof text) {
        say(ax_own);
        return 0;
    }
    last += 10;
    memmove(text + end + k + 4, text + end, n - end);
    text[end] = last >> 8;
    text[end + 1] = (uint8_t)last;
    ax_set(end + 2, k);
    memcpy(text + end + 4, ax_cmd, k);
    if (ax_write(n + k + 4, k + 4)) return fail(ax_cannot, AX_FILE);
    return 0;
}

#pragma codeseg PAGE_15
#pragma constseg PAGE_15
// Fetches the site's signed list into text[] (list_checked 0), for the
// Pi's cbb to check (below); then (list_checked 1) reads the lines it
// wrote, NAME SIZE CRC32 SHA256 for each file, for the size and CRC-32 of
// the newest CBB and the size and SHA-256 of each file: a newer CBB's files
// are not those built with this one, so .cbb update takes them as the
// release key signed them. Not static:
// far_read_list() (far.asm) calls it, from the install's page; it is in
// the screen's, which has the room.
// Puts the newer CBB, fetched as CBB.NEW, in place of the running one,
// which NextZXOS keeps open (the API's "Large dot commands"): closed, it
// can be erased, and the code in memory runs on. Else says how to, after
// the command. Not static: far_cbb_swap() (far.asm) calls it, from the
// install's page.
int cbb_swap(void)
{
    const char *cur = swap_dot ? DOT_CBB : CBB_CARD;
    sprintf(line, "%s.NEW", cur);
    esx_f_close(esx_m_gethandle());
    if (!esx_f_unlink(cur) && !esx_f_rename(line, cur)) return 0;
    cur = swap_dot ? "C:/DOT/CBB" : "/cbb/CBB";
    sprintf(line, "The new CBB is %s.NEW; after this, ERASE \"%s\": RENAME \"%s.NEW\" TO \"%s\"", cur, cur, cur, cur);
    say(line);
    return 1;
}

// Two lines, so that the messages above stay on the screen.
static const char paste_is_on[] = "Remote paste on. Off: the app or .cbb paste-receive off";
static const char paste_is_off[] = "Remote paste off; on: .cbb paste-receive on";
static const char *const end_words[] = {"Done.", "No updates: everything is current.",
                                        "Done: CBB and its files are new. Start the network: .cbb net on, or restart the Next."};

// The install's end, after its files: what the user set for remote paste
// that the network has not taken yet; then what was done.
// Not static: far_install_end() (far.asm) calls it, from the install's
// page.
int install_end(void)
{
    // Without the Pi, its message keeps the room. Without a setting the
    // Pi keeps its own: off after a first install.
    if (end_pi && paste_load()) say(paste_set[1] == 'n' ? paste_is_on : paste_is_off);
    say(end_words[end_word]);
    return 0;
}

static const char *const listed[LISTED] = {"CBB.DRV", "CBB.OVL", "cbb", "CBB"};
// The words for the Pi, here rather than among MAIN's strings.
static const char list_go[] = "s=$(stty -g); stty raw -echo -iexten && printf '\\r\\nCBBGO\\r\\n' && timeout 60 head -c %lu >" PI_DIR
                              "/cbb.list; stty $s\n";
// An older cbb without check-list says neither CBBOK nor CBBERR.
static const char list_check[] = PI_DIR "/cbb next check-list " PI_DIR "/cbb.list || echo CBBERR; rm -f " PI_DIR "/cbb.list\n";
static const char list_line[] = "CBBL %15s %lu %11s %71s";
static const char list_refused[] = "the Pi's cbb refused the site's list";
int read_list(void)
{
    char name[16], sha[72], crc[12];
    uint32_t size;
    uint8_t i, err;
    uint16_t len;
    if (list_checked) goto check;
    // The list is short: one range of up to CHUNK bytes, then cut to size.
    link_send_str("GET " SITE_DIR SITE_LIST " HTTP/1.1\r\nHost: " SITE "\r\n\r\n");
    len = 0;
    for (i = 0;; i++) {
        err = link_line(line, sizeof line, 10);
        if (err) return fail("the site did not answer", "no list");
        if (i == 0 && strncmp(line, "HTTP/1.1 200", 12) != 0) return fail("the site has no files for the Next yet", line);
        if (!line[0]) {
            // The empty line's LF, before the body.
            if (link_recv((uint8_t *)line, 10) || line[0] != '\n') return fail("the list is damaged", "no LF");
            break;
        }
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
    return 0;
check:
    // To the Pi's shell as it is, raw, as pi_send() sends the Pi's cbb.
    sprintf(line, list_go, (uint32_t)strlen((char *)text));
    link_send_str(line);
    do {
        if (link_line(line, sizeof line, 5)) return fail("the Pi did not get ready", "no CBBGO");
    } while (strcmp(line, "CBBGO"));
    for (len = 0; text[len]; len++) link_send(text[len]);
    link_prompt();
    link_send_str(list_check);
    list_size = 0;
    for (;;) {
        if (link_line(line, sizeof line, 30)) return fail("the Pi did not answer", "no CBBOK");
        if (strncmp(line, "CBBERR", 6) == 0) return fail(list_refused, line);
        if (strcmp(line, "CBBOK") == 0) break;
        if (sscanf(line, list_line, name, &size, crc, sha) != 4) continue;
        if (strcmp(name, "CBB") == 0 && strlen(crc) == 8) {
            list_size = size;
            list_crc = strtoul(crc, 0, 16);
        }
        for (i = 0; i < LISTED; i++) {
            if (strcmp(name, listed[i]) == 0 && strlen(sha) == 64) {
                list_isize[i] = size;
                strcpy(list_isha[i], sha);
            }
        }
    }
    link_prompt();
    if (!list_size) return fail("the list lacks a file", "CBB");
    return 0;
}

#pragma bssseg PAGE_15
#pragma dataseg PAGE_15

// The SHA-256 of a file, for file_sha() in the install's page: not
// static, as far_sha() (far.asm) calls it.
static struct sha256 sha_state;
static uint8_t sha_bytes[32];

uint32_t sha_run(void)
{
    uint8_t fh, i;
    uint16_t n;
    uint32_t size = 0;
    sha256_init(&sha_state);
    errno = 0;
    fh = esx_f_open(sha_path, ESX_MODE_R | ESX_MODE_OPEN_EXIST);
    if (errno) return 0;
    while ((n = esx_f_read(fh, text, CHUNK)) > 0) {
        if (sha_digest) sha256_add(&sha_state, text, n);
        size += n;
    }
    esx_f_close(fh);
    // In lowercase hex, as sha256sum prints it.
    sha256_end(&sha_state, sha_bytes);
    for (i = 0; i < 32; i++) sprintf(sha_out + 2 * i, "%02x", sha_bytes[i]);
    return size;
}

// Unpacks the logo (PackBits, tools/icon) into text[].
static void logo_unpack(void)
{
    const uint8_t *p = logo_packed;
    uint8_t *out = text, n, k;
    while (out < text + LOGO_BYTES) {
        n = *p++;
        if (n < 128) {
            for (k = 0; k <= n; k++) *out++ = *p++;
        } else {
            memset(out, *p++, 257 - n);
            out += 257 - n;
        }
    }
}

// Draws the logo as a screen loads from tape: the pixel rows in the
// screen's own order (each third, the first row of every cell, then the
// second, ...), in black on white with the border striped, then the
// colours at once.
static void logo_draw(void)
{
    uint8_t third, line, cell, x, y, border = INK_BLUE;
    uint16_t frame;
    for (third = 0; third < 3; third++) {
        for (line = 0; line < 8; line++) {
            for (cell = 0; cell < 8; cell++) {
                y = third * 64 + cell * 8 + line;
                if (y >= LOGO_ROWS * 8) continue;
                for (x = 0; x < LOGO_COLS; x++) *zx_pxy2saddr(x * 8, y) = text[y * LOGO_COLS + x];
            }
            // A frame for each row of cells' line, with stripes.
            frame = FRAMES_LO;
            while (FRAMES_LO == frame) {
                border ^= INK_BLUE ^ INK_YELLOW;
                zx_border(border);
                for (x = 0; x < 40; x++) {
                }
            }
        }
    }
    for (y = 0; y < LOGO_ROWS; y++)
        for (x = 0; x < LOGO_COLS; x++) *zx_cxy2aaddr(x, y) = text[LOGO_ROWS * 8 * LOGO_COLS + y * LOGO_COLS + x];
    zx_border(INK_BLACK);
}

// The border's colour before the screen, which the ROM keeps in BORDCR.

// Not static: far_screen_open() (far.asm) calls it.
void screen_open(void)
{
    zx_border(INK_BLACK);
    palette(0);
    zx_cls(PAPER_BLACK | INK_WHITE | BRIGHT);
    logo_unpack();
    logo_draw();
    screen_row = MESSAGE_ROW;
    // No "scroll?", should anything scroll still.
    SCR_CT = 255;
    // The name centred over the bars, 17 columns.
    colour(INK_BLUE);
    at(0, PANEL + 3);
    printf("COPY BEYOND");
    at(1, PANEL + 5);
    printf("BORDERS");
    colour(INK_WHITE);
    at(2, PANEL);
    put_text(VERSION ", " SITE);
    at(KEY_ROW, PANEL);
    printf("SPACE STOPS");
}

// Not static, as screen_open: far_screen_close() calls it. Leaves the
// screen once a key is pressed: until then it keeps its own
// colours and the messages; then the border and the palette as they were,
// on a clear screen in BASIC's colours (ATTR_P), where the logo would
// show in the wrong ones.
void screen_close(void)
{
    at(KEY_ROW, PANEL);
    printf(qr_key + 11);
    key_clear();
    palette(1);
    screen_row = 0;
}

#pragma codeseg code_compiler
#pragma constseg rodata_compiler
#pragma bssseg bss_compiler
#pragma dataseg data_compiler

// The overlays' entry points, each run in its page (far.asm).
extern int far_install(void);
extern int far_net(void);
extern int far_net_pair(void);
extern int far_boot_busy(void);
extern int far_cmd(void);
extern void far_screen_open(void);
extern void far_screen_close(void);
extern int far_uninstall(void);
extern int far_paste_receive(void);

// .cbb install and .cbb update: the screen in its page, the install in its.
// .cbb net on or off, from here: the network's code is in its page.
static char net_on_word[] = "on", net_off_word[] = "off";
static char *net_word[1];

static int net_do(char *word)
{
    net_word[0] = word;
    far_argc = 1;
    far_argv = net_word;
    return far_net();
}

// The network stops for the install, which needs the ESP and the Pi's
// shell, and runs after it: after an install always, after an update when
// it ran before.
static int install(void)
{
    int err;
    uint8_t was = net_on();
    if (was && net_do(net_off_word)) return 1;
    far_screen_open();
    err = far_install();
    // The network at power-on, through AUTOEXEC.BAS; a newer CBB that
    // update put in place has its own CBB.OVL, which this one cannot run.
    if (!err && end_word != 2) {
        ax_out = 0;
        far_autoexec();
    }
    far_screen_close();
    // After the first install, a Pi in no group joins one at once: the
    // pairing's QR code, under which the network starts.
    if (!err && !install_update) {
        pair_probe = 1;
        if (!far_pair_check()) {
            pair_probe = 0;
            return far_net_pair();
        }
        pair_probe = 0;
    }
    if ((was && end_word != 2) || (!err && !install_update)) err |= net_do(net_on_word);
    return err;
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
    // copy -s and text -s send a secret.
    if ((strcmp(argv[i], "copy") == 0 || strcmp(argv[i], "text") == 0) && i + 1 < argc && strcmp(argv[i + 1], "-s") == 0) {
        secret = 1;
        argv[i + 1] = argv[i];
        i++;
    }
    far_argc = argc - i;
    far_argv = argv + i;
    if (far_boot_busy()) return 1;
    if ((strcmp(argv[i], "paste") == 0 && argc - i <= 2) || (strcmp(argv[i], "copy") == 0 && argc - i == 2) ||
        (strcmp(argv[i], "text") == 0 && argc - i >= 2)) {
        return far_cmd();
    }
    // NextPi has no network but the ESP's.
    if (strcmp(argv[i], "pair") == 0 && argc - i <= 2) {
        if (argc - i == 2) pair_code = argv[i + 1];
        return far_net_pair();
    }
    if (strcmp(argv[i], "net") == 0) {
        far_argc = argc - i - 1;
        far_argv = argv + i + 1;
        return far_net();
    }
    if (strcmp(argv[i], "paste-receive") == 0) {
        far_argc = argc - i - 1;
        far_argv = argv + i + 1;
        return far_paste_receive();
    }
    if ((strcmp(argv[i], "uninstall") == 0 || strcmp(argv[i], "leave") == 0) && argc - i == 1) return far_uninstall();
    if ((strcmp(argv[i], "install") == 0 || strcmp(argv[i], "update") == 0) && argc - i == 1) {
        install_update = argv[i][0] == 'u';
        return install();
    }
    usage();
    return 1;
}

// The stack's high-water mark (stack.asm).
extern void stack_mark(void);
extern uint16_t stack_unused(void);

int main(int argc, char **argv)
{
    // BASIC may run at 3.5 MHz: there a byte at 115200 baud leaves too few
    // cycles to read it, the UART's 512 bytes overflow, and link.c's
    // timeouts, counted at 28 MHz, last eight times as long.
    uint8_t speed = ZXN_READ_REG(0x07) & 3;
    ZXN_WRITE_REG(0x07, 3);
    stack_mark();
    // Each command shows its own message; a nonzero result would make
    // NextZXOS add an unrelated error of its own.
    run(argc, argv);
    ZXN_WRITE_REG(0x07, speed);
    if (debug) printf("stack: %u bytes never used\n", stack_unused());
    return 0;
}
