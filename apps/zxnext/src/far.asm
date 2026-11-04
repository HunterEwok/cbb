; SPDX-License-Identifier: AGPL-3.0-only
; Copyright (C) 2026 HunterEwok

; The dot command's far pages, kept out of MAIN's 32K (README.md,
; "Memory"): PAGE_15 holds the install screen with its logo, the usage
; text, SHA-256 and .cbb uninstall; PAGE_13 the install itself, PAGE_17 .cbb net, paste,
; copy, text and pair, each an overlay. CBB stays under 64K (budget.sh). z88dk's dotn loader puts each in a page that
; NextZXOS allocates for the command and frees when it ends, as z88dk's
; own dot commands (ls) do with theirs. All have the addresses
; 0xE000-0xFFFF, the window of MMU7, which MAIN leaves empty (it ends below
; 0xE000; budget.sh checks). An overlay calls MAIN and this page directly,
; and another overlay only through its entry here, which puts the caller's
; page back after (far_sha()).
;
; This code runs from the divMMC page (code_dot), and the stack is below
; 0xE000 too (REGISTER_SP in the Makefile; z88dk's own default, the top of
; memory, is in MMU7), so changing MMU7 never pulls the ground from under
; either.

SECTION code_dot

PUBLIC _far_byte
PUBLIC _rom_char
PUBLIC _far_install
PUBLIC _far_net
PUBLIC _far_net_pair
PUBLIC _far_paste_receive
PUBLIC _far_pair_check
PUBLIC _far_cmd
PUBLIC _far_screen_open
PUBLIC _far_screen_close
PUBLIC _far_sha
PUBLIC _far_uninstall

EXTERN __z_page_table
EXTERN _install_run
EXTERN _net_cmd
EXTERN _net_pair
EXTERN _cmd_run
EXTERN _screen_open
EXTERN _screen_close
EXTERN _sha_run
EXTERN _uninstall
EXTERN _paste_receive
EXTERN _pair_check

FAR_DATA    equ 15
FAR_INSTALL equ 13
FAR_NET     equ 17
FAR_CMD     equ 17

; MMU7's page now, in a (reads NextReg 0x57).
mmu7_now:
   push bc
   ld bc,0x243b
   ld a,0x57
   out (c),a
   inc b
   in a,(c)
   pop bc
   ret

; uint8_t far_byte(const uint8_t *p) __z88dk_fastcall
;
; The byte at p in the data page. MMU7 shows it only for the read, with
; interrupts off, then shows what it showed before (the install overlay
; when that calls).
_far_byte:
   ld a,i                     ; P/V: interrupts were on
   push af
   di
   call mmu7_now
   ld e,a
   ld a,(__z_page_table + FAR_DATA)
   nextreg 0x57,a
   ld l,(hl)
   ld a,e
   nextreg 0x57,a
   pop af
   jp po,off
   ei
off:
   ld h,0
   ret

; int far_install(void), int far_net(void), int far_net_pair(void),
; int far_cmd(void), void far_screen_open(void), void far_screen_close(void)
;
; Each runs its function with its overlay's page in MMU7, then puts back
; what was there; the function's result stays in hl.
_far_install:
   ld a,FAR_INSTALL
   ld hl,_install_run
   jr far_call

_far_cmd:
   ld a,FAR_CMD
   ld hl,_cmd_run
   jr far_call

_far_screen_open:
   ld a,FAR_DATA
   ld hl,_screen_open
   jr far_call

_far_screen_close:
   ld a,FAR_DATA
   ld hl,_screen_close
   jr far_call

; uint32_t far_sha(void), from the install's page: far_call puts that page
; back after, and keeps the result in dehl.
_far_sha:
   ld a,FAR_DATA
   ld hl,_sha_run
   jr far_call

; int far_uninstall(void), in the logo's page too.
_far_uninstall:
   ld a,FAR_DATA
   ld hl,_uninstall
   jr far_call

; int far_paste_receive(void), in the logo's page too.
_far_paste_receive:
   ld a,FAR_DATA
   ld hl,_paste_receive
   jr far_call

; int far_pair_check(void), in the installer's page.
_far_pair_check:
   ld a,FAR_INSTALL
   ld hl,_pair_check
   jr far_call

_far_net:
   ld a,FAR_NET
   ld hl,_net_cmd
   jr far_call

_far_net_pair:
   ld a,FAR_NET
   ld hl,_net_pair

; a: the logical page, hl: the function.
far_call:
   push hl
   ld hl,__z_page_table
   add hl,a
   ld e,(hl)                  ; its physical page
   call mmu7_now
   pop hl
   push af
   ld a,e
   nextreg 0x57,a
   call call_hl
   pop af
   nextreg 0x57,a
   ret

call_hl:
   jp (hl)

; void rom_char(uint8_t c) __z88dk_fastcall
;
; c to the ROM's RST $10 as it is. stdout's driver (z88dk's
; zx_00_output_rom_rst) turns 10 into 13 and drops 13, which is right for
; text but not for AT's row and column. As that driver does, IY holds
; ERR_NR for the ROM, the alternate registers are kept, and MMU6 and MMU7
; are put back after.
_rom_char:
   ld a,l
   push ix
   push iy
   exx
   push bc
   push de
   push hl
   exx
   ld e,a
   ld bc,0x243b
   ld a,0x56
   out (c),a
   inc b
   in l,(c)                   ; MMU6
   dec b
   inc a
   out (c),a
   inc b
   in h,(c)                   ; MMU7
   push hl
   ld a,e
   ld iy,0x5c3a
   rst 0x10
   pop hl
   ld a,l
   nextreg 0x56,a
   ld a,h
   nextreg 0x57,a
   exx
   pop hl
   pop de
   pop bc
   exx
   pop iy
   pop ix
   ret
