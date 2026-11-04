; SPDX-License-Identifier: AGPL-3.0-only
; Copyright (C) 2026 HunterEwok

; The dot command's far pages, kept out of MAIN's 32K: PAGE_15 holds data
; that only some commands need (the install screen's logo, the usage
; text); PAGE_13 the whole of .cbb install and PAGE_17 .cbb net and pair
; through the ESP, each an overlay. z88dk's dotn
; loader puts each in a page that NextZXOS allocates for the command and
; frees when it ends, as z88dk's own dot commands (ls) do with theirs. Both
; have the addresses 0xE000-0xFFFF, the window of MMU7, which MAIN leaves
; empty (it ends below 0xE000; the Makefile checks).
;
; This code runs from the divMMC page (code_dot), where the stack is too,
; so changing MMU7 never pulls the ground from under it.

SECTION code_dot

PUBLIC _far_byte
PUBLIC _far_install
PUBLIC _far_net
PUBLIC _far_net_pair

EXTERN __z_page_table
EXTERN _install
EXTERN _net_cmd
EXTERN _net_pair

FAR_DATA    equ 15
FAR_INSTALL equ 13
FAR_NET     equ 17

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

; int far_install(void), int far_net(void), int far_net_pair(void)
;
; Each runs its function with its overlay's page in MMU7, then puts back
; what was there; the function's result stays in hl.
_far_install:
   ld a,FAR_INSTALL
   ld hl,_install
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
