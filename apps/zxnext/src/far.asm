; SPDX-License-Identifier: AGPL-3.0-only
; Copyright (C) 2026 HunterEwok

; The dot command's far page: data that only some commands need (the
; install screen's logo, the usage text) kept out of MAIN's 32K. z88dk's
; dotn loader puts the section PAGE_13 in a page that NextZXOS allocates
; for the command and frees when it ends; z88dk's own dot commands (ls)
; page theirs in the same way. Its addresses are 0xE000-0xFFFF, the window
; of MMU7, where MAIN's own top 8K shows otherwise.

SECTION code_dot

PUBLIC _far_byte

EXTERN __z_page_table

; uint8_t far_byte(const uint8_t *p) __z88dk_fastcall
;
; The byte at p in the far page. MMU7 shows the far page only for the read,
; with interrupts off, so nothing else ever sees MAIN's top 8K missing; the
; code runs from the divMMC page (code_dot) and the stack is there too.
_far_byte:
   ld a,i                     ; P/V: interrupts were on
   push af
   di
   ld a,(__z_page_table + 13)
   nextreg 0x57,a
   ld l,(hl)
   ld a,(__z_page_table + 1)  ; MAIN's page of 0xE000-0xFFFF
   nextreg 0x57,a
   pop af
   jp po,off
   ei
off:
   ld h,0
   ret
