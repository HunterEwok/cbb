; SPDX-License-Identifier: AGPL-3.0-only
; Copyright (C) 2026 HunterEwok

; The stack's high-water mark. The stack starts at 0xE000 (REGISTER_SP in
; the Makefile), the top of MAIN's last page, and grows down towards the
; end of MAIN (MAIN_END); NextZXOS, the ROM and the drivers' interrupts run
; on it too. stack_mark fills the bytes between with MARK at the start, and
; stack_unused counts how many of them still hold it, from the bottom,
; which .cbb -d shows at the end.

SECTION code_compiler

PUBLIC _stack_mark
PUBLIC _stack_unused

EXTERN __MAIN_END_tail

MARK equ 0xA5
; The bytes just under sp that stack_mark leaves alone: its own return
; address and an interrupt's.
SLACK equ 32
; The stack's top, the first byte above it.
TOP_HIGH equ 0xE0

; void stack_mark(void)
_stack_mark:
   ld hl,-SLACK
   add hl,sp
   ld de,__MAIN_END_tail
   and a
   sbc hl,de                  ; hl = the bytes to mark
   ret c
   ret z
   ld b,h
   ld c,l
   ex de,hl
   ld (hl),MARK
   dec bc
   ld a,b
   or c
   ret z
   ld d,h
   ld e,l
   inc de
   ldir
   ret

; uint16_t stack_unused(void)
_stack_unused:
   ld hl,__MAIN_END_tail
   ld de,0
unused_loop:
   ld a,h
   cp TOP_HIGH
   jr nc,unused_end
   ld a,(hl)
   cp MARK
   jr nz,unused_end
   inc hl
   inc de
   jr unused_loop
unused_end:
   ex de,hl
   ret
