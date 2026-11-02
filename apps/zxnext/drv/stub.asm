; SPDX-License-Identifier: AGPL-3.0-only
; Copyright (C) 2026 HunterEwok
;
; cbb.drv's 512 bytes, which NextZXOS calls on every frame's interrupt and
; for its API. It pages the driver's 8K bank in at $E000 (MMU7), calls it
; (bank.asm) and puts back the bank it found. The interrupts are off and the
; stack is below $4000 while a driver runs, so the program in front never
; sees the bank. Nothing here refers to its own addresses (only relative
; jumps), so the driver needs no relocations; .install writes the bank's id at BANK_IM and
; BANK_API (drv.asm lists them).

        org     $0000

NR_SELECT       equ     $243B
NR_MMU7         equ     $57

; $0000: the API (B = the call, DE and HL its values; the bank's answer in
; A, BC, DE, HL and the carry goes back as it is).
api:
        jr      api_call
        defb    0

; $0003: the interrupt. AF, BC, DE and HL are free.
im1:
        ld      bc,NR_SELECT
        ld      a,NR_MMU7
        out     (c),a
        inc     b
        in      a,(c)           ; A: the bank found
        push    af
        ld      a,0
BANK_IM equ     $-1
        nextreg NR_MMU7,a
        call    $E003
        pop     af
        nextreg NR_MMU7,a
        ret

api_call:
        push    bc
        ld      bc,NR_SELECT
        ld      a,NR_MMU7
        out     (c),a
        inc     b
        in      a,(c)           ; A: the bank found
        pop     bc
        push    af              ; the bank found
        ld      a,0
BANK_API equ    $-1
        nextreg NR_MMU7,a
        call    $E000
        push    hl
        push    af
        ld      hl,5            ; the bank found, under the answer's AF and HL
        add     hl,sp
        ld      a,(hl)
        nextreg NR_MMU7,a
        pop     af
        pop     hl
        inc     sp              ; drop the bank found; the flags stay
        inc     sp
        ret

        defs    512 - $, 0
