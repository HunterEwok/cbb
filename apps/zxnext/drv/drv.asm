; SPDX-License-Identifier: AGPL-3.0-only
; Copyright (C) 2026 HunterEwok
;
; CBB.DRV as .install reads it: the header, the 512 bytes (stub.asm) and the
; preloaded 8K ZX bank (bank.asm) with where to write its id. The Makefile
; assembles stub.bin and bank.bin first.

        org     $0000

        defm    "NDRV"
        defb    $7C + $80       ; the driver's id ($7C, unassigned), called on IM1
        defb    0               ; relocations
        defb    0               ; 8K DivMMC banks
        defb    1               ; 8K ZX banks

        binary  "stub.bin"

        ; The ZX bank: its patches, its size, its data, the patch offsets.
        defb    2
        defw    bank_end - bank_start
bank_start:
        binary  "bank.bin"
bank_end:
        defw    STUB_BANK_IM, STUB_BANK_API
