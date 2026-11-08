; SPDX-License-Identifier: AGPL-3.0-only
; Copyright (C) 2026 HunterEwok

; The dot command's far pages, kept out of MAIN's 32K (README.md,
; "Memory"): PAGE_15 holds the install screen with its logo, the usage
; text and SHA-256; PAGE_13 the install itself, PAGE_17 .cbb net and pair,
; PAGE_19 paste, copy, text, leave and uninstall, each an overlay. CBB
; stays under 64K (budget.sh): the pages from OVL_FIRST on are in
; /cbb/CBB.OVL (ovl.sh), which ovl_load() reads into theirs before the
; first call there. z88dk's dotn loader puts each in a page that
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

PUBLIC _far_usage
PUBLIC _rom_char
PUBLIC _far_install
PUBLIC _far_net
PUBLIC _far_net_pair
PUBLIC _far_boot_busy
PUBLIC _far_paste_receive
PUBLIC _far_pair_check
PUBLIC _far_cmd
PUBLIC _far_screen_open
PUBLIC _far_screen_close
PUBLIC _far_sha
PUBLIC _far_uninstall
PUBLIC _far_net_halt
PUBLIC _far_read_list
PUBLIC _far_cbb_swap
PUBLIC _far_autoexec
PUBLIC _far_install_end
PUBLIC _far_net_restart
PUBLIC _far_show
PUBLIC _far_img_banks
PUBLIC _rx_block
PUBLIC _tape_block
PUBLIC _tape_dst
PUBLIC _tape_len
PUBLIC _tape_flag
PUBLIC _rx_dst
PUBLIC _rx_left
PUBLIC _rx_border
PUBLIC _crc_block
PUBLIC _crc_ptr
PUBLIC _crc_len
PUBLIC _crc_state
PUBLIC _crc_hi_at

EXTERN __z_page_table
EXTERN _install_run
EXTERN _net_cmd
EXTERN _net_pair
EXTERN _boot_busy_check
EXTERN _cmd_run
EXTERN _screen_open
EXTERN _screen_close
EXTERN _sha_run
EXTERN _uninstall
EXTERN _usage_run
EXTERN _paste_receive
EXTERN _pair_check
EXTERN _net_halt
EXTERN _read_list
EXTERN _cbb_swap
EXTERN _autoexec
EXTERN _install_end
EXTERN _net_restart
EXTERN _ovl_load
EXTERN _show_run
EXTERN _img_banks_run

FAR_DATA    equ 15
FAR_INSTALL equ 13
FAR_NET     equ 17
FAR_OVL     equ 19
FAR_CMD     equ FAR_OVL
FAR_SHOW    equ 21
OVL_FIRST   equ 19

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

; int far_uninstall(void), in CBB.OVL's.
_far_uninstall:
   ld a,FAR_OVL
   ld hl,_uninstall
   jr far_call

; int far_autoexec(void), in CBB.OVL's.
_far_autoexec:
   ld a,FAR_OVL
   ld hl,_autoexec
   jr far_call

; int far_paste_receive(void), in CBB.OVL's.
_far_paste_receive:
   ld a,FAR_OVL
   ld hl,_paste_receive
   jr far_call

; int far_read_list(void), in the logo's page too.
_far_read_list:
   ld a,FAR_DATA
   ld hl,_read_list
   jr far_call

; int far_cbb_swap(void), in the logo's page too.
_far_cbb_swap:
   ld a,FAR_DATA
   ld hl,_cbb_swap
   jr far_call

; int far_install_end(void), in the logo's page too.
_far_install_end:
   ld a,FAR_DATA
   ld hl,_install_end
   jr far_call

; void far_usage(void), in the logo's page.
_far_usage:
   ld a,FAR_DATA
   ld hl,_usage_run
   jr far_call

; int far_pair_check(void), in CBB.OVL's.
_far_pair_check:
   ld a,FAR_OVL
   ld hl,_pair_check
   jr far_call

; int far_show(void): .cbb show and speed, in CBB.OVL's second page.
_far_show:
   ld a,FAR_SHOW
   ld hl,_show_run
   jr far_call

; int far_net_halt(void) and int far_net_restart(void): the network
; stopped and started again around a command of CBB.OVL's page.
_far_net_halt:
   ld a,FAR_NET
   ld hl,_net_halt
   jr far_call

_far_net_restart:
   ld a,FAR_NET
   ld hl,_net_restart
   jr far_call

_far_net:
   ld a,FAR_NET
   ld hl,_net_cmd
   jr far_call

; int far_boot_busy(void): whether a start of the network in the
; background holds the Pi's line, which it says.
_far_boot_busy:
   ld a,FAR_NET
   ld hl,_boot_busy_check
   jr far_call

_far_net_pair:
   ld a,FAR_NET
   ld hl,_net_pair

; a: the logical page, hl: the function. A page of CBB.OVL is read first
; when it is not yet (ovl_load(), which says why it cannot be); the call
; then gives 1, a failure, without running the function.
far_call:
   cp OVL_FIRST
   jr c,far_page
   push hl
   push af
   ld l,a
   call _ovl_load
   ld a,l
   or a
   jr z,far_loaded
   pop af
   pop hl
   ld hl,1
   ret
far_loaded:
   pop af
   pop hl
far_page:
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

; int far_img_banks(void): the driver's banks for images (cbb.c).
_far_img_banks:
   ld a,FAR_OVL
   ld hl,_img_banks_run
   jr far_call

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

SECTION PAGE_21

; uint8_t rx_block(void)
;
; Reads rx_left bytes from the selected UART to rx_dst as fast as they
; come (about 90 T-states a byte, so 2 Mbit/s at 28 MHz), and flips the
; border between rx_border and rx_border xor 7 after every 32: the
; stripes follow the bytes that really came. LINK_OK (0) when all came,
; LINK_TIMEOUT (1) when the line was quiet for some 20 seconds in all,
; LINK_BREAK (2) on SPACE; rx_dst and rx_left say how far it got. The
; UART's status and data ports differ only in their high byte, so INI
; reads a byte into (hl) and leaves b at the status port again.
RX_WAITS equ 160                ; rounds of 65536 polls, about 20 s

_rx_block:
   push ix
   ld hl,(_rx_dst)
   ld de,(_rx_left)
   ld ix,0
   ld a,RX_WAITS
   ld (rx_rounds),a
   ld bc,0x133b
   ld a,d
   or e
   jr z,rx_ok
rx_poll:
   in a,(c)
   rra
   jr nc,rx_wait
   inc b
   ini
   dec de
   ld a,e
   and 31
   jr z,rx_flip
rx_more:
   ld a,d
   or e
   jr nz,rx_poll
rx_ok:
   ld a,0
   jr rx_end
rx_flip:
   ld a,(_rx_border)
   xor 7
   ld (_rx_border),a
   out (0xfe),a
   jr rx_more
rx_wait:
   dec ix
   ld a,ixh
   or ixl
   jr nz,rx_poll
   ld a,0x7f                    ; SPACE: port 0x7ffe, bit 0
   in a,(0xfe)
   rra
   ld a,2
   jr nc,rx_end
   ld a,(rx_rounds)
   dec a
   ld (rx_rounds),a
   jr nz,rx_poll
   inc a                        ; LINK_TIMEOUT
rx_end:
   ld (_rx_dst),hl
   ld (_rx_left),de
   ld l,a
   ld h,0
   pop ix
   ret

_rx_dst:
   defw 0
_rx_left:
   defw 0
_rx_border:
   defb 1
rx_rounds:
   defb 0

; uint8_t tape_block(void)
;
; Loads a block from the tape, here the Pi's sound through EAR (NextReg
; 0xA2 bit 0), at 3.5 MHz with the ROM's timings: a pilot of 2168
; T-state halves, a sync of 667 and 735, then each bit as two halves of
; 855 (0) or 1710 (1), high bit first; the flag byte first, tape_len
; bytes to tape_dst, and the XOR of all as the last byte. The border
; flips at each edge, red and cyan in the pilot, blue and yellow in the
; data, as the ROM's loader does. 0 when it loaded, 1 when no tape
; played for some 150 seconds, or a block broke off, or SPACE stopped it, 2 when the block came damaged
; or with another flag. The interrupts are off meanwhile.
;
; tb_edge counts B up, 52 T-states a count, until EAR changes; the counts
; below are from 100: a pilot half about 43 counts, a sync half 13 to
; 15, a bit's two halves 34 (0) or 68 (1).
TAPE_FROM   equ 100
TAPE_PILOT  equ 120             ; a pilot half: 20 to 100 counts
TAPE_LONG   equ 200
TAPE_SYNC   equ 125             ; under 25 counts: the sync
TAPE_BIT    equ 151             ; a bit's halves: over 51 counts, a 1

_tape_block:
   di
   ld a,0x7f
   in a,(0xfe)
   and 0x40
   or 2                         ; red, and EAR's level now
   ld c,a
   ld hl,0
   ld (tb_wait),hl              ; 65536 quiet waits, some 150 s, at most
   ld e,0                       ; 256 pilot halves in a row, at least
tb_pilot:
   ld b,TAPE_FROM
   call tb_edge
   jr nc,tb_quiet
   ld a,b
   cp TAPE_PILOT
   jr c,tb_short
   cp TAPE_LONG
   jr nc,tb_short
   inc e
   jr nz,tb_pilot
tb_sync:
   ld b,TAPE_FROM
   call tb_edge
   jr nc,tb_none
   ld a,b
   cp TAPE_SYNC
   jr nc,tb_sync                ; the pilot still
   ld b,TAPE_FROM
   call tb_edge
   jr nc,tb_none
   ld a,c
   and 0x40
   or 1                         ; blue and yellow now
   ld c,a
   call tb_byte
   jr nc,tb_none
   ld (tb_sum),a
   ld hl,_tape_flag
   cp (hl)
   jr nz,tb_bad
   ld hl,(_tape_dst)
tb_data:
   call tb_byte
   jr nc,tb_none
   ld (hl),a
   inc hl
   ld e,a
   ld a,(tb_sum)
   xor e
   ld (tb_sum),a
   ld de,(_tape_len)
   dec de
   ld (_tape_len),de
   ld a,d
   or e
   jr nz,tb_data
   call tb_byte                 ; the checksum
   jr nc,tb_none
   ld e,a
   ld a,(tb_sum)
   xor e
   jr nz,tb_bad
   ld l,0
   jr tb_end
tb_quiet:
   ld a,0x7f                    ; SPACE?
   in a,(0xfe)
   rra
   jr nc,tb_none
   ld hl,(tb_wait)
   dec hl
   ld (tb_wait),hl
   ld a,h
   or l
   jr z,tb_none
tb_short:
   ld e,0                       ; not the pilot: from the start
   jr tb_pilot
tb_none:
   ld l,1
   jr tb_end
tb_bad:
   ld l,2
tb_end:
   ld h,0
   ei
   ret

; A byte in A, carry set; carry clear when no edge came in time or SPACE.
tb_byte:
   ld d,1                       ; a marker, out after eight bits
tb_bit:
   ld b,TAPE_FROM
   call tb_edge
   ret nc
   call tb_edge
   ret nc
   ld a,b
   cp TAPE_BIT
   ccf                          ; carry for a long one
   rl d
   jr nc,tb_bit
   ld a,d
   scf
   ret

; B counts up until EAR changes, then the border flips: carry set; carry
; clear when B wrapped or SPACE is down.
tb_edge:
   inc b                        ; 4
   jr z,tb_out                  ; 7
   ld a,0x7f                    ; 7
   in a,(0xfe)                  ; 11
   xor c                        ; 4
   and 0x40                     ; 7
   jr z,tb_edge                 ; 12: 52 a round
   ld a,c
   xor 0x47                     ; the level, and the border's colour
   ld c,a
   and 7
   out (0xfe),a
   ld a,0x7f
   in a,(0xfe)
   rra                          ; SPACE: bit 0, low when down
   ret
tb_out:
   and a
   ret

_tape_dst:
   defw 0
_tape_len:
   defw 0
_tape_flag:
   defb 0
tb_sum:
   defb 0
tb_wait:
   defw 0

; void crc_block(void)
;
; CRC-32 (IEEE 802.3) of crc_len bytes from crc_ptr, continued in
; crc_state, which holds the CRC inverted (start with 0xFFFFFFFF, invert
; at the end): with four tables of 256 bytes, one for each
; byte of the table's entries, about 110 T-states a byte, where
; crc32_update() takes over a thousand. crc_table_make() fills them.
_crc_block:
   push ix
   ld ix,(_crc_len)
   ld a,ixh
   or ixl
   jr z,crc_end
   ld hl,(_crc_state)
   ld c,l
   ld b,h
   ld de,(_crc_state + 2)
   ld hl,(_crc_ptr)
crc_loop:
   ld a,(hl)
   xor c
   push hl
   ld l,a
crc_hi:
   ld h,0                       ; crc_table_make() writes the tables' page
   ld a,b
   xor (hl)
   ld c,a
   inc h
   ld a,e
   xor (hl)
   ld b,a
   inc h
   ld a,d
   xor (hl)
   ld e,a
   inc h
   ld d,(hl)
   pop hl
   inc hl
   dec ix
   ld a,ixh
   or ixl
   jr nz,crc_loop
   ld (_crc_ptr),hl
   ld l,c
   ld h,b
   ld (_crc_state),hl
   ld (_crc_state + 2),de
crc_end:
   pop ix
   ret

_crc_ptr:
   defw 0
_crc_len:
   defw 0
_crc_state:
   defs 4

_crc_hi_at:
   defw crc_hi + 1
