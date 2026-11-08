; SPDX-License-Identifier: AGPL-3.0-only
; Copyright (C) 2026 HunterEwok
;
; cbb.drv's working part, in the 8K bank the driver pages in at $E000 for
; each call (stub.asm). On every frame's interrupt it passes the ESP's bytes
; to the Pi in frames and the Pi's frames for the ESP to the ESP, sends the
; Pi how many of its bytes it took, its hello and the clock, and types the
; characters of the Pi's key frames one a frame. It also carries .cbb's
; commands to the Pi while the network runs (calls 7 and 8): their bytes
; in frames to the Pi, the Pi's answers in a ring of their own, which .cbb
; reads. Just after power-on it starts the network itself (call 9): it
; waits for NextPi's shell, types the line that starts the link and turns
; itself on once the link answers, so that BASIC need not wait for the
; Pi. The frames are those of
; the lite member's `cbb next link` (member/README.md, "The network through
; the Next's ESP8266"). It restores the UART selection it found, so the
; program in front is not disturbed.
;
; Plain Z80: no Z80N instructions here, so the host test (drvtest) runs it
; in an emulator.

        org     $E000

PORT_STATUS     equ     $133B   ; read: status; write: a byte to send
PORT_DATA       equ     $143B   ; read: a received byte
PORT_SELECT     equ     $153B   ; bit 6: the Pi's UART instead of the ESP's
SEL_ESP         equ     $00
SEL_PI          equ     $40
ST_RX           equ     0       ; status bit: a byte to read
ST_TXFULL       equ     1       ; status bit: the send buffer is full
ST_OVER         equ     2       ; status bit: the receive buffer overflowed

LAST_K          equ     23560   ; the ROM's last key
FLAGS           equ     23611   ; bit 5: a new key in LAST_K

DRV_RTC         equ     $2003   ; NextZXOS: BC = date, DE = time (MS-DOS)

START           equ     $7E     ; a frame's first byte, doubled inside
F_FROM_ESP      equ     'E'
F_TO_ESP        equ     'e'
F_HELLO         equ     'H'
F_TIME          equ     'T'
F_ACK           equ     'A'
F_KEYS          equ     'K'
F_QUIT          equ     'Q'
F_CBB_OUT       equ     'C'     ; .cbb's bytes for the Pi's shell
F_CBB_IN        equ     'c'     ; the answers for .cbb
F_IMAGE         equ     'I'     ; an image waits on the Pi
F_IMAGE_GO      equ     'i'     ; the program is frozen: send it
F_IMAGE_HEAD    equ     'J'     ; its mode and sum; its bytes follow, raw

NR_SELECT       equ     $243B
NR_DATA         equ     $253B
NR_MMU6         equ     $56
PORT_L2         equ     $123B
BORDCR          equ     23624   ; the border's colour in bits 3-5
WINDOW          equ     $C000   ; MMU6, where the image's banks go in turn
IMG_PAL         equ     $FE00   ; 512 bytes: the image's palette
IMG_BANKS       equ     10

ESP_CHUNK       equ     48      ; the ESP's bytes in one frame to the Pi
HELLO_TICKS     equ     50      ; a hello every second
TIME_TICKS      equ     3000    ; the clock every minute

; The buffers, at fixed addresses so that their indices are simple.
ESP_RING        equ     $F000   ; 1 KB: bytes for the ESP
KEY_RING        equ     $F400   ; 256 bytes: characters to type
ESP_BUF         equ     $F500   ; the ESP's bytes on their way to the Pi
CAP             equ     $F600   ; the last 64 bytes from the Pi, for .cbb net -d
CBB_RING        equ     $F800   ; 1 KB: the Pi's answers for .cbb
CBB_OUT         equ     $FC00   ; .cbb's bytes on their way to the Pi
CBB_CHUNK       equ     64      ; .cbb's bytes in one frame to the Pi
START_LINE      equ     $FD00   ; 256 bytes: the line that starts the link (call 9)

; The start in the background (call 9): its states.
B_PROMPT        equ     1       ; waits for the shell's prompt
B_QUIET         equ     2       ; then for the shell to be quiet
B_SEND          equ     3       ; types the line
B_LINK          equ     4       ; waits for the link's CBBLINK
B_NO_PROMPT     equ     5       ; failed: no prompt in time
B_NO_LINK       equ     6       ; failed: the link did not answer
B_ON            equ     7       ; the network runs
PROMPT_TICKS    equ     9000    ; three minutes for NextPi to start
POKE_TICKS      equ     100     ; an Enter every two seconds until then
QUIET_TICKS     equ     25      ; half a second without a byte
LINK_TICKS      equ     1000    ; twenty seconds for the link to answer

        jp      api             ; $E000
        jp      im              ; $E003

; ---------------------------------------------------------------------------
; The API: B = 1 the counters (BC = the ESP's overflows, DE = dropped
; frames, HL = bytes taken from the Pi); B = 2 on (E = 1) or off (E = 0);
; B = 3 the state (A and DE = 1 when on; NextZXOS's M_DRVAPI gives a
; program only BC, DE and HL); B = 4 the bytes sent to the ESP (BC) and
; read from it (DE); B = 5 the last dropped frame (C its type, B its
; length, E the sum so far, D the byte that ended it; HL the bytes taken);
; B = 6 six of the last 64 bytes from the Pi (from E, in C, B, E, D, L, H;
; byte n of the Pi is at n mod 64); B = 7 .cbb's bytes for the Pi: D = 0
; opens (the answers' ring empty, and kept from now), D = 1 the byte E
; (a frame goes once CBB_CHUNK wait, the rest at the next interrupt),
; D = 2 sends what waits, D = 3 that and an empty frame, which stops the
; command on the Pi, D = 4 closes; B = 8 the next byte of the Pi's
; answers in E, with D = 1, or D = 0 for none yet; B = 9 the start in
; the background: D = 0 empties the line, D = 1 adds the byte E to it,
; D = 2 starts (the driver must be off), D = 3 gives its state in E
; (0 none, B_PROMPT..B_ON); call 2 ends it; B = 10 the banks for showing
; images (img_show): E the first of ten in a row, even, D one more for
; what the screen showed, E = 0 for none; the ones before come back in D
; and E. Carry set for an unknown call.
api:
        ld      a,b
        cp      1
        jr      nz,api2
        ld      bc,(esp_over)
        ld      de,(dropped)
        ld      hl,(taken)
        and     a
        ret
api2:
        cp      2
        jr      nz,api3
        xor     a
        ld      (bstate),a      ; a start in the background ends
        ld      a,e
; Turns the driver on (A = 1) or off (A = 0).
switch:
        ld      (enabled),a
        and     a
        jr      z,api_ok
        ; Turned on: a hello and the clock at the next interrupt. The
        ; counts start again: the link counts its bytes from 0, and an
        ; ack with the count of an earlier run would close its window.
        ld      hl,0
        ld      (taken),hl
        ld      (acked),hl
        ld      (esp_over),hl
        ld      (dropped),hl
        ld      (esp_sent),hl
        ld      (esp_got),hl
        xor     a
        ld      (dstate),a
        inc     a
        ld      (hello_left),a
        ld      hl,1
        ld      (time_left),hl
        call    cbb_reset
api_ok:
        and     a
        ret
api3:
        cp      3
        jr      nz,api4
        ld      a,(enabled)
        ld      e,a
        ld      d,0
        and     a
        ret
api4:
        cp      4
        jr      nz,api5
        ld      bc,(esp_sent)
        ld      de,(esp_got)
        and     a
        ret
api5:
        cp      5
        jr      nz,api6
        ld      bc,(drop_info)
        ld      de,(drop_info+2)
        ld      hl,(taken)
        and     a
        ret
api6:
        cp      6
        jr      nz,api7
        ld      a,e             ; six bytes of CAP from E (0..58)
        and     63
        ld      l,a
        ld      h,CAP >> 8
        ld      c,(hl)
        inc     l
        ld      b,(hl)
        inc     l
        ld      e,(hl)
        inc     l
        ld      d,(hl)
        inc     l
        ld      a,(hl)
        inc     l
        ld      h,(hl)
        ld      l,a
        and     a
        ret
api7:
        cp      7
        jr      nz,api8
        ld      a,d
        and     a
        jr      nz,a7_byte
        call    cbb_reset       ; D = 0: open
        inc     a
        ld      (cbb_open),a
        ret
a7_byte:
        cp      1
        jr      nz,a7_send
        ld      a,(cbb_n)
        ld      l,a
        ld      h,CBB_OUT >> 8
        ld      (hl),e
        inc     a
        ld      (cbb_n),a
        cp      CBB_CHUNK
        ld      hl,cbb_flush
        jp      z,api_pi
        and     a
        ret
a7_send:
        ld      hl,cbb_flush
        cp      2
        jp      z,api_pi
        ld      hl,cbb_stop
        cp      3
        jp      z,api_pi
        cp      4
        jp      nz,api_bad
        jp      cbb_reset       ; D = 4: close
api8:
        cp      8
        jr      nz,api9
        ld      hl,(cbb_head)
        ld      de,(cbb_tail)
        and     a
        sbc     hl,de
        ld      de,0
        ret     z               ; none yet, carry clear
        ld      hl,(cbb_head)
        push    hl
        ld      a,h
        and     3
        or      CBB_RING >> 8
        ld      h,a
        ld      e,(hl)
        pop     hl
        inc     hl
        ld      a,h
        and     3
        ld      h,a
        ld      (cbb_head),hl
        inc     d
        and     a
        ret
api9:
        cp      9
        jp      nz,api10
        ld      a,d
        and     a
        jr      nz,a9_add
        ld      (blen),a        ; D = 0: an empty line, nothing started
        ld      (bstate),a
        ret
a9_add:
        cp      1
        jr      nz,a9_start
        ld      a,(blen)
        inc     a
        jr      z,api_bad       ; 255 bytes at most
        dec     a
        ld      l,a
        ld      h,START_LINE >> 8
        ld      (hl),e
        inc     a
        ld      (blen),a
        and     a
        ret
a9_start:
        cp      2
        jr      nz,a9_state
        ld      hl,PROMPT_TICKS
        ld      (btick),hl
        ld      a,1
        ld      (bpoke),a
        xor     a
        ld      (bmatch),a
        ld      (bpos),a
        ld      a,B_PROMPT
        ld      (bstate),a
        and     a
        ret
a9_state:
        cp      3
        jp      nz,api_bad
        ld      a,(bstate)
        ld      e,a
        ld      d,0
        and     a
        ret
api10:
        cp      10
        jr      nz,api_bad
        ld      hl,(img_base)   ; L = the first bank, H = the state's
        ld      (img_base),de
        ex      de,hl
        xor     a
        ld      (img_want),a
        ret
api_bad:
        scf
        ret

; Runs HL, which sends frames to the Pi, from a call: the UART selected
; before is selected again after.
api_pi:
        ld      bc,PORT_SELECT
        in      a,(c)
        push    af
        call    jp_hl
        pop     af
        ld      bc,PORT_SELECT
        out     (c),a
        and     a
        ret
jp_hl:
        jp      (hl)

; .cbb's waiting bytes to the Pi in a frame.
cbb_flush:
        ld      a,(cbb_n)
        and     a
        ret     z
        ld      b,a
        xor     a
        ld      (cbb_n),a
        ld      a,F_CBB_OUT
        ld      hl,CBB_OUT
        jp      frame

; Those, then an empty frame: the command on the Pi stops.
cbb_stop:
        call    cbb_flush
        ld      a,F_CBB_OUT
        ld      b,0
        jp      frame

; Empties the answers' ring and the bytes waiting, and closes; A = 0,
; carry clear.
cbb_reset:
        ld      hl,0
        ld      (cbb_head),hl
        ld      (cbb_tail),hl
        xor     a
        ld      (cbb_n),a
        ld      (cbb_open),a
        ret

; ---------------------------------------------------------------------------
; The interrupt. AF, BC, DE and HL may be used; IX, IY and the alternates
; stay as they are.
im:
        ld      a,(enabled)
        and     a
        jr      z,boot
        ld      bc,PORT_SELECT
        in      a,(c)
        ld      (saved_sel),a
        call    from_pi
        ld      a,(img_want)
        and     a
        call    nz,img_show
        call    to_esp
        call    from_esp
        call    cbb_flush
        call    ack
        call    hello
        call    keys
        ld      bc,PORT_SELECT
        ld      a,(saved_sel)
        out     (c),a
        ret

; The start in the background, while the driver is off.
boot:
        ld      a,(bstate)
        dec     a
        cp      B_LINK
        ret     nc              ; none, failed or done
        ld      bc,PORT_SELECT
        in      a,(c)
        ld      (saved_sel),a
        ld      a,SEL_PI
        out     (c),a
        call    boot_step
        ld      bc,PORT_SELECT
        ld      a,(saved_sel)
        out     (c),a
        ret

boot_step:
        ld      hl,(btick)
        dec     hl
        ld      (btick),hl
        ld      a,h
        or      l
        jr      nz,bs_go
        ld      a,(bstate)      ; the time is up
        cp      B_PROMPT
        ld      a,B_NO_PROMPT
        jr      z,bs_fail
        ld      a,B_NO_LINK
bs_fail:
        ld      (bstate),a
        ld      a,3             ; Ctrl-C: stop what may run
        jp      put_raw
bs_go:
        ld      a,(bstate)
        cp      B_SEND
        jr      z,bs_send
bs_read:
        ld      bc,PORT_STATUS
        in      a,(c)
        bit     ST_RX,a
        jr      z,bs_idle
        inc     b               ; PORT_DATA
        in      a,(c)
        call    boot_byte
        ld      a,(enabled)
        and     a
        ret     nz              ; on: the rest are frames, for the next interrupt
        jr      bs_read
bs_idle:
        ld      a,(bstate)
        cp      B_QUIET
        jr      z,bs_quiet
        cp      B_PROMPT
        ret     nz
        ld      hl,bpoke        ; no prompt yet: an Enter now and then
        dec     (hl)
        ret     nz
        ld      (hl),POKE_TICKS
        ld      a,10
        jp      put_raw
bs_quiet:
        ld      hl,bquiet
        dec     (hl)
        ret     nz
        ld      a,B_SEND        ; the shell is quiet: the line goes
        ld      (bstate),a
        ld      hl,LINK_TICKS
        ld      (btick),hl
        ret
bs_send:
        ld      a,(bpos)        ; what fits in the UART's send buffer
        ld      hl,blen
        cp      (hl)
        jr      nz,bs_put
        ld      a,B_LINK
        ld      (bstate),a
        ret
bs_put:
        ld      bc,PORT_STATUS
        in      a,(c)
        bit     ST_TXFULL,a
        ret     nz
        ld      a,(bpos)
        ld      l,a
        ld      h,START_LINE >> 8
        ld      a,(hl)
        out     (c),a
        ld      hl,bpos
        inc     (hl)
        jr      bs_send

; A byte from the Pi in A, while the start waits: the prompt, then the
; link's CBBLINK; while the shell should be quiet, any byte waits longer.
boot_byte:
        ld      e,a
        ld      a,(bstate)
        cp      B_QUIET
        jr      nz,bb_text
        ld      a,QUIET_TICKS
        ld      (bquiet),a
        ret
bb_text:
        ld      hl,prompt_text
        cp      B_PROMPT
        jr      z,bb_at
        ld      hl,ready_text
bb_at:
        push    hl
        ld      a,(bmatch)
        call    add_hl_a
        ld      a,(hl)
        pop     hl
        cp      e
        jr      z,bb_more
        ld      a,(hl)          ; the byte may start the text again
        cp      e
        ld      a,0
        jr      nz,bb_set
        inc     a
bb_set:
        ld      (bmatch),a
        ret
bb_more:
        ld      a,(bmatch)
        inc     a
        ld      (bmatch),a
        call    add_hl_a
        ld      a,(hl)
        and     a
        ret     nz              ; more to come
        ld      (bmatch),a      ; the whole text
        ld      a,(bstate)
        cp      B_PROMPT
        jr      nz,bb_on
        ld      a,QUIET_TICKS
        ld      (bquiet),a
        ld      a,B_QUIET
        ld      (bstate),a
        ret
bb_on:
        ld      a,B_ON          ; the link runs: the driver turns on
        ld      (bstate),a
        ld      a,1
        jp      switch

add_hl_a:
        add     a,l
        ld      l,a
        ret     nc
        inc     h
        ret

prompt_text:
        defm    "SUP>"
        defb    0
ready_text:
        defm    "CBBLINK"
        defb    13, 10, 0

; Reads the Pi's bytes while the ring for the ESP, and the one for .cbb
; while it is open, have room for a whole frame's data, and decodes them.
from_pi:
        ld      bc,PORT_SELECT
        ld      a,SEL_PI
        out     (c),a
fp_loop:
        ld      a,(dstate)
        and     a
        jr      nz,fp_read      ; inside a frame: its room was checked
        call    esp_free        ; HL = free bytes in the ring
        call    fp_room
        ret     c
        ld      a,(cbb_open)
        and     a
        jr      z,fp_read
        call    cbb_free
        call    fp_room
        ret     c
fp_read:
        ld      bc,PORT_STATUS
        in      a,(c)
        bit     ST_RX,a
        ret     z
        inc     b               ; PORT_DATA
        in      a,(c)
        ld      hl,(taken)
        inc     hl
        ld      (taken),hl
        ; CAP + (taken & 63) = A
        ld      e,a
        ld      a,l
        and     63
        ld      l,a
        ld      h,CAP >> 8
        ld      (hl),e
        ld      a,e
        call    decode
        ld      a,(img_want)
        ld      hl,img_head
        or      (hl)
        ret     nz              ; an image first (img_show)
        jr      fp_loop

; Carry when HL, a ring's free bytes, is under a frame's data.
fp_room:
        ld      a,h
        and     a
        ret     nz              ; 256 or more
        ld      a,l
        cp      255
        ret

; HL = the free bytes in .cbb's ring, as esp_free.
cbb_free:
        ld      hl,(cbb_head)
        ld      de,(cbb_tail)
        jr      ring_free

; HL = the free bytes in the ESP's ring: (head - tail - 1) mod 1024.
esp_free:
        ld      hl,(esp_head)
        ld      de,(esp_tail)
ring_free:
        and     a
        sbc     hl,de
        dec     hl
        ld      a,h
        and     3
        ld      h,a
        ret

; One byte of the Pi's in A.
decode:
        ld      e,a
        ld      a,(dstate)
        and     a
        jr      nz,dec_in
        ld      a,e
        cp      START
        ret     nz              ; noise between frames
        jr      dec_begin
dec_in:
        ld      a,(desc)
        and     a
        jr      z,dec_plain
        xor     a
        ld      (desc),a
        ld      a,e
        cp      START
        jr      z,dec_take      ; a doubled start byte: data
        ; A single start byte: the frame broke, and a new one starts.
        call    dec_drop
        call    dec_begin
        jr      dec_take
dec_plain:
        ld      a,e
        cp      START
        jr      nz,dec_take
        ld      a,1
        ld      (desc),a
        ret
dec_begin:
        ld      a,1
        ld      (dstate),a
        xor     a
        ld      (desc),a
        ret
dec_drop:
        ; What the dropped frame had: its type, length, sum and last byte.
        ld      a,(dkind)
        ld      (drop_info),a
        ld      a,(dlen)
        ld      (drop_info+1),a
        ld      a,(dsum)
        ld      (drop_info+2),a
        ld      a,e
        ld      (drop_info+3),a
        ld      hl,(dropped)
        inc     hl
        ld      (dropped),hl
        xor     a
        ld      (dstate),a
        ret

; E is the next byte of the frame.
dec_take:
        ld      a,(dstate)
        cp      1
        jr      nz,dt_len
        ld      a,e
        ld      (dkind),a
        ld      (dsum),a
        ld      a,2
        ld      (dstate),a
        ret
dt_len:
        cp      2
        jr      nz,dt_data
        ld      a,e
        ld      (dlen),a
        ld      (dcnt),a
        ld      hl,dsum
        add     a,(hl)
        ld      (hl),a
        ld      hl,(esp_tail)   ; the data goes after the committed bytes
        ld      (esp_tent),hl
        ld      hl,(cbb_tail)
        ld      (cbb_tent),hl
        ld      a,(key_tail)
        ld      (key_tent),a
        ld      a,(dlen)
        and     a
        ld      a,4
        jr      z,dt_state
        dec     a               ; 3: the data
dt_state:
        ld      (dstate),a
        ret
dt_data:
        cp      3
        jr      nz,dt_sum
        ld      a,e
        ld      hl,dsum
        add     a,(hl)
        ld      (hl),a
        ld      a,(dkind)
        cp      F_TO_ESP
        jr      nz,dt_key
        ; ESP_RING + (esp_tent & 1023) = E
        ld      hl,(esp_tent)
        push    hl
        ld      a,h
        and     3
        or      ESP_RING >> 8
        ld      h,a
        ld      (hl),e
        pop     hl
        inc     hl
        ld      (esp_tent),hl
        jr      dt_count
dt_key:
        cp      F_KEYS
        jr      nz,dt_cbb
        ld      a,(key_head)
        ld      d,a
        ld      a,(key_tent)
        inc     a
        cp      d
        jr      z,dt_full       ; the key ring is full: the frame is lost
        dec     a
        ld      l,a
        ld      h,KEY_RING >> 8
        ld      (hl),e
        inc     a
        ld      (key_tent),a
        jr      dt_count
dt_full:
        ld      a,1
        ld      (kfull),a
        jr      dt_count
dt_cbb:
        ; CBB_RING + (cbb_tent & 1023) = E; kept only while .cbb's ring
        ; is open (dt_sum), whose room from_pi checked then.
        cp      F_CBB_IN
        jr      nz,dt_head
        ld      hl,(cbb_tent)
        push    hl
        ld      a,h
        and     3
        or      CBB_RING >> 8
        ld      h,a
        ld      (hl),e
        pop     hl
        inc     hl
        ld      (cbb_tent),hl
        jr      dt_count
dt_head:
        cp      F_IMAGE_HEAD
        jr      nz,dt_count
        ld      a,(dlen)        ; its first three bytes, at jbuf
        ld      hl,dcnt
        sub     (hl)
        cp      3
        jr      nc,dt_count
        ld      hl,jbuf
        add     a,l
        ld      l,a
        jr      nc,dt_jb
        inc     h
dt_jb:
        ld      (hl),e
dt_count:
        ld      hl,dcnt
        dec     (hl)
        ret     nz
        ld      a,4
        ld      (dstate),a
        ret
dt_sum:
        xor     a
        ld      (dstate),a
        ld      a,(dsum)
        cp      e
        jr      nz,dt_bad
        ld      a,(kfull)
        and     a
        jr      nz,dt_bad
        ld      a,(dkind)
        cp      F_TO_ESP
        jr      nz,dt_k
        ld      hl,(esp_tent)
        ld      a,h
        and     3
        ld      h,a
        ld      (esp_tail),hl
        ret
dt_k:
        cp      F_KEYS
        jr      nz,dt_c
        ld      a,(key_tent)
        ld      (key_tail),a
        ret
dt_c:
        cp      F_CBB_IN
        jr      nz,dt_q
        ld      a,(cbb_open)
        and     a
        ret     z               ; nobody reads it: dropped
        ld      hl,(cbb_tent)
        ld      a,h
        and     3
        ld      h,a
        ld      (cbb_tail),hl
        ret
dt_q:
        cp      F_IMAGE
        jr      nz,dt_j
        ld      a,(img_base)
        and     a
        ret     z               ; no banks: no image
        ld      (img_want),a
        ret
dt_j:
        cp      F_IMAGE_HEAD
        jr      nz,dt_quit
        ld      (img_head),a
        ret
dt_quit:
        cp      F_QUIT
        ret     nz
        xor     a
        ld      (enabled),a
        ret
dt_bad:
        xor     a
        ld      (kfull),a
        jp      dec_drop

; Sends the ESP what fits in its send buffer.
to_esp:
        ld      bc,PORT_SELECT
        ld      a,SEL_ESP
        out     (c),a
te_loop:
        ld      hl,(esp_head)
        ld      de,(esp_tail)
        and     a
        sbc     hl,de
        ret     z               ; nothing to send
        ld      bc,PORT_STATUS
        in      a,(c)
        bit     ST_TXFULL,a
        ret     nz
        ld      hl,(esp_head)
        push    hl
        ld      a,h
        and     3
        or      ESP_RING >> 8
        ld      h,a
        ld      a,(hl)
        out     (c),a
        ld      hl,(esp_sent)
        inc     hl
        ld      (esp_sent),hl
        pop     hl
        inc     hl
        ld      a,h
        and     3
        ld      h,a
        ld      (esp_head),hl
        jr      te_loop

; Reads up to ESP_CHUNK of the ESP's bytes and sends them to the Pi.
from_esp:
        ld      bc,PORT_SELECT
        ld      a,SEL_ESP
        out     (c),a
        ld      hl,ESP_BUF
        ld      e,0
fe_loop:
        ld      a,e
        cp      ESP_CHUNK
        jr      z,fe_send
        ld      bc,PORT_STATUS
        in      a,(c)
        bit     ST_OVER,a
        jr      z,fe_noover
        push    hl
        ld      hl,(esp_over)
        inc     hl
        ld      (esp_over),hl
        pop     hl
fe_noover:
        bit     ST_RX,a
        jr      z,fe_send
        inc     b               ; PORT_DATA
        in      a,(c)
        ld      (hl),a
        inc     hl
        inc     e
        push    hl
        ld      hl,(esp_got)
        inc     hl
        ld      (esp_got),hl
        pop     hl
        jr      fe_loop
fe_send:
        ld      a,e
        and     a
        ret     z
        ld      b,e
        ld      a,F_FROM_ESP
        ld      hl,ESP_BUF
        jp      frame           ; to the Pi

; Tells the Pi how many of its bytes were taken, when that changed.
ack:
        ld      hl,(taken)
        ld      de,(acked)
        and     a
        sbc     hl,de
        ret     z
        ld      hl,(taken)
        ld      (acked),hl
        ld      (ESP_BUF),hl
        ld      a,F_ACK
        ld      b,2
        ld      hl,ESP_BUF
        jp      frame

; The hello every second, the clock every minute.
hello:
        ld      hl,hello_left
        dec     (hl)
        jr      nz,hl_time
        ld      (hl),HELLO_TICKS
        ld      a,F_HELLO
        ld      b,hello_end - hello_text
        ld      hl,hello_text
        call    frame
hl_time:
        ld      hl,(time_left)
        dec     hl
        ld      (time_left),hl
        ld      a,h
        or      l
        ret     nz
        ld      hl,TIME_TICKS
        ld      (time_left),hl
        call    DRV_RTC
        ret     c               ; no clock
        ld      (ESP_BUF),bc
        ld      (ESP_BUF+2),de
        ld      a,F_TIME
        ld      b,4
        ld      hl,ESP_BUF
        jp      frame

; A frame to the Pi: type A, B bytes at HL (B = 0 for none).
frame:
        push    af
        ld      a,SEL_PI
        ld      de,PORT_SELECT
        call    out_de
        ld      a,START
        call    put_raw
        pop     af
        ld      c,a             ; C: the sum
        call    put
        ld      a,b
        add     a,c
        ld      c,a
        ld      a,b
        call    put
        ld      a,b
        and     a
        jr      z,fr_sum
fr_loop:
        ld      a,(hl)
        add     a,c
        ld      c,a
        ld      a,(hl)
        call    put
        inc     hl
        djnz    fr_loop
fr_sum:
        ld      a,c
        ; and put it

; Sends A to the Pi, twice when it is the start byte. Keeps BC and HL.
put:
        call    put_raw
        cp      START
        ret     nz
put_raw:
        push    bc
        ld      e,a
        ld      bc,PORT_STATUS
pr_wait:
        in      a,(c)
        bit     ST_TXFULL,a
        jr      nz,pr_wait
        out     (c),e
        ld      a,e
        pop     bc
        ret

out_de:
        push    bc
        ld      b,d
        ld      c,e
        out     (c),a
        pop     bc
        ret

; Types one character a frame, as the ROM does for a key.
keys:
        ld      a,(key_head)
        ld      hl,key_tail
        cp      (hl)
        ret     z
        ld      hl,FLAGS
        bit     5,(hl)
        ret     nz              ; the last one is not taken yet
        ld      l,a
        ld      h,KEY_RING >> 8
        ld      a,(hl)
        ld      (LAST_K),a
        ld      hl,FLAGS
        set     5,(hl)
        ld      hl,key_head
        inc     (hl)
        ret

hello_text:
        defm    "cbb.drv 0.3"
hello_end:

; ---------------------------------------------------------------------------
; An image from the Pi, over the program in front, which stays frozen in
; this interrupt until a key: what Layer 2 showed is kept in the state's
; bank and put back after. The Pi sends the image after F_IMAGE_GO: a head
; frame, then the 81920 bytes of pixels in Layer 2's order and the
; palette, raw, which go into the ten banks as they come, each column
; showing at once and the border flipping with each column that came.
img_show:
        xor     a
        ld      (img_want),a
        ld      (img_head),a
        ld      a,NR_MMU6
        call    nr_get
        ld      (sv_mmu6),a
        ld      a,F_IMAGE_GO
        ld      b,0
        call    frame
        ; The head, while the ESP's bytes go on as usual.
        ld      d,4
is_wait:
        ld      hl,0
is_wait2:
        push    de
        push    hl
        call    from_pi
        pop     hl
        pop     de
        ld      a,(img_head)
        and     a
        jr      nz,is_head
        push    de
        push    hl
        call    to_esp
        call    ack             ; the Pi's window, for what waits before it
        pop     hl
        pop     de
        dec     hl
        ld      a,h
        or      l
        jr      nz,is_wait2
        dec     d
        jr      nz,is_wait
        ret                     ; no head: the Pi gave up
is_head:
        xor     a
        ld      (img_head),a
        call    state_bank
        call    l2_save
        call    l2_on
        ; The pixels, bank by bank; HL' would be quicker, but the
        ; alternates are the program's: the sum goes on the stack's top.
        ld      bc,PORT_SELECT
        ld      a,SEL_PI
        out     (c),a
        ld      hl,0
        push    hl              ; the sum
        ld      a,(img_base)
        ld      d,a             ; D: the bank
        ld      e,IMG_BANKS
is_bank:
        ld      a,d
        call    mmu6
        ld      hl,WINDOW
is_byte:
        call    raw_byte
        jr      c,is_fail
        ld      (hl),a
        ex      (sp),hl
        add     a,l
        ld      l,a
        jr      nc,is_nc
        inc     h
is_nc:
        ex      (sp),hl
        inc     l
        jr      nz,is_byte
        ; A column came: the border flips, blue and yellow.
        ld      a,h
        and     1
        ld      c,a
        add     a,a
        add     a,a
        add     a,c
        inc     a
        out     ($FE),a
        inc     h
        ld      a,h
        cp      (WINDOW >> 8) + $20
        jr      nz,is_byte
        inc     d
        dec     e
        jr      nz,is_bank
        ; The palette: 32 bytes for 16 colours, 512 for 256.
        ld      hl,IMG_PAL
        ld      bc,512
        ld      a,(jbuf)
        cp      'H'
        jr      nz,is_pal
        ld      c,32
        ld      b,0
is_pal:
        call    raw_byte
        jr      c,is_fail
        ld      (hl),a
        inc     hl
        ex      (sp),hl
        add     a,l
        ld      l,a
        jr      nc,is_nc2
        inc     h
is_nc2:
        ex      (sp),hl
        dec     bc
        ld      a,b
        or      c
        jr      nz,is_pal
        pop     hl              ; the sum
        ld      de,(jbuf+1)
        and     a
        sbc     hl,de
        jr      nz,is_bad
        ; The colours and the whole screen, until a key.
        ld      a,(jbuf)
        cp      'H'
        jr      nz,is_colours
        ld      hl,IMG_PAL+32   ; colours 16 to 255 black
        ld      de,IMG_PAL+33
        ld      bc,479
        ld      (hl),0
        ldir
is_colours:
        ld      hl,IMG_PAL
        call    pal_write
        ld      hl,clip_all
        call    clip_set
        call    key_wait
        jr      is_end
is_fail:
        pop     hl
is_bad:
        ; Damaged or cut short: the screen as it was, a red flash.
        ld      a,2
        out     ($FE),a
is_end:
        call    state_bank
        call    l2_restore
        ld      a,(sv_mmu6)
        call    mmu6
        ld      a,(BORDCR)
        rrca
        rrca
        rrca
        and     7
        out     ($FE),a
        ret

; A raw byte from the Pi in A, or carry when none came for a while.
; Keeps BC, DE and HL.
raw_byte:
        push    bc
        push    de
        ld      bc,PORT_STATUS
        in      a,(c)
        bit     ST_RX,a
        jr      nz,rb_got       ; at once, mostly
        push    hl
        ld      h,16
        ld      de,0
rb_wait:
        in      a,(c)
        bit     ST_RX,a
        jr      nz,rb_late
        dec     de
        ld      a,d
        or      e
        jr      nz,rb_wait
        dec     h
        jr      nz,rb_wait
        pop     hl
        pop     de
        pop     bc
        scf
        ret
rb_late:
        pop     hl
rb_got:
        inc     b               ; PORT_DATA
        in      a,(c)
        pop     de
        pop     bc
        and     a
        ret

; Waits for the keys up, a key, the keys up again; the border blinks.
key_wait:
        call    kw_up
kw_down:
        call    kw_blink
        call    keys_now
        jr      z,kw_down
kw_up:
        call    keys_now
        jr      nz,kw_up
        ret
keys_now:
        xor     a
        in      a,($FE)
        cpl
        and     $1F
        ret
kw_blink:
        ld      hl,(blink)
        inc     hl
        ld      (blink),hl
        ld      a,h
        and     $10
        rrca
        rrca
        or      1               ; blue and cyan in turn
        out     ($FE),a
        ret

; The state's bank in at WINDOW.
state_bank:
        ld      a,(img_state)
; Bank A in at WINDOW.
mmu6:
        push    de
        ld      e,a
        ld      a,NR_MMU6
        call    nr_put
        pop     de
        ret

; Next register A in A.
nr_get:
        push    bc
        ld      bc,NR_SELECT
        out     (c),a
        inc     b
        in      a,(c)
        pop     bc
        ret

; Next register A = E.
nr_put:
        push    bc
        ld      bc,NR_SELECT
        out     (c),a
        inc     b
        out     (c),e
        pop     bc
        ret

; The registers Layer 2's show changes, kept in the state's bank.
l2_regs:
        defb    $12, $14, $15, $16, $17, $43, $6B, $70, $71
L2_REGS         equ     9
SV_REGS         equ     WINDOW          ; the registers' values
SV_CLIP         equ     WINDOW + 16     ; the clip window's four
SV_PORT         equ     WINDOW + 20     ; port $123B
SV_PAL          equ     WINDOW + 32     ; Layer 2's second palette
clip_all:
        defb    0, 159, 0, 255
clip_mid:
        defb    16, 143, 32, 223

l2_save:
        ld      hl,l2_regs
        ld      de,SV_REGS
        ld      b,L2_REGS
ls_reg:
        ld      a,(hl)
        call    nr_get
        ld      (de),a
        inc     hl
        inc     de
        djnz    ls_reg
        ; Each read of the clip window, written back, moves its index on.
        ld      a,$1C
        ld      e,1
        call    nr_put
        ld      hl,SV_CLIP
        ld      b,4
ls_clip:
        ld      a,$18
        call    nr_get
        ld      (hl),a
        ld      e,a
        ld      a,$18
        call    nr_put
        inc     hl
        djnz    ls_clip
        ld      bc,PORT_L2
        in      a,(c)
        ld      (SV_PORT),a
        ld      a,$43
        ld      e,$50           ; Layer 2's second palette, to read
        call    nr_put
        ld      hl,SV_PAL
        ld      d,0
ls_pal:
        ld      a,$40
        ld      e,d
        call    nr_put
        ld      a,$41
        call    nr_get
        ld      (hl),a
        inc     hl
        ld      a,$44
        call    nr_get
        ld      (hl),a
        inc     hl
        inc     d
        jr      nz,ls_pal
        ret

l2_restore:
        ld      a,(SV_PORT)
        ld      bc,PORT_L2
        out     (c),a
        ld      hl,SV_PAL
        call    pal_write
        ld      hl,SV_CLIP
        call    clip_set
        ld      hl,l2_regs
        ld      de,SV_REGS
        ld      b,L2_REGS
lr_reg:
        push    de
        ld      a,(de)
        ld      e,a
        ld      a,(hl)
        call    nr_put
        pop     de
        inc     hl
        inc     de
        djnz    lr_reg
        ret

; Layer 2's second palette, written and shown, from the 512 bytes at HL,
; two an entry as register $44 takes them.
pal_write:
        ld      a,$43
        ld      e,$54
        call    nr_put
        ld      a,$40
        ld      e,0
        call    nr_put
        ld      bc,NR_SELECT
        ld      a,$44
        out     (c),a
        inc     b
        ld      d,0
pw_loop:
        ld      a,(hl)
        out     (c),a
        inc     hl
        ld      a,(hl)
        out     (c),a
        inc     hl
        dec     d
        jr      nz,pw_loop
        ret

; The clip window from the four bytes at HL (register $1C bit 0 resets
; its index).
clip_set:
        ld      a,$1C
        ld      e,1
        call    nr_put
        ld      b,4
cs_loop:
        ld      e,(hl)
        ld      a,$18
        call    nr_put
        inc     hl
        djnz    cs_loop
        ret

; Layer 2 on for the image's mode, its banks clear, in grey through the
; middle of the screen, the border around it the ULA's.
l2_on:
        ld      a,(img_base)
        ld      d,a
        ld      b,IMG_BANKS
lo_clear:
        push    bc
        ld      a,d
        call    mmu6
        ld      hl,WINDOW
        ld      de,WINDOW+1
        ld      bc,$1FFF
        ld      (hl),0
        ldir
        pop     bc
        ld      a,(img_base)
        add     a,IMG_BANKS
        sub     b
        inc     a
        ld      d,a
        djnz    lo_clear
        ; The grey palette: 8 greys over 256 entries, or 16 entries.
        ld      hl,IMG_PAL
        ld      c,0
lo_grey:
        ld      a,(jbuf)
        cp      'H'
        ld      a,c
        jr      nz,lo_lo
        and     15
        rrca                    ; (i & 15) >> 1, in bits 0-2
        and     7
        jr      lo_g
lo_lo:
        rlca
        rlca
        rlca
        and     7               ; i >> 5
lo_g:
        ld      b,a             ; g
        rrca
        rrca
        rrca
        and     $E0             ; g << 5
        ld      e,a
        ld      a,b
        add     a,a
        add     a,a             ; g << 2
        or      e
        ld      e,a
        ld      a,b
        srl     a               ; g >> 1
        or      e
        ld      (hl),a
        inc     hl
        ld      a,b
        and     1
        ld      (hl),a
        inc     hl
        inc     c
        jr      nz,lo_grey
        ld      hl,IMG_PAL
        call    pal_write
        call    state_bank      ; the registers kept, for their other bits
        ld      a,(img_base)
        rrca                    ; the 16K bank
        and     $7F
        ld      e,a
        ld      a,$12
        call    nr_put
        ld      a,(jbuf)
        cp      'H'
        ld      e,$10
        jr      nz,lo_res
        ld      e,$20
lo_res:
        ld      a,$70
        call    nr_put
        ld      e,0
        ld      a,$16
        call    nr_put
        ld      a,$71
        call    nr_put
        ld      a,$17
        call    nr_put
        ld      e,$E3
        ld      a,$14
        call    nr_put
        ld      a,(SV_REGS+6)   ; no tilemap
        and     $7F
        ld      e,a
        ld      a,$6B
        call    nr_put
        ld      a,(SV_REGS+2)   ; Layer 2 over the ULA, no sprites
        and     $E2
        or      $04
        ld      e,a
        ld      a,$15
        call    nr_put
        ld      hl,clip_mid
        call    clip_set
        ld      a,2
        ld      bc,PORT_L2
        out     (c),a
        ret

; The state.
enabled:        defb    0
saved_sel:      defb    0
dstate:         defb    0       ; 0 between frames, 1 type, 2 length, 3 data, 4 sum
desc:           defb    0       ; the last byte was a start byte
dkind:          defb    0
dlen:           defb    0
dcnt:           defb    0
dsum:           defb    0
kfull:          defb    0
esp_head:       defw    0       ; the ring for the ESP, indices 0..1023
esp_tail:       defw    0
esp_tent:       defw    0       ; the tail with the frame being read
key_head:       defb    0
key_tail:       defb    0
key_tent:       defb    0
taken:          defw    0       ; bytes read from the Pi
acked:          defw    0
esp_over:       defw    0
dropped:        defw    0
esp_sent:       defw    0       ; bytes sent to the ESP
esp_got:        defw    0       ; bytes read from the ESP
drop_info:      defs    4, 0    ; the last dropped frame, for call 5
cbb_open:       defb    0       ; .cbb reads the Pi's answers (call 7)
cbb_n:          defb    0       ; .cbb's bytes waiting in CBB_OUT
cbb_head:       defw    0       ; .cbb's ring, indices 0..1023
cbb_tail:       defw    0
cbb_tent:       defw    0
hello_left:     defb    1
time_left:      defw    1
bstate:         defb    0       ; the start in the background (call 9)
blen:           defb    0       ; the line's bytes at START_LINE
bpos:           defb    0       ; those typed
bmatch:         defb    0       ; bytes of the awaited text seen
bpoke:          defb    0
bquiet:         defb    0
btick:          defw    0
img_base:       defb    0       ; the image's first bank (call 10), 0 none
img_state:      defb    0       ; the bank for what the screen showed
img_want:       defb    0       ; an image waits (F_IMAGE)
img_head:       defb    0       ; its head came (F_IMAGE_HEAD)
jbuf:           defs    3, 0    ; the head: the mode, the sum
sv_mmu6:        defb    0
blink:          defw    0
code_end:
