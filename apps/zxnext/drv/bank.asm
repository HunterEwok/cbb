; SPDX-License-Identifier: AGPL-3.0-only
; Copyright (C) 2026 HunterEwok
;
; cbb.drv's working part, in the 8K bank the driver pages in at $E000 for
; each call (stub.asm). On every frame's interrupt it passes the ESP's bytes
; to the Pi in frames and the Pi's frames for the ESP to the ESP, sends the
; Pi how many of its bytes it took, its hello and the clock, and types the
; characters of the Pi's key frames one a frame. The frames are those of
; the lite member's `cbb next link` (lite/README.md, "The network through
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

ESP_CHUNK       equ     48      ; the ESP's bytes in one frame to the Pi
HELLO_TICKS     equ     50      ; a hello every second
TIME_TICKS      equ     3000    ; the clock every minute

; The buffers, at fixed addresses so that their indices are simple.
ESP_RING        equ     $F000   ; 1 KB: bytes for the ESP
KEY_RING        equ     $F400   ; 256 bytes: characters to type
ESP_BUF         equ     $F500   ; the ESP's bytes on their way to the Pi

        jp      api             ; $E000
        jp      im              ; $E003

; ---------------------------------------------------------------------------
; The API: B = 1 the counters (BC = the ESP's overflows, DE = dropped
; frames, HL = bytes taken from the Pi); B = 2 on (D = 1) or off (D = 0);
; B = 3 the state (A and DE = 1 when on; NextZXOS's M_DRVAPI gives a
; program only BC, DE and HL). Carry set for an unknown call.
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
        ld      a,d
        ld      (enabled),a
        and     a
        jr      z,api_ok
        ; Turned on: a hello and the clock at the next interrupt.
        xor     a
        ld      (dstate),a
        inc     a
        ld      (hello_left),a
        ld      hl,1
        ld      (time_left),hl
api_ok:
        and     a
        ret
api3:
        cp      3
        jr      nz,api_bad
        ld      a,(enabled)
        ld      e,a
        ld      d,0
        and     a
        ret
api_bad:
        scf
        ret

; ---------------------------------------------------------------------------
; The interrupt. AF, BC, DE and HL may be used; IX, IY and the alternates
; stay as they are.
im:
        ld      a,(enabled)
        and     a
        ret     z
        ld      bc,PORT_SELECT
        in      a,(c)
        ld      (saved_sel),a
        call    from_pi
        call    to_esp
        call    from_esp
        call    ack
        call    hello
        call    keys
        ld      bc,PORT_SELECT
        ld      a,(saved_sel)
        out     (c),a
        ret

; Reads the Pi's bytes while the ring for the ESP has room for a whole
; frame's data, and decodes them.
from_pi:
        ld      bc,PORT_SELECT
        ld      a,SEL_PI
        out     (c),a
fp_loop:
        ld      a,(dstate)
        and     a
        jr      nz,fp_read      ; inside a frame: its room was checked
        call    esp_free        ; HL = free bytes in the ring
        ld      a,h
        and     a
        jr      nz,fp_read      ; 256 or more
        ld      a,l
        cp      255
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
        call    decode
        jr      fp_loop

; HL = the free bytes in the ESP's ring: (head - tail - 1) mod 1024.
esp_free:
        ld      hl,(esp_head)
        ld      de,(esp_tail)
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
        jr      nz,dt_count
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
        jr      nz,dt_q
        ld      a,(key_tent)
        ld      (key_tail),a
        ret
dt_q:
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
        defm    "cbb.drv 0.1"
hello_end:

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
hello_left:     defb    1
time_left:      defw    1
code_end:
