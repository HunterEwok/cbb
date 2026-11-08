; SPDX-License-Identifier: AGPL-3.0-only
; Copyright (C) 2026 HunterEwok

; SHA-256's compression (FIPS 180-4) for the Next, in place of sha256.c's
; C one, which runs each 32-bit operation as a call into the library and
; hashes some 1K a second. In the screen's page with sha256.c and sha_run()
; (cbb.c). The words are little-endian, as z88dk keeps uint32_t: DEHL holds
; one, L its lowest byte. The schedule (64 words) and the working
; variables (a ring of 72 words, a to h at IX+0 to IX+28, IX going down a
; word each round) are in the upper half of text[], which sha_run() leaves
; free. IY stays the ROM's.

SECTION PAGE_15

PUBLIC _sha256_compress

EXTERN _text

W equ _text+4096
V equ _text+4096+256

; void sha256_compress(struct sha256 *s) __z88dk_fastcall: h[8] at s,
; the block at s+32.
_sha256_compress:
   push ix
   ld (state),hl
   ; W[0..15], big-endian in the block.
   ld bc,32
   add hl,bc
   ld de,W+3
   ld b,16
load:
   ld a,(hl)
   ld (de),a
   inc hl
   dec de
   ld a,(hl)
   ld (de),a
   inc hl
   dec de
   ld a,(hl)
   ld (de),a
   inc hl
   dec de
   ld a,(hl)
   ld (de),a
   inc hl
   ld a,7
add7:
   inc de
   dec a
   jr nz,add7
   djnz load
   ; W[16..63] = s1(W[i-2]) + W[i-7] + s0(W[i-15]) + W[i-16].
   ld ix,W+64
   ld a,48
   ld (count),a
schedule:
   ; s0(x) = ror7 ^ ror18 ^ shr3, x = W[i-15]
   ld l,(ix-60)
   ld h,(ix-59)
   ld e,(ix-58)
   ld d,(ix-57)
   call ror8
   call rl1
   call store
   call ror8
   call rr1
   call rr1
   call rr1
   call xacc
   ld l,(ix-60)
   ld h,(ix-59)
   ld e,(ix-58)
   ld d,(ix-57)
   call sr1
   call sr1
   call sr1
   call xaccr
   ; + W[i-16] + W[i-7]
   ld a,l
   add a,(ix-64)
   ld l,a
   ld a,h
   adc a,(ix-63)
   ld h,a
   ld a,e
   adc a,(ix-62)
   ld e,a
   ld a,d
   adc a,(ix-61)
   ld d,a
   ld a,l
   add a,(ix-28)
   ld l,a
   ld a,h
   adc a,(ix-27)
   ld h,a
   ld a,e
   adc a,(ix-26)
   ld e,a
   ld a,d
   adc a,(ix-25)
   ld d,a
   ld (t1),hl
   ld (t1+2),de
   ; s1(x) = ror17 ^ ror19 ^ shr10, x = W[i-2]
   ld l,(ix-8)
   ld h,(ix-7)
   ld e,(ix-6)
   ld d,(ix-5)
   ex de,hl
   call rr1
   call store
   call rr1
   call rr1
   call xacc
   ld l,(ix-7)
   ld h,(ix-6)
   ld e,(ix-5)
   ld d,0
   call sr1
   call sr1
   call xaccr
   ld bc,t1
   call addm
   ld (ix+0),l
   ld (ix+1),h
   ld (ix+2),e
   ld (ix+3),d
   inc ix
   inc ix
   inc ix
   inc ix
   ld hl,count
   dec (hl)
   jp nz,schedule
   ; a to h from the state, at the ring's top.
   ld hl,(state)
   ld de,V+256
   ld bc,32
   ldir
   ld ix,V+256
   ld hl,k
   ld (kp),hl
   ld hl,W
   ld (wp),hl
   ld a,64
   ld (count),a
round:
   ; ch = g ^ (e & (f ^ g))
   ld a,(ix+20)
   xor (ix+24)
   and (ix+16)
   xor (ix+24)
   ld (t2),a
   ld a,(ix+21)
   xor (ix+25)
   and (ix+17)
   xor (ix+25)
   ld (t2+1),a
   ld a,(ix+22)
   xor (ix+26)
   and (ix+18)
   xor (ix+26)
   ld (t2+2),a
   ld a,(ix+23)
   xor (ix+27)
   and (ix+19)
   xor (ix+27)
   ld (t2+3),a
   ; S1(e) = ror6 ^ ror11 ^ ror25
   ld l,(ix+16)
   ld h,(ix+17)
   ld e,(ix+18)
   ld d,(ix+19)
   call ror8
   push de
   push hl
   call rl1
   call rl1
   call store
   pop hl
   pop de
   call rr1
   call rr1
   call rr1
   call xacc
   ex de,hl
   call rl1
   call rl1
   call xaccr
   ; t1 = h + S1 + ch + k[i] + w[i]
   ld a,l
   add a,(ix+28)
   ld l,a
   ld a,h
   adc a,(ix+29)
   ld h,a
   ld a,e
   adc a,(ix+30)
   ld e,a
   ld a,d
   adc a,(ix+31)
   ld d,a
   ld bc,t2
   call addm
   ld bc,(kp)
   call addm
   ld (kp),bc
   ld bc,(wp)
   call addm
   ld (wp),bc
   ld (t1),hl
   ld (t1+2),de
   ; d += t1, the next round's e
   ld a,(ix+12)
   add a,l
   ld (ix+12),a
   ld a,(ix+13)
   adc a,h
   ld (ix+13),a
   ld a,(ix+14)
   adc a,e
   ld (ix+14),a
   ld a,(ix+15)
   adc a,d
   ld (ix+15),a
   ; maj = (a & b) | (c & (a | b))
   ld a,(ix+0)
   or (ix+4)
   and (ix+8)
   ld c,a
   ld a,(ix+0)
   and (ix+4)
   or c
   ld (t2),a
   ld a,(ix+1)
   or (ix+5)
   and (ix+9)
   ld c,a
   ld a,(ix+1)
   and (ix+5)
   or c
   ld (t2+1),a
   ld a,(ix+2)
   or (ix+6)
   and (ix+10)
   ld c,a
   ld a,(ix+2)
   and (ix+6)
   or c
   ld (t2+2),a
   ld a,(ix+3)
   or (ix+7)
   and (ix+11)
   ld c,a
   ld a,(ix+3)
   and (ix+7)
   or c
   ld (t2+3),a
   ; S0(a) = ror2 ^ ror13 ^ ror22
   ld l,(ix+0)
   ld h,(ix+1)
   ld e,(ix+2)
   ld d,(ix+3)
   call rr1
   call rr1
   call store
   call ror8
   call rr1
   call rr1
   call rr1
   call xacc
   call ror8
   call rr1
   call xaccr
   ; the next round's a = t1 + S0 + maj
   ld bc,t2
   call addm
   ld bc,t1
   call addm
   ld (ix-4),l
   ld (ix-3),h
   ld (ix-2),e
   ld (ix-1),d
   dec ix
   dec ix
   dec ix
   dec ix
   ld hl,count
   dec (hl)
   jp nz,round
   ; h[j] += the ring's last eight words, now at V.
   ld ix,(state)
   ld bc,V
   ld a,8
   ld (count),a
final:
   ld l,(ix+0)
   ld h,(ix+1)
   ld e,(ix+2)
   ld d,(ix+3)
   call addm
   ld (ix+0),l
   ld (ix+1),h
   ld (ix+2),e
   ld (ix+3),d
   inc ix
   inc ix
   inc ix
   inc ix
   ld hl,count
   dec (hl)
   jr nz,final
   pop ix
   ret

; DEHL rotated right by 8.
ror8:
   ld a,l
   ld l,h
   ld h,e
   ld e,d
   ld d,a
   ret

; DEHL rotated right by 1.
rr1:
   ld a,l
   rra
   rr d
   rr e
   rr h
   rr l
   ret

; DEHL rotated left by 1.
rl1:
   ld a,d
   rla
   rl l
   rl h
   rl e
   rl d
   ret

; DEHL shifted right by 1.
sr1:
   srl d
   rr e
   rr h
   rr l
   ret

; acc = DEHL
store:
   ld (acc),hl
   ld (acc+2),de
   ret

; acc ^= DEHL, which stays.
xacc:
   ld a,(acc)
   xor l
   ld (acc),a
   ld a,(acc+1)
   xor h
   ld (acc+1),a
   ld a,(acc+2)
   xor e
   ld (acc+2),a
   ld a,(acc+3)
   xor d
   ld (acc+3),a
   ret

; DEHL ^= acc
xaccr:
   ld a,(acc)
   xor l
   ld l,a
   ld a,(acc+1)
   xor h
   ld h,a
   ld a,(acc+2)
   xor e
   ld e,a
   ld a,(acc+3)
   xor d
   ld d,a
   ret

; DEHL += the word at BC; BC moves past it.
addm:
   ld a,(bc)
   add a,l
   ld l,a
   inc bc
   ld a,(bc)
   adc a,h
   ld h,a
   inc bc
   ld a,(bc)
   adc a,e
   ld e,a
   inc bc
   ld a,(bc)
   adc a,d
   ld d,a
   inc bc
   ret

state:
   defw 0
kp:
   defw 0
wp:
   defw 0
count:
   defb 0
acc:
   defs 4
t1:
   defs 4
t2:
   defs 4

k:
   defq 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
   defq 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
   defq 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
   defq 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
   defq 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
   defq 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
   defq 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
   defq 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
