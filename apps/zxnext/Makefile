# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# .cbb, the dot command for the ZX Spectrum Next (README.md).
#   make PI_CBB=FILE
#               build/CBB, build/PIBRIDGE and build/CBB.DRV with z88dk (zcc and
#               z88dk-z80asm on the PATH, ZCCCFG set); FILE is the Pi's cbb, the
#               lite member for ARMv6, whose size and SHA-256 CBB carries with
#               the driver's (pins.sh), as it installs only those
#   make test   the host tests of the frame parser and SHA-256 with cc, and the
#               driver's in an emulator (drvtest, with cargo)

ZCC ?= zcc
ASM ?= z88dk-z80asm
CC ?= cc
CARGO ?= cargo
PI_CBB ?=
SRC := src/cbb.c src/link.c src/frame.c src/sha256.c

all: build/CBB build/PIBRIDGE build/CBB.DRV

build/pins.h: pins.sh build/CBB.DRV $(PI_CBB)
	@test -n "$(PI_CBB)" || { echo "make: PI_CBB names the Pi's cbb, which CBB installs" >&2; exit 1; }
	sh pins.sh build/CBB.DRV $(PI_CBB) >$@.new
	mv $@.new $@

build/CBB: $(SRC) src/far.asm src/logo.h src/frame.h src/link.h src/sha256.h build/pins.h
	mkdir -p build
	cd build && $(ZCC) +zxn -vn -O2 -clib=new -subtype=dotn -startup=30 -I../src -I. \
		$(addprefix ../,$(SRC)) ../src/far.asm -o cbb -create-app
	@# MAIN ends below 0xE000, where the overlays show (src/far.asm).
	@test $$(wc -c < build/cbb_MAIN.bin) -le 24576 || \
		{ echo "CBB: MAIN reaches 0xE000, where the overlays show (src/far.asm)"; mv build/CBB build/CBB.bad; exit 1; }

build/PIBRIDGE: src/pibridge.c src/link.c src/link.h src/frame.c src/frame.h
	mkdir -p build
	cd build && $(ZCC) +zxn -vn -O2 -clib=new -subtype=dotn -startup=30 -I../src \
		../src/pibridge.c ../src/link.c ../src/frame.c -o pibridge -create-app

# The driver: the 512 bytes and the bank, then the file that holds both,
# with the stub's patch offsets taken from its map.
build/drv/stub.bin: drv/stub.asm
	mkdir -p build/drv
	cp drv/stub.asm build/drv/
	cd build/drv && $(ASM) -mz80n -b -m stub.asm
	test $$(wc -c < $@) -eq 512

build/drv/bank.bin: drv/bank.asm
	mkdir -p build/drv
	cp drv/bank.asm build/drv/
	cd build/drv && $(ASM) -mz80 -b -m bank.asm

build/CBB.DRV: drv/drv.asm build/drv/stub.bin build/drv/bank.bin
	cp drv/drv.asm build/drv/
	cd build/drv && $(ASM) -mz80 -b \
		-DSTUB_BANK_IM=$$(sed -n 's/^BANK_IM *= \$$\([0-9A-F]*\).*/0x\1/p' stub.map) \
		-DSTUB_BANK_API=$$(sed -n 's/^BANK_API *= \$$\([0-9A-F]*\).*/0x\1/p' stub.map) \
		-odrv.bin drv.asm
	cp build/drv/drv.bin $@

test: build/frame_test build/sha256_test build/drv/bank.bin build/drv/stub.bin
	./build/frame_test
	./build/sha256_test
	cd drvtest && $(CARGO) test -q

build/frame_test: src/frame.c src/frame.h test/frame_test.c
	mkdir -p build
	$(CC) -std=c99 -Wall -Wextra -Werror -Isrc src/frame.c test/frame_test.c -o $@

build/sha256_test: src/sha256.c src/sha256.h test/sha256_test.c
	mkdir -p build
	$(CC) -std=c99 -Wall -Wextra -Werror -Isrc src/sha256.c test/sha256_test.c -o $@

clean:
	rm -rf build

.PHONY: all test clean
