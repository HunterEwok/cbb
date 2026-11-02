# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# .cbb, the dot command for the ZX Spectrum Next (README.md).
#   make        build/CBB, build/PIBRIDGE and build/CBB.DRV with z88dk (zcc and
#               z88dk-z80asm on the PATH, ZCCCFG set)
#   make test   the host tests of the frame parser with cc, and the driver's in
#               an emulator (drvtest, with cargo)

ZCC ?= zcc
ASM ?= z88dk-z80asm
CC ?= cc
CARGO ?= cargo
SRC := src/cbb.c src/link.c src/frame.c

all: build/CBB build/PIBRIDGE build/CBB.DRV

build/CBB: $(SRC) src/frame.h src/link.h
	mkdir -p build
	cd build && $(ZCC) +zxn -vn -O2 -clib=new -subtype=dotn -startup=30 -I../src \
		$(addprefix ../,$(SRC)) -o cbb -create-app

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

test: build/frame_test build/drv/bank.bin build/drv/stub.bin
	./build/frame_test
	cd drvtest && $(CARGO) test -q

build/frame_test: src/frame.c src/frame.h test/frame_test.c
	mkdir -p build
	$(CC) -std=c99 -Wall -Wextra -Werror -Isrc src/frame.c test/frame_test.c -o $@

clean:
	rm -rf build

.PHONY: all test clean
