# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# .cbb, the dot command for the ZX Spectrum Next (README.md).
#   make PI_CBB=FILE
#               build/CBB, build/CBB.OVL, build/PIBRIDGE and build/CBB.DRV with z88dk (zcc and
#               z88dk-z80asm on the PATH, ZCCCFG set); FILE is the Pi's cbb, the
#               one for ARMv6, whose size and SHA-256 CBB carries with
#               the driver's (pins.sh), as it installs only those
#   make test   the host tests of the frame parser and SHA-256 with cc, the
#               driver's in an emulator, and with build/CBB (make
#               PI_CBB=build/PIBRIDGE first) .cbb itself on a played Next
#               (drvtest, with cargo; README.md, "Testing on a played Next")

ZCC ?= zcc
ASM ?= z88dk-z80asm
CC ?= cc
CARGO ?= cargo
PI_CBB ?=
# The site's folder .cbb install and update fetch from; another one for a
# test build (make SITE_DIR=/zxn/).
SITE_DIR ?= /zxnext/
SRC := src/cbb.c src/link.c src/frame.c src/sha256.c

all: build/CBB build/PIBRIDGE build/CBB.DRV

build/pins.h: pins.sh build/CBB.DRV $(PI_CBB) build/CBBPI.GZ
	sh pins.sh build/CBB.DRV $(PI_CBB) build/CBBPI.GZ >$@.new
	mv $@.new $@

# The Pi's cbb as the site serves it to an install, gzipped: less than
# half the bytes to fetch and to send, which the Pi unpacks
# (packaging/zxnext/site.sh copies it).
build/CBBPI.GZ: $(PI_CBB) build/pi_cbb
	@test -n "$(PI_CBB)" || { echo "make: PI_CBB names the Pi's cbb, which CBB installs" >&2; exit 1; }
	gzip -9n -c $(PI_CBB) >$@.new
	mv $@.new $@

# Which file PI_CBB names, so that another one makes pins.h again.
build/pi_cbb: FORCE
	@mkdir -p build
	@echo '$(PI_CBB)' | cmp -s - $@ || echo '$(PI_CBB)' >$@

# SITE_DIR as cbb.c takes it, made again when it changes.
build/site.h: FORCE
	@mkdir -p build
	@echo '#define SITE_DIR "$(SITE_DIR)"' | cmp -s - $@ || echo '#define SITE_DIR "$(SITE_DIR)"' >$@

# printf and scanf with only the conversions the code uses (formats.sh).
build/formats: formats.sh $(SRC)
	mkdir -p build
	sh formats.sh $(SRC) >$@.new
	mv $@.new $@

build/CBB.OVL: build/CBB

build/CBB: mapcheck.sh budget.sh ovl.sh $(SRC) src/far.asm src/stack.asm src/sha256.asm src/logo.h src/frame.h src/link.h src/sha256.h build/pins.h build/formats build/site.h
	@# The stack starts at 0xE000, under the overlays' window (src/far.asm):
	@# z88dk's default, the top of memory, is in it. The page tables go
	@# up to the last page used, not z88dk's 223.
	rm -f build/cbb_PAGE_*.bin
	cd build && $(ZCC) +zxn -vn -O2 -clib=new -subtype=dotn -startup=30 -I../src -I. $$(cat formats) \
		-pragma-define:REGISTER_SP=0xE000 -pragma-define:DOTN_LAST_PAGE=21 \
		$(addprefix ../,$(SRC)) ../src/far.asm ../src/stack.asm ../src/sha256.asm -o cbb -create-app -m
	@# The pages from 19 on go to CBB.OVL, which CBB loads (ovl.sh).
	@sh ovl.sh build || { mv build/CBB build/CBB.bad; exit 1; }
	@# The memory budget, with room to grow everywhere (README.md, "Memory"):
	@# zcc does not check that an overlay fits its 8K page, nor MAIN the
	@# stack's room under 0xE000 (src/stack.asm).
	@sh budget.sh build || { mv build/CBB build/CBB.bad; exit 1; }
	@# No function shares its address with its own static data (mapcheck.sh).
	@sh mapcheck.sh build/cbb.map || { mv build/CBB build/CBB.bad; exit 1; }

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

.PHONY: all test clean FORCE
