#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok
#
# formats.sh FILE...: the zcc flags that build z88dk's printf and scanf
# with only the conversions the C files use (%s, %u, %lu, ...), which
# keeps some 1.4K of the divMMC page, where the library is, free. Each
# conversion found goes in both, so a format string never loses one
# whichever function takes it; one z88dk does not offer, or does not
# build (%f, %ll...), fails here rather than printing wrong on the Next.
set -eu
used=$(sed 's/%%//g' "$@" | grep -o '%[-+ #0]*[0-9]*\(\.[0-9]*\)\{0,1\}l\{0,2\}[a-zA-Z]' |
    sed 's/^%[-+ #0]*[0-9]*\(\.[0-9]*\)\{0,1\}//' | sort -u)
mask=0
for c in $used; do
    case $c in
    d) b=0x1 ;; u) b=0x2 ;; x) b=0x4 ;; X) b=0x8 ;; o) b=0x10 ;; n) b=0x20 ;;
    i) b=0x40 ;; p) b=0x80 ;; B) b=0x100 ;; s) b=0x200 ;; c) b=0x400 ;; I) b=0x800 ;;
    ld) b=0x1000 ;; lu) b=0x2000 ;; lx) b=0x4000 ;; lX) b=0x8000 ;; lo) b=0x10000 ;;
    ln) b=0x20000 ;; li) b=0x40000 ;; lp) b=0x80000 ;; lB) b=0x100000 ;;
    *)
        echo "formats.sh: %$c is not built into printf and scanf here; add it to formats.sh" >&2
        exit 1
        ;;
    esac
    mask=$((mask | b))
done
printf -- '-pragma-define:CLIB_OPT_PRINTF=0x%x -pragma-define:CLIB_OPT_SCANF=0x%x\n' "$mask" "$mask"
