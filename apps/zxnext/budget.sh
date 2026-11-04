#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok
#
# budget.sh BUILD: .cbb's memory budget (README.md, "Memory"). Each part
# keeps at least 1K free, so that a change never has to fit by the byte:
#
#   the divMMC page (CODE, 0x2000-0x3FFF)  the library, the far calls
#   MAIN (from 0x8000)                     must end 3K under 0xE000: 2K for
#                                          the stack (about 200 bytes used),
#                                          1K to grow
#   each overlay page (0xE000-0xFFFF)      8K
#
# It prints what each part has free, and fails when one has less.
set -eu
b=$1
fail=0
check() {
    # name, file, size of its room, the bytes it must leave
    used=$(wc -c <"$2")
    free=$(($3 - used))
    printf '%-8s %5d used, %5d free\n' "$1" "$used" "$free"
    if [ "$free" -lt "$4" ]; then
        echo "budget.sh: $1 leaves under $4 bytes free" >&2
        fail=1
    fi
}
check CODE "$b/cbb_CODE.bin" 8192 1024
check MAIN "$b/cbb_MAIN.bin" 24576 3072
for f in "$b"/cbb_PAGE_*.bin; do
    page=${f##*_PAGE_}
    check "PAGE_${page%.bin}" "$f" 8192 1024
done
exit $fail
