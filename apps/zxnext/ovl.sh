#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok
#
# ovl.sh BUILD: cuts the pages from OVL_FIRST on out of BUILD/CBB into
# BUILD/CBB.OVL (README.md, "Memory"). zcc links them with the rest, so
# their code calls MAIN's at its addresses, but CBB stays under 64K
# (budget.sh): NextZXOS's loader allocates each such page and leaves it
# empty (0xFE in the dotn's page table, "allocate but do not load"), and
# CBB reads it from /cbb/CBB.OVL before its first far call there (far.asm).
#
# The last four bytes of each of CBB.OVL's pages are a stamp of this
# build, which CBB checks before it runs a page, and CBB carries the stamp,
# CBB.OVL's size and its SHA-256 for .cbb install, written over the
# placeholders that pins.sh gave them.
set -eu
b=$1
map=$b/cbb.map
OVL_FIRST=19
PAGE=8192

# The address of a symbol in the map, in decimal.
addr() {
    a=$(sed -n "s/^$1 *= \\\$\\([0-9A-F]*\\) .*/\\1/p" "$map")
    test -n "$a" || { echo "ovl.sh: $1 is not in $map" >&2; exit 1; }
    printf '%d' "0x$a"
}

# Writes the bytes in hex ($2) into file $1 at offset $3.
put() {
    esc=""
    for h in $(echo "$2" | sed 's/../& /g'); do
        esc="$esc\\$(printf '%03o' "0x$h")"
    done
    # shellcheck disable=SC2059 # the escapes are the format
    printf "$esc" | dd of="$1" bs=1 seek="$3" conv=notrunc status=none
}

# The one offset of the text $2 in file $1.
find_one() {
    o=$(grep -obUaF "$2" "$1" | cut -d: -f1 || true)
    test "$(echo "$o" | wc -w)" -eq 1 || { echo "ovl.sh: $2 is not once in $1" >&2; exit 1; }
    echo "$o"
}

# The pages loaded from CBB itself, which come before the overlay's in the
# file: the divMMC page, MAIN's three, then each PAGE_ under OVL_FIRST.
loaded=0
ovl=""
for f in "$b"/cbb_PAGE_*.bin; do
    p=${f##*_PAGE_}
    p=${p%.bin}
    if [ "$p" -lt "$OVL_FIRST" ]; then
        loaded=$((loaded + 1))
    else
        ovl="$ovl $p"
    fi
done
test -n "$ovl" || { echo "ovl.sh: no page from $OVL_FIRST on" >&2; exit 1; }
start=$(((4 + loaded) * PAGE))
size=$(wc -c <"$b/CBB" | tr -d ' ')
count=$(echo "$ovl" | wc -w)
test "$size" -eq $((start + count * PAGE)) || { echo "ovl.sh: CBB is $size bytes, not $start and $count pages" >&2; exit 1; }

dd if="$b/CBB" of="$b/CBB.OVL" bs=$PAGE skip=$((start / PAGE)) status=none
dd if="$b/CBB" of="$b/CBB.new" bs=$PAGE count=$((start / PAGE)) status=none
table=$(($(addr __z_page_alloc_table) - 0x2000))
for p in $ovl; do
    put "$b/CBB.new" fe $((table + p))
done

# The stamp: the start of the SHA-256 of the pages without it.
stamp=$(sha256sum <"$b/CBB.OVL" | cut -c1-8)
i=0
for p in $ovl; do
    put "$b/CBB.OVL" "$stamp" $((i * PAGE + PAGE - 4))
    i=$((i + 1))
done
sha=$(sha256sum <"$b/CBB.OVL" | cut -c1-64)
ovl_size=$(wc -c <"$b/CBB.OVL" | tr -d ' ')
le=$(printf '%08x' "$ovl_size" | sed 's/\(..\)\(..\)\(..\)\(..\)/\4\3\2\1/')
at_stamp=$(find_one "$b/CBB.new" OVst)
at_size=$(find_one "$b/CBB.new" OVsz)
at_sha=$(find_one "$b/CBB.new" OVL-SHA256-PLACEHOLDER)
put "$b/CBB.new" "$stamp" "$at_stamp"
put "$b/CBB.new" "$le" "$at_size"
put "$b/CBB.new" "$(printf '%s' "$sha" | od -An -tx1 | tr -d ' \n')" "$at_sha"
mv "$b/CBB.new" "$b/CBB"
printf 'CBB.OVL  %5d bytes, pages%s, stamp %s\n' "$ovl_size" "$ovl" "$stamp"
