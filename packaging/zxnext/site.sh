#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Lays out the ZX Spectrum Next's files for cbb.tools, where `.cbb install`
# fetches them over plain HTTP (apps/zxnext/README.md, "Install"):
#
#   sh packaging/zxnext/site.sh BUILD PI_CBB OUTDIR
#
# BUILD is apps/zxnext/build (CBB, CBB.DRV, PIBRIDGE), PI_CBB the lite
# member for the Pi Zero (arm-unknown-linux-musleabihf). OUTDIR gets
#
#   n            CBB again: `.http -h cbb.tools -u /n -f CBB` fetches it
#   next/CBB, next/CBB.DRV, next/PIBRIDGE, next/cbb
#   next/LIST    a line NAME SIZE CRC32 MD5 for each, which .cbb checks
#                each download against (CRC-32 on the Next, MD5 on the Pi)
set -eu

[ $# -eq 3 ] || { echo "usage: $0 BUILD PI_CBB OUTDIR" >&2; exit 2; }
build=$1 pi=$2 out=$3

# CRC-32 as zlib computes it, from gzip's trailer: its first four bytes,
# little-endian.
crc32() {
    gzip -c <"$1" | tail -c 8 | od -An -tx1 -N4 | awk '{ print $4 $3 $2 $1 }'
}

mkdir -p "$out/next"
for f in CBB CBB.DRV PIBRIDGE; do
    test -s "$build/$f" || { echo "$0: $build/$f is missing" >&2; exit 1; }
    cp "$build/$f" "$out/next/$f"
done
test -s "$pi" || { echo "$0: $pi is missing" >&2; exit 1; }
cp "$pi" "$out/next/cbb"
cp "$build/CBB" "$out/n"

: >"$out/next/LIST"
for f in CBB CBB.DRV PIBRIDGE cbb; do
    p=$out/next/$f
    size=$(wc -c <"$p" | tr -d ' ')
    md5=$(md5sum <"$p" | cut -c1-32)
    printf '%s %s %s %s\n' "$f" "$size" "$(crc32 "$p")" "$md5" >>"$out/next/LIST"
done
cat "$out/next/LIST"
