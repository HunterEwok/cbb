#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Lays out the ZX Spectrum Next's files for cbb.tools, where `.cbb install`
# fetches them over plain HTTP (apps/zxnext/README.md, "Install"):
#
#   sh packaging/zxnext/site.sh BUILD PI_CBB OUTDIR
#
# BUILD is apps/zxnext/build (CBB, CBB.OVL, CBB.DRV), PI_CBB the lite
# member for the Pi Zero (arm-unknown-linux-musleabihf), the one CBB was
# built with (make PI_CBB=...). OUTDIR gets
#
#   zxnext/CBB, zxnext/CBB.OVL, zxnext/CBB.DRV, zxnext/cbb
#   zxnext/LIST  a line NAME SIZE CRC32 SHA256 for each. CBB checks its
#                overlay, the driver and the Pi's cbb against its own
#                copy of their SHA-256 (apps/zxnext/pins.sh, ovl.sh),
#                never the list's; .cbb
#                update reads the list only to tell of a newer CBB
#
# The site serves zxnext/CBB at /zxnext as well, which
# `.http -h cbb.tools -u /zxnext -f CBB` fetches (docs/maintaining.md).
set -eu

[ $# -eq 3 ] || { echo "usage: $0 BUILD PI_CBB OUTDIR" >&2; exit 2; }
build=$1 pi=$2 out=$3

# CRC-32 as zlib computes it, from gzip's trailer: its first four bytes,
# little-endian.
crc32() {
    gzip -c <"$1" | tail -c 8 | od -An -tx1 -N4 | awk '{ print $4 $3 $2 $1 }'
}

mkdir -p "$out/zxnext"
for f in CBB CBB.OVL CBB.DRV; do
    test -s "$build/$f" || { echo "$0: $build/$f is missing" >&2; exit 1; }
    cp "$build/$f" "$out/zxnext/$f"
done
test -s "$pi" || { echo "$0: $pi is missing" >&2; exit 1; }
cp "$pi" "$out/zxnext/cbb"

: >"$out/zxnext/LIST"
for f in CBB CBB.OVL CBB.DRV cbb; do
    p=$out/zxnext/$f
    size=$(wc -c <"$p" | tr -d ' ')
    sha=$(sha256sum <"$p" | cut -c1-64)
    printf '%s %s %s %s\n' "$f" "$size" "$(crc32 "$p")" "$sha" >>"$out/zxnext/LIST"
done
cat "$out/zxnext/LIST"
