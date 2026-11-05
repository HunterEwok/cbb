#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Writes pins.h, the size and SHA-256 of the files that .cbb install puts in
# place, so that a CBB installs only the driver and the Pi's cbb built with
# it, whatever the site serves (README.md, "Install"):
#
#   sh pins.sh CBB.DRV PI_CBB >pins.h
set -eu

[ $# -eq 2 ] || { echo "usage: $0 CBB.DRV PI_CBB" >&2; exit 2; }
for f in "$1" "$2"; do
	test -s "$f" || { echo "$0: $f is missing" >&2; exit 1; }
done
pin() {
	printf '#define PIN_%s_SIZE %sUL\n' "$1" "$(wc -c <"$2" | tr -d ' ')"
	printf '#define PIN_%s_SHA256 "%s"\n' "$1" "$(sha256sum <"$2" | cut -c1-64)"
}
echo "// Made by pins.sh: the files built with this CBB."
pin DRV "$1"
pin PI "$2"
# CBB.OVL is linked with CBB, so ovl.sh writes its size, its SHA-256 and
# the stamp of its pages over these, after the link.
echo '#define PIN_OVL_SIZE 0x7A73564FUL // "OVsz"'
echo '#define PIN_OVL_SHA256 "OVL-SHA256-PLACEHOLDER@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"'
echo '#define OVL_STAMP "OVst"'
