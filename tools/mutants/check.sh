#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Fails when cargo mutants left a mutant alive that the known list does not
# name (docs/testing.md, "Mutation testing"). Lines are compared without
# their line and column, so that an edit above a known survivor does not
# count as a new one; a survivor that appears once more than the list holds
# does.
#
#   tools/mutants/check.sh mutants.out/missed.txt tools/mutants/missed.txt
set -eu
missed=$1
known=$2
[ -f "$missed" ] || { echo "no $missed: cargo mutants did not finish"; exit 1; }
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
sed -E 's/^([^:]+):[0-9]+:[0-9]+: /\1: /' "$missed" | LC_ALL=C sort >"$tmp/missed"
grep -v '^#' "$known" | grep -v '^$' | LC_ALL=C sort >"$tmp/known"
LC_ALL=C comm -23 "$tmp/missed" "$tmp/known" >"$tmp/new"
if [ -s "$tmp/new" ]; then
	echo "Mutants the tests let live that $known does not name:"
	sed 's/^/  /' "$tmp/new"
	echo "Write a test that tells each from the code, or, for one that changes"
	echo "nothing (an equivalent mutant), add it to $known with why."
	exit 1
fi
echo "No new survivors ($(wc -l <"$tmp/missed") known)."
