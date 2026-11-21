#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Measures what each part of the core costs in a small device's flash: builds
# tools/size for the ESP32-C6's RISC-V once per part and once with all of them,
# and prints a Markdown table of each program's code and constants (.text,
# .rodata and .data) and its cost over the empty program, compared with
# baseline.txt. With -update it writes baseline.txt instead.
#
#   sh tools/size/size.sh [-update]
#
# It fails when everything together grows more than 10% over the baseline;
# a larger core on purpose updates baseline.txt in the same pull request
# (docs/testing.md, "Firmware size").
set -eu

cd "$(dirname "$0")/../.."
target=riscv32imac-unknown-none-elf
baseline=tools/size/baseline.txt
parts="p256 json records seal copy pair tls"
all=$(echo "$parts" | tr ' ' ',')

# The flash a program takes: its code, constants and initial data, without
# the unwinding tables a panic=abort build never reads.
flash() {
	size -A "$1" | awk '$1 == ".text" || $1 == ".rodata" || $1 == ".data" || $1 == ".sdata" || $1 == ".srodata" { n += $2 } END { print n + 0 }'
}

measure() { # name, features
	if [ -n "$2" ]; then
		cargo build -q --locked --release -p cbb-size --target "$target" --features "$2" >&2
	else
		cargo build -q --locked --release -p cbb-size --target "$target" >&2
	fi
	echo "$1 $(flash "target/$target/release/cbb-size")"
}

out=$(mktemp)
trap 'rm -f "$out"' EXIT
measure none "" >>"$out"
for p in $parts; do measure "$p" "$p" >>"$out"; done
measure all "$all" >>"$out"
measure api api >>"$out"

if [ "${1:-}" = -update ]; then
	{
		echo "# What tools/size/size.sh measured: part, bytes of flash (riscv32imac, opt-level s)."
		cat "$out"
	} >"$baseline"
	cat "$baseline"
	exit 0
fi

awk -v base="$baseline" '
BEGIN {
	while ((getline line < base) > 0) {
		if (line ~ /^#/) continue
		split(line, f, " "); was[f[1]] = f[2]
	}
}
$1 == "none" { none = $2; wasnone = was["none"] }
{ name[NR] = $1; now[NR] = $2 }
END {
	print "| Part | Flash, bytes | Cost over the empty program | Baseline cost | Change |"
	print "|---|---:|---:|---:|---:|"
	for (i = 1; i <= NR; i++) {
		n = name[i]; cost = now[i] - none
		if (n in was) {
			bcost = was[n] - wasnone
			change = bcost > 0 ? sprintf("%+.1f%%", 100 * (cost - bcost) / bcost) : "—"
		} else { bcost = "—"; change = "new" }
		if (n == "none") { cost = "—"; bcost = "—"; change = "—" }
		printf "| %s | %d | %s | %s | %s |\n", n, now[i], cost, bcost, change
		if (n == "all" && (n in was) && now[i] > was[n] * 1.10) grown = 1
	}
	if (grown) {
		print "\nEverything together grew more than 10% over tools/size/baseline.txt; if on purpose, run sh tools/size/size.sh -update." > "/dev/stderr"
		exit 1
	}
}' "$out"
