#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Runs the group simulator's seeds in batches, several at once, with one
# result file per batch, so that a stopped run resumes where it was.
#
#   sh tools/sim/seeds.sh BIN OUT JOBS SET...
#
# BIN is cbb-core's test binary (cargo test --release -p cbb-core --lib
# --no-run prints it), OUT the folder for the results, JOBS how many
# batches run at once. Each SET is NAME:FIRST:COUNT[:VAR=VALUE,...], for
# example proto:0:10000 or small:0:3000:SIM_SMALL=1,SIM_CAP=1. A batch is
# 100 seeds in one process under nice 19; its output goes to
# OUT/NAME-FIRST.txt, and a file that already ends with the test result
# is not run again. One runner per OUT: a second start exits at once.
# OUT/summary.txt counts the batches' failures by their first line.
#
# A batch waits before it starts while OUT/.pause exists or another
# program that bears no load beside it runs (a Simulator, xcodebuild, an
# emulator). To give the machine back at once:
#
#   sh tools/sim/seeds.sh pause BIN OUT    # stops the running batches
#   sh tools/sim/seeds.sh resume BIN OUT   # lets them go on
set -eu

# busy: whether another thread's simulator, build or emulator runs.
busy() {
	pgrep -f 'Simulator\.app|xcodebuild|qemu-system|/emulator/emulator' >/dev/null 2>&1
}

case "${1:-}" in
pause)
	: >"$3/.pause"
	pkill -STOP -f "$2 sim::groups_under_faults_agree" || true
	exit 0
	;;
resume)
	rm -f "$3/.pause"
	pkill -CONT -f "$2 sim::groups_under_faults_agree" || true
	exit 0
	;;
esac

if [ "${1:-}" = one ]; then
	# one batch: BIN FILE FIRST VARS
	bin=$2 file=$3 first=$4 vars=$5
	[ -n "$file" ] || exit 2
	while [ -e "$(dirname "$file")/.pause" ] || busy; do
		sleep 20
	done
	# shellcheck disable=SC2086 # the variables are split on purpose
	env SIM_ALL=1 SIM_FIRST="$first" SIM_SEEDS=100 $(echo "$vars" | tr ',' ' ') \
		nice -n 19 "$bin" sim::groups_under_faults_agree --exact >"$file.part" 2>&1 || true
	mv "$file.part" "$file"
	exit 0
fi

[ $# -ge 4 ] || {
	echo "usage: sh tools/sim/seeds.sh BIN OUT JOBS NAME:FIRST:COUNT[:VAR=VALUE,...]..." >&2
	exit 2
}
bin=$1 out=$2 jobs=$3
shift 3
mkdir -p "$out"
if ! mkdir "$out/.lock" 2>/dev/null; then
	echo "seeds: another runner holds $out/.lock" >&2
	exit 1
fi
trap 'rmdir "$out/.lock"' EXIT INT TERM

list=$out/.batches
: >"$list"
for set in "$@"; do
	name=$(echo "$set" | cut -d: -f1)
	first=$(echo "$set" | cut -d: -f2)
	count=$(echo "$set" | cut -d: -f3)
	vars=$(echo "$set" | cut -d: -f4)
	n=$first
	while [ "$n" -lt $((first + count)) ]; do
		f=$out/$name-$n.txt
		if ! tail -n 3 "$f" 2>/dev/null | grep -q '^test result'; then
			echo "$f $n ${vars:-SIM_NONE=1}" >>"$list"
		fi
		n=$((n + 100))
	done
done
if [ -s "$list" ]; then
	# shellcheck disable=SC2016 # expanded by the inner sh
	xargs -P "$jobs" -L 1 sh -c 'exec sh "$0" one "$1" "$2" "$3" "$4"' "$0" "$bin" <"$list"
fi
rm -f "$list"

{
	for set in "$@"; do
		name=$(echo "$set" | cut -d: -f1)
		files=$(ls "$out/$name"-*.txt 2>/dev/null | wc -l)
		echo "$name: $files batches"
		cat "$out/$name"-*.txt 2>/dev/null | sed -n 's/^sim seed [0-9]* failed: //p' |
			sed 's/m[0-9][0-9]*/mN/g' | sort | uniq -c | sort -rn
		for shape in $(cat "$out/$name"-*.txt 2>/dev/null | sed -n 's/^sim seed \([0-9]*\) failed: .*/\1/p' | sort -n | head -1); do
			echo "  lowest failing seed: $shape"
		done
	done
} >"$out/summary.txt"
cat "$out/summary.txt"
