#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# The weekly run of the fleet and time suites on a Linux host with Docker
# (docs/maintainers/testbench.md, "Trends and flaky cases"), from cron:
#
#   0 3 * * 0  sh $HOME/cbb-weekly/cbb/tools/bench/weekly.sh $HOME/cbb-weekly >>$HOME/cbb-weekly/weekly.log 2>&1
#
# DIR holds a checkout of the repository in DIR/cbb, which the run brings
# to origin/main and builds (Go and cargo): the bench, the Rust cbb under
# test (the fleet's computers and small devices) with cbb-helper,
# cbb-forward and cbb-relay beside it, and its time-scaled build
# (--features benchtime).
# Each run's reports go to DIR/reports/DATE/fleet and DIR/reports/DATE/time, each compared with the newest earlier run's
# metrics.json (-baseline). It keeps the last 12 runs, writes DIR/last.txt
# with the commit and each suite's result, and exits 1 when a suite
# failed. CBB_WEEKLY_SCENARIO limits the fleet to some scenarios.
set -eu

[ $# -eq 1 ] || {
	echo "usage: sh tools/bench/weekly.sh DIR" >&2
	exit 2
}
dir=$(cd "$1" && pwd)
src=$dir/cbb
bin=$dir/bin
date=$(date -u +%Y-%m-%d)
out=$dir/reports/$date
mkdir -p "$bin" "$out"

cd "$src"
git fetch -q origin main
git checkout -q --detach origin/main
commit=$(git rev-parse --short HEAD)
echo "weekly.sh: $date, main at $commit"

go build -o "$bin/bench" ./tools/bench
# The Rust cbb with what it runs beside it (tools/bench/fleet.go), and its
# time-scaled build in a directory of its own with the same helpers.
cargo build -q --locked --release --bin cbb
cargo build -q --locked --release --bin cbb --features benchtime --target-dir target/benchtime
mkdir -p "$bin/time"
cp target/release/cbb "$bin/cbb"
cp target/benchtime/release/cbb "$bin/time/cbb"
[ ! -f target/release/cbb-relay ] || cp target/release/cbb-relay "$bin/cbb-relay"
for p in cbb-helper cbb-forward; do
	CGO_ENABLED=0 go build -trimpath -o "$bin/$p" "./cmd/$p"
	cp "$bin/$p" "$bin/time/$p"
done

# baseline SUITE: the newest earlier run's metrics.json of SUITE, if any.
baseline() {
	for d in $(find "$dir/reports" -mindepth 1 -maxdepth 1 -type d | sort -r); do
		[ "$d" = "$out" ] && continue
		if [ -f "$d/$1/metrics.json" ]; then
			echo "-baseline $d/$1/metrics.json"
			return
		fi
	done
}

status=0
result() { echo "$1: $2" >>"$out/summary.txt"; }
: >"$out/summary.txt"
echo "commit: $commit" >>"$out/summary.txt"

scenario=
if [ -n "${CBB_WEEKLY_SCENARIO:-}" ]; then scenario="-scenario $CBB_WEEKLY_SCENARIO"; fi
# shellcheck disable=SC2046,SC2086 # the options split into words on purpose
if sudo "$bin/bench" -cbb "$bin/cbb" $scenario $(baseline fleet) -report "$out/fleet" fleet; then
	result fleet passed
else
	result fleet failed
	status=1
fi
# shellcheck disable=SC2046 # the option splits into words on purpose
if sudo "$bin/bench" -cbb "$bin/cbb" -cbb-time "$bin/time/cbb" $(baseline time) -report "$out/time" time; then
	result time passed
else
	result time failed
	status=1
fi
sudo chown -R "$(id -u):$(id -g)" "$out"
cp "$out/summary.txt" "$dir/last.txt"

# The last 12 runs stay.
find "$dir/reports" -mindepth 1 -maxdepth 1 -type d | sort -r | tail -n +13 | while read -r old; do rm -rf "$old"; done
cat "$dir/last.txt"
exit $status
