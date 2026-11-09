#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# The weekly run of the fleet and time suites on a Linux host with Docker
# (docs/testbench.md, "Trends and flaky cases"), from cron:
#
#   0 3 * * 0  sh $HOME/cbb-weekly/cbb/tools/bench/weekly.sh $HOME/cbb-weekly >>$HOME/cbb-weekly/weekly.log 2>&1
#
# DIR holds a checkout of the repository in DIR/cbb, which the run brings
# to origin/main and builds: the bench, the cbb under test (static), the
# time-scaled cbb (-tags benchtime) and the lite member (cargo, when
# installed). Each run's reports go to DIR/reports/DATE/fleet and
# DIR/reports/DATE/time, each compared with the newest earlier run's
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
CGO_ENABLED=0 go build -trimpath -o "$bin/cbb" ./cmd/cbb
CGO_ENABLED=0 go build -trimpath -tags benchtime -o "$bin/cbb-time" ./cmd/cbb
lite=
if command -v cargo >/dev/null 2>&1; then
	cargo build -q --locked --release -p cbb-lite
	cp target/release/cbb "$bin/cbb-lite"
	lite="-cbb-lite $bin/cbb-lite"
fi

# baseline SUITE: the newest earlier run's metrics.json of SUITE, if any.
baseline() {
	for d in $(ls -1d "$dir"/reports/*/ | sort -r); do
		[ "${d%/}" = "$out" ] && continue
		if [ -f "$d$1/metrics.json" ]; then
			echo "-baseline $d$1/metrics.json"
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
if sudo "$bin/bench" -cbb "$bin/cbb" $lite $scenario $(baseline fleet) -report "$out/fleet" fleet; then
	result fleet passed
else
	result fleet failed
	status=1
fi
# shellcheck disable=SC2046 # the option splits into words on purpose
if sudo "$bin/bench" -cbb "$bin/cbb" -cbb-time "$bin/cbb-time" $(baseline time) -report "$out/time" time; then
	result time passed
else
	result time failed
	status=1
fi
sudo chown -R "$(id -u):$(id -g)" "$out"
cp "$out/summary.txt" "$dir/last.txt"

# The last 12 runs stay.
ls -1d "$dir"/reports/*/ | sort -r | tail -n +13 | while read -r old; do rm -rf "$old"; done
cat "$dir/last.txt"
exit $status
