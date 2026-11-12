#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# A soak stand (docs/testing.md, "Soak"): a small group of this build's cbb
# runs for weeks on one machine, copies a line now and then, and has one of
# its members killed with SIGKILL at a random moment and started again; one
# line a day goes to soak.log.
#
#   sh tools/soak/soak.sh start BINDIR   start (BINDIR holds cbb and cbb-helper)
#   sh tools/soak/soak.sh status         the last lines of the log
#   sh tools/soak/soak.sh stop           stop everything, print the log, remove the folder
#
# The members talk on 127.0.0.1 only (-no-mdns, -peer), so the stand does
# not meet the network's other devices; nothing is installed. The folder is
# SOAK_DIR (~/cbb-stand/auto-checks by default; the shared bench's rule is
# one folder per thread). Settings: SOAK_MEMBERS (3), SOAK_PORT (47610, the
# first member's port), SOAK_COPY_EVERY (120 s), SOAK_KILL_MIN and
# SOAK_KILL_MAX (600 and 3600 s between kills), SOAK_DAY (86400 s between
# lines of the log).
#
# A line of soak.log: the time, "soak", then key=value: day, copies sent,
# arrived on every running member, missed, kills, starts after a kill
# whose state read whole, broken ones, the members' largest RSS in KiB and
# open files. A broken start or a missed copy also writes a line "soak
# fault" with what was seen.
set -eu

umask 022
ulimit -n 65536 2>/dev/null || true
export LC_ALL=C.UTF-8

dir=${SOAK_DIR:-$HOME/cbb-stand/auto-checks}
members=${SOAK_MEMBERS:-3}
port0=${SOAK_PORT:-47610}
copy_every=${SOAK_COPY_EVERY:-120}
kill_min=${SOAK_KILL_MIN:-600}
kill_max=${SOAK_KILL_MAX:-3600}
day=${SOAK_DAY:-86400}
cbb=$dir/bin/cbb
log=$dir/soak.log

now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
say() { echo "$(now) $*" >>"$log"; }
rand() { # a number from $1 to $2
	n=$(od -An -N4 -tu4 /dev/urandom | tr -d ' ')
	echo $(($1 + n % ($2 - $1 + 1)))
}
port() { echo $((port0 + $1)); }
cli() { # member, then the command
	m=$1
	shift
	"$cbb" -state "$dir/m$m" -socket "$dir/m$m/c.sock" "$@"
}

run_member() {
	m=$1
	peers=
	i=1
	while [ "$i" -le "$members" ]; do
		[ "$i" -ne "$m" ] && peers="$peers -peer 127.0.0.1:$(port "$i")"
		i=$((i + 1))
	done
	# shellcheck disable=SC2086 # the peers are words
	nohup "$cbb" -state "$dir/m$m" -socket "$dir/m$m/c.sock" service -name "soak-$m" \
		-port "$(port "$m")" -no-mdns $peers >>"$dir/m$m/service.log" 2>&1 &
	echo $! >"$dir/m$m/pid"
}

wait_ready() { # member
	i=0
	while [ $i -lt 60 ]; do
		cli "$1" status >/dev/null 2>&1 && return 0
		sleep 1
		i=$((i + 1))
	done
	return 1
}

start() {
	bin=$1
	[ -x "$bin/cbb" ] && [ -x "$bin/cbb-helper" ] || {
		echo "soak: $bin has no cbb and cbb-helper" >&2
		exit 2
	}
	[ ! -e "$dir/soak.pid" ] || {
		echo "soak: already running in $dir (soak.sh stop first)" >&2
		exit 1
	}
	mkdir -p "$dir/bin"
	cp "$bin/cbb" "$bin/cbb-helper" "$dir/bin/"
	m=1
	while [ "$m" -le "$members" ]; do
		mkdir -p "$dir/m$m"
		run_member "$m"
		wait_ready "$m" || {
			echo "soak: member $m did not start; see $dir/m$m/service.log" >&2
			exit 1
		}
		m=$((m + 1))
	done
	cli 1 new >/dev/null
	m=2
	while [ "$m" -le "$members" ]; do
		cli 1 pair >"$dir/pair.out" 2>&1 &
		pair=$!
		code=
		i=0
		while [ -z "$code" ] && [ $i -lt 30 ]; do
			sleep 1
			code=$(sed -n 's/^Pairing code: //p' "$dir/pair.out" | tr -d ' ')
			i=$((i + 1))
		done
		echo "$code" | cli "$m" pair -code "127.0.0.1:$(port 1)" >/dev/null
		wait "$pair" || true
		m=$((m + 1))
	done
	cli 1 status | sed -n 's/.*group \([0-9a-f]*\).*/\1/p' | head -n 1 >"$dir/group"
	say "soak start members=$members group=$(cat "$dir/group") version=$("$cbb" version 2>/dev/null | head -n 1)"
	nohup sh "$0" loop >>"$dir/loop.log" 2>&1 &
	echo $! >"$dir/soak.pid"
	echo "soak: running in $dir; sh $0 status | stop"
}

# whole: the member answers, is in the group it was in, and sees all of it.
whole() {
	st=$(cli "$1" status 2>&1) || return 1
	echo "$st" | grep -q "group $(cat "$dir/group")" || return 1
	[ "$(echo "$st" | grep -c ' Linux ')" -ge "$members" ]
}

usage() { # largest RSS in KiB and open files of the members
	rss=0
	fds=0
	m=1
	while [ "$m" -le "$members" ]; do
		p=$(cat "$dir/m$m/pid")
		r=$(awk '/^VmRSS:/ {print $2}' "/proc/$p/status" 2>/dev/null || echo 0)
		f=$(find "/proc/$p/fd" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)
		[ "${r:-0}" -gt "$rss" ] && rss=$r
		[ "$f" -gt "$fds" ] && fds=$f
		m=$((m + 1))
	done
	echo "rss_kb=$rss fds=$fds"
}

loop() {
	copies=0 arrived=0 missed=0 kills=0 whole_n=0 broken=0 days=0
	t=0
	next_kill=$(rand "$kill_min" "$kill_max")
	next_day=$day
	while :; do
		sleep "$copy_every"
		t=$((t + copy_every))
		from=$(rand 1 "$members")
		text="soak $copies $(now)"
		if echo "$text" | cli "$from" copy >/dev/null 2>&1; then
			copies=$((copies + 1))
			sleep 30
			t=$((t + 30))
			ok=1
			m=1
			while [ "$m" -le "$members" ]; do
				if [ "$(cli "$m" paste 2>/dev/null)" != "$text" ]; then
					ok=0
					say "soak fault copy=$((copies - 1)) from=$from missing_on=$m"
				fi
				m=$((m + 1))
			done
			if [ $ok -eq 1 ]; then arrived=$((arrived + 1)); else missed=$((missed + 1)); fi
		fi
		if [ "$t" -ge "$next_kill" ]; then
			m=$(rand 1 "$members")
			kill -9 "$(cat "$dir/m$m/pid")" 2>/dev/null || true
			kills=$((kills + 1))
			sleep 2
			run_member "$m"
			if wait_ready "$m" && sleep 20 && whole "$m"; then
				whole_n=$((whole_n + 1))
			else
				broken=$((broken + 1))
				say "soak fault kill=$kills member=$m status=$(cli "$m" status 2>&1 | tr '\n' '|' | cut -c1-400)"
			fi
			next_kill=$((t + $(rand "$kill_min" "$kill_max")))
		fi
		if [ "$t" -ge "$next_day" ]; then
			days=$((days + 1))
			say "soak day=$days copies=$copies arrived=$arrived missed=$missed kills=$kills whole=$whole_n broken=$broken $(usage)"
			next_day=$((t + day))
		fi
	done
}

stop() {
	[ -d "$dir" ] || {
		echo "soak: nothing in $dir"
		return 0
	}
	if [ -e "$dir/soak.pid" ]; then
		kill "$(cat "$dir/soak.pid")" 2>/dev/null || true
	fi
	m=1
	while [ -e "$dir/m$m/pid" ]; do
		kill "$(cat "$dir/m$m/pid")" 2>/dev/null || true
		m=$((m + 1))
	done
	sleep 2
	m=1
	while [ -e "$dir/m$m/pid" ]; do
		kill -9 "$(cat "$dir/m$m/pid")" 2>/dev/null || true
		m=$((m + 1))
	done
	say "soak stop"
	cat "$log"
	rm -rf "$dir"
}

case ${1:-} in
start)
	[ $# -eq 2 ] || {
		echo "usage: sh tools/soak/soak.sh start BINDIR" >&2
		exit 2
	}
	start "$2"
	;;
loop) loop ;;
status) tail -n 20 "$log" ;;
stop) stop ;;
*)
	echo "usage: sh tools/soak/soak.sh start BINDIR | status | stop" >&2
	exit 2
	;;
esac
