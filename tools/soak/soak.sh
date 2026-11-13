#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# A soak stand (docs/testing.md, "Soak"): a small group of this build's cbb
# runs for days on one machine, copies now and then, and has its members
# killed with SIGKILL at random moments and started again; one line a day
# goes to soak.log, and stop ends with a pass or fail line.
#
#   sh tools/soak/soak.sh start BINDIR   start (BINDIR holds cbb and cbb-helper)
#   sh tools/soak/soak.sh status         the last lines of the log
#   sh tools/soak/soak.sh verdict        the pass or fail line so far
#   sh tools/soak/soak.sh stop           stop everything, print the log and the
#                                        verdict, remove the folder
#
# Several stands run side by side, each with its own name, folder and ports:
# SOAK_NAME (calm), SOAK_DIR (~/cbb-stand/auto-checks/NAME), SOAK_PORT (the
# port base; members listen on base+1 to base+N; 47620 for calm, 47640 for
# load). Every command takes the same settings as start.
#
# SOAK_PROFILE is calm or load:
#   calm  SOAK_MEMBERS (3); a line every SOAK_COPY_EVERY (120 s) checked on
#         every member; a kill every SOAK_KILL_MIN to SOAK_KILL_MAX (600 to
#         3600 s).
#   load  SOAK_MEMBERS (8); the calm copies, and every SOAK_BURST_EVERY
#         (600 s) a burst of SOAK_BURST_LEN (60) copies one a second, some of
#         them texts at the limit, the burst's last copy checked on every
#         member; every SOAK_FILE_EVERY (1800 s) a file of up to
#         SOAK_FILE_MAX (64 MiB) checked by its hash on every member; the
#         kills fall inside a burst. The stand runs under nice 10 and, where
#         taskset is, on the one core SOAK_CPU (the last one), so that a calm
#         stand beside it keeps its numbers.
# SOAK_DAY (86400 s) is the time between lines of the log, SOAK_WARMUP
# (3600 s) the time after a member's start before its memory and open files
# are taken as its baseline, SOAK_SAMPLE (600 s) the time between samples of
# them for the verdict, SOAK_WINDOW (6 samples, an hour) how many samples make
# one window, whose floor (the least RSS and open files in it) is what the
# verdict compares: a single sample swings by megabytes as large copies come
# and go, a leak raises the floor. SOAK_GROW_MAX_KB bounds the floor's growth:
# 1024 (1 MiB) for calm, 4096 (4 MiB) for load, fixed before any long run was
# measured; a run over it is a finding, not a reason to move the number.
# Member 1 is never killed (SOAK_KEEP=1; 0 kills any member), so that one
# process lives the whole run. SOAK_DISK_MAX_KB (20480, 20 MiB) bounds how
# much each member's folder may grow a day, judged from SOAK_DISK_AFTER
# (21600 s) after the first measure on.
#
# A line of soak.log: the time, "soak", then key=value: day, copies sent,
# checked, arrived on every member, missed, kills, starts after a kill whose
# state read whole, broken ones, the delivery time of the checked copies in
# ms (p50, p95, max: the slowest member of each), the members' largest RSS in
# KiB and open files, the largest growth of a member's RSS floor over its
# first window's without a restart, and the members whose floor of open files
# left the first window's. A
# missed copy or a broken start also writes a line "soak fault".
#
# The verdict: PASS when no copy was missed (a checked copy that is not on
# every member within SOAK_WAIT, 60 s, is missed), the delivery time's p95 is
# at most SOAK_P95_MAX_MS (10000 ms), every start was whole, no member's RSS
# floor grew more than SOAK_GROW_MAX_KB over its first window's without a
# restart, no member's RSS floor rose in three windows in a row (a rise is
# a floor at least 64 KiB above the previous window's), and no
# member's floor of open files rose over the first window's, and the
# members' folders grew by at most SOAK_DISK_MAX_KB a day each; else FAIL with
# why. Beside it the raw numbers of single samples (the growth of a member's
# RSS over its first sample after warm-up, and the samples whose open files
# differed from it) are printed as raw_*, for reading, not judged.
#
# SOAK_PROFILE=family (one service process in two groups) is kept for wave
# 5, when one service holds several groups.
set -eu

umask 022
ulimit -n 65536 2>/dev/null || true
export LC_ALL=C.UTF-8

name=${SOAK_NAME:-calm}
profile=${SOAK_PROFILE:-calm}
case $profile in
calm)
	members=${SOAK_MEMBERS:-3}
	port0=${SOAK_PORT:-47620}
	;;
load)
	members=${SOAK_MEMBERS:-8}
	port0=${SOAK_PORT:-47640}
	;;
family)
	# One service process in two groups, the family case: it waits for
	# wave 5's several groups in one service.
	echo "soak: the family profile waits for one service in several groups (wave 5)" >&2
	exit 2
	;;
*)
	echo "soak: SOAK_PROFILE is calm or load" >&2
	exit 2
	;;
esac
dir=${SOAK_DIR:-$HOME/cbb-stand/auto-checks/$name}
copy_every=${SOAK_COPY_EVERY:-120}
kill_min=${SOAK_KILL_MIN:-600}
kill_max=${SOAK_KILL_MAX:-3600}
day=${SOAK_DAY:-86400}
warmup=${SOAK_WARMUP:-3600}
burst_every=${SOAK_BURST_EVERY:-600}
burst_len=${SOAK_BURST_LEN:-60}
file_every=${SOAK_FILE_EVERY:-1800}
file_max=${SOAK_FILE_MAX:-67108864}
wait_max=${SOAK_WAIT:-60}
sample_every=${SOAK_SAMPLE:-600}
window=${SOAK_WINDOW:-6}
grow_max_default=1024
[ "$profile" = load ] && grow_max_default=4096
grow_max=${SOAK_GROW_MAX_KB:-$grow_max_default}
p95_max=${SOAK_P95_MAX_MS:-10000}
# Member 1 is never killed (SOAK_KEEP=0 kills any member): a slow leak
# inside one long-lived process shows only in a process that lives the
# whole run.
keep=${SOAK_KEEP:-1}
# The members' folders (state, records, logs) may grow by at most
# SOAK_DISK_MAX_KB a day each, judged once SOAK_DISK_AFTER seconds have
# passed since the first measure after warm-up.
disk_max=${SOAK_DISK_MAX_KB:-20480}
disk_after=${SOAK_DISK_AFTER:-21600}
cbb=$dir/bin/cbb
log=$dir/soak.log
counts=$dir/counts

now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
secs() { date +%s; }
ms() { echo $(($(date +%s%N) / 1000000)); }
say() { echo "$(now) $*" >>"$log"; }
# sh has no local variables: each function keeps to names of its own.
rand() { # a number from $1 to $2
	_r=$(od -An -N4 -tu4 /dev/urandom | tr -d ' ')
	echo $(($1 + _r % ($2 - $1 + 1)))
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
	nohup "$cbb" -state "$dir/m$m" -socket "$dir/m$m/c.sock" service -name "$name-$m" \
		-port "$(port "$m")" -no-mdns $peers >>"$dir/m$m/service.log" 2>&1 &
	echo $! >"$dir/m$m/pid"
	secs >"$dir/m$m/since"
	rm -f "$dir/m$m/base" "$dir/m$m/win" "$dir/m$m/last" "$dir/m$m/prev" "$dir/m$m/raw"
}

wait_ready() { # member
	_w=0
	while [ $_w -lt 60 ]; do
		cli "$1" status >/dev/null 2>&1 && return 0
		sleep 1
		_w=$((_w + 1))
	done
	return 1
}

# The load stand yields to everything else: nice, and one core where it can.
confine() {
	[ "$profile" = load ] || return 0
	renice -n 10 -p $$ >/dev/null 2>&1 || true
	if command -v taskset >/dev/null 2>&1; then
		cpu=${SOAK_CPU:-$(($(getconf _NPROCESSORS_ONLN) - 1))}
		taskset -cp "$cpu" $$ >/dev/null 2>&1 || true
	fi
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
	m=1
	while [ "$m" -le "$members" ]; do
		p=$(port "$m")
		if (ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null) | grep -q "[.:]$p\b"; then
			echo "soak: port $p is in use; set SOAK_PORT to another base" >&2
			exit 1
		fi
		m=$((m + 1))
	done
	confine
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
	say "soak start name=$name profile=$profile members=$members ports=$((port0 + 1))-$((port0 + members))" \
		"group=$(cat "$dir/group") version=$("$cbb" version 2>/dev/null | head -n 1)" \
		"host=$(uname -m) cpus=$(getconf _NPROCESSORS_ONLN)"
	nohup sh "$0" loop >>"$dir/loop.log" 2>&1 &
	echo $! >"$dir/soak.pid"
	echo "soak: $name running in $dir; sh $0 status | verdict | stop (with the same settings)"
}

# whole: the member answers, is in the group it was in, and sees all of it.
whole() {
	st=$(cli "$1" status 2>&1) || return 1
	echo "$st" | grep -q "group $(cat "$dir/group")" || return 1
	[ "$(echo "$st" | grep -c ' Linux ')" -ge "$members" ]
}

# Waits until every member pastes text, at most wait_max seconds; adds the
# slowest member's delivery time to delivery.ms, and each member's, as it
# was first seen there (the members are asked in turn, so a time includes
# the asking before it), to delivery.members. Fails with the members
# that did not get it.
arrives() { # text, sent at (ms)
	text=$1
	sent=$2
	left=
	m=1
	while [ "$m" -le "$members" ]; do
		left="$left $m"
		m=$((m + 1))
	done
	end=$(($(secs) + wait_max))
	while [ -n "$left" ] && [ "$(secs)" -le "$end" ]; do
		still=
		for m in $left; do
			if [ "$(cli "$m" paste 2>/dev/null)" = "$text" ]; then
				echo "$m $(($(ms) - sent))" >>"$dir/delivery.members"
			else
				still="$still $m"
			fi
		done
		left=$still
		[ -z "$left" ] || sleep 0.2
	done
	[ -z "$left" ] || {
		missing=$left
		return 1
	}
	echo $(($(ms) - sent)) >>"$dir/delivery.ms"
}

# The same for a file, checked by its SHA-256 in each member's paste -o.
file_arrives() { # file, sent at (ms)
	want=$(sha256sum "$1" | cut -d' ' -f1)
	base=$(basename "$1")
	left=
	m=1
	while [ "$m" -le "$members" ]; do
		left="$left $m"
		m=$((m + 1))
	done
	end=$(($(secs) + wait_max * 4))
	while [ -n "$left" ] && [ "$(secs)" -le "$end" ]; do
		still=
		for m in $left; do
			out=$dir/m$m/out
			rm -rf "$out"
			mkdir -p "$out"
			if cli "$m" paste -o "$out" >/dev/null 2>&1 && [ -f "$out/$base" ] &&
				[ "$(sha256sum "$out/$base" | cut -d' ' -f1)" = "$want" ]; then
				echo "$m $(($(ms) - $2))" >>"$dir/delivery.members"
			else
				still="$still $m"
			fi
			rm -rf "$out"
		done
		left=$still
		[ -z "$left" ] || sleep 1
	done
	[ -z "$left" ] || {
		missing=$left
		return 1
	}
	echo $(($(ms) - $2)) >>"$dir/delivery.ms"
}

# A text of about n bytes, unique by its first line.
text_of() { # n, label
	printf '%s\n' "$2"
	head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n' | head -c "$1"
}

percentiles() { # p50 p95 max of delivery.ms
	if [ -s "$dir/delivery.ms" ]; then
		sort -n "$dir/delivery.ms" | awk '{a[NR]=$1} END {
			p50=a[int((NR+1)*0.50)]; p95=a[int((NR*0.95)+0.999)]; if (p95=="") p95=a[NR];
			printf "delivery_ms_p50=%d delivery_ms_p95=%d delivery_ms_max=%d", p50, p95, a[NR] }'
	else
		echo "delivery_ms_p50=- delivery_ms_p95=- delivery_ms_max=-"
	fi
}

# Each member's delivery time p95, for reading: which member was slow.
by_member() {
	if [ -s "$dir/delivery.members" ]; then
		sort -k1,1n -k2,2n "$dir/delivery.members" | awk '
			function out() { if (n) { i = int(n * 0.95 + 0.999); s = s (s == "" ? "" : ",") m ":" v[i] } }
			$1 != m { out(); m = $1; n = 0 }
			{ v[++n] = $2 }
			END { out(); print "delivery_ms_p95_by_member=" s }'
	else
		echo "delivery_ms_p95_by_member=-"
	fi
}

# Each member's RSS and open files. After its warm-up the samples go into
# windows of SOAK_WINDOW; a window's floor is its least RSS and open files.
# The first window's floor is the member's baseline, and each later window's
# floor is compared with it until the member restarts; the comparison of the
# last full window is what a sample reports.
usage() {
	rss=0 fds=0 grow=0 fds_moved= rises=0 raw_grow=0 raw_fds=
	m=1
	t=$(secs)
	while [ "$m" -le "$members" ]; do
		p=$(cat "$dir/m$m/pid")
		r=$(awk '/^VmRSS:/ {print $2}' "/proc/$p/status" 2>/dev/null || echo 0)
		r=${r:-0}
		f=$(find "/proc/$p/fd" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)
		[ "$r" -gt "$rss" ] && rss=$r
		[ "$f" -gt "$fds" ] && fds=$f
		if [ $((t - $(cat "$dir/m$m/since"))) -ge "$warmup" ] && [ "$r" -gt 0 ]; then
			# raw: this sample against the first sample after warm-up
			if [ ! -e "$dir/m$m/raw" ]; then
				echo "$r $f" >"$dir/m$m/raw"
			else
				read -r r0 f0 <"$dir/m$m/raw"
				[ $((r - r0)) -gt "$raw_grow" ] && raw_grow=$((r - r0))
				[ "$f" -eq "$f0" ] || raw_fds="$raw_fds$m,"
			fi
			echo "$r $f" >>"$dir/m$m/win"
			if [ "$(wc -l <"$dir/m$m/win")" -ge "$window" ]; then
				floor=$(sort -n "$dir/m$m/win" | awk 'NR == 1 {r = $1} {if (f == "" || $2 < f) f = $2} END {print r, f}')
				rm -f "$dir/m$m/win"
				fr=${floor% *} ff=${floor#* }
				if [ ! -e "$dir/m$m/base" ]; then
					echo "$floor" >"$dir/m$m/base"
					echo "$fr 0" >"$dir/m$m/prev"
					echo "0 0 0" >"$dir/m$m/last"
				else
					read -r r0 f0 <"$dir/m$m/base"
					read -r pr run <"$dir/m$m/prev"
					if [ "$fr" -ge $((pr + 64)) ]; then run=$((run + 1)); else run=0; fi
					echo "$fr $run" >"$dir/m$m/prev"
					up=0
					[ "$ff" -gt "$f0" ] && up=1
					echo "$((fr - r0)) $up $run" >"$dir/m$m/last"
				fi
			fi
			if [ -e "$dir/m$m/last" ]; then
				read -r g up run <"$dir/m$m/last"
				[ "$g" -gt "$grow" ] && grow=$g
				[ "$up" -eq 0 ] || fds_moved="$fds_moved$m,"
				[ "$run" -gt "$rises" ] && rises=$run
			fi
		fi
		m=$((m + 1))
	done
	echo "rss_kb=$rss fds=$fds rss_grow_kb=$grow rss_rises=$rises fds_moved=${fds_moved:-none}" \
		"raw_rss_grow_kb=$raw_grow raw_fds_moved=${raw_fds:-none}"
}

# How fast the members' folders grow, in KiB a day: 0 until SOAK_DISK_AFTER
# has passed since the first measure.
disk_rate() {
	d=$(du -sk "$dir"/m* 2>/dev/null | awk '{s += $1} END {print s + 0}')
	t=$(secs)
	if [ ! -e "$dir/disk0" ]; then
		echo "$t $d" >"$dir/disk0"
		echo 0
		return
	fi
	read -r dt0 d0 <"$dir/disk0"
	if [ $((t - dt0)) -lt "$disk_after" ]; then
		echo 0
		return
	fi
	echo $(((d - d0) * day / (t - dt0)))
}

# usage, counted for the verdict: every sample, and every day's line, is one.
sample() {
	u="$(usage) disk_kb_day=$(disk_rate)"
	g=$(echo "$u" | sed -n 's/.*disk_kb_day=\(-*[0-9]*\).*/\1/p')
	[ "${g:-0}" -le "$max_disk" ] || max_disk=$g
	g=$(echo "$u" | sed -n 's/.* rss_grow_kb=\([0-9]*\).*/\1/p')
	[ "${g:-0}" -le "$max_grow" ] || max_grow=$g
	n=$(echo "$u" | sed -n 's/.*rss_rises=\([0-9]*\).*/\1/p')
	[ "${n:-0}" -le "$max_rises" ] || max_rises=$n
	g=$(echo "$u" | sed -n 's/.*raw_rss_grow_kb=\([0-9]*\).*/\1/p')
	[ "${g:-0}" -le "$raw_grow" ] || raw_grow=$g
	echo "$u" | grep -q 'raw_fds_moved=none' || raw_fds=$((raw_fds + 1))
	echo "$u" | grep -q ' fds_moved=none' || fds_bad=$((fds_bad + 1))
	echo "$u"
}

save_counts() {
	echo "copies=$copies checked=$checked arrived=$arrived missed=$missed kills=$kills whole=$whole_n" \
		"broken=$broken max_grow=$max_grow max_rises=$max_rises fds_bad=$fds_bad" \
		"raw_grow=$raw_grow raw_fds=$raw_fds max_disk=$max_disk" >"$counts"
}

kill_one() {
	first=1
	[ "$keep" -eq 1 ] && [ "$members" -gt 1 ] && first=2
	victim=$(rand "$first" "$members")
	kill -9 "$(cat "$dir/m$victim/pid")" 2>/dev/null || true
	kills=$((kills + 1))
	sleep 2
	run_member "$victim"
	if wait_ready "$victim" && sleep 20 && whole "$victim"; then
		whole_n=$((whole_n + 1))
	else
		broken=$((broken + 1))
		say "soak fault kill=$kills member=$victim status=$(cli "$victim" status 2>&1 | tr '\n' '|' | cut -c1-400)"
	fi
	next_kill=$(($(secs) + $(rand "$kill_min" "$kill_max")))
}

check_text() { # text, from, sent at, what
	checked=$((checked + 1))
	if arrives "$1" "$3"; then
		arrived=$((arrived + 1))
	else
		missed=$((missed + 1))
		say "soak fault $4 from=$2 missing_on=$(echo "$missing" | tr ' ' ',')"
	fi
}

calm_copy() {
	from=$(rand 1 "$members")
	text="soak $name $copies $(now)"
	sent=$(ms)
	if echo "$text" | cli "$from" copy >/dev/null 2>&1; then
		copies=$((copies + 1))
		check_text "$text" "$from" "$sent" "copy=$((copies - 1))"
	fi
}

burst() {
	kill_at=0
	[ "$(secs)" -ge "$next_kill" ] && kill_at=$(rand 1 "$burst_len")
	b=1
	last=
	while [ "$b" -le "$burst_len" ]; do
		# A kill comes before the copy of its turn, so that the copies after
		# it measure how soon the restarted member gets them again.
		[ "$b" -eq "$kill_at" ] && kill_one
		from=$(rand 1 "$members")
		label="soak $name burst $copies $(now)"
		# One in ten at the limit of a text (1 MiB), the rest up to 4 KiB.
		if [ "$(rand 1 10)" -eq 1 ]; then size=1048000; else size=$(rand 16 4096); fi
		text_of "$size" "$label" >"$dir/text"
		sent=$(ms)
		if cli "$from" copy <"$dir/text" >/dev/null 2>&1; then
			copies=$((copies + 1))
			last=$from
		fi
		b=$((b + 1))
		sleep 1
	done
	[ -n "$last" ] && check_text "$(cat "$dir/text")" "$last" "$sent" "burst_last=$((copies - 1))"
	rm -f "$dir/text"
}

file_copy() {
	from=$(rand 1 "$members")
	n=$(rand 1 "$file_max")
	f=$dir/files/soak-$copies.bin
	mkdir -p "$dir/files"
	head -c "$n" /dev/urandom >"$f"
	sent=$(ms)
	if cli "$from" copy "$f" >/dev/null 2>&1; then
		copies=$((copies + 1))
		checked=$((checked + 1))
		if file_arrives "$f" "$sent"; then
			arrived=$((arrived + 1))
		else
			missed=$((missed + 1))
			say "soak fault file=$((copies - 1)) bytes=$n from=$from missing_on=$(echo "$missing" | tr ' ' ',')"
		fi
	fi
	rm -f "$f"
}

loop() {
	confine
	copies=0 checked=0 arrived=0 missed=0 kills=0 whole_n=0 broken=0 days=0 max_grow=0 max_rises=0 fds_bad=0 raw_grow=0 raw_fds=0 max_disk=0
	t0=$(secs)
	next_copy=$((t0 + copy_every))
	next_kill=$((t0 + $(rand "$kill_min" "$kill_max")))
	next_day=$((t0 + day))
	next_burst=$((t0 + burst_every))
	next_file=$((t0 + file_every))
	next_sample=$((t0 + warmup))
	while :; do
		t=$(secs)
		if [ "$t" -ge "$next_copy" ]; then
			calm_copy
			next_copy=$(($(secs) + copy_every))
		fi
		if [ "$profile" = load ] && [ "$(secs)" -ge "$next_burst" ]; then
			burst
			next_burst=$(($(secs) + burst_every))
		fi
		if [ "$profile" = load ] && [ "$(secs)" -ge "$next_file" ]; then
			file_copy
			next_file=$(($(secs) + file_every))
		fi
		if [ "$profile" = calm ] && [ "$(secs)" -ge "$next_kill" ]; then
			kill_one
		fi
		if [ "$(secs)" -ge "$next_sample" ]; then
			sample >/dev/null
			next_sample=$(($(secs) + sample_every))
		fi
		if [ "$(secs)" -ge "$next_day" ]; then
			days=$((days + 1))
			sample >"$dir/usage" # here, not in $(...): it counts for the verdict
			say "soak day=$days copies=$copies checked=$checked arrived=$arrived missed=$missed kills=$kills" \
				"whole=$whole_n broken=$broken $(percentiles) $(by_member) $(cat "$dir/usage")"
			next_day=$(($(secs) + day))
		fi
		save_counts
		sleep 1
	done
}

verdict() {
	[ -e "$counts" ] || {
		echo "soak verdict: nothing counted yet in $dir"
		return 0
	}
	# shellcheck disable=SC1090 # the counts are key=value lines this script wrote
	. "$counts"
	why=
	[ "$missed" -eq 0 ] || why="$why missed=$missed"
	[ "$broken" -eq 0 ] || why="$why broken=$broken"
	[ "$max_grow" -le "$grow_max" ] || why="$why rss_grow_kb=$max_grow>$grow_max"
	[ "${max_rises:-0}" -lt 3 ] || why="$why rss_rises=$max_rises"
	[ "$fds_bad" -eq 0 ] || why="$why fds_moved_samples=$fds_bad"
	[ "${max_disk:-0}" -le $((disk_max * members)) ] || why="$why disk_kb_day=$max_disk>$((disk_max * members))"
	raw="raw_rss_grow_kb=${raw_grow:-0} raw_fds_moved_samples=${raw_fds:-0}"
	p95=$(percentiles | sed -n 's/.*delivery_ms_p95=\([0-9]*\).*/\1/p')
	[ "${p95:-0}" -le "$p95_max" ] || why="$why delivery_ms_p95=$p95>$p95_max"
	head=$(sed -n '1s/^[^ ]* //p' "$log")
	if [ -z "$why" ]; then
		echo "$(now) soak verdict PASS copies=$copies checked=$checked kills=$kills whole=$whole $(percentiles) $(by_member) $raw | $head"
	else
		echo "$(now) soak verdict FAIL$why $(by_member) $raw | $head"
	fi
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
	verdict >>"$log"
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
verdict) verdict ;;
stop) stop ;;
*)
	echo "usage: sh tools/soak/soak.sh start BINDIR | status | verdict | stop" >&2
	exit 2
	;;
esac
