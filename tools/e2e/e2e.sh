#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# End-to-end test of the service on Linux, with Docker: three members in
# containers on one network find each other with mDNS, pair with codes,
# and sync copies; a fourth container browses them with avahi.
#
#   sh tools/e2e/e2e.sh path/to/cbb [path/to/cli]
#
# path/to/cbb is the service, a Linux binary: the Rust program (member/), or
# the Go one (cmd/cbb); cbb-helper, the Go helper the Rust one starts for what
# needs Go, goes into the containers too when it is beside it. path/to/cli,
# when given, runs the commands against that service over its socket in
# place of path/to/cbb: the Go cbb, whose output the checks below read.
#
# With CBB_E2E_COVERDIR set to a directory, a cbb built with -cover writes its
# coverage there (GOCOVERDIR in every container), for CI's coverage summary.
#
# The containers and the network are removed at the end.
set -eu

bin=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
cli=$bin
# The Rust service runs as a computer's (-full), as the Go one always does.
full=
if [ $# -gt 1 ]; then
	cli=$(cd "$(dirname "$2")" && pwd)/$(basename "$2")
	full=-full
fi
# The containers' mounts: the service, its helper when it has one, the
# commands' program.
mounts() {
	printf -- '-v %s:/cb/cbb:ro -v %s:/cb/cli:ro' "$bin" "$cli"
	if [ -f "$(dirname "$bin")/cbb-helper" ]; then
		printf -- ' -v %s/cbb-helper:/cb/cbb-helper:ro' "$(dirname "$bin")"
	fi
}
image=${E2E_IMAGE:-debian:stable-slim}
run=cbe2e-$$
net=$run-net
members="a b c"
# Every member gets a coverage directory; a cbb built without -cover ignores it.
if [ -n "${CBB_E2E_COVERDIR:-}" ]; then
	mkdir -p "$CBB_E2E_COVERDIR"
	cover=$(cd "$CBB_E2E_COVERDIR" && pwd)
else
	cover=$(mktemp -d)
	emptycover=$cover
fi

say() { printf '== %s\n' "$*"; }
fail() {
	printf 'FAIL: %s\n' "$*" >&2
	for m in $members; do
		echo "--- log of $m" >&2
		docker logs "$run-$m" 2>&1 | tail -20 >&2 || true
		docker exec "$run-$m" cat /tmp/pair.out >&2 2>/dev/null || true
	done
	exit 1
}
cleanup() {
	for c in $members avahi; do docker stop -t 2 "$run-$c" >/dev/null 2>&1 || true; done
	docker network rm "$net" >/dev/null 2>&1 || true
	[ -z "${emptycover:-}" ] || rmdir "$emptycover" 2>/dev/null || true
}
trap cleanup EXIT

cb() { # member, arguments...
	m=$1
	shift
	docker exec -i "$run-$m" /cb/cli "$@"
}

# eventually runs a command until it succeeds, for up to 20 seconds.
eventually() {
	what=$1
	shift
	i=0
	until "$@" >/dev/null 2>&1; do
		i=$((i + 1))
		[ $i -lt 40 ] || fail "$what"
		sleep 0.5
	done
}

say "starting three members"
docker network create "$net" >/dev/null
for m in $members; do
	# shellcheck disable=SC2046 # mounts prints several flags
	docker run -d --rm --name "$run-$m" --hostname "host-$m" --network "$net" \
		-e CBB_SOCKET=/tmp/c.sock $(mounts) -v "$cover:/cover" -e GOCOVERDIR=/cover "$image" \
		/cb/cbb service $full -state /tmp -socket /tmp/c.sock >/dev/null
done
for m in $members; do
	eventually "$m starts" cb "$m" status
done

pair() { # admin, joiner
	docker exec -d "$run-$1" sh -c '/cb/cli pair >/tmp/pair.out 2>&1'
	eventually "a code on $1" docker exec "$run-$1" grep -q 'Pairing code' /tmp/pair.out
	code=$(docker exec "$run-$1" sed -n 's/^Pairing code: \([0-9]*\) \([0-9]*\)$/\1\2/p' /tmp/pair.out)
	printf '%s\n' "$code" | cb "$2" pair -code || fail "$2 could not join with the code from $1"
	eventually "$1 reports the new member" docker exec "$run-$1" grep -q "host-$2 joined" /tmp/pair.out
}

say "pairing: a creates the group and admits b, makes b an admin; b admits c"
cb a new >/dev/null || fail "a could not create the group"
pair a b
eventually "a makes b an admin" cb a admin -allow-file-key host-b
is_admin() { cb "$1" status | grep '(this device)' | grep -q ' admin '; }
eventually "b is an admin" is_admin b
pair b c
wrong=000000
cb a status | grep -q '^Device .*, group ' || fail "a is in no group"

connected() { # member, count: the other devices that cbb status lists online
	[ "$(cb "$1" status | grep -v '(this device)' | grep -c ' online ')" -eq "$2" ]
}
for m in $members; do
	eventually "$m connects to the two others" connected "$m" 2
done

say "a copy on one member reaches the others"
printf 'hello from a\n' | cb a copy
for m in b c; do
	eventually "$m has the copy" sh -c "[ \"\$(docker exec $run-$m /cb/cli paste)\" = 'hello from a' ]"
done
printf 'a secret' | cb c copy -secret
eventually "a has the secret" sh -c "[ \"\$(docker exec $run-a /cb/cli paste)\" = 'a secret' ]"

say "avahi browses the members"
docker run -d --rm --name "$run-avahi" --network "$net" "$image" sleep 600 >/dev/null
docker exec "$run-avahi" sh -c 'apt-get update -qq >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq avahi-daemon avahi-utils dbus >/dev/null' ||
	fail "installing avahi"
docker exec "$run-avahi" sh -c 'mkdir -p /run/dbus && dbus-daemon --system --fork && avahi-daemon --daemonize --no-chroot'
eventually "avahi browses the members" sh -c "[ \$(docker exec $run-avahi avahi-browse -rtp _cbb._tcp | grep -c '^=') -ge 3 ]"

say "a wrong code does not join"
# shellcheck disable=SC2046 # mounts prints several flags
docker run -d --rm --name "$run-d" --network "$net" -e CBB_SOCKET=/tmp/c.sock \
	$(mounts) -v "$cover:/cover" -e GOCOVERDIR=/cover "$image" /cb/cbb service $full -state /tmp -socket /tmp/c.sock >/dev/null
members="$members d"
eventually "d starts" cb d status
admin=${members%% *}
docker exec -d "$run-$admin" sh -c '/cb/cli pair >/tmp/pair2.out 2>&1'
eventually "a code" docker exec "$run-$admin" grep -q 'Pairing code' /tmp/pair2.out
code=$(docker exec "$run-$admin" sed -n 's/^Pairing code: \([0-9]*\) \([0-9]*\)$/\1\2/p' /tmp/pair2.out)
[ "$code" = "$wrong" ] && wrong=111111
if printf '%s\n' "$wrong" | cb d pair -code >/dev/null 2>&1; then
	fail "d joined with a wrong code"
fi
cb d status | grep -q 'Not in a group' || fail "d is in a group after a wrong code"

say "all checks passed"
