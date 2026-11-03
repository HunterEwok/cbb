#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# End-to-end test of the service on Linux, with Docker: three members in
# containers on one network find each other with mDNS, pair with codes,
# sync copies, and hand cbb.local over; a fourth container plays the
# iPhone's resolver with avahi.
#
#   sh tools/e2e/e2e.sh path/to/cbb     # a static Linux binary
#
# With CBB_E2E_COVERDIR set to a directory, a cbb built with -cover writes its
# coverage there (GOCOVERDIR in every container), for CI's coverage summary.
#
# The containers and the network are removed at the end.
set -eu

bin=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
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
	done
	exit 1
}
cleanup() {
	for c in $members phone; do docker stop -t 2 "$run-$c" >/dev/null 2>&1 || true; done
	docker network rm "$net" >/dev/null 2>&1 || true
	[ -z "${emptycover:-}" ] || rmdir "$emptycover" 2>/dev/null || true
}
trap cleanup EXIT

cb() { # member, arguments...
	m=$1
	shift
	docker exec -i "$run-$m" /cb/cbb "$@"
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
	docker run -d --rm --name "$run-$m" --hostname "host-$m" --network "$net" \
		-e CBB_SOCKET=/tmp/c.sock -v "$bin:/cb/cbb:ro" -v "$cover:/cover" -e GOCOVERDIR=/cover "$image" \
		/cb/cbb service -state /tmp -socket /tmp/c.sock >/dev/null
done
for m in $members; do
	eventually "$m starts" cb "$m" status
done

pair() { # admin, joiner
	docker exec -d "$run-$1" sh -c '/cb/cbb pair >/tmp/pair.out 2>&1'
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
	eventually "$m has the copy" sh -c "[ \"\$(docker exec $run-$m /cb/cbb paste)\" = 'hello from a' ]"
done
printf 'a secret' | cb c copy -secret
eventually "a has the secret" sh -c "[ \"\$(docker exec $run-a /cb/cbb paste)\" = 'a secret' ]"

say "one of the root and the admin holds cbb.local"
holders() {
	n=0
	for m in $members; do
		if docker inspect "$run-$m" >/dev/null 2>&1 && cb "$m" status | grep -q '^Answers for cbb.local ('; then
			n=$((n + 1))
			holder=$m
		fi
	done
	[ $n -eq 1 ]
}
eventually "exactly one holder" holders
holders
first=$holder

say "the iPhone's view: avahi resolves cbb.local to the holder"
docker run -d --rm --name "$run-phone" --network "$net" "$image" sleep 600 >/dev/null
docker exec "$run-phone" sh -c 'apt-get update -qq >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq avahi-daemon avahi-utils dbus >/dev/null' ||
	fail "installing avahi"
docker exec "$run-phone" sh -c 'mkdir -p /run/dbus && dbus-daemon --system --fork && avahi-daemon --daemonize --no-chroot'
ip_of() { docker inspect -f "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}" "$run-$1"; }
resolves_to() {
	docker exec "$run-phone" avahi-resolve -4 -n cbb.local 2>/dev/null | grep -q "	$1\$"
}
eventually "cbb.local resolves to $first" resolves_to "$(ip_of "$first")"
eventually "avahi browses the members" sh -c "[ \$(docker exec $run-phone avahi-browse -rtp _cbb._tcp | grep -c '^=') -ge 3 ]"

say "the holder stops; another takes cbb.local over"
docker stop -t 5 "$run-$first" >/dev/null
members=$(echo "$members" | tr ' ' '\n' | grep -v "^$first\$" | tr '\n' ' ')
eventually "a new holder" holders
holders
eventually "cbb.local follows to $holder" resolves_to "$(ip_of "$holder")"

say "a wrong code does not join"
docker run -d --rm --name "$run-d" --network "$net" -e CBB_SOCKET=/tmp/c.sock \
	-v "$bin:/cb/cbb:ro" -v "$cover:/cover" -e GOCOVERDIR=/cover "$image" /cb/cbb service -state /tmp -socket /tmp/c.sock >/dev/null
members="$members d"
eventually "d starts" cb d status
admin=${members%% *}
docker exec -d "$run-$admin" sh -c '/cb/cbb pair >/tmp/pair2.out 2>&1'
eventually "a code" docker exec "$run-$admin" grep -q 'Pairing code' /tmp/pair2.out
code=$(docker exec "$run-$admin" sed -n 's/^Pairing code: \([0-9]*\) \([0-9]*\)$/\1\2/p' /tmp/pair2.out)
[ "$code" = "$wrong" ] && wrong=111111
if printf '%s\n' "$wrong" | cb d pair -code >/dev/null 2>&1; then
	fail "d joined with a wrong code"
fi
cb d status | grep -q 'Not in a group' || fail "d is in a group after a wrong code"

say "all checks passed"
