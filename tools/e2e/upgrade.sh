#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# The upgrade from a published release to the build under test, with
# Docker: members of the old version make a group and sync, then take the
# new version one at a time, keeping their state directories, as cbb update
# does.
#
#   sh tools/e2e/upgrade.sh path/to/old/cbb path/to/new/cbb
#
# From 0.6 on, the group must survive: the same group and devices, copies
# both ways between an updated member and those not yet updated, then
# between all. A group made before 0.6 is not carried over (records v2 have
# no migration): each member leaves it at its first start, says so in
# cbb status, keeps its settings, and a new group works.
#
# The containers, their volumes and the network are removed at the end.
set -eu

abs() { echo "$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"; }
old=$(abs "$1")
new=$(abs "$2")
image=${E2E_IMAGE:-debian:stable-slim}
run=cbup-$$
net=$run-net
members="a b c"

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
	for m in $members; do
		docker rm -f "$run-$m" >/dev/null 2>&1 || true
		docker volume rm "$run-$m" >/dev/null 2>&1 || true
	done
	docker network rm "$net" >/dev/null 2>&1 || true
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

# start runs a member on a version, with its state in its own volume.
start() { # member, binary
	docker run -d --name "$run-$1" --hostname "host-$1" --network "$net" \
		-e CBB_SOCKET=/s/c.sock -v "$run-$1:/s" -v "$2:/cb/cbb:ro" "$image" \
		/cb/cbb service -state /s -socket /s/c.sock >/dev/null
	eventually "$1 starts" cb "$1" status
}

# update stops a member and starts it again on the new version.
update() { # member
	docker stop -t 10 "$run-$1" >/dev/null
	docker rm "$run-$1" >/dev/null
	start "$1" "$new"
	cb "$1" version | grep -q "$newv" || fail "$1 does not run $newv"
}

pair() { # admin, joiner
	docker exec -d "$run-$1" sh -c '/cb/cbb pair >/s/pair.out 2>&1'
	eventually "a code on $1" docker exec "$run-$1" grep -q 'Pairing code' /s/pair.out
	code=$(docker exec "$run-$1" sed -n 's/^Pairing code: \([0-9]*\) \([0-9]*\)$/\1\2/p' /s/pair.out)
	printf '%s\n' "$code" | cb "$2" pair -code >/dev/null || fail "$2 could not join with the code from $1"
}

connected() { # member, count: the other devices that cbb status lists online
	[ "$(cb "$1" status | grep -v '(this device)' | grep -c ' online ')" -eq "$2" ]
}

has() { # member, text
	[ "$(docker exec "$run-$1" /cb/cbb paste)" = "$2" ]
}

copies() { # from, text, to...
	from=$1 text=$2
	shift 2
	printf '%s' "$text" | cb "$from" copy
	for m in "$@"; do
		eventually "$m has the copy from $from" has "$m" "$text"
	done
}

# group prints a member's group and the IDs of the group's devices.
group() {
	cb "$1" status | sed -n 's/^Device .*, group \([0-9a-f]*\)$/\1/p'
	cb "$1" status | awk '/^NAME/ { on = 1; next } on && NF { print $NF }' | sort
}

version() { "$1" version | sed -n 's/^cbb v\([0-9][0-9.]*\).*/\1/p'; }
oldv=$(version "$old")
newv=$(version "$new")
[ -n "$oldv" ] && [ -n "$newv" ] || fail "no versions: $oldv, $newv"
say "from $oldv to $newv"
# Before 0.6, minor versions below 6 of 0.x.
crossing=false
case $oldv in 0.[0-5].*) crossing=true ;; esac

docker network create "$net" >/dev/null
for m in $members; do start "$m" "$old"; done

say "the old version makes a group of three and syncs"
cb a new >/dev/null || fail "a could not create the group"
pair a b
pair a c
for m in $members; do eventually "$m connects to the two others" connected "$m" 2; done
copies a "before the update" b c

if [ "$crossing" = true ]; then
	say "each member leaves the group made before 0.6"
	for m in $members; do
		update "$m"
		cb "$m" status | grep -q 'left its group, which was made before 0.6' || fail "$m does not say it left its group"
		cb "$m" status | grep -q 'Not in a group' || fail "$m is still in a group"
		docker exec "$run-$m" test -f /s/before-0.6/identity.json || fail "$m did not keep its old group's files"
	done
	say "a new group works"
	cb a new >/dev/null || fail "a could not create a new group"
	pair a b
	pair a c
	for m in $members; do eventually "$m connects to the two others" connected "$m" 2; done
	copies b "after the update" a c
	say "all checks passed"
	exit 0
fi

before=$(group a)
[ "$(printf '%s\n' "$before" | wc -l)" -eq 4 ] || fail "a lists no group of three: $before"
say "a takes the new version first"
update a
[ "$(group a)" = "$before" ] || fail "a's group changed: $(group a)"
for m in $members; do eventually "$m connects to the two others" connected "$m" 2; done
copies a "from the new version" b c
copies b "from the old version" a c

say "the others follow"
update b
update c
for m in $members; do
	eventually "$m connects to the two others" connected "$m" 2
	[ "$(group "$m")" = "$before" ] || fail "$m's group changed"
done
copies c "all updated" a b
say "all checks passed"
