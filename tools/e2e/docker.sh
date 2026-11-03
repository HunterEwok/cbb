#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Test of the cbb image: two containers of it, run as the
# compose files run them (its own user, a read-only root file system, no
# capabilities), find each other on one network, pair with a code and sync
# both ways, and a forwarder starts and shows its key.
#
#   sh tools/e2e/docker.sh IMAGE
#
# The containers, the volumes and the network are removed at the end.
set -eu

image=$1
run=cbdock-$$
net=$run-net
tmp=$(mktemp -d)
members="a b"

say() { printf '== %s\n' "$*"; }
fail() {
	printf 'FAIL: %s\n' "$*" >&2
	for m in $members forward; do
		echo "--- log of $m" >&2
		docker logs "$run-$m" 2>&1 | tail -20 >&2 || true
	done
	exit 1
}
cleanup() {
	for c in $members forward; do docker rm -f "$run-$c" >/dev/null 2>&1 || true; done
	for m in $members forward; do docker volume rm "$run-$m" >/dev/null 2>&1 || true; done
	docker network rm "$net" >/dev/null 2>&1 || true
	rm -rf "$tmp"
}
trap cleanup EXIT

cb() { # member, arguments...
	m=$1
	shift
	docker exec -i "$run-$m" cbb "$@"
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

# start runs the image as packaging/docker/compose.home.yaml does, on a
# network of its own rather than the host's. The test's root, a, may hold
# the group's keys in its volume (CBB_KEYS_IN_FILE); b may not.
start() { # name, arguments...
	n=$1
	shift
	keys=no
	[ "$n" != a ] || keys=yes
	docker run -d --name "$run-$n" --hostname "host-$n" --network "$net" \
		-e CBB_KEYS_IN_FILE=$keys --read-only --tmpfs /run/cbb:uid=65532,gid=65532,mode=0750 \
		--cap-drop ALL --security-opt no-new-privileges \
		-v "$run-$n:/var/lib/cbb" "$image" "$@" >/dev/null
}

say "starting two members"
docker network create "$net" >/dev/null
for m in $members; do start "$m"; done
for m in $members; do
	eventually "$m starts" cb "$m" status
done
[ "$(docker exec "$run-a" cbb version | head -n 1)" != "" ] || fail "cbb version says nothing"
[ "$(docker inspect -f '{{.Config.User}}' "$image")" = "65532:65532" ] || fail "the image does not run as its own user"

say "b, a container whose user did not allow keys in a file, makes no group"
cb b new >"$tmp/new.out" 2>&1 && fail "b created a group in a container"
grep -q CBB_KEYS_IN_FILE=yes "$tmp/new.out" || fail "b's refusal does not say how to allow it: $(cat "$tmp/new.out")"

say "a creates the group and admits b"
cb a new >/dev/null || fail "a could not create the group"
docker exec "$run-a" cbb pair >"$tmp/pair.out" 2>&1 &
eventually "a code on a" grep -q 'Pairing code' "$tmp/pair.out"
code=$(sed -n 's/^Pairing code: \([0-9]*\) \([0-9]*\)$/\1\2/p' "$tmp/pair.out")
printf '%s\n' "$code" | cb b pair -code >/dev/null || fail "b could not join with the code from a"
eventually "a reports the new member" grep -q "host-b joined" "$tmp/pair.out"
wait

say "copies go both ways"
printf 'hello from a\n' | cb a copy
eventually "b has a's copy" sh -c "[ \"\$(docker exec $run-b cbb paste)\" = 'hello from a' ]"
printf 'hello from b\n' | cb b copy
eventually "a has b's copy" sh -c "[ \"\$(docker exec $run-a cbb paste)\" = 'hello from b' ]"

say "the group survives a restart, its state in the volume"
docker restart -t 2 "$run-b" >/dev/null
eventually "b starts again" cb b status
cb b status | grep -q 'Not in a group' && fail "b forgot its group"
printf 'after the restart\n' | cb a copy
eventually "b syncs after its restart" sh -c "[ \"\$(docker exec $run-b cbb paste)\" = 'after the restart' ]"

say "a forwarder starts and shows its key"
start forward forward -listen :8764
eventually "the forwarder shows its key" sh -c "docker logs $run-forward 2>&1 | grep -q 'forwarder-key: [A-Za-z0-9+/]\{43\}='"
key=$(docker exec "$run-forward" cbb forward -show-key) || fail "forward -show-key failed"
docker logs "$run-forward" 2>&1 | grep -qF "forwarder-key: $key" || fail "forward -show-key names another key than the forwarder"

say "PASS"
