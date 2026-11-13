#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# The service's tests (./internal/service) in parts at the same time, each
# part in a Docker container on a network of its own, so that their mDNS
# never meets, as CI runs them on machines of their own (docs/testing.md,
# "Running tests in parallel"):
#
#   sh tools/e2e/parallel.sh [-n PARTS] [-run REGEXP] IMAGE
#
# IMAGE is a Linux image with Go, Rust, swtpm, Xvfb and xclip. The first
# container builds the Rust cbb, phone-on-linux, cbb-helper and the test
# binary into target/parallel (the Cargo and Go caches kept in the volumes
# cbb-cargo and cbb-go); then the parts run, PARTS of them (6 by default),
# split by tools/shard, and the run waits for all. -run narrows the tests
# first, as go test -run does. Each part's output is in
# target/parallel/part-N.log; the run ends with the parts' results and the
# names of the tests that failed, and exits 1 when any part failed.
#
# The containers and the networks are removed at the end.
set -eu

parts=6
filter=.
while [ $# -gt 1 ]; do
	case $1 in
	-n) parts=$2; shift 2 ;;
	-run) filter=$2; shift 2 ;;
	*) break ;;
	esac
done
[ $# -eq 1 ] || { echo "usage: sh tools/e2e/parallel.sh [-n PARTS] [-run REGEXP] IMAGE" >&2; exit 2; }
image=$1
repo=$(cd "$(dirname "$0")/../.." && pwd)
out=$repo/target/parallel
mkdir -p "$out"
tag=cbb-part-$$

# shellcheck disable=SC2317,SC2329 # called by the trap
cleanup() {
	for i in $(seq 1 "$parts"); do
		docker rm -f "$tag-$i" >/dev/null 2>&1 || true
		docker network rm "$tag-$i" >/dev/null 2>&1 || true
	done
}
trap cleanup EXIT INT TERM

# The caches go where the image's user keeps them.
home=$(docker run --rm "$image" sh -c 'echo "$HOME"')

# run NAME ARGS... runs a container of IMAGE with the repository at /src.
run() {
	name=$1
	shift
	docker run --name "$name" -v "$repo:/src" -v "cbb-cargo:$home/.cargo/registry" -v "cbb-go:$home/go" \
		-e GOFLAGS=-buildvcs=false -e CARGO_TARGET_DIR=/src/target/parallel/cargo -w /src "$@"
}

echo "building in $image"
# shellcheck disable=SC2016 # the container's shell expands it
run "$tag-build" --rm "$image" sh -ec '
	cargo build --locked --release -p cbb-member --features testhooks
	cargo build --locked --release -p cbb-ffi --features member,tunnel,testhooks --example phone-on-linux
	b=target/parallel/bin
	mkdir -p "$b"
	cp target/parallel/cargo/release/cbb target/parallel/cargo/release/cbb-relay "$b/"
	cp target/parallel/cargo/release/examples/phone-on-linux "$b/"
	CGO_ENABLED=0 go build -tags testhooks -trimpath -o "$b/cbb-helper" ./cmd/cbb-helper
	go test -c -o "$b/service.test" ./internal/service
	go build -o "$b/shard" ./tools/shard
'

tests=$(run "$tag-list" --rm -w /src/internal/service "$image" ../../target/parallel/bin/service.test -test.list "$filter")
echo "$(echo "$tests" | grep -c '^Test') tests in $parts parts"
for i in $(seq 1 "$parts"); do
	expr=$(echo "$tests" | run "$tag-shard" --rm -i "$image" target/parallel/bin/shard -n "$parts" -i "$i" -durations tools/shard/service.txt)
	docker network create "$tag-$i" >/dev/null
	# shellcheck disable=SC2016 # the container's shell expands it
	run "$tag-$i" -d --network "$tag-$i" -w /src/internal/service \
		-e DISPLAY=:5 -e CBB_TEST_X11=1 \
		-e CBB_TEST_RUST_SERVICE=/src/target/parallel/bin/cbb -e CBB_TEST_ALONE=/src/target/parallel/bin/cbb \
		-e CBB_PHONE_ON_LINUX=/src/target/parallel/bin/phone-on-linux \
		-e PART_RUN="$expr" "$image" sh -c '
			Xvfb :5 -screen 0 640x480x24 -noreset >/tmp/xvfb.log 2>&1 &
			for _ in $(seq 1 100); do [ -e /tmp/.X11-unix/X5 ] && break; sleep 0.1; done
			exec ../../target/parallel/bin/service.test -test.run "$PART_RUN" -test.timeout 30m -test.v' >/dev/null
	echo "part $i started"
done

failed=0
for i in $(seq 1 "$parts"); do
	code=$(docker wait "$tag-$i")
	docker logs "$tag-$i" >"$out/part-$i.log" 2>&1
	if [ "$code" = 0 ]; then
		echo "part $i: ok"
	else
		failed=1
		echo "part $i: FAILED (exit $code), $out/part-$i.log"
		grep -E '^--- FAIL: ' "$out/part-$i.log" | sed 's/^/  /' || true
	fi
done
exit "$failed"
