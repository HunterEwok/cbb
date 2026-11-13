#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok
#
# Builds cbb (packaging/build.sh) and cbb-helper twice, from two copies of
# this commit in different folders with different cargo homes, as a release
# builds them, and fails unless both builds are the same bytes
# (docs/own-build.md, "Checking a release"):
#
#   sh .github/reproducible.sh [GOOS/GOARCH]
#
# The default is linux/amd64; a target with GOARM is not taken. The copies and the second cargo home go into a
# temporary folder, removed at the end.
set -eu
target=${1:-linux/amd64}
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# The second cargo home starts with the first one's downloads, so only the
# path differs, not what was fetched.
cargo_home=${CARGO_HOME:-$HOME/.cargo}
mkdir -p "$tmp/cargo"
[ ! -d "$cargo_home/registry" ] || cp -R "$cargo_home/registry" "$tmp/cargo/"
version=0.0.0-reproducible
for n in 1 2; do
	git worktree add -q --detach "$tmp/src$n" HEAD
	home=$cargo_home
	[ "$n" = 1 ] || home=$tmp/cargo
	dir=$(cd "$tmp/src$n" && CARGO_HOME=$home CBB_RELEASE_BUILD=1 CBB_VERSION=$version CBB_SOURCE=reproducible \
		sh packaging/build.sh "$target")
	mkdir -p "$tmp/out$n"
	for f in cbb cbb-relay cbb.exe cbbw.exe cbb-relay.exe; do
		[ ! -f "$tmp/src$n/$dir/$f" ] || cp "$tmp/src$n/$dir/$f" "$tmp/out$n/"
	done
	(cd "$tmp/src$n" && GOOS=${target%%/*} GOARCH=${target#*/} go build -trimpath \
		-ldflags "-s -w -X github.com/HunterEwok/cbb/internal/version.Version=v$version" \
		-o "$tmp/out$n/cbb-helper" ./cmd/cbb-helper)
done
git worktree remove --force "$tmp/src1"
git worktree remove --force "$tmp/src2"
(cd "$tmp/out1" && sha256sum -- *) >"$tmp/sums1"
(cd "$tmp/out2" && sha256sum -- *) >"$tmp/sums2"
cat "$tmp/sums1"
if ! cmp -s "$tmp/sums1" "$tmp/sums2"; then
	echo "reproducible.sh: the two builds of $target differ:" >&2
	diff "$tmp/sums1" "$tmp/sums2" >&2 || true
	exit 1
fi
echo "reproducible.sh: both builds of $target are the same"
