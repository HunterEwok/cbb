#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok
#
# The programs a release target carries, one file name a line: the one
# list the release workflow builds and copies by, looks for the test
# hooks' line in (.github/hooks-marker.sh), and CI's builds of each target
# (.github/build-targets.sh, the rustmips job) build and check by, so that
# what a release names and what its build makes cannot part.
#
#   release-programs.sh rust|go|all GOOS GOARCH
#
# rust: the Rust programs of member/packaging/build.sh's folder (cbb; the
# relay cbb-relay but on the routers' MIPS, built without the tunnel;
# cbbw.exe on Windows). go: the Go programs beside cbb (cbb-helper,
# cbb-forward), none on MIPS, where cbb runs alone.
set -eu
[ $# -eq 3 ] || { echo "usage: release-programs.sh rust|go|all GOOS GOARCH" >&2; exit 2; }
kind=$1 os=$2 arch=$3
exe=
[ "$os" != windows ] || exe=.exe
case $arch in
mips | mipsle) rust=cbb go= ;;
*)
	rust="cbb cbb-relay" go="cbb-helper cbb-forward"
	[ "$os" != windows ] || rust="cbb cbbw cbb-relay"
	;;
esac
case $kind in
rust) list=$rust ;;
go) list=$go ;;
all) list="$rust $go" ;;
*) echo "usage: release-programs.sh rust|go|all GOOS GOARCH" >&2; exit 2 ;;
esac
for p in $list; do
	echo "$p$exe"
done
