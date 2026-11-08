#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok
#
# CI's build of cbb for each target, as a release builds it: build-targets.sh
# NOTICES DIR TARGET... builds cbb (with the Rust core as WebAssembly, which
# wasm/build.sh made, and its notices in NOTICES) and its helper for each
# TARGET, GOOS/GOARCH with /N for GOARM and /vet to run go vet first, into
# DIR/GOOS-ARCH, makes the release archive in DIR/dist with
# packaging/archive.sh, and checks what the archive holds. CGO_ENABLED comes
# from the environment.
set -eu
[ $# -ge 3 ] || { echo "usage: build-targets.sh NOTICES DIR TARGET..." >&2; exit 2; }
notices=$1
dir=$2
shift 2
overlay=$PWD/target/cbb-core-overlay.json

for t in "$@"; do
	IFS=/ read -r os arch rest <<EOF
$t
EOF
	arm='' vet=''
	for part in $(echo "$rest" | tr / ' '); do
		case $part in
		vet) vet=1 ;;
		[0-9]) arm=$part ;;
		*) echo "build-targets.sh: what is $part in $t?" >&2; exit 2 ;;
		esac
	done
	name=$arch
	[ -z "$arm" ] || name=armv$arm
	out=$dir/$os-$name
	mkdir -p "$out"
	echo "::group::$os/$name"
	export GOOS="$os" GOARCH="$arch" GOARM="$arm" GOMIPS=
	case $arch in mips | mipsle) GOMIPS=softfloat ;; esac
	[ -z "$vet" ] || go vet ./...
	if [ "$os" = windows ]; then
		# cbbw.exe is the same program without a console window, for the agent.
		go build -overlay "$overlay" -tags cbbwasm -trimpath -o "$out/cbb.exe" ./cmd/cbb
		go build -overlay "$overlay" -tags cbbwasm -trimpath -ldflags=-H=windowsgui -o "$out/cbbw.exe" ./cmd/cbb
		# The tray app goes in the archive too, as at a release.
		(cd apps/desktop && go build -trimpath -ldflags=-H=windowsgui -o "$out/cbb-desktop.exe" .)
		go build -trimpath -o "$out/cbb-helper.exe" ./cmd/cbb-helper
		CORE_NOTICES=$notices sh packaging/archive.sh "$out/cbb.exe" "$os" "$name" "$dir/dist"
		unzip -Z1 "$dir/dist/cbb-$os-$name.zip" >"$out/list"
		for f in cbb.exe cbbw.exe cbb-desktop.exe cbb-helper.exe packaging/windows/install.ps1 packaging/windows/uninstall.ps1; do
			grep -qx "cbb/$f" "$out/list" || { echo "build-targets.sh: no $f in the $os/$name archive" >&2; exit 1; }
		done
		file "$out/cbb.exe" | grep -q '(console)'
		file "$out/cbbw.exe" | grep -q '(GUI)'
		file "$out/cbb-desktop.exe" | grep -q '(GUI)'
	else
		go build -overlay "$overlay" -tags cbbwasm -trimpath -o "$out/cbb" ./cmd/cbb
		# The helper beside cbb, for the archive; not for the routers (MIPS),
		# where cbb runs without it.
		if [ -z "$GOMIPS" ]; then
			go build -trimpath -o "$out/cbb-helper" ./cmd/cbb-helper
		fi
		CORE_NOTICES=$notices sh packaging/archive.sh "$out/cbb" "$os" "$name" "$dir/dist"
		tar -tzf "$dir/dist/cbb-$os-$name.tar.gz" | grep -qx "cbb/cbb"
		if [ -z "$GOMIPS" ]; then
			tar -tzf "$dir/dist/cbb-$os-$name.tar.gz" | grep -qx "cbb/cbb-helper"
		fi
		# The notices name the core's crates too.
		tar -xzOf "$dir/dist/cbb-$os-$name.tar.gz" cbb/THIRD_PARTY_NOTICES | grep -q '^chacha20poly1305 '
	fi
	echo "::endgroup::"
done
