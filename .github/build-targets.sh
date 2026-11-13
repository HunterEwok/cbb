#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok
#
# CI's build for each target, as a release builds it: build-targets.sh
# DIR TARGET... builds cbb, the Rust program
# (member/packaging/build.sh) with cbb-relay, the relay in Rust, and beside
# them the Go programs cbb-helper and cbb-forward for each TARGET,
# GOOS/GOARCH with /N for GOARM and /vet to run go vet first, into
# DIR/GOOS-ARCH, makes the release archive in DIR/dist with
# packaging/archive.sh, and checks what the archive holds. CGO_ENABLED comes
# from the environment.
set -eu
[ $# -ge 2 ] || { echo "usage: build-targets.sh DIR TARGET..." >&2; exit 2; }
dir=$1
shift

# no_hooks DIR GOOS GOARCH runs the release workflow's check on the
# target's programs in DIR.
no_hooks() {
	d=$1
	# shellcheck disable=SC2046 # the names are words
	set -- $(sh .github/release-programs.sh all "$2" "$3")
	for p in "$@"; do
		shift
		set -- "$@" "$d/$p"
	done
	sh .github/hooks-marker.sh absent "$@"
}

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
	rust=$(sh member/packaging/build.sh "$os/$arch${arm:+/$arm}")
	sh member/packaging/notices.sh "$(basename "$(dirname "$rust")")" >"$out/rust-notices"
	exe=''
	[ "$os" != windows ] || exe=.exe
	# The target's programs by the release's own list
	# (.github/release-programs.sh): cbb, cbb-relay and the Go programs
	# beside it, cbbw.exe (cbb without a console window) on Windows; on the
	# routers (MIPS) cbb alone.
	for p in $(sh .github/release-programs.sh rust "$os" "$arch"); do
		cp "$rust/$p" "$out/"
	done
	for p in $(sh .github/release-programs.sh go "$os" "$arch"); do
		go build -trimpath -o "$out/$p" "./cmd/${p%"$exe"}"
	done
	# The release workflow's check that no program carries the test hooks,
	# on the same list.
	no_hooks "$out" "$os" "$arch"
	if [ "$os" = windows ]; then
		# The tray app goes in the archive too, as at a release.
		(cd apps/desktop && go build -trimpath -ldflags=-H=windowsgui -o "$out/cbb-desktop.exe" .)
		RUST_NOTICES=$out/rust-notices sh packaging/archive.sh "$out/cbb.exe" "$os" "$name" "$dir/dist"
		unzip -Z1 "$dir/dist/cbb-$os-$name.zip" >"$out/list"
		for f in cbb.exe cbbw.exe cbb-desktop.exe cbb-helper.exe cbb-forward.exe cbb-relay.exe packaging/windows/install.ps1 packaging/windows/uninstall.ps1; do
			grep -qx "cbb/$f" "$out/list" || { echo "build-targets.sh: no $f in the $os/$name archive" >&2; exit 1; }
		done
		file "$out/cbb.exe" | grep -q '(console)'
		file "$out/cbbw.exe" | grep -q '(GUI)'
		file "$out/cbb-desktop.exe" | grep -q '(GUI)'
		unzip -p "$dir/dist/cbb-$os-$name.zip" cbb/THIRD_PARTY_NOTICES >"$out/notices"
	else
		RUST_NOTICES=$out/rust-notices sh packaging/archive.sh "$out/cbb" "$os" "$name" "$dir/dist"
		tar -tzf "$dir/dist/cbb-$os-$name.tar.gz" >"$out/list"
		for p in $(sh .github/release-programs.sh all "$os" "$arch"); do
			grep -qx "cbb/$p" "$out/list" || { echo "build-targets.sh: no $p in the $os/$name archive" >&2; exit 1; }
		done
		tar -xzOf "$dir/dist/cbb-$os-$name.tar.gz" cbb/THIRD_PARTY_NOTICES >"$out/notices"
	fi
	# The notices name the crates of cbb.
	grep -q '^chacha20poly1305 ' "$out/notices"
	grep -q '^mdns-sd ' "$out/notices"
	echo "::endgroup::"
done
