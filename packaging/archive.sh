#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Packs a built binary into the release archive for its platform:
#
#   sh packaging/archive.sh path/to/cbb linux|darwin|freebsd|windows NAME OUTDIR
#
# writes OUTDIR/cbb-<os>-<NAME>.tar.gz, which holds cbb/ with
# the binary, LICENSE, THIRD_PARTY_NOTICES (the licenses of the Go modules and
# the copied code and Go itself that the binary is built from; it needs the
# go command) and
# packaging/ (the platform's installer and tmux; OpenWrt's beside Linux's). For
# Windows the binary is cbb.exe, with the windowless cbbw.exe beside it for
# the agent and, when it was built, the tray app cbb-desktop.exe (Linux's
# archive carries cbb-desktop the same way), and the archive is cbb-windows-<NAME>.zip, which
# Windows opens without other tools. The release workflow and CI both use
# it, so a wrong path fails on every pull request, not only at a release.
# With CORE_NOTICES naming a file, the notices of the Rust core's crates
# (member/packaging/notices.sh wasm32-unknown-unknown cbb-wasm)
# follow those of the Go modules, for a binary built with the core.
set -eu

if [ $# -ne 4 ]; then
	echo "usage: sh packaging/archive.sh BINARY linux|darwin|freebsd|windows NAME OUTDIR" >&2
	exit 2
fi
bin=$1 os=$2 name=$3 out=$4
root=$(cd "$(dirname "$0")/.." && pwd)
case $os in
linux) dir=linux ;;
darwin) dir=macos ;;
freebsd) dir=freebsd ;;
windows) dir=windows ;;
*)
	echo "archive.sh: unknown OS $os" >&2
	exit 2
	;;
esac
# modules lists the modules (path, version, folder) that the Go package in
# folder $1 is built from for this OS, without this repository's own.
modules() {
	(cd "$1" && GOOS=$os go list -deps \
		-f '{{with .Module}}{{if not .Main}}{{.Path}} {{.Version}} {{.Dir}}{{end}}{{end}}' .) |
		grep -v '^github.com/HunterEwok/cbb ' || true
}

# notices writes the license files of every module that the programs for
# this OS are built from (the tray app's too, when it is packed), and of the
# code copied into internal/third_party.
notices() {
	echo "CBB is free software under the GNU Affero General Public License v3.0"
	echo "only (LICENSE). It is built with the code below, under its own licenses."
	{
		modules "$root/cmd/cbb"
		if [ -n "$desktop" ]; then modules "$root/apps/desktop"; fi
	} | sort -u | while read -r mod version moddir; do
		printf '\n================================================================\n%s %s\n' "$mod" "$version"
		license_files "$moddir"
	done
	printf '\n================================================================\n'
	printf 'The Go standard library and runtime, %s\n' "$(go env GOVERSION)"
	license_files "$(go env GOROOT)"
	for copied in "$root"/internal/third_party/*/; do
		printf '\n================================================================\n'
		printf 'internal/third_party/%s (copied; see its README.md)\n' "$(basename "$copied")"
		license_files "$copied"
	done
	if [ -n "${CORE_NOTICES:-}" ]; then
		printf '\n================================================================\n'
		cat "$CORE_NOTICES"
	fi
}

license_files() {
	for f in "$1"/LICENSE* "$1"/LICENCE* "$1"/COPYING* "$1"/NOTICE* "$1"/PATENTS*; do
		[ -f "$f" ] || continue
		printf -- '\n--- %s\n\n' "${f##*/}"
		cat "$f"
	done
}

# The tray app, when it was built beside the binary: for Windows, and for
# Linux on the architectures whose runners build it with GTK 4.
desktop=
case $os in
windows) [ ! -f "$(dirname "$bin")/cbb-desktop.exe" ] || desktop=$(dirname "$bin")/cbb-desktop.exe ;;
linux) [ ! -f "$(dirname "$bin")/cbb-desktop" ] || desktop=$(dirname "$bin")/cbb-desktop ;;
esac
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/cbb/packaging" "$out"
out=$(cd "$out" && pwd)
cp "$root/LICENSE" "$work/cbb/"
notices >"$work/cbb/THIRD_PARTY_NOTICES"
if [ "$os" = windows ]; then
	cp "$bin" "$work/cbb/cbb.exe"
	cp "$(dirname "$bin")/cbbw.exe" "$work/cbb/cbbw.exe"
	if [ -n "$desktop" ]; then
		cp "$desktop" "$work/cbb/cbb-desktop.exe"
	fi
	cp -R "$root/packaging/windows" "$work/cbb/packaging/"
	rm -f "$out/cbb-$os-$name.zip"
	(cd "$work" && zip -qrX "$out/cbb-$os-$name.zip" cbb)
	echo "$out/cbb-$os-$name.zip"
	exit 0
fi
cp "$bin" "$work/cbb/cbb"
cp -R "$root/packaging/$dir" "$root/packaging/tmux" "$root/packaging/update.sh" "$root/packaging/pair.sh" "$work/cbb/packaging/"
if [ -n "$desktop" ]; then
	cp "$desktop" "$work/cbb/cbb-desktop"
	cp "$root/apps/desktop/icon.png" "$work/cbb/packaging/linux/cbb.png"
fi
# OpenWrt runs the Linux binary, with its own installer.
if [ "$os" = linux ]; then
	cp -R "$root/packaging/openwrt" "$work/cbb/packaging/"
fi
# No AppleDouble files from macOS tar.
COPYFILE_DISABLE=1 tar -czf "$out/cbb-$os-$name.tar.gz" -C "$work" cbb
echo "$out/cbb-$os-$name.tar.gz"
