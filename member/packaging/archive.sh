#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Packs a built lite member into its release archive:
#
#   sh member/packaging/archive.sh path/to/cbb TARGET NAME OUTDIR
#
# writes OUTDIR/cbb-lite-linux-<NAME>.tar.gz, which holds
# cbb-lite/ with the binary cbb, LICENSE, README.md,
# THIRD_PARTY_NOTICES (the licenses of the crates for TARGET; see notices.sh)
# and packaging/ laid out as in the full member's Linux archive: the same
# install.sh, install-rootless.sh, uninstall.sh and firewall.sh, the tmux
# configuration, the console helper's unit, the lite member's own systemd
# units (the system's and a rootless install's) and OpenWrt's
# installer (its init script runs cbb service for the lite member too), so that
# get.sh --lite and a manual install work as for a full member. The release
# workflow and CI both use it.
set -eu

if [ $# -ne 4 ]; then
	echo "usage: sh member/packaging/archive.sh BINARY TARGET NAME OUTDIR" >&2
	exit 2
fi
bin=$1 target=$2 name=$3 out=$4
root=$(cd "$(dirname "$0")/../.." && pwd)

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
dir=$work/cbb-lite
mkdir -p "$dir/packaging/linux" "$out"
out=$(cd "$out" && pwd)
cp "$bin" "$dir/cbb"
cp "$root/LICENSE" "$root/member/README.md" "$dir/"
sh "$root/member/packaging/notices.sh" "$target" >"$dir/THIRD_PARTY_NOTICES"
cp "$root/packaging/linux/install.sh" "$root/packaging/linux/install-rootless.sh" "$root/packaging/linux/uninstall.sh" \
	"$root/packaging/linux/firewall.sh" "$root/packaging/linux/cbb.sysusers" \
	"$root/packaging/linux/cbb-console.service" "$root/member/packaging/cbb.service" \
	"$root/member/packaging/cbb-rootless.service" "$dir/packaging/linux/"
cp -R "$root/packaging/tmux" "$root/packaging/openwrt" "$root/packaging/update.sh" "$root/packaging/pair.sh" "$dir/packaging/"
tar -czf "$out/cbb-lite-linux-$name.tar.gz" -C "$work" cbb-lite
echo "$out/cbb-lite-linux-$name.tar.gz"
