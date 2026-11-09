#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Lays out the build context of the cbb image in DIR: the
# Dockerfile, the static cbb of each platform with the programs beside it
# (cbb-helper, cbb-forward, cbb-relay), in the folder the Dockerfile wants
# for it (bin-amd64, bin-arm64, bin-armv7), and the few directories and files
# the service needs in an image built from scratch, with LICENSE and, given
# notices=FILE, a release archive's THIRD_PARTY_NOTICES in
# /usr/share/doc/cbb.
#
#   sh packaging/docker/context.sh DIR amd64=path/to/cbb [arm64=path] [armv7=path] [notices=FILE]
set -eu

[ $# -ge 2 ] || {
	echo "usage: context.sh DIR ARCH=CBB..." >&2
	exit 2
}
dir=$1
shift
here=$(cd "$(dirname "$0")" && pwd)
r=$dir/rootfs
doc=$r/usr/share/doc/cbb
mkdir -p "$dir" "$doc"
cp "$here/Dockerfile" "$dir/Dockerfile"
cp "$here/../../LICENSE" "$doc/LICENSE"
for a in "$@"; do
	arch=${a%%=*}
	bin=${a#*=}
	case $arch in
	amd64 | arm64 | armv7) ;;
	notices)
		cp "$bin" "$doc/THIRD_PARTY_NOTICES"
		continue
		;;
	*)
		echo "context.sh: unknown platform $arch" >&2
		exit 2
		;;
	esac
	mkdir -p "$dir/bin-$arch"
	cp "$bin" "$dir/bin-$arch/cbb"
	for f in cbb-helper cbb-forward cbb-relay; do
		[ ! -f "$(dirname "$bin")/$f" ] || cp "$(dirname "$bin")/$f" "$dir/bin-$arch/$f"
	done
	chmod 0755 "$dir/bin-$arch/"*
done

# The service's user, 65532, owns its state and its sockets' directory.
mkdir -p "$r/etc" "$r/run/cbb" "$r/var/lib/cbb" "$r/tmp"
chmod 0750 "$r/run/cbb"
chmod 0700 "$r/var/lib/cbb"
chmod 1777 "$r/tmp"
printf 'cbb:x:65532:65532:cbb:/var/lib/cbb:/sbin/nologin\n' >"$r/etc/passwd"
printf 'cbb:x:65532:\n' >"$r/etc/group"
printf 'PRETTY_NAME="Docker container"\nNAME=Docker\n' >"$r/etc/os-release"
