#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok
#
# Builds the Aurora app's RPMs:
#   build.sh prepare      the Rust core for armv7hl and aarch64 (core/, through
#                         ffi/bind.sh aurora) and the icons (icons/, from
#                         apps/design/icon/aurora.png with ImageMagick); needs rustup
#                         and the GNU cross compilers for armhf and arm64
#   build.sh rpm TARGET [SYSTEM]
#                         builds the RPM in the Platform SDK, where mb2 runs, for
#                         a target snapshot such as AuroraOS-5.1.5.105-base-armv7hl.default;
#                         SYSTEM is the package: aurora5 (the default), aurora4
#                         or sailfish (packaging/SYSTEM), each in its own SDK
# The RPMs land in build/TARGET/RPMS/, unsigned. Nothing written here belongs in git.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
case ${1:-} in
prepare)
	"$here/../../ffi/bind.sh" aurora "$here/core"
	mkdir -p "$here/core/include"
	cp "$here/../../ffi/include/cbb_core.h" "$here/core/include/"
	convert=convert
	command -v magick >/dev/null && convert="magick"
	for size in 86 108 128 172; do
		mkdir -p "$here/icons/${size}x$size"
		$convert "$here/../design/icon/aurora.png" -resize "${size}x$size" "$here/icons/${size}x$size/tools.cbb.aurora.png"
		cp "$here/icons/${size}x$size/tools.cbb.aurora.png" "$here/icons/${size}x$size/harbour-cbb.png"
	done
	;;
rpm)
	[ $# -eq 2 ] || [ $# -eq 3 ] || { echo "usage: build.sh rpm TARGET [SYSTEM]" >&2; exit 2; }
	system=${3:-aurora5}
	case $system in
	aurora5 | aurora4) spec=tools.cbb.aurora.spec ;;
	sailfish) spec=harbour-cbb.spec ;;
	*) echo "build.sh: unknown system $system" >&2; exit 2 ;;
	esac
	[ -f "$here/core/include/cbb_core.h" ] || { echo "build.sh: run build.sh prepare first" >&2; exit 1; }
	# A build folder per target, so that one architecture's objects never
	# land in another's package.
	mkdir -p "$here/build/$2"
	cd "$here/build/$2"
	mb2 --no-snapshot -t "$2" -s "$here/packaging/$system/$spec" build "$here"
	;;
*)
	echo "usage: build.sh prepare | build.sh rpm TARGET [SYSTEM]" >&2
	exit 2
	;;
esac
