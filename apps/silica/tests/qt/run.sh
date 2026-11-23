#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok
#
# Builds and runs the Aurora app's tests on the computer (tst_silica.cpp),
# with desktop Qt 5 (qtbase5-dev) and the core built for the computer:
#   run.sh [LCOV]
# With LCOV, it builds with coverage and writes the lines of src/ that ran
# there, for tools/coverage's row cpp-aurora (docs/testing.md, "Coverage").
# It builds the core with cargo unless CBB_FFI_LIB names a libcbb_ffi.a.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../../.." && pwd)
src=$root/apps/silica/src
out=${TMPDIR:-/tmp}/cbb-silica-test
rm -rf "$out"
mkdir -p "$out"

lib=${CBB_FFI_LIB:-}
if [ -z "$lib" ]; then
	(cd "$root" && cargo build --locked -p cbb-ffi)
	lib=$root/target/debug/libcbb_ffi.a
fi

moc=$(pkg-config --variable=host_bins Qt5Core)/moc
"$moc" "$here/tst_silica.cpp" -o "$out/tst_silica.moc"
"$moc" "$src/events.h" -o "$out/moc_events.cpp"

cover=
[ $# -ge 1 ] && cover=--coverage
# shellcheck disable=SC2046 # pkg-config's flags are lists on purpose
c++ -std=c++17 -fPIC -O0 -g -Wall -Wextra -Werror $cover -I"$out" -I"$src" -I"$root/ffi/include" \
	$(pkg-config --cflags Qt5Core Qt5Test) \
	"$here/tst_silica.cpp" "$src/errors.cpp" "$src/events.cpp" "$src/membership.cpp" "$src/core.cpp" \
	"$src/platform/keystore_file.cpp" "$out/moc_events.cpp" "$lib" \
	$(pkg-config --libs Qt5Core Qt5Test) -ldl -lpthread -lm -o "$out/tst_silica"
(cd "$out" && QT_QPA_PLATFORM=offscreen ./tst_silica)

if [ -n "$cover" ]; then
	gcovr --root "$root" --filter "$src/" --exclude "$out/" --lcov "$1" "$out"
	# The paths from the repository's root, as the other rows name them.
	sed -i "s|^SF:$root/|SF:|" "$1"
	echo "run.sh: the coverage of src/ is in $1"
fi
