#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok
#
# Runs the HarmonyOS app's ohosTest suite on the computer, under Node with
# the core built for the computer (run.cjs tells what stands in for the
# phone):
#   run.sh [LCOV WATCH-LCOV]
# With them, it writes the lines that ran of entry/src/main/ets (the phone's
# app) to LCOV and of wearable/src/main/ets (the watch's) to WATCH-LCOV, for
# tools/coverage's rows ets-harmony and ets-harmony-watch (docs/testing.md,
# "Coverage"). It builds
# the core with cargo unless CBB_FFI_LIB names a libcbb_ffi.a, and installs
# TypeScript with npm ci (package-lock.json).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out=${TMPDIR:-/tmp}/cbb-harmony-test
rm -rf "$out"
mkdir -p "$out"

lib=${CBB_FFI_LIB:-}
if [ -z "$lib" ]; then
	(cd "$root" && cargo build --locked -p cbb-ffi)
	lib=$root/target/debug/libcbb_ffi.a
fi
cc -std=c11 -Wall -Wextra -Werror -I"$root/ffi/include" "$here/core-call.c" "$lib" -ldl -lpthread -lm -o "$out/core-call"

(cd "$here" && npm ci --ignore-scripts --no-audit --no-fund --silent)
node "$here/build.cjs" "$here/node_modules/typescript" "$out/js"

export CBB_TEST_OUT="$out/js" CBB_CORE_CALL="$out/core-call"
if [ $# -ge 2 ]; then
	(cd "$here" && node --test --enable-source-maps --experimental-test-coverage \
		--test-reporter=spec --test-reporter-destination=stdout \
		--test-reporter=lcov --test-reporter-destination="$out/node.info" run.cjs)
	# The app's own code, its paths from the repository's root.
	node "$here/lcov.cjs" "$out/node.info" "$root" entry/src/main/ets >"$1"
	node "$here/lcov.cjs" "$out/node.info" "$root" wearable/src/main/ets >"$2"
	echo "run.sh: the coverage of the phone's app is in $1, the watch's in $2"
else
	(cd "$here" && node --test --enable-source-maps run.cjs)
fi
