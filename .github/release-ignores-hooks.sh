#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok
#
# A release build of cbb and cbb-helper ignores the test hooks
# (member/src/testhooks.rs, internal/testhooks): with all the hooks set, each
# says and does exactly what it does without them. cbb update -check is
# given a release signed by throwaway roots that CBB_RELEASE_ROOTS names,
# which only a build with the hooks takes, and tools/hookprobe asks the
# helper to check an attestation under roots CBB_TEST_ATTEST_ROOTS names,
# which only a build with the hooks takes; a build that reads the hooks
# fails this script with "the test hooks changed what it does".
# usage: release-ignores-hooks.sh CBB CBB-HELPER RELEASE-SIGN HOOKPROBE
set -eu
cbb=$1 helper=$2 sign=$3 probe=$4
# A program that is missing or does not run fails here, not by chance below.
"$cbb" version >/dev/null || { echo "$cbb does not run" >&2; exit 1; }
"$helper" version >/dev/null || { echo "$helper does not run" >&2; exit 1; }
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/rel"
echo x >"$work/rel/notes.txt"
"$sign" drill -version 9.0.0 "$work/rel" "$work/roots.pem"
echo 9999999999999 >"$work/ahead-far"
run() {
	# The same command, without and with every hook, must answer the same.
	env -u CBB_TEST_AHEAD_FILE -u CBB_RELEASE_ROOTS -u CBB_HELPER -u CBB_TEST_ATTEST_ROOTS -u CBB_TEST_TPM_ROOTS -u CBB_TEST_BLUEZ -u CBB_TEST_LISTS_MIRROR \
		CBB_STATE="$work/state" CBB_RELEASE_DIR="$work/rel" "$@" >"$work/without" 2>&1 && echo "exit 0" >>"$work/without" || echo "exit $?" >>"$work/without"
	CBB_TEST_AHEAD_FILE="$work/ahead-far" CBB_RELEASE_ROOTS="$work/roots.pem" CBB_HELPER="$work/no-such-helper" \
		CBB_TEST_ATTEST_ROOTS="$work/roots.pem" CBB_TEST_TPM_ROOTS="$work/roots.pem" CBB_TEST_BLUEZ="unix:path=$work/bus" CBB_TEST_LISTS_MIRROR="1 $work/roots.pem" \
		CBB_STATE="$work/state" CBB_RELEASE_DIR="$work/rel" "$@" >"$work/with" 2>&1 && echo "exit 0" >>"$work/with" || echo "exit $?" >>"$work/with"
	if ! cmp -s "$work/without" "$work/with" || grep -qi "test hooks" "$work/with"; then
		echo "$*: the test hooks changed what it does" >&2
		diff "$work/without" "$work/with" >&2 || true
		exit 1
	fi
	echo "$*: the same with and without the hooks ($(tail -n 1 "$work/with"))"
}
run "$cbb" version
run "$helper" version
run "$cbb" update -check
# The release signed by the throwaway roots is refused.
! grep -q "exit 0" "$work/with" || { echo "cbb update -check took a release of other roots" >&2; exit 1; }
# The helper is asked one thing a hook changes.
said=$("$probe" "$helper" 2>&1) || { echo "$said" >&2; echo "hookprobe failed" >&2; exit 1; }
case $said in
*"cbb-helper refused an attestation"*) echo "$said" ;;
*) echo "$said" >&2; echo "cbb-helper: the test hooks changed what it does" >&2; exit 1 ;;
esac
