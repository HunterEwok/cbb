#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok
#
# Whether programs carry the line a build with the test hooks says itself
# with (member/src/testhooks.rs, internal/testhooks): the release workflow
# asks it absent from every program it publishes, and CI's hooks job asks
# it present in a build with the hooks, so that the words looked for here
# and the words the programs say cannot part. Every file named must be
# there. usage: hooks-marker.sh absent|present FILE...
set -eu
want=$1
shift
case $want in absent | present) ;; *) echo "usage: hooks-marker.sh absent|present FILE..." >&2; exit 2 ;; esac
[ $# -gt 0 ] || { echo "hooks-marker.sh: no file named" >&2; exit 2; }
for f in "$@"; do
	[ -f "$f" ] || { echo "$f is not there" >&2; exit 1; }
	if grep -aqF "test hooks build: reads the test variables" "$f"; then
		[ "$want" = present ] || { echo "$f was built with the test hooks" >&2; exit 1; }
	else
		[ "$want" = absent ] || { echo "$f does not say the test hooks' line" >&2; exit 1; }
	fi
done
echo "the test hooks' line is $want in $*"
