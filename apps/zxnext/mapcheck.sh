#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok
#
# mapcheck.sh MAP: fails when two of .cbb's own C symbols share an address
# in one section. zcc puts a function's static data at the function's own
# address when both go to the same section, as they do in the overlay
# pages (#pragma codeseg and constseg PAGE_13), and a call to the function
# then runs the data; such tables belong outside the functions.
set -eu
dups=$(grep -E '^_[A-Za-z0-9_]+ += \$[0-9A-F]+ ; addr, [a-z]+, [a-z]*, X___src_' "$1" |
    awk '{ split($0, f, ","); print $3, f[5], $1 }' | sort | awk '
        { key = $1 " " $2 }
        key == last { print prev; print; bad = 1 }
        { last = key; prev = $0 }
        END { exit !bad }') || exit 0
echo "mapcheck.sh: these share an address (static data inside a function?):" >&2
echo "$dups" | sort -u >&2
exit 1
