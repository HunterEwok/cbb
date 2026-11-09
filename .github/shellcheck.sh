#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Runs shellcheck on every shell script of the repository: each tracked *.sh
# file and each other file whose first line starts a shell, so that a new script
# is checked without being listed anywhere. Gradle's generated wrapper and
# code copied from other projects are left out. Run it from anywhere inside
# the repository.
set -eu

cd "$(git rev-parse --show-toplevel)"
list=$(mktemp)
trap 'rm -f "$list"' EXIT
git ls-files | while IFS= read -r f; do
	[ -f "$f" ] || continue
	case $f in
	apps/android/gradlew | */third_party/*) continue ;;
	*.sh) echo "$f" ;;
	*)
		if head -n 1 "$f" 2>/dev/null | grep -qE '^#!.*[/ ](sh|bash|dash|ash)( |$)'; then
			echo "$f"
		fi
		;;
	esac
done >"$list"
echo "shellcheck: $(wc -l <"$list") scripts"
tr '\n' '\0' <"$list" | xargs -0 shellcheck
