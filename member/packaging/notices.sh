#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Writes the licenses of the crates that the lite member, or another package
# of the workspace, is built from, for one target, so that a release archive
# carries their notices:
#
#   sh member/packaging/notices.sh TARGET [PACKAGE] >THIRD_PARTY_NOTICES
#
# PACKAGE is cbb-lite by default; the Go release archives take
# cbb-wasm, the Rust core the service runs.
#
# Each crate of the normal dependency graph (not build or dev dependencies)
# appears with its name, version and license expression, followed by its
# license files from the cargo registry. It needs cargo and jq, and the
# crates downloaded (cargo fetch or a build).
set -eu

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
	echo "usage: sh member/packaging/notices.sh TARGET [PACKAGE]" >&2
	exit 2
fi
target=$1
package=${2:-cbb-lite}
cd "$(dirname "$0")/../.."

meta=$(mktemp)
trap 'rm -f "$meta"' EXIT
cargo metadata --locked --format-version 1 >"$meta"

if [ "$package" = cbb-lite ]; then
	echo "The lite member of CBB is free software under the GNU Affero General"
	echo "Public License v3.0 only (LICENSE). It is built with the crates below, under"
	echo "their own licenses."
else
	echo "The Rust core in it ($package) is built with the crates below, under their own"
	echo "licenses."
fi
echo "The source code of each is on crates.io, at the version shown"
echo "(https://crates.io/crates/NAME/VERSION)."
cargo tree --locked -e normal -p "$package" --target "$target" --prefix none \
	-f '{p}' | sed 's/ (.*//; s/ (\*)$//' | sort -u |
	while read -r name version; do
		version=${version#v}
		dir=$(jq -r --arg n "$name" --arg v "$version" \
			'.packages[] | select(.name == $n and .version == $v and .source != null) | .manifest_path' "$meta")
		[ -n "$dir" ] || continue # the workspace's own crates
		dir=$(dirname "$dir")
		license=$(jq -r --arg n "$name" --arg v "$version" \
			'.packages[] | select(.name == $n and .version == $v) | .license // "see its files"' "$meta")
		printf '\n================================================================\n'
		printf '%s %s (%s)\n' "$name" "$version" "$license"
		found=
		for f in "$dir"/LICENSE* "$dir"/LICENCE* "$dir"/COPYING* "$dir"/NOTICE* "$dir"/UNLICENSE*; do
			[ -f "$f" ] || continue
			found=yes
			printf -- '\n--- %s\n\n' "${f##*/}"
			cat "$f"
		done
		if [ -z "$found" ]; then
			printf '\nThe crate ships no license file; its license is %s.\n' "$license"
		fi
	done
