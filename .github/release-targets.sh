#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok
#
# Every target of the release workflow's build matrix is built in CI by
# the release's own list of programs (.github/release-programs.sh): by
# .github/build-targets.sh (the build and buildmac jobs) or by the rustmips
# job (MIPS_TARGETS), each of which copies the list from what the build
# made and runs the release's check of it. CI never runs the release
# workflow, so a target it does not build would show its faults only at a
# tag. Run by the check job.
set -eu
release=.github/workflows/release.yml ci=.github/workflows/ci.yml
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
# The release's targets, GOOS/GOARCH[/GOARM].
grep -E '^ *- \{ goos: ' "$release" |
	sed -E 's/.*goos: ([a-z0-9]+), goarch: ([a-z0-9]+)(, goarm: "([0-9])")?.*/\1\/\2\/\4/; s/\/$//' |
	sort -u >"$work/release"
# CI's: the build job's targets, buildmac's, rustmips's, without /vet.
{
	grep -E '^ *targets: ' "$ci" | sed -E 's/^ *targets: //'
	grep -E 'build-targets\.sh "\$RUNNER_TEMP" [a-z]' "$ci" | sed -E 's/.*build-targets\.sh "\$RUNNER_TEMP" //'
	grep -E '^ *MIPS_TARGETS: ' "$ci" | sed -E 's/^ *MIPS_TARGETS: //'
} | tr ' ' '\n' | sed 's/\/vet$//' | grep . | sort -u >"$work/ci"
n=$(wc -l <"$work/release")
[ "$n" -ge 10 ] || { echo "release-targets.sh: read only $n targets of $release" >&2; exit 1; }
missing=$(comm -23 "$work/release" "$work/ci")
if [ -n "$missing" ]; then
	echo "release-targets.sh: the release builds targets CI does not:" $missing >&2
	exit 1
fi
while IFS=/ read -r os arch _; do
	sh .github/release-programs.sh all "$os" "$arch" | grep -qx "cbb\(\.exe\)\{0,1\}" ||
		{ echo "release-targets.sh: no cbb for $os/$arch" >&2; exit 1; }
done <"$work/release"
# The release copies, builds and checks by the list, as CI's builds do.
for f in "$release" .github/build-targets.sh; do
	for k in "release-programs.sh rust " "release-programs.sh all " "release-go.sh "; do
		grep -qF "$k" "$f" || { echo "release-targets.sh: $f does not use $k" >&2; exit 1; }
	done
done
echo "CI builds all $n targets of the release by its list of programs"
