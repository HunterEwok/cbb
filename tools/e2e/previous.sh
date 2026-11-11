#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Downloads the previous release's cbb for Linux on amd64, for the test of
# the promise that from 0.6 on a device of version N works in one group
# with a device of N-1 (internal/service's TestPreviousRelease):
#
#   sh tools/e2e/previous.sh OUTDIR
#
# The previous release is the newest published version 0.6.0 or later, not
# a release candidate, whose tag is not on this commit. It checks the
# archive against the release's SHA256SUMS, prints the path of its cbb and
# leaves it in OUTDIR. When there is none yet (before 0.6.0 is out), it
# says so and prints nothing, and the test skips. CBB_REPO names another
# repository on GitHub.
set -eu

[ $# -eq 1 ] || {
	echo "usage: sh tools/e2e/previous.sh OUTDIR" >&2
	exit 2
}
out=$1
repo=${CBB_REPO:-HunterEwok/cbb}
here=$(git rev-parse HEAD 2>/dev/null || echo none)

tag=$(git ls-remote --tags "https://github.com/$repo.git" 'v*' |
	awk -v here="$here" '{
		t = $2; sub("^refs/tags/", "", t); peeled = sub("\\^\\{\\}$", "", t)
		if (t !~ /^v[0-9]+\.[0-9]+\.[0-9]+$/) next
		if ($1 == here) skip[t] = 1
		seen[t] = 1
	} END { for (t in seen) if (!(t in skip)) print t }' |
	sed 's/^v//' | awk -F. '$1 > 0 || $2 >= 6' | sort -t. -k1,1n -k2,2n -k3,3n | tail -n 1)
if [ -z "$tag" ]; then
	echo "previous.sh: no release of 0.6 or later before this commit; the test of N-1 skips" >&2
	exit 0
fi

mkdir -p "$out"
out=$(cd "$out" && pwd)
base="https://github.com/$repo/releases/download/v$tag"
curl -fsSL --retry 3 -o "$out/SHA256SUMS" "$base/SHA256SUMS"
archive=cbb-linux-amd64.tar.gz
grep -q " \*\?$archive\$" "$out/SHA256SUMS" || {
	echo "previous.sh: v$tag has no cbb for Linux on amd64" >&2
	exit 1
}
curl -fsSL --retry 3 -o "$out/$archive" "$base/$archive"
(cd "$out" && grep " \*\?$archive\$" SHA256SUMS | sha256sum -c - >&2)
mkdir -p "$out/v$tag"
tar -xzf "$out/$archive" -C "$out/v$tag"
bin=$(find "$out/v$tag" -type f -name cbb | head -n 1)
[ -n "$bin" ] || {
	echo "previous.sh: $archive of v$tag holds no cbb" >&2
	exit 1
}
echo "previous.sh: v$tag's cbb from $archive" >&2
echo "$bin"
