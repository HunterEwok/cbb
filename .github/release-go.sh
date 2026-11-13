#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok
#
# Builds the Go programs of a release target (.github/release-programs.sh
# go) into DIR as the release does, with TAG as their version, and checks
# that each carries the tag: a release cbb takes only a helper of its own
# release. The release workflow builds with it under its tag, and CI's
# builds of every target (.github/build-targets.sh) under a tag of their
# own, so CI runs the release's own lines. GOOS, GOARCH, GOARM and
# CGO_ENABLED come from the environment.
#
#   release-go.sh DIR TAG
set -eu
[ $# -eq 2 ] || { echo "usage: release-go.sh DIR TAG" >&2; exit 2; }
dir=$1 tag=$2
os=${GOOS:-$(go env GOOS)} arch=${GOARCH:-$(go env GOARCH)}
exe=
[ "$os" != windows ] || exe=.exe
ldflags="-s -w -X github.com/HunterEwok/cbb/internal/version.Version=$tag"
for p in $(sh .github/release-programs.sh go "$os" "$arch"); do
	go build -trimpath -ldflags "$ldflags" -o "$dir/$p" "./cmd/${p%"$exe"}"
	# -trimpath leaves -ldflags out of the build info, so the tag itself is looked for.
	grep -aqF -- "$tag" "$dir/$p" || { echo "release-go.sh: $p does not carry $tag" >&2; exit 1; }
done
