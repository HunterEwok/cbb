#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok
#
# The controls of release-ignores-hooks.sh, for CI's jobs that run it: cbb
# and cbb-helper built with the test hooks (E2E_FEATURES, E2E_TAGS) carry
# the release workflow's marker (hooks-marker.sh), release-ignores-hooks.sh
# refuses them, and hookprobe sees the helper take its hook. Each control
# must fail for the hooks, not for another reason, so each looks for the
# words it fails with. RUNNER_TEMP holds release-sign and hookprobe, built
# by the step before, and takes the builds.
set -eu
: "${RUNNER_TEMP:?}" "${E2E_FEATURES:?}" "${E2E_TAGS:?}"
exe=$(go env GOEXE)
cargo build --locked --release -p cbb-member --features "$E2E_FEATURES" --target-dir "$RUNNER_TEMP/hooks"
go build -tags "$E2E_TAGS" -o "$RUNNER_TEMP/cbb-helper-hooks$exe" ./cmd/cbb-helper
cbb=$RUNNER_TEMP/hooks/release/cbb$exe helper=$RUNNER_TEMP/cbb-helper-hooks$exe
sh .github/hooks-marker.sh present "$cbb" "$helper"
if out=$(sh .github/release-ignores-hooks.sh "$cbb" "$helper" "$RUNNER_TEMP/release-sign$exe" "$RUNNER_TEMP/hookprobe$exe" 2>&1); then
	echo "$out"
	echo "the script took a build with the hooks" >&2
	exit 1
fi
echo "$out"
echo "$out" | grep -qF "the test hooks changed what it does" || { echo "the script failed for another reason" >&2; exit 1; }
said=$("$RUNNER_TEMP/hookprobe$exe" "$helper")
echo "$said"
case $said in *"cbb-helper took an attestation"*) ;; *) echo "hookprobe did not see the hook" >&2; exit 1 ;; esac
