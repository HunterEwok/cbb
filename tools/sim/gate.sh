#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# The simulator's gate for a records head: merges COMMIT onto this
# checkout's HEAD in a throwaway worktree (nothing is pushed or changed
# here), builds cbb-core's tests and runs the first 200 plain seeds and
# seed 153 with the records model's small rooms. It prints PASS, or FAIL
# with each failing seed's line, and exits 0 or 1.
#
#   sh tools/sim/gate.sh COMMIT [REMOTE_BRANCH]
#
# COMMIT is fetched from origin's REMOTE_BRANCH (claude/project-thread-z0iryb
# by default) when it is not here yet. SEEDS=N runs N plain seeds instead
# of 200. The worktree and its target stay in ${GATE_DIR:-/tmp/cbb-gate}
# between runs, so a second run builds only what changed.
set -eu

commit=${1:?usage: sh tools/sim/gate.sh COMMIT [REMOTE_BRANCH]}
branch=${2:-claude/project-thread-z0iryb}
seeds=${SEEDS:-200}
dir=${GATE_DIR:-/tmp/cbb-gate}
top=$(git rev-parse --show-toplevel)
cd "$top"

git cat-file -e "$commit^{commit}" 2>/dev/null || git fetch -q origin "$branch"
git cat-file -e "$commit^{commit}" || { echo "gate: $commit not found on origin/$branch" >&2; exit 2; }
base=$(git rev-parse HEAD)

if [ -d "$dir/tree" ]; then
	git -C "$dir/tree" merge --abort >/dev/null 2>&1 || true
	git -C "$dir/tree" checkout -q --detach "$base"
	git -C "$dir/tree" reset -q --hard "$base"
else
	mkdir -p "$dir"
	git worktree add -q --detach "$dir/tree" "$base"
fi
cd "$dir/tree"
git -c user.name=gate -c user.email=gate@localhost merge -q --no-edit "$commit" >/dev/null 2>&1 || {
	echo "FAIL: $commit does not merge onto $(git rev-parse --short "$base") without conflicts" >&2
	git diff --name-only --diff-filter=U >&2
	exit 1
}
echo "gate: $(git rev-parse --short "$base") + $(git rev-parse --short "$commit")" >&2

export CARGO_TARGET_DIR="$dir/target"
cargo test -q --release -p cbb-core --features std --lib --no-run 2>&1 | grep -E '^(error|warning: unused)' >&2 || true
bin=$(ls -t "$CARGO_TARGET_DIR"/release/deps/cbb_core-* | grep -v '\.d$' | head -1)

out="$dir/out.txt"
: >"$out"
SIM_ALL=1 SIM_FIRST=0 SIM_SEEDS="$seeds" "$bin" sim::groups_under_faults_agree --nocapture >>"$out" 2>&1 || true
SIM_SEED=153 SIM_SMALL=1 SIM_ROOMS=14,8,5 "$bin" sim::groups_under_faults_agree --nocapture >>"$out" 2>&1 || true

if grep -q 'failed:' "$out"; then
	echo "FAIL"
	grep 'failed:' "$out" | sed 's/^sim //' | sort -u
	exit 1
fi
if [ "$(grep -c 'test result: ok' "$out")" -ne 2 ]; then
	echo "FAIL: the simulator did not finish; see $out"
	exit 1
fi
echo "PASS: $seeds plain seeds and seed 153 at 14,8,5"
