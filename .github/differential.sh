#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# The differential comparison of the four implementations
# (docs/differential.md): a corpus from tools/difffuzz, the verdict test of
# each of Go, the lite member's Rust core, the Kotlin kit and the Swift kit
# (Swift in its container, as the phone kit job runs it on Linux), then the
# comparison, which fails on any case they read differently and writes
# those cases to OUT/failures.jsonl.
#
# Usage: differential.sh SEED BODIES SETS OUT, from the repository's root.
set -eu

seed=$1
bodies=$2
sets=$3
out=$(mkdir -p "$4" && cd "$4" && pwd)
root=$(pwd)

go run ./tools/difffuzz gen -seed "$seed" -n "$bodies" -sets "$sets" -o "$out/corpus.jsonl"
export CBB_VERDICTS="$out/corpus.jsonl"

CBB_VERDICTS_OUT="$out/go-group.txt" go test ./internal/group -run '^TestVerdicts$' -count=1
CBB_VERDICTS_OUT="$out/go-release.txt" go test ./internal/release -run '^TestVerdicts$' -count=1
(cd core/ && CBB_VERDICTS_OUT="$out/rust.txt" cargo test --locked --release --lib command::verdicts)
# --rerun: Gradle does not see the corpus change between runs.
(cd apps/android && CBB_VERDICTS_OUT="$out/kotlin.txt" ./gradlew --no-daemon -q -p kit test --tests '*.VerdictTest' --rerun)
sh ffi/bind.sh host "$out/core"
docker run --rm -v "$root:/src" -v "$out:/out" -w /src/apps/ios/CBBKit \
	-e CBB_VERDICTS=/out/corpus.jsonl -e CBB_VERDICTS_OUT=/out/swift.txt swift:6.2-noble \
	swift test -Xlinker -L/out/core --filter VerdictTests

go run ./tools/difffuzz compare -corpus "$out/corpus.jsonl" -failures "$out/failures.jsonl" \
	go="$out/go-group.txt,$out/go-release.txt" rust="$out/rust.txt" kotlin="$out/kotlin.txt" swift="$out/swift.txt"
