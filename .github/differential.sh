#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# The differential comparison of the three implementations
# (docs/differential.md): a corpus from tools/difffuzz, the verdict test of
# each of Go, the Rust core and the Kotlin kit, then the comparison, which fails on any case they read differently and writes
# those cases to OUT/failures.jsonl.
#
# Usage: differential.sh SEED BODIES OUT, from the repository's root.
set -eu

seed=$1
bodies=$2
out=$(mkdir -p "$3" && cd "$3" && pwd)

go run ./tools/difffuzz gen -seed "$seed" -n "$bodies" -o "$out/corpus.jsonl"
export CBB_VERDICTS="$out/corpus.jsonl"

CBB_VERDICTS_OUT="$out/go-release.txt" go test ./internal/release -run '^TestVerdicts$' -count=1
(cd core/ && CBB_VERDICTS_OUT="$out/rust.txt" cargo test --locked --release --lib command::verdicts)
# --rerun: Gradle does not see the corpus change between runs.
(cd apps/android && CBB_VERDICTS_OUT="$out/kotlin.txt" ./gradlew --no-daemon -q -p kit test --tests '*.VerdictTest' --rerun)

go run ./tools/difffuzz compare -corpus "$out/corpus.jsonl" -failures "$out/failures.jsonl" \
	go="$out/go-release.txt" rust="$out/rust.txt" kotlin="$out/kotlin.txt"
