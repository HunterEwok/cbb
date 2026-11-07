#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok
#
# Builds the core's WebAssembly module and writes a go build overlay that
# puts it where internal/core embeds it under the tag cbbwasm, so that no
# build output lands in the source tree:
#   sh wasm/build.sh
#   go test -overlay target/cbb-core-overlay.json -tags cbbwasm ./internal/core
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
rustup target add wasm32-unknown-unknown >/dev/null 2>&1 || true
cargo build --locked --release -p cbb-wasm --target wasm32-unknown-unknown
module=$root/target/wasm32-unknown-unknown/release/cbb_wasm.wasm
embed=$root/internal/core/cbb_core.wasm
# Git Bash on Windows: paths as Go reads them there.
if command -v cygpath >/dev/null 2>&1; then
	module=$(cygpath -m "$module")
	embed=$(cygpath -m "$embed")
fi
printf '{"Replace":{"%s":"%s"}}\n' "$embed" "$module" >target/cbb-core-overlay.json
echo "target/cbb-core-overlay.json"
