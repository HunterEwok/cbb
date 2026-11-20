#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# The recovery drills (docs/testing.md, "Recovery drills"), played on whole
# members of this build, as a person plays them after a loss:
#
#   sh tools/e2e/drills.sh [COUNT]
#
#   - the root is lost and a computer takes the group back with the
#     recovery key, then hands it to an admin (TestRecovery);
#   - a new phone restores the group with the recovery sheet once the root
#     is lost (TestFFIPhoneRestore, the phone's member on Linux);
#   - a device restored from yesterday's backup gets back in while the
#     group went on (TestDrillRestoreFromYesterday);
#   - a removed device restored from a backup made before its removal
#     stays out (TestDrillRemovedStaysOut).
#
# It builds cbb, cbb-helper and phone-on-linux, then runs each drill COUNT
# times (1 without it). What a real iPhone's Secure Enclave and Face ID add
# is the hand checklist in the bench's test plan.
set -eu

count=${1:-1}
top=$(git rev-parse --show-toplevel)
cd "$top"
cargo build --locked --release -p cbb-member
cargo build --locked --release -p cbb-ffi --features member,tunnel --example phone-on-linux
CGO_ENABLED=0 go build -trimpath -o target/release/cbb-helper ./cmd/cbb-helper
CBB_TEST_RUST_SERVICE="$top/target/release/cbb" CBB_TEST_ALONE="$top/target/release/cbb" \
	CBB_PHONE_ON_LINUX="$top/target/release/examples/phone-on-linux" \
	go test -timeout 60m -count "$count" ./internal/service \
	-run '^(TestRecovery|TestFFIPhoneRestore|TestDrillRestoreFromYesterday|TestDrillRemovedStaysOut)$' -v
