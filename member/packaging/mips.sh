#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Builds the lite member for 32-bit MIPS routers, without the tunnel:
#
#   sh member/packaging/mips.sh mips|mipsel
#
# mips-unknown-linux-musl (big-endian) and mipsel-unknown-linux-musl are
# Tier 3 in Rust, so the standard library is built from source on nightly
# Rust, and zig links the static musl binary (cargo-zigbuild); both soft
# float, as OpenWrt's MIPS targets. GotaTun needs 64-bit atomics, which
# 32-bit MIPS lacks, so the build leaves out sync away from home (the
# feature tunnel; docs/roadmap.md, item 37). The binary is not
# position-independent: a static PIE crashed at its start under
# qemu-mips. It lands in target/<target>/release/cbb.
set -eu

nightly="nightly-2026-10-26"
case ${1:-} in
mips | mipsel) target=$1-unknown-linux-musl ;;
*)
	echo "usage: sh member/packaging/mips.sh mips|mipsel" >&2
	exit 2
	;;
esac
cd "$(dirname "$0")/../.."
RUSTFLAGS="-C relocation-model=static" cargo "+$nightly" zigbuild --locked --release \
	-Zbuild-std=std,panic_abort --target "$target" --no-default-features
echo "target/$target/release/cbb"
