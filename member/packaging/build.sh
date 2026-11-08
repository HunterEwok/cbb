#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Builds cbb, the Rust program, for one of the release's targets, named as
# Go names it, and prints the folder that holds it:
#
#   sh member/packaging/build.sh GOOS/GOARCH[/GOARM]
#
# For Windows the folder holds cbb.exe and cbbw.exe, the same program
# without a console window. Linux's builds are static musl binaries linked
# with Rust's own lld (.cargo/config.toml); FreeBSD's and Windows' are linked
# with zig (cargo-zigbuild), and FreeBSD's ARM64, Tier 3 in Rust, builds the
# standard library from source on the nightly Rust that mips.sh pins; the
# routers' MIPS builds are mips.sh's, without sync away from home; macOS's
# build on a Mac with Apple's linker. CBB_VERSION and CBB_SOURCE, when set,
# name the version and the commit that cbb version prints.
set -eu

cd "$(dirname "$0")/../.."
nightly=$(sed -n 's/^nightly="\(.*\)"$/\1/p' member/packaging/mips.sh)
tool=build toolchain=stable std='' features=''
case ${1:-} in
linux/amd64) target=x86_64-unknown-linux-musl ;;
linux/arm64) target=aarch64-unknown-linux-musl ;;
linux/arm/7) target=armv7-unknown-linux-musleabihf ;;
linux/arm/6) target=arm-unknown-linux-musleabihf ;;
linux/mips | linux/mipsle)
	arch=mips
	[ "$1" = linux/mips ] || arch=mipsel
	bin=$(sh member/packaging/mips.sh "$arch" | tail -n 1)
	dirname "$bin"
	exit 0
	;;
freebsd/amd64) target=x86_64-unknown-freebsd tool=zigbuild ;;
freebsd/arm64) target=aarch64-unknown-freebsd tool=zigbuild toolchain=$nightly std=-Zbuild-std=std,panic_abort ;;
darwin/amd64) target=x86_64-apple-darwin ;;
darwin/arm64) target=aarch64-apple-darwin ;;
windows/amd64) target=x86_64-pc-windows-gnu tool=zigbuild features=windowless ;;
windows/arm64) target=aarch64-pc-windows-gnullvm tool=zigbuild features=windowless ;;
*)
	echo "usage: sh member/packaging/build.sh GOOS/GOARCH[/GOARM]" >&2
	exit 2
	;;
esac
# The architecture as the release's archives name it, which cbb update
# downloads for (member/src/update_os.rs).
CBB_ARCH=${1#*/}
case $CBB_ARCH in arm/*) CBB_ARCH=armv${CBB_ARCH#arm/} ;; esac
export CBB_ARCH
if [ -n "$std" ]; then
	rustup toolchain install "$toolchain" --profile minimal --component rust-src >&2
else
	rustup target add --toolchain "$toolchain" "$target" >&2
fi
# shellcheck disable=SC2086 # std and the features are one word or none
cargo "+$toolchain" "$tool" --locked --release -p cbb-lite --target "$target" \
	${std} ${features:+--features "$features"} >&2
echo "target/$target/release"
