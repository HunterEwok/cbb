#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok
#
# Builds the Rust core's entry point, the C functions of include/cbb_core.h
# (docs/core-api.md), for the phone apps and the phone kits' tests:
#   bind.sh ios OUT       OUT/iphoneos/libcbb_ffi.a and OUT/iphonesimulator/libcbb_ffi.a,
#                         for the iPhone app (needs Xcode)
#   bind.sh android OUT   OUT/jniLibs/<abi>/libcbb_ffi.so, for the Android app (needs
#                         ANDROID_NDK_HOME and cargo-ndk)
#   bind.sh host OUT      OUT/libcbb_ffi.a, for the Swift kit's tests on this computer:
#                         swift test -Xlinker -LOUT
#   bind.sh aurora OUT    OUT/arm/libcbb_ffi.a and OUT/arm64/libcbb_ffi.a, for the
#                         Aurora and Sailfish app (apps/silica/build.sh)
# OUT is made absolute; nothing it writes belongs in git. The Kotlin kit's
# tests build the host's shared library themselves (apps/android/kit). Every
# library carries the member (the feature member, docs/core-api.md, "The
# member"): the phones' apps sync through it.
set -eu
if [ $# -ne 2 ]; then
	echo "usage: bind.sh ios|android|host|aurora OUT" >&2
	exit 2
fi
target=$1
case $2 in
/*) out=$2 ;;
*) out=$(pwd)/$2 ;;
esac
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
mkdir -p "$out"

# The same library from any checkout: the paths of this checkout and of
# cargo's sources are written as fixed names into what the library keeps of
# them, so F-Droid's build of the APK is the same as ours.
cargo_home=${CARGO_HOME:-$HOME/.cargo}
# rustup's cargo where a build's PATH has none (F-Droid's gradle step).
command -v cargo >/dev/null || PATH=$cargo_home/bin:$PATH
RUSTFLAGS="--remap-path-prefix=$root=/cbb --remap-path-prefix=$cargo_home=/cargo"
export RUSTFLAGS

case $target in
ios)
	for t in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios; do
		rustup target add "$t" >/dev/null
		IPHONEOS_DEPLOYMENT_TARGET=17.0 cargo build --locked -p cbb-ffi --features member --release --target "$t"
	done
	mkdir -p "$out/iphoneos" "$out/iphonesimulator"
	cp target/aarch64-apple-ios/release/libcbb_ffi.a "$out/iphoneos/"
	lipo -create target/aarch64-apple-ios-sim/release/libcbb_ffi.a target/x86_64-apple-ios/release/libcbb_ffi.a \
		-output "$out/iphonesimulator/libcbb_ffi.a"
	;;
android)
	rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android >/dev/null
	for abi in arm64-v8a armeabi-v7a x86_64; do
		cargo ndk --platform 29 -t "$abi" -o "$out/jniLibs" build --locked -p cbb-ffi --features member --release
	done
	;;
host)
	# Only the static library: the linker would take a shared one beside it,
	# which the tests would then have to find at run time.
	cargo build --locked -p cbb-ffi --features member --release
	cp target/release/libcbb_ffi.a "$out/"
	;;
aurora)
	# The Aurora and Sailfish apps' static libraries, by qmake's QT_ARCH. Only
	# the static library: building the shared one needs the SDK's linker.
	# With member (and join): the app joins by its QR code and syncs as a
	# member, with its key in OP-TEE; with tunnel, it syncs away from home
	# through the group's hub as the other phones do.
	# GotaTun, which the tunnel takes, is also a shared library, which needs
	# the target's linker even here: the GNU cross compilers, or LINKER_ARM and
	# LINKER_ARM64 in the environment.
	export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_GNUEABIHF_LINKER="${LINKER_ARM:-arm-linux-gnueabihf-gcc}"
	export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="${LINKER_ARM64:-aarch64-linux-gnu-gcc}"
	for pair in arm:armv7-unknown-linux-gnueabihf arm64:aarch64-unknown-linux-gnu; do
		arch=${pair%%:*}
		t=${pair#*:}
		rustup target add "$t" >/dev/null
		cargo rustc --locked -p cbb-ffi --features member,tunnel --lib --release --target "$t" --crate-type staticlib
		mkdir -p "$out/$arch"
		cp "target/$t/release/libcbb_ffi.a" "$out/$arch/"
	done
	;;
*)
	echo "bind.sh: unknown target $target" >&2
	exit 2
	;;
esac
