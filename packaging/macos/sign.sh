#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Signs cbb or CBB.app for macOS with the hardened runtime, which
# notarization requires:
#
#   sh packaging/macos/sign.sh IDENTITY path/to/cbb
#   sh packaging/macos/sign.sh IDENTITY path/to/cbb-helper
#   sh packaging/macos/sign.sh IDENTITY path/to/cbb-forward (or cbb-relay)
#   sh packaging/macos/sign.sh IDENTITY path/to/CBB.app
#
# IDENTITY is a Developer ID Application identity in a keychain (its SHA-1
# hash or name), as the release workflow passes, or "-" for an ad hoc
# signature, as CI's build job passes to check that the program runs under
# the hardened runtime with its Rust core (cbb version). A Developer ID
# signature carries a secure timestamp, which notarization requires; an ad hoc
# one cannot. The binary keeps its identifier tools.cbb.cli, so that every
# release is the same program to macOS; cbb-helper, the Go helper cbb starts
# as its child, keeps tools.cbb.helper, and the servers cbb-forward and
# cbb-relay keep tools.cbb.forward and tools.cbb.relay. An app, built by xcodebuild without
# signing, is signed from the inside out: its nested code first, then the
# bundle, which keeps the identifier of its Info.plist.
#
# Nothing asks the hardened runtime for an entitlement: no program compiles
# code at run time.
set -eu

if [ $# -ne 2 ]; then
	echo "usage: sh packaging/macos/sign.sh IDENTITY|- path/to/cbb|path/to/cbb-helper|path/to/CBB.app" >&2
	exit 2
fi
identity=$1
bin=$2

# sign PATH [codesign flags] signs one piece of code.
sign() {
	path=$1
	shift
	if [ "$identity" = - ]; then
		codesign --force --options runtime "$@" --sign - "$path"
	else
		codesign --force --options runtime --timestamp "$@" --sign "$identity" "$path"
	fi
}

case $bin in
*.app | *.app/)
	bin=${bin%/}
	# The deepest first, since signing a bundle seals what it holds.
	find "$bin/Contents" -depth \( -name '*.dylib' -o -name '*.framework' -o -name '*.appex' -o -name '*.xpc' \) |
		while read -r nested; do sign "$nested"; done
	sign "$bin"
	codesign --verify --deep --strict --verbose=2 "$bin"
	codesign --display --verbose=2 "$bin" 2>&1 | grep -q 'flags=.*runtime'
	exit 0
	;;
esac

identifier=tools.cbb.cli
case $bin in
*/cbb-helper | cbb-helper | */cbb-helper-* | cbb-helper-*) identifier=tools.cbb.helper ;;
*/cbb-forward | cbb-forward) identifier=tools.cbb.forward ;;
*/cbb-relay | cbb-relay) identifier=tools.cbb.relay ;;
esac
sign "$bin" --identifier "$identifier"
codesign --verify --strict --verbose=2 "$bin"
# The runtime flag is what notarization and the checks below rely on.
codesign --display --verbose=2 "$bin" 2>&1 | grep -q 'flags=.*runtime'
# No entitlement weakens the hardened runtime.
if codesign --display --entitlements - --xml "$bin" 2>/dev/null | grep -q 'com.apple.security'; then
	echo "sign.sh: $bin carries an entitlement" >&2
	exit 1
fi
# The program must still start under the hardened runtime.
# An Intel build runs on an Apple silicon runner only through Rosetta.
if [ "$(lipo -archs "$bin")" != "$(uname -m)" ] && ! arch -x86_64 /usr/bin/true 2>/dev/null; then
	echo "sign.sh: $(lipo -archs "$bin") does not run here (no Rosetta); not run" >&2
	exit 0
fi
case $identifier in
tools.cbb.forward | tools.cbb.relay)
	# A server takes only flags and has no version; that it refuses an
	# argument shows it loads under the hardened runtime.
	out=$("$bin" version 2>&1) || true
	echo "$out"
	echo "$out" | grep -q 'takes only flags'
	exit 0
	;;
esac
out=$("$bin" version)
echo "$out"
if [ "$identifier" = tools.cbb.helper ]; then
	# The helper says only its version; the rules it runs are checked in cbb.
	echo "$out" | grep -q '^cbb '
	exit 0
fi
echo "$out" | grep -q '^rules: the Rust core .*, abi [0-9]'
