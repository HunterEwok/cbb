#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Signs cbb for macOS with the hardened runtime, which notarization requires:
#
#   sh packaging/macos/sign.sh IDENTITY path/to/cbb
#
# IDENTITY is a Developer ID Application identity in a keychain (its SHA-1
# hash or name), as the release workflow passes, or "-" for an ad hoc
# signature, as CI's build job passes to check that the program runs under
# the hardened runtime with its Rust core (cbb version). A Developer ID
# signature carries a secure timestamp, which notarization requires; an ad hoc
# one cannot. The binary keeps its identifier tools.cbb.cli, so that every
# release is the same program to macOS.
set -eu

if [ $# -ne 2 ]; then
	echo "usage: sh packaging/macos/sign.sh IDENTITY|- path/to/cbb" >&2
	exit 2
fi
identity=$1
bin=$2

if [ "$identity" = - ]; then
	codesign --force --options runtime --identifier tools.cbb.cli --sign - "$bin"
else
	codesign --force --options runtime --timestamp --identifier tools.cbb.cli --sign "$identity" "$bin"
fi
codesign --verify --strict --verbose=2 "$bin"
# The runtime flag is what notarization and the checks below rely on.
codesign --display --verbose=2 "$bin" 2>&1 | grep -q 'flags=.*runtime'
# The group's rules come from the Rust core, which wazero compiles to
# machine code at run time; it must still load under the hardened runtime.
# An Intel build runs on an Apple silicon runner only through Rosetta.
if [ "$(lipo -archs "$bin")" != "$(uname -m)" ] && ! arch -x86_64 /usr/bin/true 2>/dev/null; then
	echo "sign.sh: $(lipo -archs "$bin") does not run here (no Rosetta); not run" >&2
	exit 0
fi
out=$("$bin" version)
echo "$out"
echo "$out" | grep -q '^rules: the Rust core .*, abi [0-9]'
