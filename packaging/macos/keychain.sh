#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# A keychain of its own for a release's signing identities on a CI runner:
#
#   sh packaging/macos/keychain.sh create DIR
#   P12=base64 P12_PASSWORD=... sh packaging/macos/keychain.sh import DIR KIND TEAM
#   sh packaging/macos/keychain.sh delete DIR
#
# create makes DIR/cbb.keychain-db with a random password, kept in DIR, and
# puts it first in the user's search list, so that codesign, productsign and
# xcodebuild find its identities. import takes a base64 PKCS#12 file from
# $P12 and its password from $P12_PASSWORD, lets Apple's signing tools use
# its key without a prompt, and prints the SHA-1 hash of the one identity
# named "KIND: ... (TEAM)", for example "Developer ID Application" and the
# team ID; it fails when there is none, so that a wrong certificate in the
# secrets stops the release. delete removes the keychain and DIR again.
set -eu

usage() {
	echo "usage: sh packaging/macos/keychain.sh create DIR | import DIR KIND TEAM | delete DIR" >&2
	exit 2
}
[ $# -ge 2 ] || usage
cmd=$1
dir=$2
kc=$dir/cbb.keychain-db

case $cmd in
create)
	[ $# -eq 2 ] || usage
	mkdir -p "$dir"
	chmod 700 "$dir"
	(umask 077 && openssl rand -hex 24 >"$dir/pass")
	pass=$(cat "$dir/pass")
	security create-keychain -p "$pass" "$kc"
	# No lock while the release runs (six hours at most).
	security set-keychain-settings -lut 21600 "$kc"
	security unlock-keychain -p "$pass" "$kc"
	# shellcheck disable=SC2046 # the search list, one keychain per word
	security list-keychains -d user -s "$kc" $(security list-keychains -d user | tr -d '"')
	;;
import)
	[ $# -eq 4 ] || usage
	kind=$3
	team=$4
	: "${P12:?no P12}" "${P12_PASSWORD:?no P12_PASSWORD}"
	pass=$(cat "$dir/pass")
	(umask 077 && printf '%s' "$P12" | base64 -D >"$dir/identity.p12")
	security import "$dir/identity.p12" -k "$kc" -P "$P12_PASSWORD" -f pkcs12 \
		-T /usr/bin/codesign -T /usr/bin/productsign -T /usr/bin/productbuild -T /usr/bin/xcodebuild >/dev/null
	rm -f "$dir/identity.p12"
	security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$pass" "$kc" >/dev/null
	# Installer identities are not code signing ones, so every identity is listed.
	id=$(security find-identity -v "$kc" | grep -F "\"$kind: " | grep -F "($team)\"" | awk '{print $2}' | head -n 1)
	if [ -z "$id" ]; then
		echo "keychain.sh: no \"$kind: ... ($team)\" identity in the certificate given" >&2
		security find-identity -v "$kc" >&2
		exit 1
	fi
	echo "$id"
	;;
delete)
	[ $# -eq 2 ] || usage
	security delete-keychain "$kc" 2>/dev/null || true
	rm -rf "$dir"
	;;
*)
	usage
	;;
esac
