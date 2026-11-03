#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Sends a signed program, app or installer to Apple's notary service and waits
# for its answer:
#
#   ASC_KEY=... ASC_KEY_ID=... ASC_ISSUER_ID=... sh packaging/macos/notarize.sh FILE
#
# The App Store Connect API key (its .p8 text, key ID and issuer ID) signs in.
# A bare program is sent in a zip, since the service takes only zip, pkg and
# dmg; it cannot carry a ticket, so Gatekeeper fetches it online the first
# time. An .app or a .pkg gets its ticket stapled, for Macs offline. A refusal
# prints the service's log, which names each problem, and fails.
set -eu

if [ $# -ne 1 ]; then
	echo "usage: sh packaging/macos/notarize.sh FILE" >&2
	exit 2
fi
file=$1
: "${ASC_KEY:?no ASC_KEY}" "${ASC_KEY_ID:?no ASC_KEY_ID}" "${ASC_ISSUER_ID:?no ASC_ISSUER_ID}"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
(umask 077 && printf '%s\n' "$ASC_KEY" >"$tmp/key.p8")
auth="--key $tmp/key.p8 --key-id $ASC_KEY_ID --issuer $ASC_ISSUER_ID"

case $file in
*.pkg | *.dmg | *.zip) sub=$file ;;
*)
	sub=$tmp/$(basename "$file").zip
	ditto -c -k --keepParent "$file" "$sub"
	;;
esac

# shellcheck disable=SC2086 # $auth is three flags with their values
xcrun notarytool submit "$sub" $auth --wait --timeout 1h --output-format json >"$tmp/result.json"
id=$(plutil -extract id raw -o - "$tmp/result.json")
status=$(plutil -extract status raw -o - "$tmp/result.json")
echo "notarize.sh: $(basename "$file"): $status ($id)"
if [ "$status" != Accepted ]; then
	# shellcheck disable=SC2086
	xcrun notarytool log "$id" $auth >&2 || true
	exit 1
fi

case $file in
*.app | *.pkg | *.dmg)
	xcrun stapler staple "$file"
	xcrun stapler validate "$file"
	;;
esac
