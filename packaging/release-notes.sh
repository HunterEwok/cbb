#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Writes the notes of a release to standard output:
#
#   sh packaging/release-notes.sh v1.2.3
#
# what Copy Beyond Borders is, the version's section of CHANGELOG.md, how to install
# it, how to verify the files, where the source and the license are, and
# where to report problems. The release workflow publishes them; GitHub
# appends the list of merged pull requests.
set -eu

if [ $# -ne 1 ]; then
	echo "usage: sh packaging/release-notes.sh vX.Y.Z" >&2
	exit 2
fi
tag=$1
version=${tag#v}
root=$(cd "$(dirname "$0")/.." && pwd)
repo=https://github.com/HunterEwok/clipboardbridge

# The version's section, without its heading, up to the next one. A
# pre-release (v1.2.3-rc.1) without a section of its own takes Unreleased: the
# changes since the last release, which the release pull request moves under
# its version.
section=$version
case $version in
*-*) grep -q "^## \[$version\]" "$root/CHANGELOG.md" || section=Unreleased ;;
esac
changes=$(awk -v v="$section" '
	index($0, "## [" v "]") == 1 { on = 1; next }
	on && /^## \[/ { exit }
	on && /^\[[^]]*\]: / { next } # the link definitions at the end of the file
	on { print }
' "$root/CHANGELOG.md" |
	# Links relative to the repository point at this tag on the release page.
	sed "s#](\([^h#)][^)]*\))#]($repo/blob/$tag/\1)#g")
if [ -z "$(printf '%s' "$changes" | tr -d '[:space:]')" ]; then
	echo "release-notes.sh: CHANGELOG.md has no section for $version" >&2
	exit 1
fi

cat <<NOTES
Copy Beyond Borders is one clipboard for your Apple devices and every Linux machine on your home
network: copy on one device, paste on another. It works only on the local network, with
no cloud, accounts or telemetry, and all traffic is end-to-end encrypted between paired
devices.

## What's changed in $version
$changes

## Install

**Linux** with systemd (x86-64, ARM64, ARMv7, ARMv6):

\`\`\`sh
curl -fsSL $repo/releases/download/$tag/get.sh | sudo sh
\`\`\`

\`get.sh\` downloads the archive for the machine, checks it against \`SHA256SUMS\`, installs
the service and, when ufw is active, allows CBB's ports from the home network only.

**macOS** (Apple silicon; \`amd64\` instead of \`arm64\` for Intel), in Terminal:

\`\`\`sh
curl -fsSLO $repo/releases/download/$tag/clipboardbridge-darwin-arm64.tar.gz
tar -xzf clipboardbridge-darwin-arm64.tar.gz
sudo sh clipboardbridge/packaging/macos/install.sh clipboardbridge/cbb
\`\`\`

Or with Homebrew, on macOS or Linux (x86-64, ARM64): \`brew install hunterewok/tap/clipboardbridge\`,
then the command it prints to start the service.

**Android** 10 or later: open \`clipboardbridge-$version.apk\` on the phone and allow the
install. The app makes its own group and adds the computers by their \`cbb pair\` QR code.
For a Wear OS 3 watch paired with that phone, install \`clipboardbridge-wear-$version.apk\` on
the watch (with \`adb install\` over the watch's wireless debugging).

**Lite member** for small Linux devices (a router, a Raspberry Pi Zero), with systemd:

\`\`\`sh
curl -fsSL $repo/releases/download/$tag/get.sh | sudo CBB_VERSION=$tag sh -s -- --lite
\`\`\`

Its command is \`cbb\` too; \`clipboardbridge-lite/README.md\` in its archive has the rest.

Then follow the [quick start]($repo/blob/$tag/docs/guide/quickstart.md): \`sudo cbb pair\` on each
computer, and the phone app scans its QR code. Without the app, \`cbb new\` on the first computer
makes the group ([without the app]($repo/blob/$tag/docs/guide/without-app.md)).

## Verify the downloads

Every file is listed in \`SHA256SUMS\` and has a build provenance attestation, signed with
Sigstore, that ties it to this repository, this tag and the GitHub Actions run that built
it:

\`\`\`sh
sha256sum --ignore-missing -c SHA256SUMS            # macOS: shasum -a 256 -c SHA256SUMS
gh attestation verify clipboardbridge-linux-arm64.tar.gz --repo HunterEwok/clipboardbridge
\`\`\`

## Files

| File | For |
|------|-----|
| \`clipboardbridge-linux-amd64.tar.gz\` | Linux, x86-64 |
| \`clipboardbridge-linux-arm64.tar.gz\` | Linux, ARM64 (Raspberry Pi 3, 4, 5 with a 64-bit system) |
| \`clipboardbridge-linux-armv7.tar.gz\` | Linux, ARMv7 (Raspberry Pi 2, 3, 4 with a 32-bit system) |
| \`clipboardbridge-linux-armv6.tar.gz\` | Linux, ARMv6 (Raspberry Pi Zero W, 1) |
| \`clipboardbridge-darwin-arm64.tar.gz\` | macOS, Apple silicon |
| \`clipboardbridge-darwin-amd64.tar.gz\` | macOS, Intel |
| \`clipboardbridge-windows-amd64.zip\` | Windows 10 (1809 or later) and 11, x86-64 |
| \`clipboardbridge-windows-arm64.zip\` | Windows 10 (1809 or later) and 11, ARM64 |
| \`clipboardbridge-lite-linux-amd64.tar.gz\` | the lite member for small Linux devices, x86-64, static |
| \`clipboardbridge-lite-linux-arm64.tar.gz\` | the lite member, ARM64, static |
| \`clipboardbridge-lite-linux-armv6.tar.gz\` | the lite member, ARMv6 and ARMv7 (Raspberry Pi Zero, 1, 2), static |
| \`clipboardbridge-$version.apk\` | Android 10 and later, signed with the project's release key |
| \`clipboardbridge-wear-$version.apk\` | Wear OS 3 and later, through the paired Android phone, signed with the same key |
| \`clipboardbridge-fdroid-$version.apk\` | the F-Droid build: no Wear OS watch, updated by F-Droid, signed with the same key |
| \`get.sh\` | the installer for Linux (\`--lite\` for the lite member) and macOS |
| \`get.ps1\` | the Windows installer |
| \`SHA256SUMS\` | SHA-256 checksums of all of the above |

Each archive holds \`clipboardbridge/\`: the program, \`LICENSE\`, \`THIRD_PARTY_NOTICES\` with
the licenses of the code it is built from, and \`packaging/\` with the installer for its
system. Each \`clipboardbridge-lite\` archive holds \`clipboardbridge-lite/\`: the program
\`cbb\`, \`LICENSE\`, \`THIRD_PARTY_NOTICES\` with the licenses of the crates it is built from, \`README.md\`, and
\`packaging/\` with the Linux installer and the lite member's systemd unit.

## Source and license

Copy Beyond Borders is free software under the [GNU Affero General Public License, version 3
only]($repo/blob/$tag/LICENSE). The complete source of this release is the tag
[\`$tag\`]($repo/tree/$tag) and the source archives below, from which these files are built
by [the release workflow]($repo/blob/$tag/.github/workflows/release.yml).

## Problems and security

Report bugs as [issues]($repo/issues). Report vulnerabilities privately, as
[SECURITY.md]($repo/blob/$tag/SECURITY.md) explains, never in a public issue.

The full list of changes is in [CHANGELOG.md]($repo/blob/$tag/CHANGELOG.md).
NOTES
