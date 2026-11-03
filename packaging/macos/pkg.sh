#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Makes the Mac's installer package, CBB.app and the service in one file:
#
#   sh packaging/macos/pkg.sh VERSION path/to/cbb path/to/CBB.app OUT.pkg [IDENTITY]
#
# VERSION is the release's (0.6.0, 0.6.0-rc.1). cbb and CBB.app come signed
# (sign.sh); cbb is the universal program, for Apple silicon and Intel.
# IDENTITY, a Developer ID Installer identity in a keychain (its SHA-1 hash
# or name), signs the package with a secure timestamp; without it the package
# is unsigned, for CI's test of it. The package puts the app in /Applications
# and cbb with install.sh and its files in /usr/local/share/cbb/package; its
# postinstall script then runs install.sh, as get.sh does with sudo, for the
# user signed in at the screen, and opens the app in the menu bar.
# uninstall.sh removes the app and the package's receipt with the rest.
set -eu

if [ $# -ne 4 ] && [ $# -ne 5 ]; then
	echo "usage: sh packaging/macos/pkg.sh VERSION path/to/cbb path/to/CBB.app OUT.pkg [IDENTITY]" >&2
	exit 2
fi
version=$1
bin=$2
app=${3%/}
out=$4
identity=${5:-}
here=$(cd "$(dirname "$0")" && pwd)
case $version in
'' | *[!0-9A-Za-z.-]*)
	echo "pkg.sh: a version is digits, letters, dots and dashes, not $version" >&2
	exit 2
	;;
esac
for arch in arm64 x86_64; do
	if ! lipo "$bin" -verify_arch "$arch" 2>/dev/null; then
		echo "pkg.sh: $bin has no $arch; make it with lipo -create from both builds" >&2
		exit 1
	fi
done

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
root=$work/root
share=$root/usr/local/share/cbb/package
mkdir -p "$root/Applications" "$share/macos" "$work/scripts"
ditto "$app" "$root/Applications/CBB.app"
ditto "$bin" "$share/cbb"
for f in install.sh uninstall.sh tools.cbb.plist tools.cbb.agent.plist; do
	cp "$here/$f" "$share/macos/"
done
# install.sh reads it beside its folder, as in a release archive.
cp "$here/../update.sh" "$share/"

cat >"$work/scripts/postinstall" <<'EOF'
#!/bin/sh
# The package's files are in place; this installs the service from them, as
# sudo sh install.sh does (packaging/macos/install.sh), and opens the app for
# the user signed in at the screen, who joins the cbb group. Its output goes
# to /var/log/install.log. Without a terminal, install.sh keeps the answers
# given before about the firewall and automatic updates, and asks nothing.
set -eu
pkg=/usr/local/share/cbb/package
user=$(stat -f %Su /dev/console 2>/dev/null || true)
case $user in root | loginwindow | _mbsetupuser) user= ;; esac
SUDO_USER=$user sh "$pkg/macos/install.sh" "$pkg/cbb"
# install.sh made its own copies of everything.
rm -rf "$pkg"
if [ -n "$user" ]; then
	launchctl asuser "$(id -u "$user")" sudo -u "$user" open -g /Applications/CBB.app || true
fi
EOF
chmod 0755 "$work/scripts/postinstall"

# The app stays in /Applications, even when a copy of it is elsewhere.
pkgbuild --analyze --root "$root" "$work/component.plist" >/dev/null
n=0
while /usr/libexec/PlistBuddy -c "Print :$n" "$work/component.plist" >/dev/null 2>&1; do
	/usr/libexec/PlistBuddy -c "Set :$n:BundleIsRelocatable false" "$work/component.plist"
	n=$((n + 1))
done
pkgbuild --root "$root" --component-plist "$work/component.plist" --scripts "$work/scripts" \
	--identifier tools.cbb.pkg --version "$version" --install-location / --ownership recommended \
	"$work/cbb-component.pkg" >/dev/null

cat >"$work/distribution.xml" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
    <title>CBB</title>
    <options customize="never" require-scripts="true" rootVolumeOnly="true" hostArchitectures="arm64,x86_64"/>
    <domains enable_localSystem="true" enable_anywhere="false" enable_currentUserHome="false"/>
    <allowed-os-versions>
        <os-version min="14.0"/>
    </allowed-os-versions>
    <choices-outline>
        <line choice="tools.cbb.pkg"/>
    </choices-outline>
    <choice id="tools.cbb.pkg" visible="false">
        <pkg-ref id="tools.cbb.pkg"/>
    </choice>
    <pkg-ref id="tools.cbb.pkg" version="$version" onConclusion="none">cbb-component.pkg</pkg-ref>
</installer-gui-script>
EOF

if [ -n "$identity" ]; then
	productbuild --distribution "$work/distribution.xml" --package-path "$work" \
		--sign "$identity" --timestamp "$out"
	pkgutil --check-signature "$out"
else
	productbuild --distribution "$work/distribution.xml" --package-path "$work" "$out"
fi
echo "$out"
