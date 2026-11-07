#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Builds the iPhone app for the App Store, with its share extension, widgets
# and Apple Watch app, signed with the project's Apple Distribution
# certificate and App Store profiles; with upload, sends it to TestFlight:
#
#   KEYCHAIN=... PROFILES=... sh apps/ios/testflight.sh VERSION BUILD OUTDIR [upload]
#
# Run from the repository root, after xcodegen generate in apps/ios and the
# libraries the app links (mobile/cbbtun/bind.sh ios, ffi/bind.sh ios),
# as the release workflow does. KEYCHAIN holds the Apple Distribution identity
# (packaging/macos/keychain.sh); PROFILES is a base64 tar.gz of the four App
# Store profiles, one for each App ID (tools.cbb, .share, .widgets,
# .watchkitapp), which it installs and gives each target by its App ID.
# VERSION is the release's (0.6.0, 0.6.0-rc.1; the App Store takes only its
# numbers), BUILD the build number, higher with each upload. It writes the
# archive and the .ipa to OUTDIR. upload sends the build to App Store
# Connect with the App Store Connect API key in ASC_KEY (its .p8 text),
# ASC_KEY_ID and ASC_ISSUER_ID; TestFlight then offers it to the testers
# once Apple has processed it.
set -eu

team=U2ZJ8F2JCJ
if [ $# -ne 3 ] && [ $# -ne 4 ]; then
	echo "usage: sh apps/ios/testflight.sh VERSION BUILD OUTDIR [upload]" >&2
	exit 2
fi
version=${1%%-*}
build=$2
out=$3
upload=${4:-}
case $upload in '' | upload) ;; *)
	echo "usage: sh apps/ios/testflight.sh VERSION BUILD OUTDIR [upload]" >&2
	exit 2
	;;
esac
case $version.$build in *[!0-9.]* | .*)
	echo "testflight.sh: the version is numbers like 1.2.3 and the build a number, not $1 and $2" >&2
	exit 2
	;;
esac
: "${KEYCHAIN:?no KEYCHAIN}" "${PROFILES:?no PROFILES}"
if [ -n "$upload" ]; then
	: "${ASC_KEY:?no ASC_KEY}" "${ASC_KEY_ID:?no ASC_KEY_ID}" "${ASC_ISSUER_ID:?no ASC_ISSUER_ID}"
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$out" "$tmp/profiles"
printf '%s' "$PROFILES" | base64 -D | tar -xzf - -C "$tmp/profiles"

# Each profile goes where Xcode looks for profiles (the second folder since
# Xcode 16) and to its target by its App ID.
xcconfig=$tmp/signing.xcconfig
map=$tmp/profiles.plist
printf '<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict/></plist>\n' >"$map"
for dir in "$HOME/Library/MobileDevice/Provisioning Profiles" "$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles"; do
	mkdir -p "$dir"
done
get() { /usr/libexec/PlistBuddy -c "Print :$1" "$tmp/profile.plist"; }
found=
for f in "$tmp"/profiles/*.mobileprovision; do
	[ -f "$f" ] || continue
	security cms -D -i "$f" >"$tmp/profile.plist"
	uuid=$(get UUID)
	id=$(get Entitlements:application-identifier)
	# An App Store profile names no devices.
	if get ProvisionedDevices >/dev/null 2>&1; then
		echo "testflight.sh: $(basename "$f") is not an App Store profile; skipped" >&2
		continue
	fi
	case $id in
	"$team.tools.cbb") target=CBB ;;
	"$team.tools.cbb.share") target=ShareExtension ;;
	"$team.tools.cbb.widgets") target=Widgets ;;
	"$team.tools.cbb.watchkitapp") target=Watch ;;
	*)
		echo "testflight.sh: $(basename "$f") is for $id; skipped" >&2
		continue
		;;
	esac
	for dir in "$HOME/Library/MobileDevice/Provisioning Profiles" "$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles"; do
		cp "$f" "$dir/$uuid.mobileprovision"
	done
	echo "CBB_PROFILE_$target = $uuid" >>"$xcconfig"
	/usr/libexec/PlistBuddy -c "Add :${id#"$team".} string $uuid" "$map"
	echo "testflight.sh: $target signs with the profile \"$(get Name)\" ($uuid), until $(get ExpirationDate)"
	found="$found $target"
done
for target in CBB ShareExtension Widgets Watch; do
	case " $found " in *" $target "*) ;; *)
		echo "testflight.sh: no App Store profile for $target in PROFILES" >&2
		exit 1
		;;
	esac
done

# Every target signs by hand with its own profile; the Swift packages take
# none (an empty CBB_PROFILE_ for them).
cat >>"$xcconfig" <<EOF
CODE_SIGN_STYLE = Manual
DEVELOPMENT_TEAM = $team
CODE_SIGN_IDENTITY = Apple Distribution
PROVISIONING_PROFILE_SPECIFIER = \$(CBB_PROFILE_\$(TARGET_NAME))
OTHER_CODE_SIGN_FLAGS = --keychain $KEYCHAIN
MARKETING_VERSION = $version
CURRENT_PROJECT_VERSION = $build
EOF

archive=$out/CBB.xcarchive
rm -rf "$archive"
# The whole log only when it fails: it runs to many thousands of lines.
if ! xcodebuild archive -project apps/ios/CBB.xcodeproj -scheme CBB -configuration Release \
	-destination 'generic/platform=iOS' -archivePath "$archive" -xcconfig "$xcconfig" >"$tmp/archive.log" 2>&1; then
	grep -E 'error: ' "$tmp/archive.log" >&2 || true
	tail -n 100 "$tmp/archive.log" >&2
	exit 1
fi
tail -n 5 "$tmp/archive.log"
[ -d "$archive/Products/Applications/CBB.app" ]

# options DESTINATION writes the export's options: the App Store, signed by
# hand with the profiles above.
options() {
	cat >"$tmp/export.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyLists-1.0.dtd">
<plist version="1.0">
<dict>
	<key>method</key><string>app-store-connect</string>
	<key>destination</key><string>$1</string>
	<key>teamID</key><string>$team</string>
	<key>signingStyle</key><string>manual</string>
	<key>signingCertificate</key><string>Apple Distribution</string>
	<key>uploadSymbols</key><true/>
	<key>manageAppVersionAndBuildNumber</key><false/>
</dict>
</plist>
EOF
	/usr/libexec/PlistBuddy -c "Add :provisioningProfiles dict" -c "Merge $map :provisioningProfiles" "$tmp/export.plist"
}

options export
xcodebuild -exportArchive -archivePath "$archive" -exportOptionsPlist "$tmp/export.plist" -exportPath "$out"
ipa=$(find "$out" -maxdepth 1 -name '*.ipa' | head -n 1)
[ -n "$ipa" ]
echo "testflight.sh: $ipa, version $version ($build)"

if [ -n "$upload" ]; then
	(umask 077 && printf '%s\n' "$ASC_KEY" >"$tmp/AuthKey.p8")
	options upload
	xcodebuild -exportArchive -archivePath "$archive" -exportOptionsPlist "$tmp/export.plist" \
		-exportPath "$tmp/upload" -authenticationKeyPath "$tmp/AuthKey.p8" \
		-authenticationKeyID "$ASC_KEY_ID" -authenticationKeyIssuerID "$ASC_ISSUER_ID"
	echo "testflight.sh: version $version ($build) sent to App Store Connect; TestFlight shows it once Apple has processed it"
fi
