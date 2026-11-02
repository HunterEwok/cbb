#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
#
# Builds the iPhone app and its watch app, signed by a free Personal Team (an
# Apple ID signed in to Xcode, no developer account), and installs them on a
# connected iPhone and its paired Apple Watch. Such a build runs for 7 days;
# then run this again. CONTRIBUTING.md, "The iPhone app on your own phone".
#
#   apps/ios/device.sh            build, install on the phone and the watch, launch
#   apps/ios/device.sh --all      also the share extension and the widgets
#   apps/ios/device.sh --test     run the app's unit tests on the phone
#
# The environment can set CBB_TEAM (the team's 10-character ID; by default the
# Personal Team of the Apple ID signed in to Xcode), CBB_DEVICE (the phone's
# identifier, when more than one is connected) and CBB_BUNDLE_ID.
#
# A free team may have three apps on a phone at a time, an extension counting
# as one, and the app group and shared keychain need the developer account, so
# the share extension (which finds the group only through them) and the widgets
# are left out unless --all. The build is Debug: messages show the error
# underneath.
set -eu

all=0
test=0
for a in "$@"; do
	case $a in
	--all) all=1 ;;
	--test) test=1 ;;
	*) echo "usage: $0 [--all] [--test]" >&2; exit 2 ;;
	esac
done

cd "$(dirname "$0")"
root=$(cd ../.. && pwd)

team=${CBB_TEAM:-}
if [ -z "$team" ]; then
	# The Personal Team of the Apple ID signed in to Xcode: a certificate of
	# another team (a paid one whose agreement lapsed, say) would not do.
	team=$(defaults export com.apple.dt.Xcode - 2>/dev/null | /usr/bin/python3 -I -c '
import plistlib, sys
try:
    p = plistlib.loads(sys.stdin.buffer.read())
except Exception:
    sys.exit()
teams = p.get("IDEProvisioningTeamByIdentifier") or p.get("IDEProvisioningTeams") or {}
free = {t.get("teamID") for ts in teams.values() for t in ts if t.get("isFreeProvisioningTeam")}
free.discard(None)
if len(free) == 1:
    print(free.pop())
')
fi
if [ -z "$team" ]; then
	echo "no Personal Team: sign in to Xcode (Settings, Accounts) with your Apple ID," >&2
	echo "or set CBB_TEAM to the team's 10-character ID" >&2
	exit 1
fi
lower=$(printf %s "$team" | tr '[:upper:]' '[:lower:]')
# Not the release identifier: the developer account will register that one.
bundle=${CBB_BUNDLE_ID:-dev.$lower.clipboardbridge}

# The paired devices from devicectl: "platform udid name tunnel" lines, the
# tunnel "connected" when Xcode can reach the device now.
list=$(mktemp)
trap 'rm -f "$list" device.yml' EXIT
xcrun devicectl list devices --json-output "$list" >/dev/null
devices=$(/usr/bin/python3 -I - "$list" <<'EOF'
import json, sys
for d in json.load(open(sys.argv[1]))["result"]["devices"]:
    hw, cp = d.get("hardwareProperties", {}), d.get("connectionProperties", {})
    if cp.get("pairingState") != "paired":
        continue
    print(hw.get("platform", ""), hw.get("udid", ""), d.get("deviceProperties", {}).get("name", "").replace(" ", "_") or "-", cp.get("tunnelState", "-"))
EOF
)
phone=${CBB_DEVICE:-$(printf '%s\n' "$devices" | awk '$1 == "iOS" { print $2; exit }')}
watch=$(printf '%s\n' "$devices" | awk '$1 == "watchOS" { print $2; exit }')
watchtunnel=$(printf '%s\n' "$devices" | awk '$1 == "watchOS" { print $4; exit }')
if [ -z "$phone" ]; then
	echo "no iPhone: connect it by cable, unlock it, trust this Mac and turn on" >&2
	echo "Developer Mode (Settings, Privacy & Security)" >&2
	exit 1
fi

# The tunnel and the Rust core the app links, when not built yet.
[ -d Cbbtun.xcframework ] || "$root/mobile/cbbtun/bind.sh" ios "$PWD/Cbbtun.xcframework"
[ -d CbbCore/iphoneos ] || sh "$root/lite/ffi/bind.sh" ios "$PWD/CbbCore"

if [ "$all" = 1 ]; then
	xcodegen generate --spec project.yml
else
	grep -v -e '- target: ShareExtension$' -e '- target: Widgets$' project.yml >device.yml
	xcodegen generate --spec device.yml
fi

# Under /tmp, which macOS empties at a restart; .noindex keeps Spotlight
# from listing the built app beside the installed one. CBB_DERIVED moves it.
derived=${CBB_DERIVED:-/tmp/cbb-device.noindex}
set -- -project ClipboardBridge.xcodeproj -configuration Debug -derivedDataPath "$derived" \
	-allowProvisioningUpdates -allowProvisioningDeviceRegistration \
	DEVELOPMENT_TEAM="$team" CODE_SIGN_STYLE=Automatic CBB_BUNDLE_ID="$bundle"

# A free team's profile lists the devices it runs on, and only a build for a
# device adds it: a build of the watch app for the watch puts the watch in
# the profiles, or the watch refuses the app ("could not verify its
# integrity"). Xcode must reach the watch for that.
if [ "$test" = 0 ] && [ -n "$watch" ]; then
	if [ "$watchtunnel" = connected ]; then
		xcodebuild build -scheme Watch -destination "id=$watch" "$@" ||
			echo "the watch was not added to the profile; the watch app may not run on it" >&2
	else
		echo "Xcode does not reach the watch now: with the watch unlocked near the phone, open" >&2
		echo "Xcode, Window, Devices and Simulators until it shows the watch connected, then run" >&2
		echo "this again; until then a watch new to this team refuses the app" >&2
	fi
fi

if [ "$test" = 1 ]; then
	xcodebuild test -scheme ClipboardBridge -destination "id=$phone" "$@"
	exit
fi
xcodebuild build -scheme ClipboardBridge -destination "id=$phone" "$@"

app=$derived/Build/Products/Debug-iphoneos/ClipboardBridge.app
xcrun devicectl device install app --device "$phone" "$app"
if [ -n "$watch" ] && [ -d "$app/Watch/Watch.app" ]; then
	xcrun devicectl device install app --device "$watch" "$app/Watch/Watch.app" ||
		echo "the watch app was not installed: turn on Developer Mode on the watch, keep it unlocked near the phone" >&2
fi
xcrun devicectl device process launch --device "$phone" "$bundle" ||
	echo "installed; on the first run trust the developer in Settings, General, VPN & Device Management" >&2
echo "installed $bundle (team $team); it runs for 7 days"
