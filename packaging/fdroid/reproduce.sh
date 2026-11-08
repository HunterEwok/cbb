#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok
#
# Builds the app's F-Droid APK twice and checks that the two are the same, which F-Droid
# needs to publish the APK of our release (docs/apps.md, "F-Droid"):
#   reproduce.sh CHECKOUT ELSEWHERE
# CHECKOUT, the repository, is built where it is. ELSEWHERE, a new or empty directory, gets
# its committed files without .git, as a tarball has them, and is built there with another
# time zone, umask and cargo target directory. Both need what the app's
# build needs: the Android SDK with the NDK of cbb.ndk (apps/android/gradle.properties), the
# Rust of cbb.rust with the Android targets and cargo-ndk, and a JDK. CI's fdroid job runs
# it.
set -eu
if [ $# -ne 2 ]; then
	echo "usage: reproduce.sh CHECKOUT ELSEWHERE" >&2
	exit 2
fi
one=$(cd "$1" && pwd)
mkdir -p "$2"
two=$(cd "$2" && pwd)
if [ -n "$(ls -A "$two")" ]; then
	echo "reproduce.sh: $two is not empty" >&2
	exit 2
fi
git -C "$one" archive HEAD | tar -x -C "$two"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

apk=apps/android/app/build/outputs/apk/fdroid/release/app-fdroid-release-unsigned.apk
(cd "$one/apps/android" && ./gradlew --no-daemon :app:assembleFdroidRelease)
(
	umask 077
	TZ=Pacific/Kiritimati
	export TZ
	cd "$two/apps/android" && ./gradlew --no-daemon :app:assembleFdroidRelease
)

if cmp -s "$one/$apk" "$two/$apk"; then
	echo "the two F-Droid APKs are the same"
	exit 0
fi
echo "the two F-Droid APKs differ; their entries (size, CRC-32, name):" >&2
# The entries' lists, not the files unzipped: R8's resource names differ only in case
# (res/9n.9.png and res/9N.9.png), which a Mac's disk keeps as one file.
unzip -lv "$one/$apk" | awk '{ print $1, $7, $8 }' >"$work/one"
unzip -lv "$two/$apk" | awk '{ print $1, $7, $8 }' >"$work/two"
if diff "$work/one" "$work/two" >&2; then
	echo "(the same files: the archives differ in their order, times or alignment)" >&2
fi
exit 1
