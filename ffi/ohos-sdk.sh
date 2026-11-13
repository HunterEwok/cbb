#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok
#
# OpenHarmony's native SDK (clang, the musl sysroot, Node-API's and HUKS's
# headers) in DIR, for bind.sh harmony and the HarmonyOS app's native module;
# on Linux x86_64, with unzip and about 6 GB free while it unpacks:
#   ohos-sdk.sh DIR       downloads the public SDK into DIR/dl (kept for the
#                         next run and checked against its SHA-256) and
#                         unpacks its Linux native part into DIR/native
#   ohos-sdk.sh DIR ets   also its ArkTS part and tools into DIR/ets and
#                         DIR/toolchains, for apps/harmony/check.sh
# It prints the native directory, which bind.sh takes as OHOS_NDK_HOME. The
# SDK is OpenHarmony's, free to download; the HarmonyOS SDK, which builds the
# app itself, needs a Huawei developer account and is not this one.
set -eu
if [ $# -lt 1 ] || [ $# -gt 2 ] || { [ $# -eq 2 ] && [ "$2" != ets ]; }; then
	echo "usage: ohos-sdk.sh DIR [ets]" >&2
	exit 2
fi
dir=$1
parts=native
[ $# -eq 1 ] || parts="native ets toolchains"
version=6.0-Release
url=https://repo.huaweicloud.com/openharmony/os/$version/ohos-sdk-windows_linux-public.tar.gz
sum=a315834ac133625efc912bd078f3e2b2550868d04aef1b5aa4f9679c8b3c9d8e
size=2487576829
tarball=$dir/dl/ohos-sdk-$version.tar.gz

have=true
for p in $parts; do
	[ -d "$dir/$p" ] || have=false
done
[ -x "$dir/native/llvm/bin/clang" ] || have=false
if [ "$have" = true ]; then
	echo "$dir/native"
	exit 0
fi
mkdir -p "$dir/dl"
# The mirror drops long downloads now and then, so a download resumes; and
# it may go on past the end, so the file is cut to its size.
i=0
until [ "$(stat -L -c %s "$tarball" 2>/dev/null || echo 0)" -ge $size ]; do
	i=$((i + 1))
	if [ $i -gt 30 ]; then
		echo "ohos-sdk.sh: the download keeps failing" >&2
		exit 1
	fi
	curl -fsSL -C - -o "$tarball" "$url" || sleep 3
done
truncate -s $size "$tarball"
if ! echo "$sum  $tarball" | sha256sum -c --status; then
	rm -f "$tarball"
	echo "ohos-sdk.sh: the download does not match its SHA-256; run it again" >&2
	exit 1
fi
# The tarball holds a zip per part and system; only the Linux ones asked.
tmp=$dir/tmp
for p in $parts; do
	rm -rf "$tmp" "${dir:?}/$p"
	mkdir -p "$tmp"
	tar -xzf "$tarball" -C "$tmp" --wildcards "*linux/$p-linux-x64-*.zip"
	unzip -q "$(find "$tmp" -name "$p-linux-x64-*.zip" | head -n 1)" -d "$dir"
done
rm -rf "$tmp"
echo "$dir/native"
