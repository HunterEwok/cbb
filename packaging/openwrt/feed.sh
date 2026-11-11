#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Builds the OpenWrt package feed from a release's Linux archives:
#
#   sh packaging/openwrt/feed.sh VERSION DIST OUTDIR [KEY]
#
# It runs where apk-tools 3 has mkpkg and mkndx, as in Alpine 3.23 and later:
# OpenWrt's own apk leaves them out. For each Linux archive in DIST
# (cbb-linux-<arch>.tar.gz) it writes OUTDIR/<arch>/ with
# cbb-<version>.apk and the index packages.adb, signed with the
# ECDSA P-256 key KEY when one is given. One package serves every OpenWrt
# CPU of its Go architecture, so it is marked noarch, and a router adds the
# feed of its architecture (docs/guide/install.md, "OpenWrt"). VERSION is
# the release tag (v0.6.0, v0.6.0-rc.1).
set -eu

[ $# -eq 3 ] || [ $# -eq 4 ] || {
	echo "usage: sh packaging/openwrt/feed.sh VERSION DIST OUTDIR [KEY]" >&2
	exit 2
}
tag=$1 dist=$2 out=$3 key=${4:-}
here=$(cd "$(dirname "$0")" && pwd)

# apk's versions: 0.6.0-r1, and 0.6.0_rc1-r1 for v0.6.0-rc.1. apk knows
# only its own pre-release words, so a tag with another one (v0.6.0-ci.1)
# stops here rather than in apk mkpkg.
version=${tag#v}
case $version in
*-*)
	pre=$(echo "${version#*-}" | tr -d '.')
	case $pre in
	alpha[0-9]* | beta[0-9]* | pre[0-9]* | rc[0-9]*) ;;
	*)
		echo "feed.sh: apk cannot take the pre-release \"${version#*-}\" of $tag: use alpha, beta, pre or rc and a number" >&2
		exit 1
		;;
	esac
	version=${version%%-*}_$pre
	;;
esac
version=$version-r1

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$out"
built=0
for archive in "$dist"/cbb-linux-*.tar.gz; do
	[ -f "$archive" ] || continue
	arch=${archive##*/cbb-linux-}
	arch=${arch%.tar.gz}
	root=$work/$arch/root
	mkdir -p "$root/usr/bin" "$root/usr/share/cbb" "$root/etc/init.d" "$root/etc/config" \
		"$root/etc/hotplug.d/ntp" "$root/etc/capabilities" "$root/lib/upgrade/keep.d"
	tar -xzf "$archive" -C "$work/$arch" cbb/cbb
	mv "$work/$arch/cbb/cbb" "$root/usr/bin/cbb"
	cp "$here/cbb.init" "$root/etc/init.d/cbb"
	cp "$here/cbb.config" "$root/etc/config/cbb"
	cp "$here/cbb.ntp" "$root/etc/hotplug.d/ntp/50-cbb"
	cp "$here/cbb.json" "$root/etc/capabilities/cbb.json"
	cp "$here/cbb.keep" "$root/lib/upgrade/keep.d/cbb"
	cp "$here/firewall.sh" "$root/usr/share/cbb/firewall.sh"
	# firewall.sh speaks through l10n.sh; the package, kept small for a
	# router's flash, carries no catalog, so its messages are in English.
	cp "$here/../l10n.sh" "$root/usr/share/cbb/l10n.sh"
	chmod 0755 "$root/usr/bin/cbb" "$root/etc/init.d/cbb"
	chmod 0644 "$root/etc/config/cbb" "$root/etc/hotplug.d/ntp/50-cbb" \
		"$root/etc/capabilities/cbb.json" "$root/lib/upgrade/keep.d/cbb" \
		"$root/usr/share/cbb/firewall.sh" "$root/usr/share/cbb/l10n.sh"

	mkdir -p "$out/$arch"
	apk mkpkg \
		--info "name:cbb" \
		--info "version:$version" \
		--info "arch:noarch" \
		--info "description:CBB: one clipboard for your phones and computers" \
		--info "license:AGPL-3.0-only" \
		--info "origin:cbb" \
		--info "url:https://cbb.tools" \
		--script "post-install:$here/apk-post-install" \
		--script "post-upgrade:$here/apk-post-install" \
		--script "pre-deinstall:$here/apk-pre-deinstall" \
		--files "$root" \
		--output "$out/$arch/cbb-$version.apk"
	if [ -n "$key" ]; then
		apk mkndx --allow-untrusted --sign-key "$key" --output "$out/$arch/packages.adb" "$out/$arch"/*.apk
	else
		apk mkndx --allow-untrusted --output "$out/$arch/packages.adb" "$out/$arch"/*.apk
	fi
	echo "$out/$arch/cbb-$version.apk"
	built=$((built + 1))
done
if [ $built -eq 0 ]; then
	echo "feed.sh: no cbb-linux-*.tar.gz in $dist" >&2
	exit 1
fi
