#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok
#
# Aurora's Platform SDK 5.1.5 in DIR, for build.sh; as root on Linux x86_64,
# with 7z and about 10 GB free:
#   psdk.sh DIR setup [ARCH...]   downloads the SDK's chroot, tooling and the
#                                 targets of ARCH (armv7hl, aarch64; both when
#                                 none) into DIR/dl, kept for the next run and
#                                 each checked against its SHA-256, unpacks the
#                                 chroot into DIR/root, makes the tooling and
#                                 the targets, adds QCA's headers to them and
#                                 the user builder, who builds
#   psdk.sh DIR run COMMAND       runs COMMAND in the SDK as builder
set -eu
if [ $# -lt 2 ]; then
	echo "usage: psdk.sh DIR setup [ARCH...] | psdk.sh DIR run COMMAND" >&2
	exit 2
fi
dir=$1
root=$dir/root
sdk=AuroraOS-5.1.5.105-base

mounts() {
	for m in proc sys dev dev/pts; do
		mountpoint -q "$root/$m" || mount --bind "/$m" "$root/$m"
	done
	rm -f "$root/etc/resolv.conf"
	cp /etc/resolv.conf "$root/etc/resolv.conf"
}

case $2 in
run)
	[ $# -eq 3 ] || { echo "usage: psdk.sh DIR run COMMAND" >&2; exit 2; }
	mounts
	exec chroot "$root" su - builder -c "$3"
	;;
setup) shift 2 ;;
*)
	echo "psdk.sh: unknown command $2" >&2
	exit 2
	;;
esac
archs=${*:-armv7hl aarch64}

psdk=https://sdk-repo.omprussia.ru/sdk/installers/5.1.5/5.1.5.105-release/AuroraPSDK/Aurora_OS-5.1.5.105-MB2-Aurora_
omp=https://releases.omprussia.ru/releases/5.1.5.105/omp/main/pj:oss:
qca=qca-qt5-devel-2.3.2+omp46-1.1.19.omp
mkdir -p "$dir/dl"
fetch() { # name url sha256
	if ! echo "$3  $dir/dl/$1" | sha256sum -c --status - 2>/dev/null; then
		curl -fsSL --retry 5 --retry-all-errors -o "$dir/dl/$1" "$2"
		echo "$3  $dir/dl/$1" | sha256sum -c -
	fi
}
fetch chroot.tar.bz2 "${psdk}Platform_SDK_Chroot-x86_64.tar.bz2" 5f6ef3f903cd187f73166ee9dd20b10948159ea3ba78cbaa2f5a92441c2bedd2
fetch tooling.tar.7z "${psdk}SDK_Tooling-x86_64.tar.7z" e16a37d5f04cdeca585208eaf047d3bf3e491f4d3dcfa13aba73db06cc6dac26
for a in $archs; do
	case $a in
	armv7hl)
		fetch target-armv7hl.tar.7z "${psdk}SDK_Target-armv7hl.tar.7z" 757de4f283f4bcc9075d430b51d1d650c7ffc13a06bb3bd6d701643d9ef7338d
		fetch "$qca.armv7hl.rpm" "$omp/armv7hl/$qca.armv7hl.rpm" 92f348d40872bf419d25905a0b02f9d017730b2a0c395ba9cea8d58fee148c0a
		;;
	aarch64)
		fetch target-aarch64.tar.7z "${psdk}SDK_Target-aarch64.tar.7z" b4b6c83cbf189a1f0f9e0ab91e75ea6d25fe14266ba7f8b77e27bb70fd1446b5
		fetch "$qca.aarch64.rpm" "$omp/aarch64/$qca.aarch64.rpm" db2eca799fa3c0a208753d0303dcf18f4bf77f055c77ede37345b9077d63c126
		;;
	*)
		echo "psdk.sh: unknown architecture $a" >&2
		exit 2
		;;
	esac
done

mkdir -p "$root"
tar -xjf "$dir/dl/chroot.tar.bz2" --numeric-owner -p -C "$root"
mounts
mkdir -p "$root/mnt/dl"
mountpoint -q "$root/mnt/dl" || mount --bind "$dir/dl" "$root/mnt/dl"
# sdk-assistant refuses root and asks sudo for what it installs.
chroot "$root" /bin/bash -lc "
	set -e
	id builder >/dev/null 2>&1 || useradd -m -u 1000 builder
	echo 'builder ALL=(ALL) NOPASSWD: ALL' >/etc/sudoers.d/builder
	chmod 440 /etc/sudoers.d/builder
"
chroot "$root" su - builder -c "
	set -e
	sdk-assistant -y tooling create $sdk file:///mnt/dl/tooling.tar.7z
	for a in $archs; do
		sdk-assistant -y target create $sdk-\$a file:///mnt/dl/target-\$a.tar.7z
		# sb2 maps /mnt away, so the package goes through the home folder.
		cp /mnt/dl/$qca.\$a.rpm ~/
		# Into the snapshot that sdk-assistant made and mb2 builds in.
		sb2 -t $sdk-\$a.default -m sdk-install -R rpm -i --nodeps ~/$qca.\$a.rpm
		rm ~/$qca.\$a.rpm
	done
"
umount "$root/mnt/dl"
