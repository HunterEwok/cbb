#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok
#
# A Platform SDK in DIR, for build.sh; as root on Linux x86_64, with 7z and
# about 10 GB free. SYSTEM in the environment picks it: aurora5 (the default,
# Aurora's SDK 5.1.5), aurora4 (Aurora's 4.0.2, armv7hl only) or sailfish
# (Sailfish OS's 4.6):
#   psdk.sh DIR setup [ARCH...]   downloads the SDK's chroot, tooling and the
#                                 targets of ARCH (armv7hl, aarch64; every one
#                                 the SDK has when none) into DIR/dl, kept for
#                                 the next run and each checked against its
#                                 SHA-256, unpacks the chroot into DIR/root,
#                                 makes the tooling and the targets, on Aurora 5
#                                 adds QCA's headers to them, and the user
#                                 builder, who builds
#   psdk.sh DIR run COMMAND       runs COMMAND in the SDK as builder
# The targets are named SDK-ARCH.default, SDK being AuroraOS-5.1.5.105-base,
# AuroraOS-4.0.2.303-base or SailfishOS-4.6.0.13 (psdk.sh DIR name prints it).
set -eu
if [ $# -lt 2 ]; then
	echo "usage: psdk.sh DIR setup [ARCH...] | psdk.sh DIR run COMMAND | psdk.sh DIR name" >&2
	exit 2
fi
dir=$1
root=$dir/root
system=${SYSTEM:-aurora5}

# Where each SDK's parts come from, and their SHA-256.
qca=
case $system in
aurora5)
	sdk=AuroraOS-5.1.5.105-base
	all="armv7hl aarch64"
	ext=7z
	base=https://sdk-repo.omprussia.ru/sdk/installers/5.1.5/5.1.5.105-release/AuroraPSDK/Aurora_OS-5.1.5.105-MB2-Aurora_
	chroot_url=${base}Platform_SDK_Chroot-x86_64.tar.bz2
	chroot_sum=5f6ef3f903cd187f73166ee9dd20b10948159ea3ba78cbaa2f5a92441c2bedd2
	tooling_url=${base}SDK_Tooling-x86_64.tar.7z
	tooling_sum=e16a37d5f04cdeca585208eaf047d3bf3e491f4d3dcfa13aba73db06cc6dac26
	target_armv7hl=757de4f283f4bcc9075d430b51d1d650c7ffc13a06bb3bd6d701643d9ef7338d
	target_aarch64=b4b6c83cbf189a1f0f9e0ab91e75ea6d25fe14266ba7f8b77e27bb70fd1446b5
	# QCA's headers, which the SDK lacks, for the key in OP-TEE.
	omp=https://releases.omprussia.ru/releases/5.1.5.105/omp/main/pj:oss:
	qca=qca-qt5-devel-2.3.2+omp46-1.1.19.omp
	qca_armv7hl=92f348d40872bf419d25905a0b02f9d017730b2a0c395ba9cea8d58fee148c0a
	qca_aarch64=db2eca799fa3c0a208753d0303dcf18f4bf77f055c77ede37345b9077d63c126
	;;
aurora4)
	sdk=AuroraOS-4.0.2.303-base
	all=armv7hl
	ext=bz2
	base=https://sdk-repo.omprussia.ru/sdk/installers/4.0.2/PlatformSDK/4.0.2.303/Aurora_OS-4.0.2.303-base-Aurora_
	chroot_url=${base}Platform_SDK_Chroot-i486.tar.bz2
	chroot_sum=ca6f2d9a1a9acddbc32c7e6033a93868883d844dc5dc694aee8d0eae689f5ba6
	tooling_url=${base}SDK_Tooling-i486.tar.bz2
	tooling_sum=7468b8f27036a3848bef1a8b66a2b02f4e6fc3024945090f19ba708bd8c99903
	target_armv7hl=14e7699cd2c5f2d14bef41c3df1110b68edf78c47dea9a1896d3c2095ec725e0
	;;
sailfish)
	sdk=SailfishOS-4.6.0.13
	all="armv7hl aarch64"
	ext=7z
	base=https://releases.sailfishos.org/sdk/targets/Sailfish_OS-4.6.0.13-Sailfish_SDK_
	# Jolla publishes only its latest chroot; when it changes, its sum here
	# changes with it.
	chroot_url=https://releases.sailfishos.org/sdk/installers/latest/Jolla-latest-SailfishOS_Platform_SDK_Chroot-i486.tar.bz2
	chroot_sum=7b2c351b888f6a3d1a9ff8ced5a341805d87b14f056f00e391c15e194b786e4f
	tooling_url=${base}Tooling-i486.tar.7z
	tooling_sum=f28f3f4231f7fb2d58a599ff6e4633385064d1646ab38b6800d14704430069ae
	target_armv7hl=c3effb2012dec48529286d4f11b9795013a5ea588a398550b920bba3b19e901e
	target_aarch64=7618f5dfead433dd837e6c895fdea9399452954e412624f5a406ce367e810dd1
	;;
*)
	echo "psdk.sh: unknown SYSTEM $system" >&2
	exit 2
	;;
esac

mounts() {
	for m in proc sys dev dev/pts; do
		mountpoint -q "$root/$m" || mount --bind "/$m" "$root/$m"
	done
	rm -f "$root/etc/resolv.conf"
	cp /etc/resolv.conf "$root/etc/resolv.conf"
}

case $2 in
name)
	echo "$sdk"
	exit 0
	;;
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
archs=${*:-$all}

mkdir -p "$dir/dl"
fetch() { # name url sha256
	if ! echo "$3  $dir/dl/$1" | sha256sum -c --status - 2>/dev/null; then
		# Jolla's server cuts long transfers off: each try goes on from
		# where the last one stopped.
		rm -f "$dir/dl/$1"
		n=0
		until curl -fsSL -C - -o "$dir/dl/$1" "$2"; do
			n=$((n + 1))
			[ $n -lt 30 ] || { echo "psdk.sh: cannot download $2" >&2; exit 1; }
			sleep 2
		done
		echo "$3  $dir/dl/$1" | sha256sum -c -
	fi
}
fetch chroot.tar.bz2 "$chroot_url" "$chroot_sum"
fetch "tooling.tar.$ext" "$tooling_url" "$tooling_sum"
for a in $archs; do
	case " $all " in
	*" $a "*) ;;
	*)
		echo "psdk.sh: $system has no architecture $a" >&2
		exit 2
		;;
	esac
	eval "sum=\$target_$a"
	case $system in
	aurora5) url=${base}SDK_Target-$a.tar.7z ;;
	aurora4) url=${base}SDK_Target-$a.tar.bz2 ;;
	sailfish) url=${base}Target-$a.tar.7z ;;
	esac
	fetch "target-$a.tar.$ext" "$url" "$sum"
	if [ -n "$qca" ]; then
		eval "sum=\$qca_$a"
		fetch "$qca.$a.rpm" "$omp/$a/$qca.$a.rpm" "$sum"
	fi
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
	sdk-assistant -y tooling create $sdk file:///mnt/dl/tooling.tar.$ext
	for a in $archs; do
		sdk-assistant -y target create $sdk-\$a file:///mnt/dl/target-\$a.tar.$ext
		if [ -n '$qca' ]; then
			# sb2 maps /mnt away, so the package goes through the home folder.
			cp /mnt/dl/$qca.\$a.rpm ~/
			# Into the snapshot that sdk-assistant made and mb2 builds in.
			sb2 -t $sdk-\$a.default -m sdk-install -R rpm -i --nodeps ~/$qca.\$a.rpm
			rm ~/$qca.\$a.rpm
		fi
	done
"
umount "$root/mnt/dl"
