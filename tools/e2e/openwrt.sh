#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Tests the OpenWrt installer on OpenWrt itself (CI's openwrt job):
#
#   sh tools/e2e/openwrt.sh rootfs RELEASE_DIR   # in openwrt/rootfs, with docker
#   sh tools/e2e/openwrt.sh vm RELEASE_DIR       # OpenWrt booted in QEMU with KVM
#   sh tools/e2e/openwrt.sh feed RELEASE_DIR     # the apk feed, built in Alpine
#
# RELEASE_DIR holds a linux-amd64 release archive, SHA256SUMS and get.sh, as
# get.sh's CBB_RELEASE_DIR takes them. rootfs installs and removes it in
# OpenWrt's root file system, without procd. vm boots OpenWrt's x86-64 image
# with lan on a user-mode network that forwards SSH, installs it, and checks
# the procd instance, the interface list, the hub's firewall rule (procd
# service data that fw4 loads), the wait for NTP, and the removal. feed
# builds the signed apk feed with packaging/openwrt/feed.sh and a key made
# for the test in Alpine, whose apk has mkpkg and mkndx (OpenWrt's leaves
# them out), and installs and removes the package from it in openwrt/rootfs.
# The scripts in single quotes run on OpenWrt, which expands them.
# shellcheck disable=SC2016
set -eu

release=25.12.6
image=openwrt/rootfs:x86_64-$release@sha256:14401c04218c2e0da0448f099710ada2460636a92395f353351cc616cf3f67af
alpine=alpine:3.23@sha256:3d67941fed5ae436b2bb9791cb3f50a252441c7706bbc5b4e738936df8ff8306

[ $# -eq 2 ] || {
	echo "usage: sh tools/e2e/openwrt.sh rootfs|vm|feed RELEASE_DIR" >&2
	exit 2
}
mode=$1
rel=$(cd "$2" && pwd)
work=${RUNNER_TEMP:-/tmp}/openwrt-e2e
mkdir -p "$work"

# The checks after an install, and after the removal, in OpenWrt's shell.
installed_files='
test -x /usr/bin/cbb
test -x /etc/init.d/cbb
test -f /etc/config/cbb
test -f /etc/hotplug.d/ntp/50-cbb
test -f /lib/upgrade/keep.d/cbb
test -f /etc/capabilities/cbb.json
grep -q "^cbb:" /etc/passwd
grep -q "^cbb:" /etc/group
test "$(ls -ld /etc/cbb/state | awk "{print \$3}")" = cbb
ls /etc/rc.d | grep -q cbb
ash -n /etc/init.d/cbb
ash -n /usr/share/cbb/firewall.sh
'
# set -x names the check that failed in CI's log.
installed="
set -ex
$installed_files
test \"\$(uci get cbb.main.port)\" = 9000
"
removed='
set -e
for f in /usr/bin/cbb /etc/init.d/cbb /etc/config/cbb /etc/hotplug.d/ntp/50-cbb \
	/lib/upgrade/keep.d/cbb /etc/capabilities/cbb.json /usr/share/cbb /etc/cbb \
	/etc/cbb-update; do
	if [ -e "$f" ]; then echo "left behind: $f" >&2; exit 1; fi
done
if ls /etc/rc.d | grep -q cbb; then echo "left enabled" >&2; exit 1; fi
'

case $mode in
rootfs)
	docker run --rm -v "$rel:/rel:ro" "$image" /bin/sh -c "
		set -e
		mkdir -p /var/lock /var/run /tmp
		CBB_VERIFY=skip CBB_RELEASE_DIR=/rel sh /rel/get.sh --port 9000
		$installed
		sh /usr/share/cbb/uninstall.sh --purge
		$removed
		echo 'rootfs: installed and removed'
		CBB_VERIFY=skip CBB_RELEASE_DIR=/rel sh /rel/get.sh --lite --port 9000
		$installed
		cbb version | grep -q 'lite member'
		sh /usr/share/cbb/uninstall.sh --purge
		$removed
		echo 'rootfs: the lite member installed and removed'
	"
	;;
feed)
	src=$(cd "$(dirname "$0")/../.." && pwd)
	mkdir -p "$work/key"
	openssl ecparam -name prime256v1 -genkey -noout -out "$work/key/private.pem"
	openssl ec -in "$work/key/private.pem" -pubout -out "$work/key/public.pem" 2>/dev/null
	mkdir -p "$work/feed"
	docker run --rm -v "$rel:/rel:ro" -v "$src:/src:ro" -v "$work/key:/key:ro" -v "$work/feed:/feed" "$alpine" \
		sh /src/packaging/openwrt/feed.sh v0.0.0-rc.1 /rel /feed /key/private.pem
	docker run --rm -v "$work/feed:/feed:ro" -v "$work/key:/key:ro" "$image" /bin/sh -c "
		set -e
		mkdir -p /var/lock /var/run /tmp
		test -f /feed/amd64/packages.adb
		# Without our key apk refuses the feed.
		if apk add --repositories-file /dev/null --repository /feed/amd64/packages.adb cbb 2>/dev/null; then
			echo 'apk took a feed signed with an unknown key' >&2
			exit 1
		fi
		cp /key/public.pem /etc/apk/keys/cbb.pem
		apk add --repositories-file /dev/null --repository /feed/amd64/packages.adb cbb
		apk info -e cbb
		$installed_files
		apk del cbb
		for f in /usr/bin/cbb /etc/init.d/cbb /usr/share/cbb/firewall.sh; do
			if [ -e \"\$f\" ]; then echo \"apk del left \$f\" >&2; exit 1; fi
		done
		if ls /etc/rc.d | grep -q cbb; then echo 'left enabled' >&2; exit 1; fi
		echo 'feed: signed, installed and removed'
	"
	;;
vm)
	img=$work/openwrt-$release-x86-64-generic-ext4-combined.img
	if [ ! -f "$img" ]; then
		base=https://downloads.openwrt.org/releases/$release/targets/x86/64
		curl -fsSL -o "$img.gz" "$base/${img##*/}.gz"
		curl -fsSL -o "$work/sha256sums" "$base/sha256sums"
		want=$(awk -v f="*${img##*/}.gz" '$2 == f { print $1 }' "$work/sha256sums")
		if [ -z "$want" ] || [ "$(sha256sum "$img.gz" | cut -d' ' -f1)" != "$want" ]; then
			echo "the image does not match OpenWrt's sha256sums" >&2
			exit 1
		fi
		# OpenWrt pads its images, which gzip reports as trailing garbage.
		gunzip -f "$img.gz" || [ -s "$img" ]
	fi
	# lan (eth0) is OpenWrt's 192.168.1.1 on a user-mode network of that
	# range, with SSH forwarded; wan (eth1) gets an address by DHCP.
	qemu-system-x86_64 -enable-kvm -m 512 -smp 2 -display none -daemonize \
		-pidfile "$work/qemu.pid" -serial "file:$work/console.log" \
		-drive "file=$img,format=raw,if=virtio" \
		-netdev "user,id=lan,net=192.168.1.0/24,host=192.168.1.2,dhcpstart=192.168.1.100,hostfwd=tcp:127.0.0.1:2222-192.168.1.1:22" \
		-device virtio-net-pci,netdev=lan \
		-netdev user,id=wan -device virtio-net-pci,netdev=wan
	trap 'kill "$(cat "$work/qemu.pid")" 2>/dev/null || true' EXIT
	opts="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o PubkeyAuthentication=no -o PasswordAuthentication=yes -p 2222"
	# A fresh OpenWrt lets root in without a password.
	# shellcheck disable=SC2086 # $opts is words
	run() { sshpass -p '' ssh $opts root@127.0.0.1 "$@"; }
	i=0
	until run true 2>/dev/null; do
		i=$((i + 1))
		if [ $i -gt 90 ]; then
			echo "OpenWrt did not answer on SSH; its console:" >&2
			cat "$work/console.log" >&2
			exit 1
		fi
		sleep 2
	done
	# Dropbear has no SFTP server, so the files go through tar.
	tar -C "$rel" -cf - . | run 'mkdir -p /tmp/rel && tar -C /tmp/rel -xf -'
	run 'CBB_VERIFY=skip CBB_RELEASE_DIR=/tmp/rel sh /tmp/rel/get.sh --port 9000'
	run "$installed"
	run '
		set -ex
		ubus call service list "{\"name\":\"cbb\"}" | grep -q "\"running\": true"
		for i in $(seq 30); do cbb status 2>&1 | grep -q "Not in a group" && break; sleep 1; done
		cbb status 2>&1 | grep -q "Not in a group"
		logread -e cbb | grep -q "work only on br-lan"
		# Out of a group the member port opens only for a join: cbb pair
		# waits for the phone there.
		cbb pair </dev/null >/tmp/pair.out 2>&1 &
		for i in $(seq 20); do netstat -ltn | grep -q ":9000 " && break; sleep 1; done
		netstat -ltn | grep -q ":9000 "
		kill $!
		echo "vm: the service runs on br-lan, and a join waits on port 9000"

		# The port of the hub: service data, which fw4 loads. fw4 names such
		# a rule by its source (ubus:cbb[instance1] rule N) in
		# its comment, not by the name in the data.
		sh /usr/share/cbb/firewall.sh hub-open 51820
		test "$(sh /usr/share/cbb/firewall.sh hub-port)" = 51820
		hubrule() { nft list ruleset | grep "ubus:cbb" | grep -q "dport 51820"; }
		for i in $(seq 20); do hubrule && break; sleep 1; done
		if ! hubrule; then
			echo "no hub rule in nftables; the service data and what fw4 makes of it:" >&2
			ubus call service get_data "{\"type\":\"firewall\"}" >&2 || true
			fw4 print 2>&1 | grep -i -B2 -A2 cbb >&2 || true
			exit 1
		fi
		sh /usr/share/cbb/firewall.sh hub-close
		for i in $(seq 20); do hubrule || break; sleep 1; done
		if hubrule; then echo "the hub rule stayed" >&2; exit 1; fi
		if grep -q cbb /etc/config/firewall; then echo "/etc/config/firewall was changed" >&2; exit 1; fi
		echo "vm: the hub rule came and went with the service data"

		# After a boot the service waits for NTP; ntpd itself stays out of it.
		# The old process may take a moment to exit, and NTP events that
		# ntpd sent before it stopped may still bring the flag back, more than
		# once; then the start proves nothing and is tried again. Only a
		# service that runs without the flag fails, and the wait must be seen
		# without the flag at least once.
		/etc/init.d/sysntpd stop
		waited=
		for try in 1 2 3 4 5; do
			/etc/init.d/cbb stop
			for i in $(seq 20); do pgrep -f "cbb service" >/dev/null || break; sleep 1; done
			if pgrep -f "cbb service" >/dev/null; then echo "it did not stop" >&2; exit 1; fi
			rm -f /var/state/cbb.time
			/etc/init.d/cbb start
			sleep 2
			if [ ! -f /var/state/cbb.time ]; then
				if pgrep -f "cbb service" >/dev/null; then echo "it started before NTP" >&2; exit 1; fi
				waited=1
				break
			fi
			echo "vm: a late NTP event set the flag again; checking the wait once more"
		done
		if [ -z "$waited" ]; then echo "late NTP events kept setting the flag; the wait was never checked" >&2; exit 1; fi
		ACTION=stratum sh /etc/hotplug.d/ntp/50-cbb
		for i in $(seq 20); do pgrep -f "cbb service" >/dev/null && break; sleep 1; done
		pgrep -f "cbb service" >/dev/null
		echo "vm: it waited for NTP and started after it"

		# UCI: the port reaches the service as CBB_PORT after a reload, and
		# back; procd starts a killed service again.
		svcpid() { pgrep -x -f "/usr/bin/cbb service.*" | head -n1; }
		hasenv() { p=$(svcpid); [ -n "$p" ] && tr "\0" "\n" </proc/$p/environ | grep -qx "$1"; }
		hasenv CBB_PORT=9000
		for port in 9001 9000; do
			uci set cbb.main.port=$port && uci commit cbb
			/etc/init.d/cbb reload
			for i in $(seq 20); do hasenv CBB_PORT=$port && break; sleep 1; done
			hasenv CBB_PORT=$port
		done
		old=$(svcpid)
		kill -9 "$old"
		for i in $(seq 30); do p=$(svcpid); [ -n "$p" ] && [ "$p" != "$old" ] && break; sleep 1; done
		p=$(svcpid); [ -n "$p" ] && [ "$p" != "$old" ]
		echo "vm: UCI changes reach the service, and procd starts it again"

		# A sysupgrade keeps the state, the settings and the program: its
		# list of kept files and its backup hold them.
		touch /etc/cbb/state/keep-probe
		sysupgrade -l >/tmp/keep.list
		for f in /etc/cbb/state/keep-probe /etc/config/cbb /usr/bin/cbb /etc/init.d/cbb; do
			grep -qx "$f" /tmp/keep.list || { echo "sysupgrade would not keep $f" >&2; exit 1; }
		done
		sysupgrade -b /tmp/backup.tgz
		tar -tzf /tmp/backup.tgz | grep -qx "etc/cbb/state/keep-probe"
		echo "vm: a sysupgrade keeps the state, the settings and the program"

		sh /usr/share/cbb/uninstall.sh --purge
		if pgrep -f "cbb service" >/dev/null; then echo "still running" >&2; exit 1; fi
	'
	run "$removed"
	echo "vm: installed, checked and removed"

	# The lite member, from the same init script.
	run 'CBB_VERIFY=skip CBB_RELEASE_DIR=/tmp/rel sh /tmp/rel/get.sh --lite --port 9000'
	run "$installed"
	run '
		set -ex
		cbb version | grep -q "lite member"
		ubus call service list "{\"name\":\"cbb\"}" | grep -q "\"running\": true"
		for i in $(seq 30); do logread -e cbb | grep -q "work only on br-lan" && break; sleep 1; done
		logread -e cbb | grep -q "work only on br-lan"
		grep -qx br-lan /var/run/cbb/interfaces
		cbb status 2>&1 | grep -q "Not in a group"
		sh /usr/share/cbb/uninstall.sh --purge
	'
	run "$removed"
	echo "vm: the lite member installed, checked and removed"
	;;
*)
	echo "usage: sh tools/e2e/openwrt.sh rootfs|vm|feed RELEASE_DIR" >&2
	exit 2
	;;
esac
