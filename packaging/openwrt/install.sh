#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Installs cbb, the full member or the lite one, on OpenWrt
# 25.12 or later, as root:
#
#   sh install.sh [--port N] [--auto-update on|off] [--no-pair] path/to/cbb
#
# It installs the binary to /usr/bin, the user and group cbb,
# the procd init script, the settings in /etc/config/cbb (kept
# when they exist), the NTP hook that starts the service once the clock is
# set, the capability file and the list of files sysupgrade keeps, and
# starts or restarts the service. The keys live in
# /etc/cbb/state. The service works on the devices of the lan
# zone; list other zones in /etc/config/cbb. Its firewall rules
# come and go with the service (the init script); /etc/config/firewall is
# not touched. --auto-update on|off (or CBB_AUTO_UPDATE) answers whether the
# full member updates itself once a day to a signed release, from cron,
# which it asks otherwise and keeps (packaging/update.sh). The lite member,
# once running and in no group, starts pairing and shows its QR code at once
# (packaging/pair.sh); --no-pair (CBB_PAIR=no) leaves that for later. uninstall.sh
# removes it all again.
set -eu

if [ "${CBB_ERROR_DETAILS:-}" = 1 ]; then
	set -x
fi
failed() {
	rc=$1
	if [ "$rc" -ne 0 ] && [ "$rc" -ne 2 ] && [ "${CBB_ERROR_DETAILS:-}" != 1 ]; then
		echo "install.sh: failed (exit status $rc). For every command it ran: CBB_ERROR_DETAILS=1, and run it again." >&2
	fi
}
trap 'failed $?' EXIT

usage() {
	echo "usage: sh install.sh [--port N] [--auto-update on|off] [--no-pair] path/to/cbb" >&2
	exit 2
}
port=
auto=
while [ $# -gt 1 ]; do
	case $1 in
	--port)
		port=$2
		shift
		;;
	--auto-update)
		case $2 in
		on | off) auto=$2 ;;
		*) usage ;;
		esac
		shift
		;;
	# get.sh passes the firewall choice; the rules here are the service's own.
	--express | --no-firewall) ;;
	--no-pair) CBB_PAIR=no ;;
	*) usage ;;
	esac
	shift
done
[ $# -eq 1 ] || usage
case $port in
'') ;;
*[!0-9]*) usage ;;
*)
	if [ "$port" -lt 1024 ] || [ "$port" -gt 65535 ]; then
		echo "install.sh: --port takes a port from 1024 to 65535" >&2
		exit 2
	fi
	;;
esac
bin=$1
case $bin in
*/*) ;;
*) bin=./$bin ;;
esac
here=$(cd "$(dirname "$0")" && pwd)

if [ "$(id -u)" -ne 0 ]; then
	echo "install.sh: run it as root" >&2
	exit 1
fi
if [ ! -f /etc/openwrt_release ]; then
	echo "install.sh: this installer is for OpenWrt" >&2
	exit 1
fi
if ! command -v apk >/dev/null 2>&1; then
	echo "install.sh: OpenWrt 25.12 or later is required (it installs packages with apk)" >&2
	exit 1
fi
if ! "$bin" version >/dev/null 2>&1; then
	echo "install.sh: $bin does not run on this router; is it built for $(uname -m)?" >&2
	exit 1
fi

# OpenWrt's functions.sh reads unset variables, such as IPKG_INSTROOT.
set +u
# shellcheck disable=SC1091
. /lib/functions.sh
gid=$(group_add_next cbb)
if ! user_exists cbb; then
	user_add cbb "" "$gid" "CBB" /var/run/cbb /bin/false
fi
set -u

# put MODE SOURCE TARGET; OpenWrt's busybox may have no install.
put() {
	cp "$2" "$3.new"
	chmod "$1" "$3.new"
	mv -f "$3.new" "$3"
}
mkdir -p /usr/share/cbb /etc/hotplug.d/ntp /lib/upgrade/keep.d /etc/capabilities
put 0755 "$bin" /usr/bin/cbb
put 0755 "$here/cbb.init" /etc/init.d/cbb
put 0644 "$here/cbb.ntp" /etc/hotplug.d/ntp/50-cbb
put 0644 "$here/cbb.keep" /lib/upgrade/keep.d/cbb
put 0644 "$here/cbb.json" /etc/capabilities/cbb.json
put 0644 "$here/firewall.sh" /usr/share/cbb/firewall.sh
put 0644 "$here/uninstall.sh" /usr/share/cbb/uninstall.sh
if [ ! -f /etc/config/cbb ]; then
	put 0644 "$here/cbb.config" /etc/config/cbb
fi
if [ -n "$port" ]; then
	uci set cbb.main.port="$port"
	uci commit cbb
fi
port=$(uci -q get cbb.main.port || echo 8764)
mkdir -p /etc/cbb/state
chmod 0700 /etc/cbb/state
chown cbb:cbb /etc/cbb/state
# How this copy came, and automatic updates.
# shellcheck source=packaging/update.sh
. "$here/../update.sh"
update_setup /usr/bin/cbb "$bin" "$auto"

# The router is up and has set its clock long ago; the wait for NTP is for
# the next boot.
mkdir -p /var/state
touch /var/state/cbb.time

/etc/init.d/cbb enable
if ! ubus call service list >/dev/null 2>&1; then
	# A root file system without procd, such as a container.
	echo "CBB is installed; procd is not running here, so it starts at the next boot."
	exit 0
fi
/etc/init.d/cbb restart

answers() { # cbb
	i=0
	while [ $i -lt 40 ]; do
		out=$(CBB_SOCKET=/var/run/cbb/control.sock "$1" status 2>&1) && return 0
		case $out in *"in a group"* | *"no group"*) return 0 ;; esac
		sleep 1
		i=$((i + 1))
	done
	echo "install.sh: the service did not answer within 40 s: $out" >&2
	echo "install.sh: see logread -e cbb" >&2
	return 1
}
answers /usr/bin/cbb || true
echo "CBB is running on TCP port $port, on the lan zone. To remove it: sh /usr/share/cbb/uninstall.sh"
echo "Packages from outside OpenWrt's feeds are left out by attended sysupgrade (ASU, owut): install it again after one."
if /usr/bin/cbb version 2>/dev/null | grep -q "lite member"; then
	# shellcheck source=packaging/pair.sh
	. "$here/../pair.sh"
	if ! CBB_SOCKET=/var/run/cbb/control.sock pair_now /usr/bin/cbb cbb -name router; then
		echo "Next: run su -s /bin/sh cbb -c 'cbb pair -name router' and scan its QR code with the CBB app on your phone."
	fi
else
	echo "Next: run cbb pair and scan its QR code with the CBB app on your phone."
fi
