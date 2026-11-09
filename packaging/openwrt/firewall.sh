#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# The hub's port in fw4 on OpenWrt (/usr/share/cbb/firewall.sh):
#
#   sh firewall.sh kind                      # fw4, or none
#   sh firewall.sh hub-open PORT | hub-close  # cbb global hub runs them, as root
#   sh firewall.sh hub-port | hub-commands PORT
#
# The same commands as packaging/linux/firewall.sh for the hub. The rules
# are the service's own procd data, which fw4 reads (the init script): the
# member port and mDNS from the zones in /etc/config/cbb, and the
# hub's UDP port from wan while /etc/cbb/firewall.hub names it.
# hub-open writes that file and reloads the service, which publishes the
# rule; hub-close removes it. /etc/config/firewall is never touched.
set -eu
# The messages in the user's language (packaging/l10n.sh, beside this file
# where install.sh put it, or in the archive).
cbb_l10n=$(cd "$(dirname "$0")" && pwd)/l10n
[ -f "$cbb_l10n.sh" ] || cbb_l10n=${cbb_l10n%/l10n}/../l10n
# shellcheck source=packaging/l10n.sh
. "$cbb_l10n.sh"

hubstate=/etc/cbb/firewall.hub

usage() {
	echo "usage: sh firewall.sh kind | hub-open PORT | hub-close | hub-port | hub-commands PORT" >&2
	exit 2
}

kind() {
	if [ -x /sbin/fw4 ]; then echo fw4; else echo none; fi
}

# apply has the service publish its rules again, and fw4 load them.
apply() {
	/etc/init.d/cbb reload >/dev/null 2>&1 || true
	/etc/init.d/firewall reload >/dev/null 2>&1 || true
}

[ $# -ge 1 ] || usage
cmd=$1
shift
case $cmd in
kind)
	kind
	;;
hub-port)
	if [ -f "$hubstate" ]; then
		read -r _ p <"$hubstate" || true
		echo "${p:-}"
	fi
	;;
hub-commands)
	[ $# -eq 1 ] || usage
	echo "  uci add firewall rule"
	echo "  uci set firewall.@rule[-1].name='cbb hub'"
	echo "  uci set firewall.@rule[-1].src=wan"
	echo "  uci set firewall.@rule[-1].proto=udp"
	echo "  uci set firewall.@rule[-1].dest_port=$1"
	echo "  uci set firewall.@rule[-1].target=ACCEPT"
	echo "  uci commit firewall && /etc/init.d/firewall reload"
	;;
hub-open)
	[ $# -eq 1 ] || usage
	case $1 in '' | *[!0-9]*) usage ;; esac
	[ "$(id -u)" -eq 0 ] || {
		note firewall.sh "run it as root"
		exit 1
	}
	mkdir -p /etc/cbb
	echo "fw4 $1" >"$hubstate"
	apply
	;;
hub-close)
	[ "$(id -u)" -eq 0 ] || {
		note firewall.sh "run it as root"
		exit 1
	}
	[ -f "$hubstate" ] || exit 0
	read -r _ p <"$hubstate" || true
	rm -f "$hubstate"
	apply
	say "Firewall: closed the hub's UDP port %s." "$p"
	;;
*) usage ;;
esac
